#pragma once
#include "ModelJson.h"
#include "AgentAssertions.h"
#include <stdio.h>
#include <algorithm>

static const size_t kAgentTaskEvidenceLimit = 256;

struct AgentTaskStep {
    std::string title, criterion, kind, status, reason;
    int retries, last_mutation;
    int assigned_model, actual_model;
    std::string model_name, output;
    std::string agreement_group, proposal, started, finished, failure;
    std::vector<int> depends_on, evidence_ids;
    std::vector<AgentAssertion> checks;
    AgentTaskStep() : status("pending"), retries(0), last_mutation(-1), assigned_model(-1), actual_model(-1) {}
};

struct AgentTaskEvidence {
    std::string tool, arguments, result;
    std::string context_revision;
    std::string observed, target, context, source_digest, project_scope;
    int step;
    bool success, read_only, truncated;
};

struct AgentTaskOperation {
    std::string id, tool, arguments, result, state;
    std::string context_revision;
    std::string rollback_arguments, rollback_expected, rollback_target, rollback_state;
    int step, risk;
    AgentTaskOperation() : step(-1), risk(2), state("dispatching") {}
};

static bool TaskOperationMatches(const AgentTaskOperation& op, int step,
    const std::string& tool, const std::string& arguments,
    const std::string& context_revision)
{
    if (op.step != step || op.risk == 0 || op.tool != tool || op.arguments != arguments) return false;
    bool repeatable = tool == "run" || tool == "go" || tool == "step_into" ||
        tool == "step_over" || tool == "trace_into" || tool == "trace_over";
    if (repeatable && op.state == "completed" && !op.context_revision.empty() &&
        !context_revision.empty() && op.context_revision != context_revision) return false;
    return true;
}

struct AgentTask {
    std::string id, goal, title, state, last_feedback;
    std::vector<AgentTaskStep> steps;
    std::vector<AgentTaskEvidence> evidence;
    std::vector<std::string> events;
    std::vector<std::string> timeline;
    std::string server_binding;
    std::string target_identity, context_revision;
    int replans;
    std::string checkpoint_stamp;
    std::vector<AgentTaskOperation> operations;
    std::vector<std::string> checkpoint_history;
    bool recovering;
    bool waiting_event;
    std::string wait_cursor;
    AgentTask() : replans(0), state("idle"), recovering(false), waiting_event(false) {}
};

static bool TaskString(const ModelJson& json, const char* key, std::string* value, size_t max)
{
    const ModelJson* field = json.get(key);
    if (!field || field->kind != ModelJson::STRING || field->value.empty() || field->value.size() > max) return false;
    *value = field->value;
    return true;
}

static int TaskCurrentStep(const AgentTask& task)
{
    for (size_t i = 0; i < task.steps.size(); ++i)
        if (task.steps[i].status != "done") return (int)i;
    return -1;
}

static bool ParseTaskPlan(const std::string& text, AgentTask* task)
{
    ModelJson json;
    if (!ModelJson::parse(text, &json)) return false;
    std::string title;
    const ModelJson* steps = json.get("steps");
    if (!TaskString(json, "title", &title, 160) || !steps || steps->kind != ModelJson::ARRAY ||
        steps->items.empty() || steps->items.size() > 8) return false;
    std::vector<AgentTaskStep> parsed;
    for (size_t i = 0; i < steps->items.size(); ++i) {
        AgentTaskStep step;
        const ModelJson* group = steps->items[i].get("agreement_group");
        if (group) {
            if (group->kind != ModelJson::STRING || group->value.size() > 64 || group->value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos) return false;
            step.agreement_group = group->value;
        }
        if (!ParseAssertions(steps->items[i].get("checks"), &step.checks)) return false;
        if (!TaskString(steps->items[i], "title", &step.title, 256) ||
            !TaskString(steps->items[i], "criterion", &step.criterion, 2048) ||
            !TaskString(steps->items[i], "kind", &step.kind, 32) ||
            (step.kind != "analysis" && step.kind != "observation" && step.kind != "mutation")) return false;
        if (!step.agreement_group.empty() && step.kind != "analysis") return false;
        const ModelJson* model = steps->items[i].get("model_slot");
        if (model) {
            if (model->kind != ModelJson::NUMBER || model->value.size() != 1 || model->value[0] < '0' || model->value[0] > '3') return false;
            step.assigned_model = model->value[0] - '0';
        }
        const ModelJson* dependencies = steps->items[i].get("depends_on");
        if (dependencies) {
            if (dependencies->kind != ModelJson::ARRAY || dependencies->items.size() > i) return false;
            for (size_t d = 0; d < dependencies->items.size(); ++d) {
                const ModelJson& index = dependencies->items[d];
                if (index.kind != ModelJson::NUMBER || index.value.size() != 1 || index.value[0] < '1' ||
                    (size_t)(index.value[0] - '0') > i) return false;
                int value = index.value[0] - '1';
                for (size_t k = 0; k < step.depends_on.size(); ++k) if (step.depends_on[k] == value) return false;
                step.depends_on.push_back(value);
            }
        }
        parsed.push_back(step);
    }
    task->title = title;
    task->steps.swap(parsed);
    task->state = "running";
    return true;
}

static bool TaskToolSucceeded(const std::string& text)
{
    ModelJson json;
    if (!ModelJson::parse(text, &json) || json.kind != ModelJson::OBJECT || json.get("error")) return false;
    const ModelJson* result = json.get("result");
    if (!result || result->kind == ModelJson::NIL) return false;
    const ModelJson* is_error = result->get("isError");
    const ModelJson* ok = result->get("ok");
    const ModelJson* success = result->get("success");
    return !(is_error && is_error->kind == ModelJson::BOOLEAN && is_error->value == "true") &&
        !(ok && ok->kind == ModelJson::BOOLEAN && ok->value == "false") &&
        !(success && success->kind == ModelJson::BOOLEAN && success->value == "false");
}

static bool TaskObservationSucceeded(const std::string& tool, const std::string& text)
{
    return TaskToolSucceeded(text) || AgentLookupMiss(tool, text);
}

static bool TaskHasFailedTool(const AgentTask& task, int step, bool read_only)
{
    for (size_t i = 0; i < task.evidence.size(); ++i) {
        const AgentTaskEvidence& evidence = task.evidence[i];
        if (evidence.step == step && evidence.read_only == read_only && !evidence.success) return true;
    }
    return false;
}

static bool ParseTaskContract(const std::string& text, AgentTask* task)
{
    ModelJson root; AgentTask parsed;
    if (text.size() > 128 * 1024 || !ModelJson::parse(text, &root) || !TaskString(root, "goal", &parsed.goal, 8192) || !ParseTaskPlan(text, &parsed)) return false;
    bool has_check = false;
    for (size_t i = 0; i < parsed.steps.size(); ++i) {
        if (parsed.steps[i].kind != "analysis" && parsed.steps[i].checks.empty()) return false;
        if (!parsed.steps[i].checks.empty()) has_check = true;
    }
    if (!has_check) return false;
    *task = parsed; return true;
}

static std::string TaskNumber(int value)
{
    char text[32];
    sprintf_s(text, sizeof(text), "%d", value);
    return text;
}

static std::string TaskJson(const AgentTask& task, bool compact = false)
{
    std::string out = "{\"version\":2,\"id\":";
    ModelJson::quote(&out, task.id);
    out += ",\"goal\":"; ModelJson::quote(&out, task.goal);
    out += ",\"title\":"; ModelJson::quote(&out, task.title);
    out += ",\"state\":"; ModelJson::quote(&out, task.state);
    out += ",\"feedback\":"; ModelJson::quote(&out, task.last_feedback);
    out += ",\"target_identity\":"; ModelJson::quote(&out, task.target_identity);
    out += ",\"context_revision\":"; ModelJson::quote(&out, task.context_revision);
    out += ",\"waiting_event\":" + std::string(task.waiting_event ? "true" : "false");
    out += ",\"wait_cursor\":"; ModelJson::quote(&out, task.wait_cursor);
    out += ",\"replans\":" + TaskNumber(task.replans);
    out += ",\"steps\":[";
    for (size_t i = 0; i < task.steps.size(); ++i) {
        const AgentTaskStep& step = task.steps[i];
        if (i) out += ',';
        out += "{\"index\":" + TaskNumber((int)i + 1) + ",\"title\":";
        ModelJson::quote(&out, step.title);
        out += ",\"criterion\":"; ModelJson::quote(&out, step.criterion);
        out += ",\"kind\":"; ModelJson::quote(&out, step.kind);
        if (!step.checks.empty()) out += ",\"checks\":" + AssertionsJson(step.checks);
        out += ",\"status\":"; ModelJson::quote(&out, step.status);
        out += ",\"reason\":"; ModelJson::quote(&out, step.reason);
        out += ",\"model_slot\":" + TaskNumber(step.assigned_model) + ",\"actual_model_slot\":" + TaskNumber(step.actual_model);
        out += ",\"model_name\":"; ModelJson::quote(&out, step.model_name);
        out += ",\"agreement_group\":"; ModelJson::quote(&out, step.agreement_group);
        out += ",\"proposal\":"; ModelJson::quote(&out, compact ? step.proposal.substr(0, 2048) : step.proposal);
        out += ",\"started\":"; ModelJson::quote(&out, step.started);
        out += ",\"finished\":"; ModelJson::quote(&out, step.finished);
        out += ",\"failure\":"; ModelJson::quote(&out, step.failure);
        out += ",\"shared_result\":"; ModelJson::quote(&out, compact ? step.output.substr(0, 2048) : step.output);
        out += ",\"depends_on\": [";
        for (size_t d = 0; d < step.depends_on.size(); ++d) { if (d) out += ','; out += TaskNumber(step.depends_on[d] + 1); }
        out += "],\"verified_evidence\":[";
        for (size_t e = 0; e < step.evidence_ids.size(); ++e) { if (e) out += ','; out += TaskNumber(step.evidence_ids[e]); }
        out += ']';
        out += ",\"retries\":" + TaskNumber(step.retries) +
            ",\"last_mutation_evidence\":" + TaskNumber(step.last_mutation + 1) + "}";
    }
    out += "],\"evidence\":[";
    bool first = true;
    for (size_t i = 0; i < task.evidence.size(); ++i) {
        const AgentTaskEvidence& item = task.evidence[i];
        if (compact && (item.step != TaskCurrentStep(task) || i + 12 < task.evidence.size())) continue;
        if (!first) out += ',';
        first = false;
        out += "{\"id\":" + TaskNumber((int)i + 1) + ",\"step\":" + TaskNumber(item.step + 1) + ",\"tool\":";
        ModelJson::quote(&out, item.tool);
        out += ",\"arguments\":"; ModelJson::quote(&out, compact ? item.arguments.substr(0, 2048) : item.arguments);
        out += ",\"result\":"; ModelJson::quote(&out, item.result);
        out += ",\"context_revision\":"; ModelJson::quote(&out, item.context_revision);
        out += ",\"observed\":"; ModelJson::quote(&out, item.observed);
        out += ",\"target\":"; ModelJson::quote(&out, item.target);
        out += ",\"context\":"; ModelJson::quote(&out, compact ? std::string() : item.context);
        out += ",\"source_digest\":"; ModelJson::quote(&out, item.source_digest);
        out += ",\"project_scope\":"; ModelJson::quote(&out, item.project_scope);
        out += std::string(",\"success\":") + (item.success ? "true" : "false") +
            ",\"read_only\":" + (item.read_only ? "true" : "false") +
            ",\"truncated\":" + (item.truncated ? "true" : "false") + "}";
    }
    out += "],\"events\":[";
    for (size_t i = 0; i < task.events.size(); ++i) {
        if (compact) break;
        if (i) out += ',';
        ModelJson::quote(&out, task.events[i]);
    }
    out += "]";
    out += ",\"timeline\":[";
    for (size_t i = 0; i < task.timeline.size(); ++i) { if (i) out += ','; out += task.timeline[i]; }
    out += ']';
    if (!compact) {
        out += ",\"server_binding\":"; ModelJson::quote(&out, task.server_binding);
        out += ",\"operations\":[";
        for (size_t i = 0; i < task.operations.size(); ++i) {
            const AgentTaskOperation& op = task.operations[i];
            if (i) out += ',';
            out += "{\"id\":"; ModelJson::quote(&out, op.id);
            out += ",\"step\":" + TaskNumber(op.step + 1) + ",\"risk\":" + TaskNumber(op.risk);
            out += ",\"tool\":"; ModelJson::quote(&out, op.tool);
            out += ",\"arguments\":"; ModelJson::quote(&out, op.arguments);
            out += ",\"context_revision\":"; ModelJson::quote(&out, op.context_revision);
            out += ",\"result\":"; ModelJson::quote(&out, op.result);
            out += ",\"state\":"; ModelJson::quote(&out, op.state);
            out += ",\"rollback_arguments\":"; ModelJson::quote(&out, op.rollback_arguments);
            out += ",\"rollback_expected\":"; ModelJson::quote(&out, op.rollback_expected);
            out += ",\"rollback_target\":"; ModelJson::quote(&out, op.rollback_target);
            out += ",\"rollback_state\":"; ModelJson::quote(&out, op.rollback_state);
            out += '}';
        }
        out += "],\"checkpoint_history\":[";
        for (size_t i = 0; i < task.checkpoint_history.size(); ++i) { if (i) out += ','; out += task.checkpoint_history[i]; }
        out += ']';
    }
    return out + "}";
}

static int TaskAssertionEvidence(const AgentTask& task, int step, const AgentAssertion& assertion)
{
    ModelJson required; if (!ModelJson::parse(assertion.arguments, &required)) return -1;
    for (size_t i = task.evidence.size(); i > 0; --i) {
        const AgentTaskEvidence& evidence = task.evidence[i - 1]; ModelJson args;
        if (evidence.step != step || evidence.tool != assertion.tool || (int)i - 1 <= task.steps[step].last_mutation ||
            (!task.context_revision.empty() && evidence.context_revision != task.context_revision) ||
            !ModelJson::parse(evidence.arguments, &args) || !AssertionEqual(args, required)) continue;
        return evidence.success && evidence.read_only && !evidence.truncated && AssertionReceipt(assertion, evidence.arguments, evidence.result) ? (int)i : -1;
    }
    return -1;
}

static bool TaskLaunchContextEvidence(const AgentTask& task, int step, const AgentTaskEvidence& evidence)
{
    if (evidence.tool != "get_debug_context") return false;
    ModelJson receipt;
    if (!ModelJson::parse(evidence.result, &receipt)) return false;
    const ModelJson* context = receipt.get("result");
    const ModelJson* pid = context ? context->get("process_id") : NULL;
    const ModelJson* session = context ? context->get("session") : NULL;
    const ModelJson* modules = context ? context->get("modules") : NULL;
    if (!pid || pid->kind != ModelJson::NUMBER || pid->raw == "0" ||
        !session || session->kind != ModelJson::STRING || session->value.empty() ||
        !modules || modules->kind != ModelJson::ARRAY) return false;
    for (size_t i = 0; i < task.operations.size(); ++i) {
        const AgentTaskOperation& op = task.operations[i];
        if (op.step != step || op.tool != "debug_open_process" || op.state != "completed") continue;
        ModelJson args;
        if (!ModelJson::parse(op.arguments, &args)) continue;
        const ModelJson* path = args.get("path");
        if (!path || path->kind != ModelJson::STRING) continue;
        for (size_t m = 0; m < modules->items.size(); ++m) {
            const ModelJson* loaded = modules->items[m].get("path");
            if (!loaded || loaded->kind != ModelJson::STRING || loaded->value.size() != path->value.size()) continue;
            bool same = true;
            for (size_t c = 0; c < loaded->value.size(); ++c) {
                char a = loaded->value[c], b = path->value[c];
                if (a == '/') a = '\\';
                if (b == '/') b = '\\';
                if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
                if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
                if (a != b) { same = false; break; }
            }
            if (same) return true;
        }
    }
    return false;
}

static bool ApplyTaskCheck(const std::string& text, const std::string& candidate,
    AgentTask* task, int retry_limit)
{
    int current = TaskCurrentStep(*task);
    if (current < 0) return false;
    ModelJson json;
    if (!ModelJson::parse(text, &json)) return false;
    const ModelJson* index = json.get("step");
    std::string status, reason, adjustment;
    if (!index || index->kind != ModelJson::NUMBER || index->value != TaskNumber(current + 1) ||
        !TaskString(json, "status", &status, 32) || !TaskString(json, "reason", &reason, 2048)) return false;
    AgentTaskStep& step = task->steps[current];
    std::vector<int> verified_ids;
    if (status == "verified") {
        const ModelJson* ids = json.get("evidence");
        if (!ids || ids->kind != ModelJson::ARRAY || ids->items.size() > 64) return false;
        bool observed = false;
        for (size_t i = 0; i < ids->items.size(); ++i) {
            const ModelJson& id = ids->items[i];
            int match = -1;
            for (size_t e = 0; e < task->evidence.size(); ++e)
                if (id.kind == ModelJson::NUMBER && id.value == TaskNumber((int)e + 1)) match = (int)e;
            if (match < 0) {
                status = "needs_verification";
                reason = "The verifier cited an unknown evidence ID.";
                adjustment = "Cite a recorded read-only receipt for this step.";
                break;
            }
            const AgentTaskEvidence& evidence = task->evidence[match];
            if (evidence.step != current || !evidence.success || evidence.truncated ||
                !evidence.read_only || match <= step.last_mutation ||
                (!task->context_revision.empty() && evidence.context_revision != task->context_revision)) {
                status = "needs_verification";
                reason = "The cited receipt is not a usable read-only observation for this step.";
                adjustment = "Cite a current, complete read-only receipt recorded after the last change.";
                break;
            }
            observed = true;
            verified_ids.push_back(match + 1);
        }
        if (status == "verified" && step.criterion.find("debug_open_process") != std::string::npos) {
            bool launch_observed = false;
            for (size_t i = 0; i < verified_ids.size(); ++i)
                if (TaskLaunchContextEvidence(*task, current, task->evidence[verified_ids[i] - 1])) launch_observed = true;
            if (!launch_observed) {
                status = "needs_verification";
                reason = "The cited receipts do not confirm that the launched executable is loaded.";
                adjustment = "Read get_debug_context and cite its receipt showing the target process and matching main module.";
            }
        }
        for (size_t c = 0; c < step.checks.size(); ++c) {
            int latest = TaskAssertionEvidence(*task, current, step.checks[c]);
            bool matched = std::find(verified_ids.begin(), verified_ids.end(), latest) != verified_ids.end();
            if (!matched) {
                status = "needs_verification"; reason = "Deterministic tool assertion has not passed.";
                adjustment = "Collect fresh matching read-only receipts for the required checks; do not weaken expected values.";
                break;
            }
        }
        if (status == "verified" && !observed && (step.kind != "analysis" || candidate.empty() || step.last_mutation >= 0)) {
            status = "needs_verification";
            reason = "Missing successful observation after the last state-changing call.";
            adjustment = "Use a read-only MCP tool to check the completion criterion; do not repeat the change.";
        }
    }
    else if (status != "retry" && status != "needs_verification" && status != "blocked" && status != "replan") return false;
    if (status != "verified" && adjustment.empty() && !TaskString(json, "adjustment", &adjustment, 2048)) return false;
    step.reason = reason;
    task->last_feedback = reason + (adjustment.empty() ? "" : "\nAdjustment: " + adjustment);
    if (status == "verified") {
        step.status = "done"; task->state = "running";
        step.evidence_ids.swap(verified_ids);
        step.output = candidate.empty() ? reason : candidate;
        if (step.output.size() > 8192) {
            size_t end = 8192;
            while (end && ((unsigned char)step.output[end] & 0xc0) == 0x80) --end;
            step.output.resize(end);
            step.output += " [shared answer truncated]";
        }
    }
    else if (status == "replan") { step.status = "retrying"; task->state = "replanning"; }
    else if (status == "blocked") { step.status = "blocked"; task->state = "blocked"; }
    else if (status == "retry") {
        if (step.retries >= retry_limit) { step.status = "blocked"; task->state = "blocked"; }
        else { ++step.retries; step.status = "retrying"; task->state = "retrying"; }
    }
    else { step.status = "verifying"; task->state = "verifying"; }
    return true;
}
