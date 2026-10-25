#pragma once
#include "AgentTasks.h"
#include "AgentContext.h"
#include <ctype.h>
#include <set>
#include <map>

static std::string CheckpointCanonical(const ModelJson& json)
{
    if (json.kind == ModelJson::OBJECT) {
        std::map<std::string, std::string> fields;
        for (size_t i = 0; i < json.keys.size(); ++i) fields[json.keys[i]] = CheckpointCanonical(json.items[i]);
        std::string out = "{";
        for (std::map<std::string, std::string>::const_iterator i = fields.begin(); i != fields.end(); ++i) {
            if (out.size() > 1) out += ',';
            ModelJson::quote(&out, i->first); out += ':'; out += i->second;
        }
        return out + "}";
    }
    if (json.kind == ModelJson::ARRAY) {
        std::string out = "[";
        for (size_t i = 0; i < json.items.size(); ++i) { if (i) out += ','; out += CheckpointCanonical(json.items[i]); }
        return out + "]";
    }
    return json.raw;
}

static bool CheckpointInt(const ModelJson& json, const char* key, int low, int high, int* value)
{
    const ModelJson* field = json.get(key);
    if (!field || field->kind != ModelJson::NUMBER) return false;
    for (int i = low; i <= high; ++i) if (field->value == TaskNumber(i)) { *value = i; return true; }
    return false;
}

static bool CheckpointText(const ModelJson& json, const char* key, size_t limit, std::string* value)
{
    const ModelJson* field = json.get(key);
    if (!field || field->kind != ModelJson::STRING || field->value.size() > limit) return false;
    *value = field->value; return true;
}

static bool CheckpointBool(const ModelJson& json, const char* key, bool* value)
{
    const ModelJson* field = json.get(key);
    if (!field || field->kind != ModelJson::BOOLEAN) return false;
    *value = field->value == "true"; return true;
}

static bool CheckpointIds(const ModelJson& json, const char* key, int low, int high, std::vector<int>* values)
{
    const ModelJson* array = json.get(key);
    if (!array || array->kind != ModelJson::ARRAY || array->items.size() > kAgentTaskEvidenceLimit) return false;
    std::set<int> seen;
    for (size_t i = 0; i < array->items.size(); ++i) {
        int number = low - 1;
        for (int n = low; n <= high; ++n) if (array->items[i].kind == ModelJson::NUMBER && array->items[i].value == TaskNumber(n)) number = n;
        if (number < low || !seen.insert(number).second) return false;
        values->push_back(number);
    }
    return true;
}

// Deserialize only the current checkpoint format; never infer missing operation receipts.
static bool ParseAgentCheckpoint(const std::string& text, AgentTask* output, bool recover = true)
{
    ModelJson json;
    if (text.size() > 8 * 1024 * 1024 || !ModelJson::parse(text, &json)) return false;
    int version;
    AgentTask task;
    if (!CheckpointInt(json, "version", 2, 2, &version) ||
        !TaskString(json, "id", &task.id, 96) || !TaskString(json, "goal", &task.goal, 256 * 1024) ||
        !TaskString(json, "title", &task.title, 160) || !TaskString(json, "state", &task.state, 32) ||
        !CheckpointText(json, "feedback", 4096, &task.last_feedback) ||
        !TaskString(json, "server_binding", &task.server_binding, 64) || task.server_binding.size() != 64) return false;
    for (size_t i = 0; i < task.id.size(); ++i)
        if (!(task.id[i] >= '0' && task.id[i] <= '9') && !(task.id[i] >= 'a' && task.id[i] <= 'z') &&
            !(task.id[i] >= 'A' && task.id[i] <= 'Z') && task.id[i] != '-') return false;
    if (json.get("target_identity") && !CheckpointText(json, "target_identity", 256, &task.target_identity)) return false;
    if (json.get("context_revision") && !CheckpointText(json, "context_revision", 256, &task.context_revision)) return false;
    if (json.get("waiting_event") && !CheckpointBool(json, "waiting_event", &task.waiting_event)) return false;
    if (json.get("wait_cursor") && !CheckpointText(json, "wait_cursor", 20, &task.wait_cursor)) return false;
    if (task.waiting_event && (task.wait_cursor.empty() || task.wait_cursor.find_first_not_of("0123456789") != std::string::npos)) return false;
    if (json.get("replans") && !CheckpointInt(json, "replans", 0, 5, &task.replans)) return false;
    const ModelJson* steps = json.get("steps");
    const ModelJson* evidence = json.get("evidence");
    const ModelJson* operations = json.get("operations");
    const ModelJson* history = json.get("checkpoint_history");
    if (!steps || steps->kind != ModelJson::ARRAY || steps->items.empty() || steps->items.size() > 8 ||
        !evidence || evidence->kind != ModelJson::ARRAY || evidence->items.size() > kAgentTaskEvidenceLimit ||
        !operations || operations->kind != ModelJson::ARRAY || operations->items.size() > 128 ||
        !history || history->kind != ModelJson::ARRAY || history->items.size() > 512) return false;
    for (size_t i = 0; i < steps->items.size(); ++i) {
        const ModelJson& item = steps->items[i];
        AgentTaskStep step;
        const char* optional[] = { "agreement_group", "proposal", "started", "finished", "failure" };
        std::string* fields[] = { &step.agreement_group, &step.proposal, &step.started, &step.finished, &step.failure };
        for (int f = 0; f < 5; ++f) if (steps->items[i].get(optional[f]) &&
            !CheckpointText(steps->items[i], optional[f], f == 1 ? 8192 : 64, fields[f])) return false;
        if (!ParseAssertions(item.get("checks"), &step.checks)) return false;
        int last;
        if (!TaskString(item, "title", &step.title, 256) || !TaskString(item, "criterion", &step.criterion, 2048) ||
            !TaskString(item, "kind", &step.kind, 32) ||
            (step.kind != "analysis" && step.kind != "observation" && step.kind != "mutation") ||
            !TaskString(item, "status", &step.status, 32) ||
            (step.status != "done" && step.status != "pending" && step.status != "running" && step.status != "verifying" &&
             step.status != "retrying" && step.status != "blocked" && step.status != "failed" && step.status != "cancelled") ||
            !CheckpointText(item, "reason", 4096, &step.reason) ||
            !CheckpointText(item, "shared_result", 8300, &step.output) ||
            !CheckpointText(item, "model_name", 512, &step.model_name) ||
            !CheckpointInt(item, "model_slot", -1, 3, &step.assigned_model) ||
            !CheckpointInt(item, "actual_model_slot", -1, 3, &step.actual_model) ||
            !CheckpointInt(item, "retries", 0, 5, &step.retries) ||
            !CheckpointInt(item, "last_mutation_evidence", 0, (int)evidence->items.size(), &last) ||
            !CheckpointIds(item, "depends_on", 1, (int)i, &step.depends_on) ||
            !CheckpointIds(item, "verified_evidence", 1, (int)evidence->items.size(), &step.evidence_ids)) return false;
        step.last_mutation = last - 1;
        if (!step.agreement_group.empty() && (step.kind != "analysis" || step.agreement_group.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::string::npos)) return false;
        for (size_t d = 0; d < step.depends_on.size(); ++d) --step.depends_on[d];
        task.steps.push_back(step);
    }
    for (size_t i = 0; i < evidence->items.size(); ++i) {
        const ModelJson& item = evidence->items[i]; AgentTaskEvidence e;
        if (!CheckpointInt(item, "step", 1, (int)task.steps.size(), &e.step) ||
            !TaskString(item, "tool", &e.tool, 512) || !CheckpointText(item, "arguments", 256 * 1024, &e.arguments) ||
            !CheckpointText(item, "result", 8192, &e.result) || !CheckpointBool(item, "success", &e.success) ||
            !CheckpointBool(item, "read_only", &e.read_only) || !CheckpointBool(item, "truncated", &e.truncated)) return false;
        if (item.get("context_revision") && !CheckpointText(item, "context_revision", 256, &e.context_revision)) return false;
        const char* names[] = { "observed", "target", "context", "source_digest", "project_scope" };
        std::string* fields[] = { &e.observed, &e.target, &e.context, &e.source_digest, &e.project_scope };
        for (int f = 0; f < 5; ++f) if (item.get(names[f]) && !CheckpointText(item, names[f], f == 2 ? 16384 : 256, fields[f])) return false;
        --e.step; task.evidence.push_back(e);
    }
    std::set<std::string> ids;
    for (size_t i = 0; i < operations->items.size(); ++i) {
        const ModelJson& item = operations->items[i]; AgentTaskOperation op; ModelJson args;
        if (!TaskString(item, "id", &op.id, 128) || !ids.insert(op.id).second ||
            !CheckpointInt(item, "step", 1, (int)task.steps.size(), &op.step) || !CheckpointInt(item, "risk", 0, 2, &op.risk) ||
            !TaskString(item, "tool", &op.tool, 512) || !CheckpointText(item, "arguments", 256 * 1024, &op.arguments) ||
            !ModelJson::parse(op.arguments, &args) || args.kind != ModelJson::OBJECT ||
            !CheckpointText(item, "result", 8 * 1024 * 1024, &op.result) || !TaskString(item, "state", &op.state, 32) ||
            (op.state != "dispatching" && op.state != "completed" && op.state != "failed" && op.state != "uncertain" && op.state != "resolved") ||
            (op.state == "completed" && !TaskToolSucceeded(op.result))) return false;
        --op.step; op.arguments = CheckpointCanonical(args);
        if (item.get("context_revision") &&
            !CheckpointText(item, "context_revision", 256, &op.context_revision)) return false;
        const char* names[] = { "rollback_arguments", "rollback_expected", "rollback_target", "rollback_state" };
        std::string* fields[] = { &op.rollback_arguments, &op.rollback_expected, &op.rollback_target, &op.rollback_state };
        for (int f = 0; f < 4; ++f) if (item.get(names[f]) && !CheckpointText(item, names[f], f < 2 ? 16384 : 256, fields[f])) return false;
        if (!op.rollback_state.empty() && op.rollback_state != "available" && op.rollback_state != "unsupported" &&
            op.rollback_state != "dispatching" && op.rollback_state != "uncertain" && op.rollback_state != "undone") return false;
        if (op.rollback_state == "available" && (op.tool != "write_memory" || op.rollback_target.empty() ||
            !ModelJson::parse(op.rollback_arguments, &args) || args.kind != ModelJson::OBJECT ||
            op.rollback_expected.empty())) return false;
        if (op.rollback_state == "dispatching" && recover) op.rollback_state = "uncertain";
        if (op.state == "dispatching") op.state = op.risk == 0 ? "failed" : "uncertain";
        task.operations.push_back(op);
    }
    for (size_t i = 0; i < history->items.size(); ++i) {
        std::string role = ContextRole(history->items[i].raw);
        if (role != "user" && role != "assistant" && role != "tool") return false;
        task.checkpoint_history.push_back(history->items[i].raw);
    }
    std::vector<ContextBlock> blocks;
    if (!ContextBlocks(task.checkpoint_history, &blocks)) return false;
    if (!blocks.empty() && !blocks.back().complete) task.checkpoint_history.resize(blocks.back().first);
    for (size_t i = 0; i < task.steps.size(); ++i) {
        const AgentTaskStep& step = task.steps[i];
        if (step.last_mutation >= 0 && task.evidence[step.last_mutation].step != (int)i) return false;
        for (size_t e = 0; e < step.evidence_ids.size(); ++e) {
            const AgentTaskEvidence& ev = task.evidence[step.evidence_ids[e] - 1];
            if (ev.step != (int)i || !ev.success || !ev.read_only || ev.truncated ||
                step.evidence_ids[e] - 1 <= step.last_mutation) return false;
        }
        if (step.status == "done" && step.kind != "analysis" && step.evidence_ids.empty()) return false;
        if (step.status == "done") for (size_t c = 0; c < step.checks.size(); ++c) {
            bool matched = false;
            for (size_t e = 0; e < step.evidence_ids.size(); ++e) {
                const AgentTaskEvidence& ev = task.evidence[step.evidence_ids[e] - 1];
                if (ev.tool == step.checks[c].tool && AssertionReceipt(step.checks[c], ev.arguments, ev.result)) matched = true;
            }
            if (!matched) return false;
        }
    }
    const ModelJson* timeline = json.get("timeline");
    if (timeline) {
        if (timeline->kind != ModelJson::ARRAY || timeline->items.size() > 256) return false;
        for (size_t i = 0; i < timeline->items.size(); ++i) {
            const ModelJson& event = timeline->items[i];
            std::string time, kind, detail;
            if (event.kind != ModelJson::OBJECT || event.raw.size() > 16384 || !CheckpointText(event, "time", 64, &time) ||
                !CheckpointText(event, "kind", 64, &kind) || !CheckpointText(event, "detail", 4096, &detail)) return false;
            task.timeline.push_back(event.raw);
        }
    }
    int current = TaskCurrentStep(task);
    task.recovering = recover && current >= 0;
    bool disagreement = current >= 0 && task.state == "blocked" && task.steps[current].failure == "disagreement";
    if (disagreement) task.recovering = false;
    if (current >= 0 && recover && !disagreement) {
        task.steps[current].status = "verifying";
        task.steps[current].retries = 0;
        task.steps[current].evidence_ids.clear();
        for (size_t i = 0; i < task.evidence.size(); ++i)
            if (task.evidence[i].step == current) task.evidence[i].success = false;
        task.last_feedback = "Recover interrupted step with fresh read-only observations. Do not repeat state changes. "
            "If completion cannot be verified, stop and request explicit /resume retry.";
        task.state = "recovering";
    }
    *output = task; return true;
}

// Caller must obtain explicit confirmation and persist an audit entry before using this.
static bool PrepareAuthorizedTaskRetry(AgentTask* task)
{
    int current = TaskCurrentStep(*task);
    if (current < 0) return false;
    for (size_t i = 0; i < task->operations.size(); ++i)
        if (task->operations[i].step == current && task->operations[i].risk != 0)
            task->operations[i].state = "resolved";
    task->recovering = false; task->state = "running";
    task->steps[current].status = "pending"; task->steps[current].retries = 0;
    task->steps[current].evidence_ids.clear();
    for (size_t i = 0; i < task->evidence.size(); ++i)
        if (task->evidence[i].step == current) task->evidence[i].success = false;
    task->last_feedback = "User explicitly authorized retry after inspecting the current debugger state.";
    std::string group = task->steps[current].agreement_group;
    if (!group.empty()) for (size_t i = current; i < task->steps.size(); ++i) if (task->steps[i].agreement_group == group) {
        task->steps[i].status = "pending"; task->steps[i].proposal.clear(); task->steps[i].failure.clear();
    }
    return true;
}

static bool PrepareInvalidVerifierContinuation(AgentTask* task, bool ignore_errors = false)
{
    // Model and summary failures can interrupt a step after read-only tools
    // have returned. Resume it in verification mode so prior changes cannot
    // be repeated automatically.
    if (task->state != "blocked" && task->state != "failed") return false;
    int current = TaskCurrentStep(*task);
    if (current < 0) return false;
    AgentTaskStep& step = task->steps[current];
    bool legacy = step.failure == "verification" && step.reason.empty();
    std::string reason = step.reason + " " + task->last_feedback;
    std::transform(reason.begin(), reason.end(), reason.begin(), [](unsigned char c) { return (char)tolower(c); });
    bool external = reason.find("authorization") != std::string::npos ||
        reason.find("permission") != std::string::npos ||
        reason.find("external input") != std::string::npos ||
        reason.find("user input") != std::string::npos ||
        reason.find("deny_read_only") != std::string::npos ||
        reason.find("-32005") != std::string::npos;
    bool failed_change = TaskHasFailedTool(*task, current, false);
    bool failed_read = TaskHasFailedTool(*task, current, true);
    if ((step.status != "blocked" && step.status != "failed") ||
        (!ignore_errors && (failed_change || (external && !failed_read))) ||
        (!ignore_errors && !legacy && step.failure != "invalid_verifier" && step.failure != "verification" &&
            step.failure != "model_response")) return false;
    step.status = "verifying";
    step.failure.clear();
    step.finished.clear();
    step.retries = 0;
    task->recovering = true;
    task->state = "verifying";
    task->last_feedback = "Previous model or verification response failed. Collect fresh read-only evidence for this step; do not repeat completed changes.";
    return true;
}
