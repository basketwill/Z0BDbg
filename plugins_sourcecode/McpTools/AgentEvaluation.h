#pragma once
#include "ModelJson.h"
#include "AgentCheckpoint.h"
#include <map>
#include <vector>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

struct AgentModelMeasurement {
    std::string model, endpoint, phase, currency;
    DWORD elapsed_ms;
    unsigned int http_attempts;
    double input_tokens, output_tokens, cached_tokens, reasoning_tokens, estimated_cost;
    bool valid, finished, usage_known, cost_known;
    AgentModelMeasurement() : elapsed_ms(0), http_attempts(1), input_tokens(0), output_tokens(0),
        cached_tokens(0), reasoning_tokens(0), estimated_cost(0), valid(false), finished(false), usage_known(false), cost_known(false) {}
};

struct AgentEvaluation {
    std::string id, project, task_id, outcome, feedback, updated;
    std::string failure_class;
    DWORD elapsed_ms;
    bool managed;
    unsigned int tool_proposed, tool_dispatched, tool_success, tool_failed, tool_denied, tool_reused, tool_uncertain;
    unsigned int tool_invalid, planned_steps, verified_steps;
    DWORD tool_ms;
    std::vector<AgentModelMeasurement> requests;
    AgentEvaluation() : elapsed_ms(0), managed(false), tool_proposed(0), tool_dispatched(0), tool_success(0),
        tool_failed(0), tool_denied(0), tool_reused(0), tool_uncertain(0), tool_invalid(0), planned_steps(0), verified_steps(0), tool_ms(0) {}
};

static std::string EvaluationNumber(double number)
{
    char text[96]; sprintf_s(text, sizeof(text), "%.10g", number); return text;
}

static bool EvaluationCount(const ModelJson* field, double* value)
{
    if (!field || field->kind != ModelJson::NUMBER || field->value.empty()) return false;
    double number = strtod(field->value.c_str(), NULL);
    if (!_finite(number) || number < 0 || number != floor(number) || number > 1000000000000.0) return false;
    *value = number; return true;
}

static bool EvaluationPrice(const std::string& text, double* value)
{
    ModelJson json;
    if (text.empty() || !ModelJson::parse(text, &json) || json.kind != ModelJson::NUMBER) return false;
    double number = strtod(text.c_str(), NULL);
    if (!_finite(number) || number < 0 || number > 1000000) return false;
    *value = number; return true;
}

static void ReadEvaluationUsage(const ModelJson& response, const std::string& input_price,
    const std::string& output_price, const std::string& cached_price, AgentModelMeasurement* measurement)
{
    measurement->usage_known = measurement->cost_known = false;
    measurement->input_tokens = measurement->output_tokens = measurement->cached_tokens = measurement->reasoning_tokens = measurement->estimated_cost = 0;
    const ModelJson* usage = response.get("usage");
    if (!usage || usage->kind != ModelJson::OBJECT) return;
    const ModelJson* input = usage->get("prompt_tokens");
    const ModelJson* output = usage->get("completion_tokens");
    if (!input) input = usage->get("input_tokens");
    if (!output) output = usage->get("output_tokens");
    if (!EvaluationCount(input, &measurement->input_tokens) || !EvaluationCount(output, &measurement->output_tokens)) return;
    const ModelJson* details = usage->get("prompt_tokens_details");
    const ModelJson* cached = details ? details->get("cached_tokens") : NULL;
    if (!cached) cached = usage->get("prompt_cache_hit_tokens");
    if (cached && (!EvaluationCount(cached, &measurement->cached_tokens) || measurement->cached_tokens > measurement->input_tokens)) return;
    details = usage->get("completion_tokens_details");
    const ModelJson* reasoning = details ? details->get("reasoning_tokens") : NULL;
    if (reasoning && (!EvaluationCount(reasoning, &measurement->reasoning_tokens) || measurement->reasoning_tokens > measurement->output_tokens)) return;
    measurement->usage_known = true;
    double in, out, cache;
    if (!EvaluationPrice(input_price, &in) || !EvaluationPrice(output_price, &out)) return;
    cache = in;
    if (measurement->cached_tokens && !EvaluationPrice(cached_price, &cache)) return;
    measurement->estimated_cost = ((measurement->input_tokens - measurement->cached_tokens) * in +
        measurement->cached_tokens * cache + measurement->output_tokens * out) / 1000000.0;
    measurement->cost_known = true;
}

static std::string EvaluationJson(const AgentEvaluation& evaluation)
{
    std::string out = "{\"version\":1";
    const char* names[] = { "id", "project", "task_id", "outcome", "feedback", "updated" };
    const std::string* values[] = { &evaluation.id, &evaluation.project, &evaluation.task_id, &evaluation.outcome, &evaluation.feedback, &evaluation.updated };
    for (int i = 0; i < 6; ++i) { out += ",\""; out += names[i]; out += "\":"; ModelJson::quote(&out, *values[i]); }
    out += ",\"failure_class\":"; ModelJson::quote(&out, evaluation.failure_class);
    out += std::string(",\"managed\":") + (evaluation.managed ? "true" : "false");
    out += ",\"elapsed_ms\":" + EvaluationNumber(evaluation.elapsed_ms) + ",\"tool_ms\":" + EvaluationNumber(evaluation.tool_ms);
    const char* counts[] = { "tool_proposed", "tool_dispatched", "tool_success", "tool_failed", "tool_denied", "tool_reused", "tool_uncertain" };
    unsigned int numbers[] = { evaluation.tool_proposed, evaluation.tool_dispatched, evaluation.tool_success, evaluation.tool_failed,
        evaluation.tool_denied, evaluation.tool_reused, evaluation.tool_uncertain };
    for (int i = 0; i < 7; ++i) out += ",\"" + std::string(counts[i]) + "\":" + EvaluationNumber(numbers[i]);
    out += ",\"tool_invalid\":" + EvaluationNumber(evaluation.tool_invalid) + ",\"planned_steps\":" +
        EvaluationNumber(evaluation.planned_steps) + ",\"verified_steps\":" + EvaluationNumber(evaluation.verified_steps);
    out += ",\"requests\":[";
    for (size_t i = 0; i < evaluation.requests.size(); ++i) {
        const AgentModelMeasurement& request = evaluation.requests[i];
        if (i) out += ',';
        out += "{\"model\":"; ModelJson::quote(&out, request.model);
        out += ",\"endpoint\":"; ModelJson::quote(&out, request.endpoint);
        out += ",\"phase\":"; ModelJson::quote(&out, request.phase);
        out += ",\"currency\":"; ModelJson::quote(&out, request.currency);
        out += std::string(",\"valid\":") + (request.valid ? "true" : "false");
        out += std::string(",\"finished\":") + (request.finished ? "true" : "false");
        out += ",\"elapsed_ms\":" + EvaluationNumber(request.elapsed_ms) + ",\"http_attempts\":" + EvaluationNumber(request.http_attempts);
        out += ",\"input_tokens\":" + (request.usage_known ? EvaluationNumber(request.input_tokens) : "null");
        out += ",\"output_tokens\":" + (request.usage_known ? EvaluationNumber(request.output_tokens) : "null");
        out += ",\"cached_tokens\":" + (request.usage_known ? EvaluationNumber(request.cached_tokens) : "null");
        out += ",\"reasoning_tokens\":" + (request.usage_known ? EvaluationNumber(request.reasoning_tokens) : "null");
        out += ",\"estimated_cost\":" + (request.cost_known ? EvaluationNumber(request.estimated_cost) : "null") + "}";
    }
    return out + "]}";
}

static bool ParseEvaluation(const std::string& text, AgentEvaluation* evaluation)
{
    ModelJson json; int version;
    if (text.size() > 1024 * 1024 || !ModelJson::parse(text, &json) || !CheckpointInt(json, "version", 1, 1, &version)) return false;
    AgentEvaluation result;
    const char* names[] = { "id", "project", "task_id", "outcome", "feedback", "updated" };
    std::string* fields[] = { &result.id, &result.project, &result.task_id, &result.outcome, &result.feedback, &result.updated };
    for (int i = 0; i < 6; ++i) if (!CheckpointText(json, names[i], 512, fields[i])) return false;
    if (json.get("failure_class") && !CheckpointText(json, "failure_class", 64, &result.failure_class)) return false;
    if (result.id.empty() || result.project.empty() ||
        (result.outcome != "verified" && result.outcome != "failed" && result.outcome != "unrated" && result.outcome != "cancelled" && result.outcome != "running") ||
        (!result.feedback.empty() && result.feedback != "success" && result.feedback != "failure") ||
        !CheckpointBool(json, "managed", &result.managed)) return false;
    const char* counts[] = { "tool_proposed", "tool_dispatched", "tool_success", "tool_failed", "tool_denied", "tool_reused", "tool_uncertain",
        "tool_invalid", "planned_steps", "verified_steps" };
    unsigned int* values[] = { &result.tool_proposed, &result.tool_dispatched, &result.tool_success, &result.tool_failed,
        &result.tool_denied, &result.tool_reused, &result.tool_uncertain, &result.tool_invalid, &result.planned_steps, &result.verified_steps };
    double count;
    for (int i = 0; i < 10; ++i) {
        if (!EvaluationCount(json.get(counts[i]), &count) || count > 4294967295.0) return false;
        *values[i] = (unsigned int)count;
    }
    if (result.tool_success + (double)result.tool_failed > result.tool_dispatched ||
        result.tool_uncertain > result.tool_failed || result.verified_steps > result.planned_steps) return false;
    if (!EvaluationCount(json.get("elapsed_ms"), &count) || count > 4294967295.0) return false;
    result.elapsed_ms = (DWORD)count;
    if (!EvaluationCount(json.get("tool_ms"), &count) || count > 4294967295.0) return false;
    result.tool_ms = (DWORD)count;
    const ModelJson* requests = json.get("requests");
    if (!requests || requests->kind != ModelJson::ARRAY || requests->items.size() > 512) return false;
    for (size_t i = 0; i < requests->items.size(); ++i) {
        const ModelJson& record = requests->items[i]; AgentModelMeasurement request;
        if (!CheckpointText(record, "model", 512, &request.model) || !CheckpointText(record, "endpoint", 64, &request.endpoint) ||
            !CheckpointText(record, "phase", 32, &request.phase) || !CheckpointText(record, "currency", 16, &request.currency) ||
            !CheckpointBool(record, "valid", &request.valid) || !CheckpointBool(record, "finished", &request.finished) ||
            !EvaluationCount(record.get("elapsed_ms"), &count) || count > 4294967295.0) return false;
        request.elapsed_ms = (DWORD)count;
        if (request.valid && !request.finished) return false;
        if (!EvaluationCount(record.get("http_attempts"), &count) || count < 1 || count > 100) return false;
        request.http_attempts = (unsigned int)count;
        const ModelJson* input = record.get("input_tokens");
        const ModelJson* output = record.get("output_tokens");
        const ModelJson* cached = record.get("cached_tokens");
        const ModelJson* reasoning = record.get("reasoning_tokens");
        if (!input || !output || !cached || !reasoning) return false;
        if (input->kind == ModelJson::NIL) {
            if (output->kind != ModelJson::NIL || cached->kind != ModelJson::NIL || reasoning->kind != ModelJson::NIL) return false;
        }
        else {
            if (!EvaluationCount(input, &request.input_tokens) || !EvaluationCount(output, &request.output_tokens) ||
                !EvaluationCount(cached, &request.cached_tokens) || !EvaluationCount(reasoning, &request.reasoning_tokens) ||
                request.cached_tokens > request.input_tokens || request.reasoning_tokens > request.output_tokens) return false;
            request.usage_known = true;
        }
        const ModelJson* cost = record.get("estimated_cost");
        if (!cost) return false;
        if (cost->kind != ModelJson::NIL) {
            if (!request.usage_known || (request.currency != "USD" && request.currency != "CNY") || cost->kind != ModelJson::NUMBER) return false;
            request.estimated_cost = strtod(cost->raw.c_str(), NULL);
            if (!_finite(request.estimated_cost) || request.estimated_cost < 0 || request.estimated_cost > 1000000000000.0) return false;
            request.cost_known = true;
        }
        result.requests.push_back(request);
    }
    *evaluation = result; return true;
}

struct EvaluationTotals {
    unsigned int runs, tasks, task_success, task_cancelled, task_unfinished, rated_chats, chat_success;
    double elapsed_ms, dispatched, tool_success, denied, reused, invalid, uncertain, requests, valid_requests, http_attempts;
    double input_tokens, output_tokens, missing_usage, missing_cost, retry_billing_unknown, planned_steps, verified_steps, pending_requests, pending_tools;
    std::map<std::string, double> costs;
    EvaluationTotals() : runs(0), tasks(0), task_success(0), task_cancelled(0), task_unfinished(0), rated_chats(0), chat_success(0),
        elapsed_ms(0), dispatched(0), tool_success(0), denied(0), reused(0), invalid(0), uncertain(0), requests(0),
        valid_requests(0), http_attempts(0), input_tokens(0), output_tokens(0), missing_usage(0), missing_cost(0),
        retry_billing_unknown(0), planned_steps(0), verified_steps(0), pending_requests(0), pending_tools(0) {}
};

static EvaluationTotals SummarizeEvaluations(const std::vector<AgentEvaluation>& evaluations)
{
    EvaluationTotals totals;
    std::map<std::string, const AgentEvaluation*> tasks;
    for (size_t i = 0; i < evaluations.size(); ++i) {
        const AgentEvaluation& e = evaluations[i];
        ++totals.runs; totals.elapsed_ms += e.elapsed_ms;
        totals.dispatched += e.tool_dispatched; totals.tool_success += e.tool_success; totals.denied += e.tool_denied;
        totals.reused += e.tool_reused; totals.invalid += e.tool_invalid; totals.uncertain += e.tool_uncertain;
        totals.pending_tools += e.tool_dispatched - e.tool_success - e.tool_failed;
        if (e.managed) {
            std::string key = e.task_id.empty() ? e.id : e.task_id;
            if (tasks.find(key) == tasks.end() || tasks[key]->id < e.id) tasks[key] = &e;
        }
        else if (!e.feedback.empty()) { ++totals.rated_chats; if (e.feedback == "success") ++totals.chat_success; }
        for (size_t r = 0; r < e.requests.size(); ++r) {
            const AgentModelMeasurement& request = e.requests[r];
            ++totals.requests; totals.http_attempts += request.http_attempts;
            if (request.valid) ++totals.valid_requests;
            if (!request.finished) ++totals.pending_requests;
            if (request.usage_known) { totals.input_tokens += request.input_tokens; totals.output_tokens += request.output_tokens; }
            else ++totals.missing_usage;
            if (request.cost_known) totals.costs[request.currency] += request.estimated_cost;
            else ++totals.missing_cost;
            if (request.http_attempts > 1) ++totals.retry_billing_unknown;
        }
    }
    for (std::map<std::string, const AgentEvaluation*>::const_iterator i = tasks.begin(); i != tasks.end(); ++i) {
        const AgentEvaluation& e = *i->second;
        totals.planned_steps += e.planned_steps; totals.verified_steps += e.verified_steps;
        if (e.outcome == "cancelled" && e.feedback.empty()) { ++totals.task_cancelled; continue; }
        if (e.outcome == "running" && e.feedback.empty()) { ++totals.task_unfinished; continue; }
        ++totals.tasks;
        if (e.feedback == "success" || (e.feedback.empty() && e.outcome == "verified")) ++totals.task_success;
    }
    return totals;
}
