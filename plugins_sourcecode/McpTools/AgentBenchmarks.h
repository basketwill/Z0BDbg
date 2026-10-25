#pragma once
#include "AgentTasks.h"
#include "AgentCheckpoint.h"
#include "AgentEvaluation.h"
#include <vector>

typedef AgentAssertion AgentBenchmarkCheck;
struct AgentBenchmarkCase {
    std::string name, goal;
    std::string expected_answer;
    std::vector<AgentBenchmarkCheck> checks;
};
struct AgentBenchmarkSuite {
    std::string id, fingerprint;
    std::vector<AgentBenchmarkCase> cases;
};

static bool BenchmarkSubset(const ModelJson& actual, const ModelJson& expected)
{
    if (actual.kind != expected.kind) return false;
    if (expected.kind == ModelJson::OBJECT) {
        for (size_t i = 0; i < expected.keys.size(); ++i) {
            const ModelJson* field = actual.get(expected.keys[i].c_str());
            if (!field || !BenchmarkSubset(*field, expected.items[i])) return false;
        }
        return true;
    }
    return CheckpointCanonical(actual) == CheckpointCanonical(expected);
}

static bool ParseBenchmarkSuite(const std::string& data, AgentBenchmarkSuite* suite)
{
    ModelJson json; AgentBenchmarkSuite parsed;
    if (data.size() > 64 * 1024 || !ModelJson::parse(data, &json) || !TaskString(json, "id", &parsed.id, 96)) return false;
    const ModelJson* cases = json.get("cases");
    if (!cases || cases->kind != ModelJson::ARRAY || cases->items.empty() || cases->items.size() > 16) return false;
    for (size_t i = 0; i < cases->items.size(); ++i) {
        AgentBenchmarkCase test;
        if (!TaskString(cases->items[i], "name", &test.name, 160) || !TaskString(cases->items[i], "goal", &test.goal, 4096)) return false;
        const ModelJson* checks = cases->items[i].get("checks");
        if (!checks || checks->kind != ModelJson::ARRAY || checks->items.empty() || checks->items.size() > 8) return false;
        const ModelJson* answer = cases->items[i].get("expected_answer");
        if (answer) {
            if (answer->kind != ModelJson::OBJECT || answer->raw.size() > 4096 || !AssertionSubstantive(*answer)) return false;
            test.expected_answer = answer->raw;
        }
        for (size_t c = 0; c < checks->items.size(); ++c) {
            AgentBenchmarkCheck check;
            const ModelJson* args = checks->items[c].get("arguments"), *expected = checks->items[c].get("expected");
            if (!TaskString(checks->items[c], "tool", &check.tool, 128) || !McpReadOnlyTool(check.tool) ||
                !args || args->kind != ModelJson::OBJECT || !expected || expected->kind != ModelJson::OBJECT || expected->keys.empty()) return false;
            if (!AssertionSubstantive(*expected)) return false;
            check.arguments = CheckpointCanonical(*args); check.expected = CheckpointCanonical(*expected);
            test.checks.push_back(check);
        }
        parsed.cases.push_back(test);
    }
    *suite = parsed; return true;
}

static bool BenchmarkCaseDiagnosisPass(const AgentBenchmarkCase& test, const std::string& answer)
{
    if (test.expected_answer.empty()) return true;
    ModelJson actual, expected;
    return ModelJson::parse(answer, &actual) && ModelJson::parse(test.expected_answer, &expected) && AssertionEqual(actual, expected, true);
}

struct AgentBenchmarkMetrics {
    unsigned count, passed;
    double elapsed, cost;
    bool cost_known;
    std::string currency;
    AgentBenchmarkMetrics() : count(0), passed(0), elapsed(0), cost(0), cost_known(true) {}
};

static bool BenchmarkMetrics(const ModelJson& report, AgentBenchmarkMetrics* metrics) {
    const ModelJson* cases = report.get("cases"), *requested = report.get("requested_cases");
    double count;
    if (!report.get("state") || report.get("state")->value != "completed" || !cases ||
        cases->kind != ModelJson::ARRAY || cases->items.empty() || cases->items.size() > 160 ||
        !EvaluationCount(requested, &count) || count != cases->items.size()) return false;
    AgentBenchmarkMetrics result; std::set<std::string> ids;
    for (size_t i = 0; i < cases->items.size(); ++i) {
        const ModelJson& item = cases->items[i];
        const ModelJson* pass = item.get("passed"), *evaluation = item.get("evaluation");
        int repeat, test; AgentEvaluation record;
        if (!CheckpointInt(item, "repeat", 1, 10, &repeat) || !CheckpointInt(item, "case", 1, 16, &test) ||
            !ids.insert(TaskNumber(repeat) + ":" + TaskNumber(test)).second || !pass || pass->kind != ModelJson::BOOLEAN ||
            !evaluation || !ParseEvaluation(evaluation->raw, &record)) return false;
        ++result.count; if (pass->value == "true") ++result.passed;
        result.elapsed += record.elapsed_ms;
        if (record.requests.empty()) result.cost_known = false;
        for (size_t r = 0; r < record.requests.size(); ++r) {
            const AgentModelMeasurement& request = record.requests[r];
            if (!request.cost_known || !request.finished || request.http_attempts > 1 || request.currency.empty()) result.cost_known = false;
            if (result.currency.empty()) result.currency = request.currency;
            if (result.currency != request.currency) result.cost_known = false;
            result.cost += request.estimated_cost;
        }
    }
    *metrics = result; return true;
}

static bool BenchmarkComparable(const ModelJson& baseline, const ModelJson& candidate) {
    const char* keys[] = { "suite", "suite_fingerprint", "fixture", "sample", "requested_cases" };
    for (int i = 0; i < 5; ++i) if (!baseline.get(keys[i]) || !candidate.get(keys[i]) ||
        baseline.get(keys[i])->raw != candidate.get(keys[i])->raw) return false;
    const ModelJson* a = baseline.get("cases"), *b = candidate.get("cases");
    if (!a || !b || a->kind != ModelJson::ARRAY || b->kind != ModelJson::ARRAY || a->items.size() != b->items.size()) return false;
    std::set<std::string> left, right;
    for (size_t i = 0; i < a->items.size(); ++i) {
        if (!a->items[i].get("case") || !a->items[i].get("repeat") || !b->items[i].get("case") || !b->items[i].get("repeat")) return false;
        left.insert(a->items[i].get("case")->raw + ":" + a->items[i].get("repeat")->raw);
        right.insert(b->items[i].get("case")->raw + ":" + b->items[i].get("repeat")->raw);
    }
    return left == right;
}

static std::string BenchmarkRegression(const AgentBenchmarkMetrics& a, const AgentBenchmarkMetrics& b,
    double success_pp, double time_percent, double cost_percent) {
    std::string failures;
    if (100.0 * a.passed / a.count - 100.0 * b.passed / b.count > success_pp + 0.000001) failures += "success rate; ";
    if (b.elapsed > a.elapsed * (1 + time_percent / 100) + 0.000001) failures += "elapsed time; ";
    if (!a.cost_known || !b.cost_known || a.currency != b.currency) failures += "cost unavailable or incomparable; ";
    else if (b.cost > a.cost * (1 + cost_percent / 100) + 0.000001) failures += "estimated cost; ";
    return failures;
}

static bool BenchmarkCaseEvidencePass(const AgentTask& task, const AgentBenchmarkCase& test, const std::string& answer = "", bool check_answer = true)
{
    if (task.state != "completed" || (check_answer && !BenchmarkCaseDiagnosisPass(test, answer))) return false;
    for (size_t c = 0; c < test.checks.size(); ++c) {
        ModelJson expected; if (!ModelJson::parse(test.checks[c].expected, &expected)) return false;
        bool found = false;
        for (size_t i = 0; i < task.evidence.size(); ++i) {
            const AgentTaskEvidence& evidence = task.evidence[i]; ModelJson args, root, result;
            if (!evidence.success || !evidence.read_only || evidence.truncated || evidence.tool != test.checks[c].tool ||
                (!task.context_revision.empty() && evidence.context_revision != task.context_revision) ||
                (!evidence.target.empty() && evidence.target != task.target_identity) ||
                !ModelJson::parse(evidence.arguments, &args) || CheckpointCanonical(args) != test.checks[c].arguments ||
                !ModelJson::parse(evidence.result, &root) || !root.get("result")) continue;
            result = *root.get("result");
            if (result.get("structuredContent")) result = *result.get("structuredContent");
            if (BenchmarkSubset(result, expected)) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

static std::string BenchmarkCasePrompt(const AgentBenchmarkCase& test)
{
    std::string prompt = test.goal + "\nRead-only task. Collect fresh evidence with these exact tool argument objects and verify the expected result fields:\n";
    for (size_t c = 0; c < test.checks.size(); ++c)
        prompt += test.checks[c].tool + " " + test.checks[c].arguments + (test.expected_answer.empty() ? " => " + test.checks[c].expected : "") + "\n";
    if (!test.expected_answer.empty()) {
        ModelJson expected; ModelJson::parse(test.expected_answer, &expected);
        prompt += "Return your final diagnosis as a JSON object without Markdown fences. Required top-level field names: ";
        for (size_t i = 0; i < expected.keys.size(); ++i) { if (i) prompt += ", "; prompt += expected.keys[i]; }
        prompt += "\nGround all values in actual debugger receipts.\n";
    }
    return prompt;
}
