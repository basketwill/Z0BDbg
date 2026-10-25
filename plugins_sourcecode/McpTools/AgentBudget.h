#pragma once
#include "AgentEvaluation.h"

struct AgentBudgetReservation {
    double tokens, cost;
    AgentBudgetReservation() : tokens(0), cost(0) {}
};

class AgentBudgetLedger {
    CRITICAL_SECTION lock;
    double used_tokens, used_cost, token_limit, cost_limit;
    bool failed;
    std::string currency;
    bool (*save)(const std::string&, void*);
    void* context;
    std::string json() const {
        std::string out = "{\"version\":1,\"tokens\":" + EvaluationNumber(used_tokens) + ",\"cost\":" + EvaluationNumber(used_cost) + ",\"currency\":";
        ModelJson::quote(&out, currency); return out + '}';
    }
    bool persist() { if (save && !save(json(), context)) failed = true; return !failed; }
public:
    AgentBudgetLedger() : used_tokens(0), used_cost(0), token_limit(0), cost_limit(0), failed(false), save(NULL), context(NULL) { InitializeCriticalSection(&lock); }
    ~AgentBudgetLedger() { DeleteCriticalSection(&lock); }
    bool initialize(double tokens, double cost, const std::string& unit, const std::string& previous,
        bool (*writer)(const std::string&, void*) = NULL, void* writer_context = NULL) {
        token_limit = tokens; cost_limit = cost; currency = unit; save = writer; context = writer_context;
        if (!previous.empty()) {
            ModelJson root; double version;
            if (!ModelJson::parse(previous, &root) || !EvaluationCount(root.get("version"), &version) || version != 1 ||
                !EvaluationCount(root.get("tokens"), &used_tokens) || !root.get("cost") ||
                !EvaluationPrice(root.get("cost")->raw, &used_cost) || !root.get("currency") || root.get("currency")->value != unit) return false;
        }
        return persist();
    }
    bool reserve(double input, int* output, double in_price, double out_price, const std::string& unit,
        AgentBudgetReservation* reservation, std::string* error) {
        EnterCriticalSection(&lock);
        int allowed = *output > 0 ? *output : 4096;
        if (token_limit > 0) allowed = (std::min)(allowed, (int)(std::max)(0.0, token_limit - used_tokens - input));
        if (cost_limit > 0) {
            if (unit != currency || in_price < 0 || out_price < 0) {
                *error = "Cost budget requires configured prices in the budget currency."; LeaveCriticalSection(&lock); return false;
            }
            double remaining = cost_limit - used_cost - input * in_price / 1000000.0;
            if (remaining < 0) allowed = 0;
            else if (out_price > 0) allowed = (std::min)(allowed, (int)(std::min)(65536.0, floor(remaining * 1000000.0 / out_price)));
        }
        if (failed || allowed < 1) { *error = failed ? "Budget journal failed; no request sent." : "Task token/cost budget exhausted; no request sent."; LeaveCriticalSection(&lock); return false; }
        *output = allowed;
        reservation->tokens = input + allowed;
        reservation->cost = cost_limit > 0 ? (input * in_price + allowed * out_price) / 1000000.0 : 0;
        used_tokens += reservation->tokens; used_cost += reservation->cost;
        bool ok = persist();
        if (!ok) *error = "Budget reservation could not be persisted; no request sent.";
        LeaveCriticalSection(&lock); return ok;
    }
    bool settle(const AgentBudgetReservation& reservation, const AgentModelMeasurement& usage) {
        EnterCriticalSection(&lock);
        double old_tokens = used_tokens, old_cost = used_cost;
        if (usage.usage_known) used_tokens += usage.input_tokens + usage.output_tokens - reservation.tokens;
        if (cost_limit > 0 && usage.cost_known && usage.currency == currency) used_cost += usage.estimated_cost - reservation.cost;
        if (!persist()) { used_tokens = old_tokens; used_cost = old_cost; }
        bool ok = !failed && (token_limit <= 0 || used_tokens <= token_limit) && (cost_limit <= 0 || used_cost <= cost_limit + 1e-9);
        LeaveCriticalSection(&lock); return ok;
    }
    std::string snapshot() { EnterCriticalSection(&lock); std::string out = json(); LeaveCriticalSection(&lock); return out; }
    bool constrained() const { return token_limit > 0 || cost_limit > 0; }
};

// UTF-8 byte count plus framing is deliberately conservative, not a vendor tokenizer.
static size_t AgentTokenEstimate(const std::string& serialized)
{
    return serialized.size() + 128;
}
