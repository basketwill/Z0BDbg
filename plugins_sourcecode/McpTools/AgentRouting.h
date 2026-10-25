#pragma once
#include "AgentModels.h"
#include "AgentEvaluation.h"
#include <set>

struct AgentRouteCandidate {
    int slot;
    AgentModelCapability capability;
    std::string name, endpoint, currency;
    double input_price, output_price;
    unsigned int samples, valid, task_samples, task_success;
    double elapsed_ms;
    bool eligible, keyword;
    AgentRouteCandidate() : slot(0), input_price(-1), output_price(-1), samples(0), valid(0), task_samples(0), task_success(0),
        elapsed_ms(0), eligible(false), keyword(false) { ZeroMemory(&capability, sizeof(capability)); }
};

static void AgentRouteHistory(const std::vector<AgentEvaluation>& evaluations, AgentRouteCandidate* candidate)
{
    std::set<std::string> tasks;
    for (size_t i = 0; i < evaluations.size(); ++i) {
        const AgentEvaluation& run = evaluations[i]; bool participated = false;
        for (size_t r = 0; r < run.requests.size(); ++r) {
            const AgentModelMeasurement& request = run.requests[r];
            if (!request.finished || request.model != candidate->name || request.endpoint != candidate->endpoint ||
                (request.phase != "execution" && request.phase != "parallel_analysis")) continue;
            ++candidate->samples; if (request.valid) ++candidate->valid;
            candidate->elapsed_ms += request.elapsed_ms; participated = true;
        }
        if (!participated || (run.outcome != "verified" && run.outcome != "failed" && run.feedback.empty())) continue;
        std::string identity = run.task_id.empty() ? run.id : run.task_id;
        if (!tasks.insert(identity).second) continue;
        ++candidate->task_samples;
        if (run.feedback == "success" || (run.feedback.empty() && run.outcome == "verified")) ++candidate->task_success;
    }
}

static double AgentRouteScore(const AgentRouteCandidate& candidate, int mode, bool complex, const std::string& currency)
{
    if (!candidate.eligible) return -1e9;
    double quality = candidate.capability.quality / 100.0;
    double reliability = (candidate.valid + 3.0) / (candidate.samples + 4.0);
    double success = (candidate.task_success + 1.0) / (candidate.task_samples + 2.0);
    double latency = candidate.samples >= 3 ? candidate.elapsed_ms / candidate.samples : candidate.capability.latency_ms;
    double speed = 1.0 / (1.0 + latency / 5000.0);
    bool priced = candidate.currency == currency && candidate.input_price >= 0 && candidate.output_price >= 0;
    double economy = priced ? 1.0 / (1.0 + candidate.input_price + candidate.output_price) : 0;
    double score = (complex ? 4 : 2) * quality + 2 * reliability + success + speed + economy;
    if (mode == 2) score = 6 * quality + 2 * reliability + 2 * success + speed * .25;
    if (mode == 3) score = (complex ? 2 : 1) * quality + reliability + success + 6 * economy;
    if (mode == 4) score = quality + reliability + success + 6 * speed;
    return score + (candidate.keyword ? .5 : 0);
}

static int AgentBestRoute(const std::vector<AgentRouteCandidate>& candidates, int mode, bool complex, const std::string& currency)
{
    double best = -1e9; int slot = -1;
    for (size_t i = 0; i < candidates.size(); ++i) {
        double score = AgentRouteScore(candidates[i], mode, complex, currency);
        if (score > best) { best = score; slot = candidates[i].slot; }
    }
    return slot;
}
