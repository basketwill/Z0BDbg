#pragma once
#include "AgentTasks.h"
#include "AgentCheckpoint.h"

static std::string AgentBoundedText(const std::string& text, size_t limit)
{
    if (text.size() <= limit) return text;
    while (limit && ((unsigned char)text[limit] & 0xc0) == 0x80) --limit;
    return text.substr(0, limit);
}

static std::string AgentFailureClass(std::string reason)
{
    for (size_t i = 0; i < reason.size(); ++i) reason[i] = (char)tolower((unsigned char)reason[i]);
    if (reason.find("disagreement") != std::string::npos) return "disagreement";
    if (reason.find("cancel") != std::string::npos || reason.find("paus") != std::string::npos) return "interrupted";
    if (reason.find("deadline") != std::string::npos || reason.find("timed out") != std::string::npos || reason.find("time budget") != std::string::npos) return "timeout";
    if (reason.find("budget") != std::string::npos || reason.find("quota") != std::string::npos) return "budget";
    if (reason.find("permission") != std::string::npos || reason.find("isolation") != std::string::npos || reason.find("authoriz") != std::string::npos) return "permission";
    if (reason.find("target") != std::string::npos || reason.find("session changed") != std::string::npos) return "target_changed";
    if (reason.find("checkpoint") != std::string::npos || reason.find("journal") != std::string::npos) return "persistence";
    if (reason.find("transport") != std::string::npos || reason.find("http") != std::string::npos) return "transport";
    if (reason.find("schema") != std::string::npos || reason.find("capabilit") != std::string::npos || reason.find("unavailable tool") != std::string::npos) return "capability";
    if (reason.find("verif") != std::string::npos || reason.find("assertion") != std::string::npos) return "verification";
    if (reason.find("invalid") != std::string::npos || reason.find("model") != std::string::npos) return "model_response";
    return "unknown";
}
static void RecordTaskTimeline(AgentTask* task, const std::string& time, const std::string& kind, int step, int model, const std::string& detail)
{
    std::string event = "{\"time\":"; ModelJson::quote(&event, time);
    event += ",\"kind\":"; ModelJson::quote(&event, kind);
    event += ",\"step\":" + TaskNumber(step + 1) + ",\"model\":" + TaskNumber(model) + ",\"detail\":";
    ModelJson::quote(&event, AgentBoundedText(detail, 4096)); event += '}';
    if (task->timeline.size() >= 256) task->timeline.erase(task->timeline.begin()); task->timeline.push_back(event);
}
static std::string AnalysisClaims(const std::string& answer)
{
    ModelJson json;
    if (ModelJson::parse(answer, &json) && json.get("claims") && json.get("claims")->kind == ModelJson::OBJECT && !json.get("claims")->keys.empty())
        return CheckpointCanonical(*json.get("claims"));
    return answer;
}
static bool AnalysisAgreement(const AgentTask& task, const std::string& group)
{
    std::string reference; bool found = false;
    for (size_t i = 0; i < task.steps.size(); ++i) if (task.steps[i].agreement_group == group) {
        if (task.steps[i].proposal.empty() || task.steps[i].failure == "result_truncated") return false;
        ModelJson proposal;
        if (ModelJson::parse(task.steps[i].proposal, &proposal) && (!proposal.get("claims") || proposal.get("claims")->kind != ModelJson::OBJECT || proposal.get("claims")->keys.empty())) return false;
        std::string claims = AnalysisClaims(task.steps[i].proposal);
        if (found && claims != reference) return false; reference = claims; found = true;
    }
    return found;
}
static bool ResolveAnalysisAgreement(AgentTask* task, const std::string& group, int selected)
{
    int current = TaskCurrentStep(*task);
    if (task->state != "blocked" || current < 0 || task->steps[current].agreement_group != group) return false;
    if (group.empty() || selected < 0 || selected >= (int)task->steps.size() || task->steps[selected].agreement_group != group || task->steps[selected].proposal.empty()) return false;
    for (size_t i = 0; i < task->steps.size(); ++i) if (task->steps[i].agreement_group == group &&
        (task->steps[i].kind != "analysis" || task->steps[i].proposal.empty() || !task->steps[i].checks.empty() || task->steps[i].last_mutation >= 0)) return false;
    for (size_t i = 0; i < task->operations.size(); ++i) if (task->operations[i].risk != 0 && task->operations[i].step >= 0 &&
        task->steps[task->operations[i].step].agreement_group == group) return false;
    std::string chosen = task->steps[selected].proposal;
    for (size_t i = 0; i < task->steps.size(); ++i) if (task->steps[i].agreement_group == group) {
        task->steps[i].output = chosen; task->steps[i].status = "done"; task->steps[i].failure.clear();
        task->steps[i].reason = "User resolved disagreement by selecting step " + TaskNumber(selected + 1);
    }
    task->state = "running"; task->recovering = false; return true;
}
