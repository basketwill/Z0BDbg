#pragma once
#include "AgentCheckpoint.h"

struct AgentQueuedTask {
    std::string id, project, server, prompt, skill, state, reason, updated;
    std::string created;
    int model;
    int priority, slices;
    std::string last_started;
    AgentQueuedTask() : model(0), priority(0), slices(0), state("queued") {}
};
static std::string QueueJson(const AgentQueuedTask& task)
{
    std::string out = "{\"version\":1,\"model\":" + TaskNumber(task.model);
    const char* names[] = { "id", "project", "server", "prompt", "skill", "state", "reason", "updated" };
    const std::string* values[] = { &task.id, &task.project, &task.server, &task.prompt, &task.skill, &task.state, &task.reason, &task.updated };
    for (int i = 0; i < 8; ++i) { out += ",\""; out += names[i]; out += "\":"; ModelJson::quote(&out, *values[i]); }
    out += ",\"priority\":" + TaskNumber(task.priority) + ",\"slices\":" + TaskNumber(task.slices);
    out += ",\"last_started\":"; ModelJson::quote(&out, task.last_started);
    out += ",\"created\":"; ModelJson::quote(&out, task.created); return out + '}';
}
static bool ParseQueuedTask(const std::string& data, AgentQueuedTask* output)
{
    ModelJson root; AgentQueuedTask task;
    if (data.size() > 128 * 1024 || !ModelJson::parse(data, &root) || !root.get("version") || root.get("version")->raw != "1" ||
        !TaskString(root, "id", &task.id, 96) || !TaskString(root, "project", &task.project, 2048) ||
        !TaskString(root, "server", &task.server, 64) || !TaskString(root, "prompt", &task.prompt, 65536) ||
        !CheckpointText(root, "skill", 65536, &task.skill) || !TaskString(root, "state", &task.state, 32) ||
        !CheckpointText(root, "reason", 8192, &task.reason) || !CheckpointText(root, "updated", 64, &task.updated) ||
        !CheckpointInt(root, "model", 0, 4, &task.model)) return false;
    if (task.id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != std::string::npos) return false;
    if (root.get("created") && !CheckpointText(root, "created", 64, &task.created)) return false;
    if (root.get("last_started") && !CheckpointText(root, "last_started", 64, &task.last_started)) return false;
    if (root.get("priority") && !CheckpointInt(root, "priority", -5, 5, &task.priority)) return false;
    if (root.get("slices") && !CheckpointInt(root, "slices", 0, 100, &task.slices)) return false;
    if (task.state != "queued" && task.state != "running" && task.state != "paused" && task.state != "waiting" &&
        task.state != "completed" && task.state != "blocked" && task.state != "cancelled") return false;
    *output = task; return true;
}
static bool QueueCreatedLess(const AgentQueuedTask& a, const AgentQueuedTask& b) {
    int ap = a.priority - (std::min)(10, a.slices), bp = b.priority - (std::min)(10, b.slices);
    if (ap != bp) return ap > bp;
    if (a.last_started != b.last_started) return a.last_started < b.last_started;
    if (a.created != b.created) return a.created < b.created; return a.id < b.id;
}
static bool QueueRunnable(const AgentQueuedTask& task, bool paused, bool cancelled)
{
    return !paused && !cancelled && (task.state == "queued" || task.state == "running" || task.state == "waiting");
}
static unsigned __int64 QueueTime(const std::string& stamp) {
    unsigned year, month, day, hour, minute, second;
    if (sscanf_s(stamp.c_str(), "%u-%u-%uT%u:%u:%u", &year, &month, &day, &hour, &minute, &second) != 6 || year < 2000 || year > 9999 ||
        month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return 0;
    SYSTEMTIME time = {}; time.wYear = (WORD)year; time.wMonth = (WORD)month; time.wDay = (WORD)day;
    time.wHour = (WORD)hour; time.wMinute = (WORD)minute; time.wSecond = (WORD)second;
    FILETIME file; if (!SystemTimeToFileTime(&time, &file)) return 0;
    return ((unsigned __int64)file.dwHighDateTime << 32) | file.dwLowDateTime;
}
struct QueueFairLess {
    unsigned __int64 now;
    explicit QueueFairLess(unsigned __int64 value) : now(value) {}
    int score(const AgentQueuedTask& task) const {
        unsigned __int64 waiting = QueueTime(task.last_started.empty() ? task.created : task.last_started);
        unsigned age = waiting && now > waiting ? (unsigned)((std::min)(10ULL, (now - waiting) / 1200000000ULL)) : 0;
        return task.priority + age - (std::min)(10, task.slices);
    }
    bool operator()(const AgentQueuedTask& a, const AgentQueuedTask& b) const {
        int left = score(a), right = score(b);
        if (left != right) return left > right;
        if (a.last_started != b.last_started) return a.last_started < b.last_started;
        if (a.created != b.created) return a.created < b.created; return a.id < b.id;
    }
};
