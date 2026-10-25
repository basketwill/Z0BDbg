#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <stdio.h>
#include "ModelJson.h"

// The debugger produces events; transport threads wait without blocking its UI.
class DebugRuntimeFeed {
    CRITICAL_SECTION lock;
    HANDLE changed;
    unsigned __int64 sequence, generation, module_epoch, stop_epoch;
    DWORD process_id, thread_id;
    int status;
    std::string instance;
    std::string last_stop;
    std::vector<std::string> events, modules;
public:
    DebugRuntimeFeed() : changed(NULL), sequence(0), generation(0), module_epoch(0), stop_epoch(0), process_id(0), thread_id(0), status(0) {
        InitializeCriticalSection(&lock);
        changed = CreateEventW(NULL, TRUE, FALSE, NULL);
        FILETIME now; GetSystemTimeAsFileTime(&now);
        char text[80]; sprintf_s(text, sizeof(text), "%08lx%08lx-%lu", now.dwHighDateTime, now.dwLowDateTime, GetCurrentProcessId()); instance = text;
    }
    ~DebugRuntimeFeed() { if (changed) CloseHandle(changed); DeleteCriticalSection(&lock); }
    static std::string number(unsigned __int64 value) { char text[32]; sprintf_s(text, sizeof(text), "%I64u", value); return text; }
    static std::string state_number(int value) { char text[16]; sprintf_s(text, sizeof(text), "%d", value); return text; }
    void update(DWORD pid, DWORD tid, int state, bool new_session = false) {
        EnterCriticalSection(&lock);
        bool state_changed = pid != process_id || tid != thread_id || state != status || new_session;
        if (pid != process_id || new_session) { ++generation; modules.clear(); last_stop.clear(); ++module_epoch; }
        if (state != 18) last_stop.clear();
        process_id = pid; thread_id = tid; status = state;
        if (state_changed) {
            ++sequence;
            events.push_back("{\"sequence\":" + number(sequence) + ",\"event\":{\"state_changed\":true,\"status\":" + state_number(state) + "}}");
            if (events.size() > 256) events.erase(events.begin());
            if (changed) SetEvent(changed);
        }
        LeaveCriticalSection(&lock);
    }
    void push(const std::string& payload, bool module_change, bool stopped, const std::string& module = "") {
        EnterCriticalSection(&lock);
        ++sequence;
        events.push_back("{\"sequence\":" + number(sequence) + ",\"event\":" + payload + "}");
        if (events.size() > 256) events.erase(events.begin());
        if (module_change) { ++module_epoch; if (modules.size() >= 128) modules.erase(modules.begin()); if (!module.empty()) modules.push_back(module); }
        if (stopped) { ++stop_epoch; last_stop = payload; }
        if (changed) SetEvent(changed);
        LeaveCriticalSection(&lock);
    }
    std::string context() {
        EnterCriticalSection(&lock);
        std::string out = "{\"ok\":true,\"session\":";
        ModelJson::quote(&out, instance + ":" + number(generation));
        out += ",\"process_id\":" + number(process_id) + ",\"thread_id\":" + number(thread_id) + ",\"status\":" + state_number(status);
        out += ",\"revision\":"; ModelJson::quote(&out, number(thread_id) + ":" + state_number(status) + ":" + number(module_epoch) + ":" + number(stop_epoch));
        out += ",\"sequence\":" + number(sequence) + ",\"module_events\":[";
        for (size_t i = 0; i < modules.size(); ++i) { if (i) out += ','; out += modules[i]; }
        out += "],\"last_stop\":" + (last_stop.empty() ? "null" : last_stop) + "}";
        LeaveCriticalSection(&lock); return out;
    }
    std::string wait(unsigned __int64 cursor, DWORD timeout) {
        EnterCriticalSection(&lock);
        bool ready = cursor < sequence;
        if (!ready && changed) ResetEvent(changed);
        LeaveCriticalSection(&lock);
        if (!ready && changed) WaitForSingleObject(changed, timeout);
        EnterCriticalSection(&lock);
        std::string out = "{\"ok\":true,\"cursor\":" + number(sequence) + ",\"gap\":" +
            (cursor > sequence || sequence - cursor > events.size() ? "true" : "false") + ",\"events\":[";
        unsigned __int64 first = sequence - events.size();
        bool comma = false;
        for (size_t i = 0; i < events.size(); ++i) if (first + i + 1 > cursor) { if (comma) out += ','; out += events[i]; comma = true; }
        out += "]}";
        LeaveCriticalSection(&lock); return out;
    }
};
