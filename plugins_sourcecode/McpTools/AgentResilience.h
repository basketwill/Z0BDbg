#pragma once
#include <windows.h>
#include <map>
#include <string>

struct AgentServiceHealth {
    unsigned failures, openings;
    DWORD opened, cooldown;
    bool probing;
    AgentServiceHealth() : failures(0), openings(0), opened(0), cooldown(0), probing(false) {}
};

class AgentServiceRegistry {
    CRITICAL_SECTION lock;
    std::map<std::string, AgentServiceHealth> services;
public:
    AgentServiceRegistry() { InitializeCriticalSection(&lock); }
    ~AgentServiceRegistry() { DeleteCriticalSection(&lock); }
    bool acquire(const std::string& key, DWORD now, DWORD* remaining) {
        EnterCriticalSection(&lock);
        if (services.find(key) == services.end() && services.size() >= 256) {
            for (std::map<std::string, AgentServiceHealth>::iterator i = services.begin(); i != services.end(); ++i)
                if (!i->second.cooldown && !i->second.failures) { services.erase(i); break; }
            if (services.size() >= 256) { *remaining = 1000; LeaveCriticalSection(&lock); return false; }
        }
        AgentServiceHealth& h = services[key];
        bool allowed = !h.cooldown;
        *remaining = 0;
        if (h.cooldown) {
            DWORD elapsed = now - h.opened;
            if (elapsed >= h.cooldown && !h.probing) { h.probing = true; allowed = true; }
            else *remaining = elapsed < h.cooldown ? h.cooldown - elapsed : 100;
        }
        LeaveCriticalSection(&lock); return allowed;
    }
    void finish(const std::string& key, DWORD now, bool success, bool failure) {
        EnterCriticalSection(&lock);
        std::map<std::string, AgentServiceHealth>::iterator found = services.find(key);
        if (found == services.end()) { LeaveCriticalSection(&lock); return; }
        AgentServiceHealth& h = found->second;
        bool probe = h.probing; h.probing = false;
        if (success) h = AgentServiceHealth();
        else if (failure && (++h.failures >= 3 || probe)) {
            h.opened = now;
            h.cooldown = 15000UL << (h.openings < 3 ? h.openings : 3);
            if (h.openings < 3) ++h.openings;
        }
        LeaveCriticalSection(&lock);
    }
    std::string describe(DWORD now) {
        EnterCriticalSection(&lock); std::string out;
        for (std::map<std::string, AgentServiceHealth>::const_iterator i = services.begin(); i != services.end(); ++i) {
            const AgentServiceHealth& h = i->second;
            out += i->first + ": " + (h.probing ? "probing" : h.cooldown ? (now - h.opened < h.cooldown ? "open" : "probe-ready") : "closed") + "\n";
        }
        LeaveCriticalSection(&lock); return out;
    }
};

static unsigned AgentReadBackoff(unsigned attempt) {
    return 250U << (attempt < 4 ? attempt : 4);
}
