#pragma once

#include <string>
#include <cwctype>

struct AgentModelCapability {
    int context_tokens, quality, latency_ms;
    bool tool_calls;
};

struct AgentModelProfile {
    wchar_t url[512];
    wchar_t name[128];
    wchar_t key[256];
    wchar_t effort[16];
    wchar_t keywords[512];
    wchar_t input_price[32], output_price[32], cached_input_price[32], price_currency[8];
    int timeout_seconds;
    bool enabled;
    bool reviewer;
    AgentModelCapability capability;
};

struct AgentModelSettings {
    bool auto_route;
    bool failover;
    bool review;
    int routing_mode;
    AgentModelProfile profiles[3];
};

static std::wstring AgentLowerText(const std::wstring& text)
{
    std::wstring result = text;
    for (size_t i = 0; i < result.size(); ++i) result[i] = (wchar_t)std::towlower(result[i]);
    return result;
}

static bool AgentProfileReady(const AgentModelProfile& profile)
{
    return profile.enabled && profile.url[0] && profile.name[0];
}

static int AgentRouteModel(const AgentModelSettings& settings, const std::wstring& prompt)
{
    if (!settings.auto_route) return 0;
    std::wstring text = AgentLowerText(prompt);
    size_t best_length = 0;
    int selected = 0;
    for (int i = 0; i < 3; ++i) {
        const AgentModelProfile& profile = settings.profiles[i];
        if (!AgentProfileReady(profile)) continue;
        std::wstring words = AgentLowerText(profile.keywords);
        size_t start = 0;
        while (start < words.size()) {
            size_t end = words.find_first_of(L",;|\r\n\xFF0C\xFF1B", start);
            if (end == std::wstring::npos) end = words.size();
            std::wstring word = words.substr(start, end - start);
            size_t first = word.find_first_not_of(L" \t");
            if (first != std::wstring::npos) {
                word = word.substr(first, word.find_last_not_of(L" \t") - first + 1);
                if (word.size() > best_length && text.find(word) != std::wstring::npos) {
                    selected = i + 1;
                    best_length = word.size();
                }
            }
            start = end + 1;
        }
    }
    return selected;
}
