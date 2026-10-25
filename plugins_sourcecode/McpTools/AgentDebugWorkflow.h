#pragma once

#include "ModelJson.h"
#include <cstdlib>
#include <stdio.h>
#include <string>

static bool AgentTextHas(const std::wstring& text, const wchar_t* word)
{
    return text.find(word) != std::wstring::npos;
}

static bool AgentNeedsManagedDebugTask(const std::wstring& prompt)
{
    std::wstring text = prompt;
    for (size_t i = 0; i < text.size(); ++i)
        if (text[i] >= L'A' && text[i] <= L'Z') text[i] += L'a' - L'A';
    const bool explicit_debug = AgentTextHas(text, L"\u8c03\u8bd5") || AgentTextHas(text, L"\u6392\u67e5") ||
        AgentTextHas(text, L"\u5b9a\u4f4d\u5d29\u6e83") || AgentTextHas(text, L"debug ") ||
        AgentTextHas(text, L"debug\t") || AgentTextHas(text, L"trace ");
    const bool file_target = AgentTextHas(text, L".exe") || AgentTextHas(text, L".dll");
    const bool target = file_target || AgentTextHas(text, L"\u7a0b\u5e8f") ||
        AgentTextHas(text, L"\u8fdb\u7a0b") || AgentTextHas(text, L"\u6a21\u5757") ||
        AgentTextHas(text, L"process");
    const bool event_work = AgentTextHas(text, L"\u65ad\u70b9") || AgentTextHas(text, L"\u547d\u4e2d") ||
        AgentTextHas(text, L"\u8c03\u7528\u94fe") || AgentTextHas(text, L"\u5f02\u5e38") ||
        AgentTextHas(text, L"breakpoint") || AgentTextHas(text, L"exception");
    const bool observe = AgentTextHas(text, L"\u89c2\u5bdf") || AgentTextHas(text, L"\u8ffd\u8e2a") ||
        AgentTextHas(text, L"\u5206\u6790") || AgentTextHas(text, L"\u76d1\u63a7") ||
        AgentTextHas(text, L"collect") || AgentTextHas(text, L"monitor");
    return (explicit_debug && target) || (event_work && observe && target) ||
        (file_target && observe);
}

static bool AgentParseBreakpointSample(const std::string& json,
    unsigned __int64* address, unsigned* max_hits, unsigned* timeout_seconds)
{
    ModelJson root;
    if (!address || !max_hits || !timeout_seconds || !ModelJson::parse(json, &root) ||
        root.kind != ModelJson::OBJECT) return false;
    const ModelJson* location = root.get("address");
    const ModelJson* hits = root.get("max_hits");
    const ModelJson* timeout = root.get("timeout_seconds");
    if (!location || location->kind != ModelJson::STRING || location->value.empty() ||
        !hits || hits->kind != ModelJson::NUMBER || !timeout || timeout->kind != ModelJson::NUMBER ||
        hits->raw.empty() || timeout->raw.empty() ||
        hits->raw.find_first_not_of("0123456789") != std::string::npos ||
        timeout->raw.find_first_not_of("0123456789") != std::string::npos ||
        hits->raw.size() > 2 || timeout->raw.size() > 3) return false;
    *max_hits = (unsigned)strtoul(hits->raw.c_str(), NULL, 10);
    *timeout_seconds = (unsigned)strtoul(timeout->raw.c_str(), NULL, 10);
    if (*max_hits < 1 || *max_hits > 16 || *timeout_seconds < 1 || *timeout_seconds > 120) return false;
    const std::string& value = location->value;
    size_t start = value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') ? 2 : 0;
    if (start == value.size() || value.size() - start > 16 ||
        value.find_first_not_of("0123456789abcdefABCDEF", start) != std::string::npos) return false;
    *address = _strtoui64(value.c_str() + start, NULL, 16);
    return *address != 0;
}

static bool AgentBreakpointStopMatches(const ModelJson* stop, unsigned __int64 address)
{
    if (!stop || stop->kind != ModelJson::OBJECT) return false;
    const ModelJson* location = stop->get("exceptionAddress");
    const ModelJson* code = stop->get("exceptionCode");
    return location && location->kind == ModelJson::STRING && code &&
        code->kind == ModelJson::NUMBER &&
        _strtoui64(location->value.c_str(), NULL, 0) == address &&
        code->raw == "2147483651";
}

static std::string AgentDebugObservationSummary(const std::string& tool, const std::string& response)
{
    ModelJson rpc;
    if (!ModelJson::parse(response, &rpc)) return "";
    const ModelJson* result = rpc.get("result");
    if (!result || result->kind != ModelJson::OBJECT) return "";
    std::string detail = tool;
    const char* keys[] = { "process_id", "thread_id", "status", "sequence", "cursor",
        "address", "name", "path", "read", "size", "return", "count", "reason" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const ModelJson* field = result->get(keys[i]);
        if (!field || (field->kind != ModelJson::STRING && field->kind != ModelJson::NUMBER)) continue;
        detail += " "; detail += keys[i]; detail += "=";
        detail += field->value.size() > 120 ? field->value.substr(0, 120) : field->value;
    }
    const ModelJson* stop = result->get("last_stop");
    if (stop && stop->kind == ModelJson::OBJECT) {
        const char* fields[] = { "debugEventName", "exceptionCode", "exceptionAddress", "processId", "threadId" };
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
            const ModelJson* field = stop->get(fields[i]);
            if (!field) continue;
            detail += " "; detail += fields[i]; detail += "="; detail += field->value;
        }
    }
    const ModelJson* events = result->get("events");
    if (events && events->kind == ModelJson::ARRAY) {
        char count[32];
        sprintf_s(count, sizeof(count), "%u", (unsigned)events->items.size());
        detail += " events="; detail += count;
    }
    return detail;
}

static bool AgentDebugObservationRelevant(const std::string& tool)
{
    return tool == "get_debug_context" || tool == "wait_debug_event" ||
        tool == "sample_breakpoint_hits" || tool == "resolve_symbol" ||
        tool == "set_software_breakpoint" || tool == "register_list" ||
        tool == "stack_read" || tool == "read_memory" ||
        tool == "disassemble" || tool == "static_disassemble" ||
        tool == "module_list" || tool == "debug_open_process";
}
