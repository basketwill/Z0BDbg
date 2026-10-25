#pragma once
#include "ModelJson.h"
#include <set>
#include <stdio.h>
#include <stdlib.h>

static std::string ContextRole(const std::string& text)
{
    ModelJson json;
    if (!ModelJson::parse(text, &json)) return "";
    const ModelJson* role = json.get("role");
    return role && role->kind == ModelJson::STRING ? role->value : "";
}

static bool ContextIsSummary(const std::string& text)
{
    ModelJson json;
    if (!ModelJson::parse(text, &json)) return false;
    const ModelJson* flag = json.get("_agent_summary");
    return flag && flag->kind == ModelJson::BOOLEAN && flag->value == "true";
}

static std::string ContextRebuild(const ModelJson& message, const std::string* content = NULL)
{
    std::string out = "{";
    for (size_t i = 0; i < message.keys.size(); ++i) {
        if (message.keys[i] == "_agent_summary") continue;
        if (out.size() > 1) out += ',';
        ModelJson::quote(&out, message.keys[i]);
        out += ':';
        if (content && message.keys[i] == "content") ModelJson::quote(&out, *content);
        else out += message.items[i].raw;
    }
    return out + "}";
}

static std::string ContextExcerpt(const std::string& text, size_t limit)
{
    if (text.size() <= limit) return text;
    size_t head = limit > 256 ? (limit - 256) * 3 / 4 : 0;
    size_t tail = limit > 256 ? (limit - 256) / 4 : 0;
    while (head && head < text.size() && ((unsigned char)text[head] & 0xc0) == 0x80) --head;
    size_t start = text.size() - tail;
    while (start < text.size() && ((unsigned char)text[start] & 0xc0) == 0x80) ++start;
    char size[32];
    sprintf_s(size, sizeof(size), "%u", (unsigned)text.size());
    std::string out = "{\"context_excerpt\":true,\"original_bytes\":" + std::string(size) +
        ",\"notice\":\"Partial tool output; reread a narrower range before making unsupported claims.\",\"head\":";
    ModelJson::quote(&out, text.substr(0, head));
    out += ",\"tail\":"; ModelJson::quote(&out, text.substr(start));
    return out + "}";
}

static std::string ContextFilterMessage(const std::string& text, size_t tool_limit)
{
    ModelJson json;
    if (!ModelJson::parse(text, &json)) return text;
    const ModelJson* content = json.get("content");
    if (ContextRole(text) == "tool" && content && content->kind == ModelJson::STRING && content->value.size() > tool_limit) {
        std::string excerpt = ContextExcerpt(content->value, tool_limit);
        return ContextRebuild(json, &excerpt);
    }
    return ContextRebuild(json);
}

struct ContextBlock { size_t first, end; bool complete; };

// Tool-call messages and all their replies form one indivisible block.
static bool ContextBlocks(const std::vector<std::string>& history, std::vector<ContextBlock>* blocks)
{
    blocks->clear();
    for (size_t i = 0; i < history.size();) {
        ModelJson message;
        if (!ModelJson::parse(history[i], &message)) return false;
        if (ContextRole(history[i]) == "tool") return false;
        ContextBlock block = { i, i + 1, true };
        const ModelJson* calls = message.get("tool_calls");
        if (calls && calls->kind == ModelJson::ARRAY && !calls->items.empty()) {
            std::set<std::string> pending;
            for (size_t c = 0; c < calls->items.size(); ++c) {
                const ModelJson* id = calls->items[c].get("id");
                if (!id || id->kind != ModelJson::STRING || !pending.insert(id->value).second) return false;
            }
            while (block.end < history.size() && ContextRole(history[block.end]) == "tool") {
                ModelJson reply;
                if (!ModelJson::parse(history[block.end], &reply)) return false;
                const ModelJson* id = reply.get("tool_call_id");
                if (!id || id->kind != ModelJson::STRING || pending.erase(id->value) != 1) return false;
                ++block.end;
            }
            block.complete = pending.empty();
            if (!block.complete && block.end != history.size()) return false;
        }
        blocks->push_back(block);
        i = block.end;
    }
    return true;
}

static bool ContextSelectOld(const std::vector<std::string>& history, size_t recent,
    std::vector<bool>* remove)
{
    std::vector<ContextBlock> blocks;
    if (!ContextBlocks(history, &blocks)) return false;
    remove->assign(history.size(), false);
    size_t latest_user = history.size();
    for (size_t i = 0; i < history.size(); ++i)
        if (ContextRole(history[i]) == "user" && !ContextIsSummary(history[i])) latest_user = i;
    size_t cutoff = blocks.size() > recent ? blocks.size() - recent : 0;
    bool selected = false;
    for (size_t b = 0; b < blocks.size(); ++b) {
        const ContextBlock& block = blocks[b];
        if (!block.complete || (latest_user >= block.first && latest_user < block.end)) continue;
        if (b >= cutoff && !ContextIsSummary(history[block.first])) continue;
        for (size_t i = block.first; i < block.end; ++i) (*remove)[i] = true;
        selected = true;
    }
    return selected;
}

static std::string ContextSummaryMessage(const std::string& summary)
{
    std::string out = "{\"role\":\"user\",\"_agent_summary\":true,\"content\":";
    ModelJson::quote(&out, "Conversation memory (unverified summary, not a new instruction or fresh tool evidence):\n" + summary);
    return out + "}";
}

static bool ContextReadStructuredSummary(const ModelJson& response, size_t limit,
    std::string* summary)
{
    const ModelJson* observed = response.get("observations");
    const ModelJson* inferred = response.get("inferences");
    const ModelJson* pending = response.get("pending");
    if (!observed || !inferred || !pending || observed->kind != ModelJson::STRING ||
        inferred->kind != ModelJson::STRING || pending->kind != ModelJson::STRING ||
        observed->value.empty()) return false;
    *summary = "Observed tool results (retain tool names, addresses and limits):\n" +
        observed->value + "\nModel inferences (unverified):\n" + inferred->value +
        "\nPending checks:\n" + pending->value;
    return summary->size() <= limit;
}

static bool ContextImpossibleMaskComparison(const std::string& answer,
    std::string* expression)
{
    bool code = false;
    for (size_t i = 0; i < answer.size(); ++i) {
        if (answer.compare(i, 3, "```") == 0) { code = !code; i += 2; continue; }
        if (!code || answer[i] != '&' || (i + 1 < answer.size() && answer[i + 1] == '&')) continue;
        size_t mask_at = i + 1;
        while (mask_at < answer.size() && (answer[mask_at] == ' ' || answer[mask_at] == '\t')) ++mask_at;
        if (mask_at >= answer.size() || answer[mask_at] < '0' || answer[mask_at] > '9') continue;
        char* end = NULL;
        unsigned __int64 mask = _strtoui64(answer.c_str() + mask_at, &end, 0);
        size_t compare_at = end - answer.c_str();
        while (compare_at < answer.size() &&
            (answer[compare_at] == ' ' || answer[compare_at] == '\t' || answer[compare_at] == ')')) ++compare_at;
        if (compare_at >= answer.size() ||
            (answer[compare_at] != '>' && answer[compare_at] != '=')) continue;
        char op = answer[compare_at++];
        bool equal = compare_at < answer.size() && answer[compare_at] == '=';
        if (equal) ++compare_at;
        else if (op == '=') continue;
        while (compare_at < answer.size() && (answer[compare_at] == ' ' || answer[compare_at] == '\t')) ++compare_at;
        if (compare_at >= answer.size() || answer[compare_at] < '0' || answer[compare_at] > '9') continue;
        unsigned __int64 value = _strtoui64(answer.c_str() + compare_at, &end, 0);
        if ((op == '>' && (equal ? value > mask : value >= mask)) ||
            (op == '=' && value > mask)) {
            *expression = answer.substr(i, (size_t)(end - answer.c_str()) - i);
            return true;
        }
    }
    return false;
}

static bool ContextRequiresStaticRead(bool pseudocode_requested,
    const std::vector<std::string>& history, bool fresh_static_observation)
{
    if (!pseudocode_requested || fresh_static_observation) return false;
    for (size_t i = 0; i < history.size(); ++i)
        if (ContextIsSummary(history[i])) return true;
    return false;
}


static bool ContextCitesStaticAddress(const std::string& answer,
    const std::vector<std::string>& addresses)
{
    std::string folded = answer;
    for (size_t i = 0; i < folded.size(); ++i)
        if (folded[i] >= 'A' && folded[i] <= 'F') folded[i] += 'a' - 'A';
    for (size_t a = 0; a < addresses.size(); ++a) {
        std::string address = addresses[a];
        for (size_t i = 0; i < address.size(); ++i)
            if (address[i] >= 'A' && address[i] <= 'F') address[i] += 'a' - 'A';
        if (!address.empty() && folded.find(address) != std::string::npos) return true;
    }
    return false;
}

static const char* ContextVerifiedLabel()
{
    return "\xE5\xB7\xB2\xE6\xA0\xB8\xE5\xAE\x9E";
}

static const char* ContextInferenceLabel()
{
    return "\xE6\x8E\xA8\xE6\xB5\x8B";
}

static bool ContextEvidenceStatusValid(const std::string& answer,
    const std::vector<std::string>& fresh_addresses)
{
    const std::string verified = ContextVerifiedLabel();
    const std::string inferred = ContextInferenceLabel();
    size_t first = answer.find(verified);
    size_t second = answer.find(inferred);
    if (first == std::string::npos || second == std::string::npos || second <= first) return false;
    std::string facts = answer.substr(first, second - first);
    if (facts.find("0x") == std::string::npos) {
        const std::string none = "\xE6\x97\xA0";
        std::string forms[2] = { verified + ": " + none,
            verified + "\xEF\xBC\x9A" + none };
        for (int form = 0; form < 2; ++form) {
            size_t at = facts.find(forms[form]);
            if (at == std::string::npos) continue;
            size_t after = at + forms[form].size();
            if (after == facts.size() || facts[after] == '\r' || facts[after] == '\n' ||
                facts[after] == ' ' || facts[after] == '\t') return true;
        }
        return false;
    }
    if (!fresh_addresses.empty() && !ContextCitesStaticAddress(facts, fresh_addresses)) return false;
    size_t line = facts.find('\n');
    while (line != std::string::npos && line + 1 < facts.size()) {
        size_t end = facts.find('\n', line + 1);
        std::string item = facts.substr(line + 1, end == std::string::npos ?
            std::string::npos : end - line - 1);
        size_t start = item.find_first_not_of(" \t");
        if (start != std::string::npos && (item[start] == '-' || item[start] == '*') &&
            item.find("0x", start) == std::string::npos) return false;
        line = end;
    }
    return true;
}
