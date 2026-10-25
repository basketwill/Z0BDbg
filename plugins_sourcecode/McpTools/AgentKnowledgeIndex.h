#pragma once
#include "AgentMemory.h"
#include <map>
#include <math.h>

typedef std::map<unsigned int, double> AgentSparseVector;

static AgentSparseVector KnowledgeVector(const std::string& text)
{
    AgentSparseVector vector;
    std::set<std::wstring> terms = MemoryTerms(text);
    for (std::set<std::wstring>::const_iterator it = terms.begin(); it != terms.end(); ++it) {
        unsigned int hash = 2166136261U;
        for (size_t i = 0; i < it->size(); ++i) { hash ^= (*it)[i]; hash *= 16777619U; }
        vector[hash % 65536] += 1.0;
    }
    double norm = 0;
    for (AgentSparseVector::iterator i = vector.begin(); i != vector.end(); ++i) norm += i->second * i->second;
    norm = sqrt(norm);
    if (norm) for (AgentSparseVector::iterator i = vector.begin(); i != vector.end(); ++i) i->second /= norm;
    return vector;
}

static double KnowledgeCosine(const AgentSparseVector& a, const AgentSparseVector& b)
{
    double sum = 0;
    for (AgentSparseVector::const_iterator i = a.begin(); i != a.end(); ++i) {
        AgentSparseVector::const_iterator match = b.find(i->first);
        if (match != b.end()) sum += i->second * match->second;
    }
    return sum;
}

static std::string KnowledgeVectorJson(const AgentSparseVector& vector)
{
    std::string out = "["; char number[80];
    for (AgentSparseVector::const_iterator i = vector.begin(); i != vector.end(); ++i) {
        if (out.size() > 1) out += ',';
        sprintf_s(number, sizeof(number), "[%u,%.17g]", i->first, i->second); out += number;
    }
    return out + ']';
}

static bool ParseKnowledgeVector(const ModelJson& json, AgentSparseVector* vector)
{
    if (json.kind != ModelJson::ARRAY || json.items.size() > 2048) return false;
    AgentSparseVector parsed;
    for (size_t i = 0; i < json.items.size(); ++i) {
        const ModelJson& pair = json.items[i];
        if (pair.kind != ModelJson::ARRAY || pair.items.size() != 2 ||
            pair.items[0].kind != ModelJson::NUMBER || pair.items[1].kind != ModelJson::NUMBER) return false;
        const std::string& key = pair.items[0].value;
        if (key.empty() || key.find_first_not_of("0123456789") != std::string::npos || key.size() > 5) return false;
        unsigned int slot = (unsigned int)atoi(key.c_str()); double value = atof(pair.items[1].value.c_str());
        if (slot >= 65536 || !_finite(value) || value <= 0 || value > 1 || parsed.count(slot)) return false;
        parsed[slot] = value;
    }
    *vector = parsed; return true;
}

struct KnowledgeIndexNode { std::string stamp; AgentSparseVector vector; };

class AgentKnowledgeIndex {
    std::map<std::string, KnowledgeIndexNode> nodes;
public:
    unsigned int changed;
    AgentKnowledgeIndex() : changed(0) {}
    bool load(const std::string& data) {
        ModelJson root;
        if (!ModelJson::parse(data, &root) || !root.get("version") || root.get("version")->raw != "1" ||
            !root.get("nodes") || root.get("nodes")->kind != ModelJson::ARRAY || root.get("nodes")->items.size() > 16384) return false;
        std::map<std::string, KnowledgeIndexNode> parsed;
        for (size_t i = 0; i < root.get("nodes")->items.size(); ++i) {
            const ModelJson& item = root.get("nodes")->items[i]; KnowledgeIndexNode node;
            const ModelJson* id = item.get("id"), *stamp = item.get("stamp"), *vector = item.get("vector");
            if (!id || id->kind != ModelJson::STRING || id->value.size() != 64 || parsed.count(id->value) ||
                !stamp || stamp->kind != ModelJson::STRING || stamp->value.size() != 64 || !vector || !ParseKnowledgeVector(*vector, &node.vector)) return false;
            node.stamp = stamp->value; parsed[id->value] = node;
        }
        nodes.swap(parsed); return true;
    }
    template<class Digest> void update(const std::vector<AgentMemoryEntry>& entries, Digest digest) {
        std::set<std::string> current; changed = 0;
        for (size_t i = 0; i < entries.size(); ++i) {
            const AgentMemoryEntry& entry = entries[i]; current.insert(entry.id);
            std::string stamp = digest(MemoryJson(entry));
            if (nodes.count(entry.id) && nodes[entry.id].stamp == stamp) continue;
            KnowledgeIndexNode node; node.stamp = stamp; node.vector = KnowledgeVector(entry.text + " " + entry.source);
            nodes[entry.id] = node; ++changed;
        }
        for (std::map<std::string, KnowledgeIndexNode>::iterator i = nodes.begin(); i != nodes.end();) {
            if (!current.count(i->first)) { nodes.erase(i++); ++changed; } else ++i;
        }
    }
    std::string json() const {
        std::string out = "{\"version\":1,\"representation\":\"hashed-term-cosine-v1\",\"nodes\":[";
        for (std::map<std::string, KnowledgeIndexNode>::const_iterator i = nodes.begin(); i != nodes.end(); ++i) {
            if (out[out.size() - 1] != '[') out += ',';
            out += "{\"id\":"; ModelJson::quote(&out, i->first);
            out += ",\"stamp\":"; ModelJson::quote(&out, i->second.stamp);
            out += ",\"vector\":" + KnowledgeVectorJson(i->second.vector) + '}';
        }
        return out + "]}";
    }
    std::vector<MemoryMatch> search(const std::vector<AgentMemoryEntry>& entries, const std::string& query, size_t limit) const {
        AgentSparseVector vector = KnowledgeVector(query); std::vector<MemoryMatch> results;
        std::map<std::string, std::string> facts; std::set<std::string> conflicts;
        for (size_t i = 0; i < entries.size(); ++i) {
            const AgentMemoryEntry& e = entries[i]; if (MemoryExpired(e) || !e.superseded_by.empty()) continue;
            std::string key = e.project + "\n" + e.fact_key;
            if (!e.fact_key.empty()) {
                if (facts.count(key) && facts[key] != e.text) conflicts.insert(key); else facts[key] = e.text;
            }
        }
        std::set<std::string> active, conflicting_ids;
        for (size_t i = 0; i < entries.size(); ++i) if (!MemoryExpired(entries[i]) && entries[i].superseded_by.empty()) active.insert(entries[i].id);
        for (size_t i = 0; i < entries.size(); ++i) if (active.count(entries[i].id))
            for (size_t c = 0; c < entries[i].conflicts.size(); ++c) if (active.count(entries[i].conflicts[c])) {
                conflicting_ids.insert(entries[i].id); conflicting_ids.insert(entries[i].conflicts[c]);
            }
        for (size_t i = 0; i < entries.size(); ++i) {
            const AgentMemoryEntry& e = entries[i];
            if ((e.kind == "result" && !e.verified) || MemoryExpired(e) || !e.superseded_by.empty() ||
                conflicts.count(e.project + "\n" + e.fact_key) || conflicting_ids.count(e.id)) continue;
            std::map<std::string, KnowledgeIndexNode>::const_iterator node = nodes.find(e.id); if (node == nodes.end()) continue;
            MemoryMatch match; match.entry = e; match.score = KnowledgeCosine(vector, node->second.vector) + (e.kind == "preference" ? .05 : 0);
            if (match.score > 0) results.push_back(match);
        }
        std::sort(results.begin(), results.end(), MemoryMatchLess);
        if (results.size() > limit) results.resize(limit); return results;
    }
};
