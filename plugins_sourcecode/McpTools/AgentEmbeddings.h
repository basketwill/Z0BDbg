#pragma once
#include "AgentKnowledgeIndex.h"
#include <float.h>

typedef std::vector<double> AgentDenseVector;
static bool ParseDenseVector(const ModelJson& json, AgentDenseVector* output) {
    if (json.kind != ModelJson::ARRAY || json.items.empty() || json.items.size() > 4096) return false;
    AgentDenseVector vector; double norm = 0;
    for (size_t i = 0; i < json.items.size(); ++i) {
        if (json.items[i].kind != ModelJson::NUMBER) return false;
        double value = strtod(json.items[i].value.c_str(), NULL);
        if (!_finite(value) || fabs(value) > 1000000) return false;
        vector.push_back(value); norm += value * value;
    }
    if (norm <= 1e-20 || !_finite(norm)) return false;
    norm = sqrt(norm); for (size_t i = 0; i < vector.size(); ++i) vector[i] /= norm;
    output->swap(vector); return true;
}
static bool ParseEmbeddingResponse(const std::string& text, size_t count, std::vector<AgentDenseVector>* output) {
    ModelJson root;
    if (text.size() > 8 * 1024 * 1024 || !ModelJson::parse(text, &root) || root.get("error")) return false;
    const ModelJson* data = root.get("data");
    if (!data || data->kind != ModelJson::ARRAY || data->items.size() != count || !count || count > 32) return false;
    std::vector<AgentDenseVector> vectors(count); std::set<size_t> seen;
    size_t dimension = 0;
    for (size_t i = 0; i < count; ++i) {
        const ModelJson* index = data->items[i].get("index"), *value = data->items[i].get("embedding");
        if (!index || index->kind != ModelJson::NUMBER || index->value.find_first_not_of("0123456789") != std::string::npos || index->value.size() > 2 || !value) return false;
        size_t n = atoi(index->value.c_str());
        if (n >= count || !seen.insert(n).second || !ParseDenseVector(*value, &vectors[n])) return false;
        if (dimension && dimension != vectors[n].size()) return false;
        dimension = vectors[n].size();
    }
    output->swap(vectors); return true;
}
static double DenseCosine(const AgentDenseVector& a, const AgentDenseVector& b) {
    if (a.size() != b.size()) return -1;
    double value = 0; for (size_t i = 0; i < a.size(); ++i) value += a[i] * b[i]; return value;
}
struct AgentDenseNode { std::string stamp; AgentDenseVector vector; };
class AgentEmbeddingIndex {
public:
    std::string identity;
    size_t dimension;
    std::map<std::string, AgentDenseNode> nodes;
    AgentEmbeddingIndex() : dimension(0) {}
    bool load(const std::string& text, const std::string& expected) {
        ModelJson root; AgentEmbeddingIndex parsed;
        if (text.size() > 64 * 1024 * 1024 || !ModelJson::parse(text, &root) || !root.get("version") || root.get("version")->raw != "2" ||
            !root.get("identity") || root.get("identity")->value != expected || !root.get("nodes") || root.get("nodes")->kind != ModelJson::ARRAY || root.get("nodes")->items.size() > 8192) return false;
        parsed.identity = expected; size_t total = 0;
        for (size_t i = 0; i < root.get("nodes")->items.size(); ++i) {
            const ModelJson& item = root.get("nodes")->items[i]; AgentDenseNode node;
            const ModelJson* id = item.get("id"), *stamp = item.get("stamp"), *vector = item.get("vector");
            if (!id || id->kind != ModelJson::STRING || id->value.size() != 64 || !stamp || stamp->kind != ModelJson::STRING || stamp->value.size() != 64 ||
                parsed.nodes.count(id->value) || !vector || !ParseDenseVector(*vector, &node.vector)) return false;
            if (parsed.dimension && parsed.dimension != node.vector.size()) return false;
            parsed.dimension = node.vector.size(); total += parsed.dimension; if (total > 2000000) return false;
            node.stamp = stamp->value; parsed.nodes[id->value] = node;
        }
        *this = parsed; return true;
    }
    std::string json() const {
        std::string out = "{\"version\":2,\"identity\":"; ModelJson::quote(&out, identity); out += ",\"nodes\":[";
        for (std::map<std::string, AgentDenseNode>::const_iterator i = nodes.begin(); i != nodes.end(); ++i) {
            if (out[out.size() - 1] != '[') out += ',';
            out += "{\"id\":"; ModelJson::quote(&out, i->first); out += ",\"stamp\":"; ModelJson::quote(&out, i->second.stamp);
            out += ",\"vector\":[";
            for (size_t n = 0; n < i->second.vector.size(); ++n) { if (n) out += ','; char number[64]; sprintf_s(number, sizeof(number), "%.17g", i->second.vector[n]); out += number; }
            out += "]}";
        }
        return out + "]}";
    }
    std::vector<MemoryMatch> search(const std::vector<AgentMemoryEntry>& entries, const AgentDenseVector& query, size_t limit) const {
        std::vector<MemoryMatch> matches;
        for (size_t i = 0; i < entries.size(); ++i) {
            std::map<std::string, AgentDenseNode>::const_iterator node = nodes.find(entries[i].id);
            if (node == nodes.end()) continue;
            MemoryMatch match; match.entry = entries[i]; match.score = DenseCosine(query, node->second.vector);
            if (match.score > 0) matches.push_back(match);
        }
        std::sort(matches.begin(), matches.end(), MemoryMatchLess); if (matches.size() > limit) matches.resize(limit); return matches;
    }
};
static std::vector<MemoryMatch> HybridMemoryMatches(const std::vector<MemoryMatch>& lexical, const std::vector<MemoryMatch>& dense, size_t limit) {
    std::map<std::string, MemoryMatch> combined;
    const std::vector<MemoryMatch>* sources[] = { &lexical, &dense };
    for (int s = 0; s < 2; ++s) for (size_t i = 0; i < sources[s]->size(); ++i) {
        const MemoryMatch& match = (*sources[s])[i];
        if (!combined.count(match.entry.id)) { combined[match.entry.id] = match; combined[match.entry.id].score = 0; }
        combined[match.entry.id].score += 1.0 / (60 + i + 1);
    }
    std::vector<MemoryMatch> result;
    for (std::map<std::string, MemoryMatch>::iterator i = combined.begin(); i != combined.end(); ++i) {
        i->second.score *= .5 + i->second.entry.confidence / 200.0; result.push_back(i->second);
    }
    std::sort(result.begin(), result.end(), MemoryMatchLess); if (result.size() > limit) result.resize(limit); return result;
}
