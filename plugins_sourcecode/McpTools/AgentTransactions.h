#pragma once
#include "AgentCheckpoint.h"

static bool AgentHexBytes(const std::string& text, std::string* normalized) {
    normalized->clear();
    for (size_t i = 0; i < text.size(); ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c >= 'a' && c <= 'f') c -= 'a' - 'A';
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return false;
        *normalized += c;
        if (normalized->size() > 8192) return false;
    }
    return !normalized->empty() && normalized->size() % 2 == 0;
}

static bool AgentMemoryChange(const std::string& arguments, std::string* observation,
    std::string* expected, std::string* address) {
    ModelJson args;
    if (!ModelJson::parse(arguments, &args) || args.kind != ModelJson::OBJECT) return false;
    const ModelJson* at = args.get("address"), *hex = args.get("hex");
    if (!hex) hex = args.get("data");
    if (!at || (at->kind != ModelJson::NUMBER && at->kind != ModelJson::STRING) ||
        !hex || hex->kind != ModelJson::STRING || !AgentHexBytes(hex->value, expected)) return false;
    *address = at->raw;
    *observation = "{\"address\":" + at->raw + ",\"size\":" + TaskNumber((int)expected->size() / 2) + "}";
    return true;
}

static bool AgentSnapshotHex(const ModelJson& data, size_t bytes, std::string* hex) {
    const ModelJson* value = data.get("hex"), *read = data.get("read"), *ok = data.get("ok");
    return value && value->kind == ModelJson::STRING && read && read->kind == ModelJson::NUMBER &&
        read->raw == TaskNumber((int)bytes) && (!ok || ok->raw == "true") &&
        AgentHexBytes(value->value, hex) && hex->size() == bytes * 2;
}
