#pragma once

#include "ModelJson.h"
#include "McpToolTraits.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <set>
#include <vector>

struct ModelToolBinding {
    std::string model_name;
    std::string mcp_name;
    std::string input_schema;
    bool read_only;
    McpOperationRisk risk;
    ModelToolBinding() : read_only(false), risk(MCP_DANGEROUS) {}
};

static bool ValidModelToolName(const std::string& name)
{
    if (name.empty() || name.size() > 64) return false;
    for (size_t i = 0; i < name.size(); ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
            !(c >= '0' && c <= '9') && c != '_' && c != '-') return false;
    }
    return true;
}

static bool ModelToolSchema(const ModelJson* schema, std::string* output)
{
    if (!schema) {
        *output = "{\"type\":\"object\"}";
        return true;
    }
    if (schema->kind != ModelJson::OBJECT) return false;
    const ModelJson* type = schema->get("type");
    if (type && (type->kind != ModelJson::STRING || type->value != "object")) return false;
    const ModelJson* properties = schema->get("properties");
    if (properties && properties->kind != ModelJson::OBJECT) return false;
    const ModelJson* required = schema->get("required");
    if (required) {
        if (required->kind != ModelJson::ARRAY) return false;
        if (!properties && !required->items.empty()) return false;
        for (size_t i = 0; i < required->items.size(); ++i) {
            const ModelJson& item = required->items[i];
            if (item.kind != ModelJson::STRING ||
                (properties && !properties->get(item.value.c_str()))) return false;
        }
    }
    *output = schema->raw;
    if (!type) output->insert(1, "\"type\":\"object\"" +
        std::string(schema->items.empty() ? "" : ","));
    return true;
}

static bool PriorityDebuggerTool(const std::string& name)
{
    return name == "get_debug_context" || name == "get_event_capabilities" || name == "get_isolation_policy" ||
        name == "wait_debug_event" || name == "get_status" ||
        name == "run" || name == "go" || name == "pause" ||
        name == "read_memory" || name == "write_memory" ||
        name == "debug_find_process" || name == "debug_open_process" || name == "debug_attach_pid" || name == "debug_stop" ||
        name == "register_get" || name == "register_list" || name == "register_set" ||
        name == "stack_get_pointers" || name == "stack_read" ||
        name == "thread_list" || name == "thread_get" ||
        name == "module_list" || name == "module_get" ||
        name == "breakpoint_list" || name == "resolve_symbol" || name == "set_software_breakpoint" ||
        name == "delete_software_breakpoint" || name == "dump_memory_region";
}

static bool BuildModelTools(const std::string& remote_result, std::string* tools_json,
    std::vector<ModelToolBinding>* bindings, std::string* error, size_t max_tools = 128)
{
    ModelJson root;
    if (!ModelJson::parse(remote_result, &root)) {
        *error = "Remote MCP tools list is invalid JSON.";
        return false;
    }
    const ModelJson* tools = root.get("tools");
    if (!tools || tools->kind != ModelJson::ARRAY) {
        *error = "Remote MCP tools list has no tools array.";
        return false;
    }
    bindings->clear();
    std::set<std::string> reserved;
    for (size_t i = 0; i < tools->items.size(); ++i) {
        const ModelJson& tool = tools->items[i];
        const ModelJson* name = tool.get("name");
        if (!name || name->kind != ModelJson::STRING || name->value.empty() ||
            !reserved.insert(name->value).second) {
            *error = "Remote MCP has a missing or duplicate tool name.";
            return false;
        }
    }
    std::vector<bool> selected(tools->items.size(), tools->items.size() <= max_tools);
    if (tools->items.size() > max_tools) {
        size_t count = 0;
        for (size_t i = 0; i < tools->items.size(); ++i)
            if (count < max_tools && PriorityDebuggerTool(tools->items[i].get("name")->value)) { selected[i] = true; ++count; }
        for (size_t i = 0; i < tools->items.size() && count < max_tools; ++i)
            if (!selected[i]) { selected[i] = true; ++count; }
    }
    *tools_json = "[";
    for (size_t i = 0; i < tools->items.size(); ++i) {
        if (!selected[i]) continue;
        const ModelJson& tool = tools->items[i];
        std::string original = tool.get("name")->value;
        std::string alias = original;
        if (!ValidModelToolName(alias)) {
            char number[32];
            sprintf_s(number, sizeof(number), "mcp_tool_%u", (unsigned)i + 1);
            alias = number;
            while (reserved.find(alias) != reserved.end()) alias += '_';
        }
        std::string schema;
        if (!ModelToolSchema(tool.get("inputSchema"), &schema)) {
            *error = "Remote MCP tool has an invalid object inputSchema: " + original;
            return false;
        }
        if (!bindings->empty()) *tools_json += ',';
        ModelToolBinding binding;
        binding.model_name = alias;
        binding.mcp_name = original;
        binding.input_schema = schema;
        binding.read_only = McpReadOnlyTool(original);
        const ModelJson* annotations = tool.get("annotations");
        const ModelJson* read_only = annotations ? annotations->get("readOnlyHint") : NULL;
        if (read_only && read_only->kind == ModelJson::BOOLEAN)
            binding.read_only = read_only->value == "true";
        const ModelJson* destructive = annotations ? annotations->get("destructiveHint") : NULL;
        if (McpKnownDangerousTool(original) || (destructive && destructive->kind == ModelJson::BOOLEAN && destructive->value == "true"))
            binding.risk = MCP_DANGEROUS;
        else if (McpKnownModifyTool(original)) binding.risk = MCP_MODIFY;
        else binding.risk = binding.read_only ? MCP_READ_ONLY : MCP_DANGEROUS;
        binding.read_only = binding.risk == MCP_READ_ONLY;
        bindings->push_back(binding);
        *tools_json += "{\"type\":\"function\",\"function\":{\"name\":";
        ModelJson::quote(tools_json, alias);
        *tools_json += ",\"description\":";
        const ModelJson* description = tool.get("description");
        std::string detail = description && description->kind == ModelJson::STRING
            ? description->value : std::string();
        detail += " [operation risk: " + std::string(McpRiskName(binding.risk)) + "]";
        if (binding.risk != MCP_READ_ONLY && original != "write_memory")
            detail += " [automatic undo: unavailable]";
        if (alias != original) detail = "MCP tool " + original + ". " + detail;
        ModelJson::quote(tools_json, detail);
        *tools_json += ",\"parameters\":" + schema + "}}";
    }
    *tools_json += "]";
    return true;
}

static bool FindRemoteToolBinding(const std::string& remote_result, const std::string& name,
    ModelToolBinding* binding, std::string* error)
{
    ModelJson root;
    if (!ModelJson::parse(remote_result, &root)) return false;
    const ModelJson* tools = root.get("tools");
    if (!tools || tools->kind != ModelJson::ARRAY) return false;
    const ModelJson* found = NULL;
    std::set<std::string> names;
    for (size_t i = 0; i < tools->items.size(); ++i) {
        const ModelJson* item_name = tools->items[i].get("name");
        if (!item_name || item_name->kind != ModelJson::STRING || item_name->value.empty() ||
            !names.insert(item_name->value).second) {
            *error = "Remote MCP has a missing or duplicate tool name.";
            return false;
        }
        if (item_name->value == name) found = &tools->items[i];
    }
    if (!found) return false;
    std::vector<ModelToolBinding> selected;
    std::string selected_json, catalog = "{\"tools\":[" + found->raw + "]}";
    if (!BuildModelTools(catalog, &selected_json, &selected, error) || selected.size() != 1) return false;
    *binding = selected[0];
    return true;
}

static bool ValidateToolValue(const ModelJson& value, const ModelJson& schema, int depth = 0)
{
    if (depth > 16 || schema.kind != ModelJson::OBJECT) return false;
    const ModelJson* type = schema.get("type");
    if (type && type->kind == ModelJson::ARRAY) {
        if (type->items.empty() || type->items.size() > 8) return false;
        for (size_t i = 0; i < type->items.size(); ++i) {
            if (type->items[i].kind != ModelJson::STRING) return false;
            ModelJson alternative = schema;
            for (size_t k = 0; k < alternative.keys.size(); ++k) if (alternative.keys[k] == "type") alternative.items[k] = type->items[i];
            if (ValidateToolValue(value, alternative, depth + 1)) return true;
        }
        return false;
    }
    if (type && type->kind == ModelJson::STRING) {
        const std::string& name = type->value;
        if ((name == "object" && value.kind != ModelJson::OBJECT) ||
            (name == "array" && value.kind != ModelJson::ARRAY) ||
            (name == "string" && value.kind != ModelJson::STRING) ||
            (name == "boolean" && value.kind != ModelJson::BOOLEAN) ||
            ((name == "number" || name == "integer") && value.kind != ModelJson::NUMBER) ||
            (name == "null" && value.kind != ModelJson::NIL)) return false;
        if (name == "integer" && value.kind == ModelJson::NUMBER) {
            double number = strtod(value.raw.c_str(), NULL);
            if (!_finite(number) || floor(number) != number) return false;
        }
    }
    const ModelJson* allowed = schema.get("enum");
    if (allowed && allowed->kind == ModelJson::ARRAY) {
        bool found = false;
        for (size_t i = 0; i < allowed->items.size(); ++i)
            if (allowed->items[i].kind == value.kind && allowed->items[i].value == value.value &&
                (value.kind != ModelJson::OBJECT && value.kind != ModelJson::ARRAY || allowed->items[i].raw == value.raw)) found = true;
        if (!found) return false;
    }
    if (value.kind == ModelJson::NUMBER) {
        double number = strtod(value.raw.c_str(), NULL);
        const ModelJson* low = schema.get("minimum"), *high = schema.get("maximum");
        if (!_finite(number) || (low && low->kind == ModelJson::NUMBER && number < strtod(low->raw.c_str(), NULL)) ||
            (high && high->kind == ModelJson::NUMBER && number > strtod(high->raw.c_str(), NULL))) return false;
    }
    if (value.kind == ModelJson::OBJECT) {
        const ModelJson* required = schema.get("required"), *properties = schema.get("properties"), *extra = schema.get("additionalProperties");
        if (required && required->kind == ModelJson::ARRAY)
            for (size_t i = 0; i < required->items.size(); ++i) if (!value.get(required->items[i].value.c_str())) return false;
        for (size_t i = 0; i < value.keys.size(); ++i) {
            const ModelJson* child = properties ? properties->get(value.keys[i].c_str()) : NULL;
            if (child && !ValidateToolValue(value.items[i], *child, depth + 1)) return false;
            if (!child && extra && extra->kind == ModelJson::BOOLEAN && extra->value == "false") return false;
        }
    }
    if (value.kind == ModelJson::ARRAY) {
        const ModelJson* item = schema.get("items"), *limit = schema.get("maxItems");
        if (limit && limit->kind == ModelJson::NUMBER && value.items.size() > strtod(limit->raw.c_str(), NULL)) return false;
        if (item && item->kind == ModelJson::OBJECT)
            for (size_t i = 0; i < value.items.size(); ++i) if (!ValidateToolValue(value.items[i], *item, depth + 1)) return false;
    }
    return true;
}

static bool ValidateToolArguments(const ModelToolBinding& binding, const std::string& arguments)
{
    ModelJson args, schema;
    return ModelJson::parse(arguments, &args) && args.kind == ModelJson::OBJECT &&
        (binding.input_schema.empty() || (ModelJson::parse(binding.input_schema, &schema) && ValidateToolValue(args, schema)));
}

static bool ResolveModelTool(const std::vector<ModelToolBinding>& bindings,
    const std::string& model_name, std::string* mcp_name)
{
    for (size_t i = 0; i < bindings.size(); ++i) {
        if (bindings[i].model_name == model_name) {
            *mcp_name = bindings[i].mcp_name;
            return true;
        }
    }
    return false;
}
