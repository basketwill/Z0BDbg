#pragma once
#include "ModelJson.h"
#include "McpToolTraits.h"
#include <vector>

struct AgentAssertion {
    std::string tool, arguments, expected;
};

static bool AgentLookupMiss(const std::string& tool, const std::string& receipt)
{
    if (tool != "find_import_by_name" && tool != "resolve_symbol") return false;
    ModelJson root;
    if (!ModelJson::parse(receipt, &root) || root.kind != ModelJson::OBJECT || root.get("error")) return false;
    const ModelJson* result = root.get("result");
    const ModelJson* ok = result ? result->get("ok") : NULL;
    const ModelJson* address = result ? result->get("address") : NULL;
    const ModelJson* is_error = result ? result->get("isError") : NULL;
    return result && result->kind == ModelJson::OBJECT &&
        ok && ok->kind == ModelJson::BOOLEAN && ok->value == "false" &&
        address && address->kind == ModelJson::STRING &&
        (address->value == "0x0" || address->value == "0x00000000" || address->value == "0x0000000000000000") &&
        !(is_error && is_error->kind == ModelJson::BOOLEAN && is_error->value == "true");
}

static bool AssertionEqual(const ModelJson& actual, const ModelJson& expected, bool subset = false)
{
    if (actual.kind != expected.kind) return false;
    if (expected.kind == ModelJson::OBJECT) {
        if (!subset && actual.keys.size() != expected.keys.size()) return false;
        for (size_t i = 0; i < expected.keys.size(); ++i) {
            const ModelJson* value = actual.get(expected.keys[i].c_str());
            if (!value || !AssertionEqual(*value, expected.items[i], subset)) return false;
        }
        return true;
    }
    if (expected.kind == ModelJson::ARRAY) {
        if (actual.items.size() != expected.items.size()) return false;
        for (size_t i = 0; i < expected.items.size(); ++i)
            if (!AssertionEqual(actual.items[i], expected.items[i], subset)) return false;
        return true;
    }
    return actual.value == expected.value;
}

static bool AssertionSubstantive(const ModelJson& expected)
{
    if (expected.kind == ModelJson::OBJECT || expected.kind == ModelJson::ARRAY) {
        for (size_t i = 0; i < expected.items.size(); ++i)
            if ((expected.kind != ModelJson::OBJECT || expected.keys[i] != "ok") && AssertionSubstantive(expected.items[i])) return true;
        return false;
    }
    return true;
}

static bool ParseAssertions(const ModelJson* json, std::vector<AgentAssertion>* assertions)
{
    assertions->clear();
    if (!json) return true;
    if (json->kind != ModelJson::ARRAY || json->items.empty() || json->items.size() > 8) return false;
    for (size_t i = 0; i < json->items.size(); ++i) {
        const ModelJson* tool = json->items[i].get("tool"), *args = json->items[i].get("arguments"), *expected = json->items[i].get("expected");
        if (!tool || tool->kind != ModelJson::STRING || !McpReadOnlyTool(tool->value) || tool->value.size() > 128 ||
            !args || args->kind != ModelJson::OBJECT || args->raw.size() > 8192 || !expected ||
            expected->kind != ModelJson::OBJECT || expected->raw.size() > 8192 || !AssertionSubstantive(*expected)) return false;
        AgentAssertion assertion; assertion.tool = tool->value; assertion.arguments = args->raw; assertion.expected = expected->raw;
        assertions->push_back(assertion);
    }
    return true;
}

static std::string AssertionsJson(const std::vector<AgentAssertion>& assertions)
{
    std::string out = "[";
    for (size_t i = 0; i < assertions.size(); ++i) {
        if (i) out += ',';
        out += "{\"tool\":"; ModelJson::quote(&out, assertions[i].tool);
        out += ",\"arguments\":" + assertions[i].arguments + ",\"expected\":" + assertions[i].expected + "}";
    }
    return out + ']';
}

static bool AssertionReceipt(const AgentAssertion& assertion, const std::string& arguments, const std::string& receipt)
{
    ModelJson args, required, expected, root;
    if (!ModelJson::parse(arguments, &args) || !ModelJson::parse(assertion.arguments, &required) || !AssertionEqual(args, required) ||
        !ModelJson::parse(assertion.expected, &expected) || !ModelJson::parse(receipt, &root) || root.get("error") || !root.get("result")) return false;
    const ModelJson* result = root.get("result");
    if (result->get("isError") && result->get("isError")->value == "true") return false;
    if (result->get("structuredContent")) result = result->get("structuredContent");
    if (result->get("ok") && result->get("ok")->value == "false" && !AgentLookupMiss(assertion.tool, receipt)) return false;
    if (result->get("success") && result->get("success")->value == "false") return false;
    return AssertionEqual(*result, expected, true);
}
