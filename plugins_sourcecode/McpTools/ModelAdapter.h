#pragma once

#include "ModelJson.h"
#include <stdio.h>
#include <stdlib.h>
#include <set>
#include <vector>

enum ModelProvider {
    MODEL_COMPATIBLE,
    MODEL_OPENAI,
    MODEL_QWEN,
    MODEL_DEEPSEEK,
    MODEL_GLM
};

struct ModelRequestOptions {
    std::string reasoning_effort;
    int max_output_tokens;
    std::string temperature;
    std::string top_p;
    std::string tool_choice;
    bool stream;
    bool stream_usage;

    ModelRequestOptions() : max_output_tokens(0), tool_choice("auto"), stream(false), stream_usage(false) {}
};

enum ModelToolSupport {
    MODEL_TOOLS_UNVERIFIED,
    MODEL_TOOLS_SUPPORTED,
    MODEL_TOOLS_UNAVAILABLE
};

static ModelToolSupport ToolSupportForModel(ModelProvider provider,
    const std::string& model)
{
    if (model.empty() || model.compare(0, 15, "text-embedding-") == 0 ||
        model.compare(0, 10, "embedding-") == 0 ||
        model.compare(0, 7, "rerank-") == 0)
        return MODEL_TOOLS_UNAVAILABLE;
    if (provider == MODEL_QWEN && (model == "qwen-plus" || model == "qwen-max" ||
        model == "qwen3.8-max")) return MODEL_TOOLS_SUPPORTED;
    if (provider == MODEL_DEEPSEEK && (model == "deepseek-chat" ||
        model == "deepseek-reasoner")) return MODEL_TOOLS_SUPPORTED;
    // GLM model names change frequently, but the Zhipu compatible endpoint
    // uses the same tool-call contract across the glm-* family.
    if (provider == MODEL_GLM && model.compare(0, 4, "glm-") == 0)
        return MODEL_TOOLS_SUPPORTED;
    return MODEL_TOOLS_UNVERIFIED;
}

struct ModelToolCall {
    std::string id;
    std::string name;
    std::string arguments_json;
};

static bool ModelMessageText(const ModelJson& message, std::string* text)
{
    const ModelJson* content = message.get("content");
    text->clear();
    if (!content || content->kind == ModelJson::NIL) return true;
    if (content->kind == ModelJson::STRING) {
        *text = content->value;
        return true;
    }
    if (content->kind != ModelJson::ARRAY) return false;
    for (size_t i = 0; i < content->items.size(); ++i) {
        const ModelJson& part = content->items[i];
        const ModelJson* type = part.get("type");
        const ModelJson* value = part.get("text");
        if (!type || type->kind != ModelJson::STRING || type->value != "text" ||
            !value || value->kind != ModelJson::STRING) return false;
        *text += value->value;
    }
    return true;
}

static bool ReadModelToolCalls(const ModelJson& message, int round,
    std::vector<ModelToolCall>* output, std::string* error)
{
    output->clear();
    const ModelJson* calls = message.get("tool_calls");
    if (!calls || calls->kind == ModelJson::NIL) return true;
    if (calls->kind != ModelJson::ARRAY || calls->items.size() > 8) {
        *error = "Model returned an invalid number of tool calls (limit 8 per turn).";
        return false;
    }
    std::set<std::string> ids;
    for (size_t i = 0; i < calls->items.size(); ++i) {
        const ModelJson& call = calls->items[i];
        const ModelJson* function = call.get("function");
        const ModelJson* name = function ? function->get("name") : NULL;
        const ModelJson* args = function ? function->get("arguments") : NULL;
        const ModelJson* id = call.get("id");
        if (!name || name->kind != ModelJson::STRING || name->value.empty() || !args) {
            *error = "Model returned a tool call without a function name or arguments.";
            return false;
        }
        ModelToolCall normalized;
        normalized.name = name->value;
        if (id && id->kind == ModelJson::STRING && !id->value.empty())
            normalized.id = id->value;
        else {
            char generated[48];
            sprintf_s(generated, sizeof(generated), "call_mcp_%d_%u", round, (unsigned)i + 1);
            normalized.id = generated;
        }
        if (!ids.insert(normalized.id).second) {
            *error = "Model returned duplicate tool call IDs.";
            return false;
        }
        ModelJson parsed;
        if (args->kind == ModelJson::STRING) {
            if (!ModelJson::parse(args->value, &parsed) || parsed.kind != ModelJson::OBJECT) {
                *error = "Model returned invalid JSON tool arguments.";
                return false;
            }
            normalized.arguments_json = parsed.raw;
        }
        else if (args->kind == ModelJson::OBJECT)
            normalized.arguments_json = args->raw;
        else {
            *error = "Model tool arguments must be a JSON object.";
            return false;
        }
        output->push_back(normalized);
    }
    return true;
}

static bool SupportsReasoningEffort(ModelProvider provider, const std::string& model)
{
    return model == "glm-5.3" || provider == MODEL_COMPATIBLE || provider == MODEL_OPENAI ||
        (provider == MODEL_GLM && model.compare(0, 4, "glm-") == 0);
}

static bool Glm53Model(const std::string& model)
{
    return model == "glm-5.3";
}

static bool ValidModelSamplingNumber(const std::string& input, double minimum,
    double maximum, bool exclusive_minimum)
{
    if (input.empty()) return false;
    ModelJson value;
    if (!ModelJson::parse(input, &value) || value.kind != ModelJson::NUMBER)
        return false;
    double number = atof(input.c_str());
    return (exclusive_minimum ? number > minimum : number >= minimum) &&
        number <= maximum;
}

static void AppendProviderOptions(ModelProvider provider, const std::string& model,
    const ModelRequestOptions& options, std::string* body)
{
    if (provider == MODEL_QWEN && model.compare(0, 4, "qwen") == 0) {
        *body += ",\"enable_thinking\":false";
    }
    if (Glm53Model(model)) {
        *body += ",\"reasoning_effort\":";
        ModelJson::quote(body, options.reasoning_effort == "high" || options.reasoning_effort == "max" ?
            options.reasoning_effort : "low");
    }
    else if (SupportsReasoningEffort(provider, model) &&
        (options.reasoning_effort == "low" || options.reasoning_effort == "medium" ||
         options.reasoning_effort == "high")) {
        *body += ",\"reasoning_effort\":";
        ModelJson::quote(body, options.reasoning_effort);
    }
    if (options.max_output_tokens > 0 && options.max_output_tokens <= 65536) {
        char count[32];
        sprintf_s(count, sizeof(count), "%d", options.max_output_tokens);
        *body += provider == MODEL_OPENAI ?
            ",\"max_completion_tokens\":" : ",\"max_tokens\":";
        *body += count;
    }
    if (ValidModelSamplingNumber(options.temperature, 0, 2, false))
        *body += ",\"temperature\":" + options.temperature;
    if (ValidModelSamplingNumber(options.top_p, 0, 1, true))
        *body += ",\"top_p\":" + options.top_p;
}

static std::string BuildModelRequest(ModelProvider provider, const std::string& model,
    const std::vector<std::string>& messages, const std::string& tools,
    const ModelRequestOptions& options)
{
    std::string body = "{\"model\":";
    ModelJson::quote(&body, model);
    body += ",\"messages\":[";
    for (size_t i = 0; i < messages.size(); ++i) {
        if (i) body += ',';
        body += messages[i];
    }
    body += "]";
    if (tools != "[]") {
        body += ",\"tools\":" + tools + ",\"tool_choice\":";
        ModelJson::quote(&body, options.tool_choice == "none" ||
            options.tool_choice == "required" ? options.tool_choice : "auto");
    }
    AppendProviderOptions(provider, model, options, &body);
    if (options.stream) body += ",\"stream\":true";
    if (options.stream && options.stream_usage) body += ",\"stream_options\":{\"include_usage\":true}";
    body += "}";
    return body;
}

static bool FitModelHistory(ModelProvider provider, const std::string& model,
    const std::string& system_message, const std::string& tools,
    std::vector<std::string>* history, size_t max_messages, size_t max_bytes,
    const ModelRequestOptions& options)
{
    for (;;) {
        std::vector<std::string> messages;
        messages.push_back(system_message);
        messages.insert(messages.end(), history->begin(), history->end());
        if (messages.size() <= max_messages &&
            BuildModelRequest(provider, model, messages, tools, options).size() <= max_bytes)
            return true;
        if (history->size() <= 1) return false;
        size_t next_user = history->size() - 1;
        for (size_t i = 1; i + 1 < history->size(); ++i) {
            ModelJson item;
            if (ModelJson::parse((*history)[i], &item)) {
                const ModelJson* role = item.get("role");
                if (role && role->kind == ModelJson::STRING && role->value == "user") {
                    next_user = i;
                    break;
                }
            }
        }
        history->erase(history->begin(), history->begin() + next_user);
    }
}

static bool ExtractModelMessage(ModelProvider provider, const ModelJson& response,
    const ModelJson** message)
{
    const ModelJson* choices = response.get("choices");
    if (!choices || choices->kind != ModelJson::ARRAY || choices->items.empty())
        return false;
    *message = choices->items[0].get("message");
    if (!*message || (*message)->kind != ModelJson::OBJECT)
        return false;
    const ModelJson* content = (*message)->get("content");
    const ModelJson* calls = (*message)->get("tool_calls");
    std::string text;
    if (!ModelMessageText(**message, &text)) return false;
    if (calls && calls->kind != ModelJson::ARRAY && calls->kind != ModelJson::NIL)
        return false;
    if (provider == MODEL_DEEPSEEK || provider == MODEL_GLM) {
        const ModelJson* reasoning = (*message)->get("reasoning_content");
        if (reasoning && reasoning->kind != ModelJson::STRING && reasoning->kind != ModelJson::NIL)
            return false;
    }
    return content || calls;
}

static std::string BuildAssistantFinalMessage(ModelProvider provider,
    const ModelJson& message, const std::string& answer)
{
    std::string output = "{\"role\":\"assistant\",\"content\":";
    ModelJson::quote(&output, answer);
    if (provider == MODEL_DEEPSEEK) {
        const ModelJson* reasoning = message.get("reasoning_content");
        if (reasoning && reasoning->kind == ModelJson::STRING) {
            output += ",\"reasoning_content\":";
            ModelJson::quote(&output, reasoning->value);
        }
    }
    output += "}";
    return output;
}

static bool BuildAssistantToolMessage(ModelProvider provider, const ModelJson& message,
    const std::vector<ModelToolCall>& calls, std::string* output)
{
    if (calls.empty()) return false;
    *output = "{\"role\":\"assistant\",\"content\":";
    std::string content;
    if (!ModelMessageText(message, &content)) return false;
    const ModelJson* original_content = message.get("content");
    if (original_content && original_content->kind != ModelJson::NIL)
        ModelJson::quote(output, content);
    else if (provider == MODEL_QWEN)
        *output += "\"\"";
    else
        *output += "null";
    if (provider == MODEL_DEEPSEEK) {
        const ModelJson* reasoning = message.get("reasoning_content");
        if (reasoning && reasoning->kind == ModelJson::STRING) {
            *output += ",\"reasoning_content\":";
            ModelJson::quote(output, reasoning->value);
        }
    }
    *output += ",\"tool_calls\":[";
    for (size_t i = 0; i < calls.size(); ++i) {
        if (i) *output += ',';
        *output += "{\"id\":";
        ModelJson::quote(output, calls[i].id);
        *output += ",\"type\":\"function\",\"function\":{\"name\":";
        ModelJson::quote(output, calls[i].name);
        *output += ",\"arguments\":";
        ModelJson::quote(output, calls[i].arguments_json);
        *output += "}}";
    }
    *output += "]}";
    return true;
}

static unsigned ModelRetryDelayMs(unsigned status, unsigned retry_after_ms, int attempt)
{
    if (attempt >= 2) return 0;
    if (status != 0 && status != 408 && status != 429 && status != 500 &&
        status != 502 && status != 503 && status != 504) return 0;
    if (retry_after_ms) return retry_after_ms > 30000 ? 30000 : retry_after_ms;
    return attempt == 0 ? 1000 : 2000;
}

static std::string ModelErrorText(unsigned status, const std::string& body)
{
    ModelJson root;
    std::string detail;
    if (ModelJson::parse(body, &root)) {
        const ModelJson* error = root.get("error");
        const ModelJson* message = error && error->kind == ModelJson::OBJECT
            ? error->get("message") : root.get("message");
        if (message && message->kind == ModelJson::STRING)
            detail = message->value;
    }
    if (detail.size() > 500) detail.resize(500);
    char code[32];
    sprintf_s(code, sizeof(code), "%u", status);
    std::string output = "Model API HTTP ";
    output += code;
    if (status == 401 || status == 403) output += " (check API key and account access)";
    else if (status == 404) output += " (check API URL and model name)";
    else if (status == 429) output += " (rate or quota limit)";
    else if (status == 400) output += " (unsupported request or tool schema)";
    else if (status == 0) output += " (network or timeout failure)";
    if (!detail.empty()) output += ": " + detail;
    return output;
}
