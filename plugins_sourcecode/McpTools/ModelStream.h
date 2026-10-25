#pragma once

#include "ModelJson.h"

struct ModelStreamTool {
    std::string id;
    std::string name;
    std::string arguments;
};

struct ModelStream {
    std::string pending;
    std::string event_data;
    std::string content;
    std::string reasoning;
    std::string finish_reason;
    std::string error;
    std::string usage;
    std::vector<ModelStreamTool> tools;
    bool done;
    bool content_changed;

    ModelStream() : done(false), content_changed(false) {}

    bool event() {
        if (event_data.empty()) return true;
        std::string data = event_data;
        event_data.clear();
        if (data == "[DONE]") { done = true; return true; }
        ModelJson root;
        if (!ModelJson::parse(data, &root)) {
            error = "Model API returned invalid streaming JSON.";
            return false;
        }
        const ModelJson* api_error = root.get("error");
        if (api_error) {
            const ModelJson* message = api_error->get("message");
            error = message && message->kind == ModelJson::STRING ? message->value :
                "Model API returned a streaming error.";
            return false;
        }
        const ModelJson* tokens = root.get("usage");
        if (tokens && tokens->kind == ModelJson::OBJECT) usage = tokens->raw;
        const ModelJson* choices = root.get("choices");
        if (!choices || choices->kind != ModelJson::ARRAY || choices->items.empty())
            return true;
        const ModelJson& choice = choices->items[0];
        const ModelJson* finish = choice.get("finish_reason");
        if (finish && finish->kind == ModelJson::STRING)
            finish_reason = finish->value;
        const ModelJson* delta = choice.get("delta");
        if (!delta || delta->kind != ModelJson::OBJECT) return true;
        const ModelJson* text = delta->get("content");
        if (text && text->kind == ModelJson::STRING && !text->value.empty()) {
            content += text->value;
            content_changed = true;
        }
        const ModelJson* thought = delta->get("reasoning_content");
        if (thought && thought->kind == ModelJson::STRING)
            reasoning += thought->value;
        const ModelJson* calls = delta->get("tool_calls");
        if (!calls) return true;
        if (calls->kind != ModelJson::ARRAY) {
            error = "Model API returned invalid streaming tool calls.";
            return false;
        }
        for (size_t i = 0; i < calls->items.size(); ++i) {
            const ModelJson& call = calls->items[i];
            const ModelJson* index = call.get("index");
            if (!index || index->kind != ModelJson::NUMBER || index->value.size() > 1 ||
                index->value.empty() || index->value[0] < '0' || index->value[0] > '7') {
                error = "Model API returned an invalid streaming tool index.";
                return false;
            }
            size_t slot = (size_t)(index->value[0] - '0');
            if (tools.size() <= slot) tools.resize(slot + 1);
            const ModelJson* id = call.get("id");
            if (id && id->kind == ModelJson::STRING) tools[slot].id += id->value;
            const ModelJson* function = call.get("function");
            if (function && function->kind == ModelJson::OBJECT) {
                const ModelJson* name = function->get("name");
                const ModelJson* arguments = function->get("arguments");
                if (name && name->kind == ModelJson::STRING) tools[slot].name += name->value;
                if (arguments && arguments->kind == ModelJson::STRING)
                    tools[slot].arguments += arguments->value;
            }
        }
        return true;
    }

    bool feed(const char* data, size_t size) {
        pending.append(data, size);
        if (pending.size() > 1024 * 1024) {
            error = "Model streaming event exceeds the local limit.";
            return false;
        }
        size_t end;
        while ((end = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, end);
            pending.erase(0, end + 1);
            if (!line.empty() && line[line.size() - 1] == '\r') line.resize(line.size() - 1);
            if (line.empty()) {
                if (!event()) return false;
            }
            else if (line.compare(0, 5, "data:") == 0) {
                if (!event_data.empty()) event_data += '\n';
                size_t start = line.size() > 5 && line[5] == ' ' ? 6 : 5;
                event_data += line.substr(start);
            }
        }
        return true;
    }

    bool complete() {
        if (!pending.empty()) {
            pending += '\n';
            if (!feed("", 0)) return false;
        }
        if (!event()) return false;
        if (!done && finish_reason.empty()) {
            error = "Model API ended the stream before completing a response.";
            return false;
        }
        return true;
    }

    std::string response() const {
        std::string result = "{\"choices\":[{\"finish_reason\":";
        ModelJson::quote(&result, finish_reason);
        result += ",\"message\":{\"role\":\"assistant\",\"content\":";
        if (content.empty() && !tools.empty()) result += "null";
        else ModelJson::quote(&result, content);
        if (!reasoning.empty()) {
            result += ",\"reasoning_content\":";
            ModelJson::quote(&result, reasoning);
        }
        if (!tools.empty()) {
            result += ",\"tool_calls\":[";
            for (size_t i = 0; i < tools.size(); ++i) {
                if (i) result += ',';
                result += "{\"id\":";
                ModelJson::quote(&result, tools[i].id);
                result += ",\"type\":\"function\",\"function\":{\"name\":";
                ModelJson::quote(&result, tools[i].name);
                result += ",\"arguments\":";
                ModelJson::quote(&result, tools[i].arguments);
                result += "}}";
            }
            result += ']';
        }
        result += "}}]";
        if (!usage.empty()) result += ",\"usage\":" + usage;
        result += '}';
        return result;
    }
};
