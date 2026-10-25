#include "ModelJson.h"
#include "McpRpcError.h"
#include "AgentDebugWorkflow.h"
#include "ModelAdapter.h"
#include "ModelStream.h"
#include "ModelTools.h"
#include <assert.h>

int main()
{
    std::string rpc_error = McpRpcErrorResponse("7", MCP_RPC_LISTENER_STOPPED);
    assert(rpc_error == "{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32002,\"message\":\"local MCP listener stopped\",\"data\":{\"error_id\":1005}}}");
    ModelJson parsed_error;
    assert(ModelJson::parse(McpRpcErrorResponse("", MCP_RPC_DEBUGGER_START_FAILED, "path \\\"C:\\\\test\\\""), &parsed_error));
    assert(parsed_error.get("id") && parsed_error.get("id")->kind == ModelJson::NIL);
    assert(parsed_error.get("error") && parsed_error.get("error")->get("message") &&
        parsed_error.get("error")->get("message")->value == "path \\\"C:\\\\test\\\"");
    assert(parsed_error.get("error")->get("data")->get("error_id")->raw == "1010");
    ModelJson tool_error;
    assert(ModelJson::parse(McpToolErrorResult(MCP_RPC_PYTHON_CODE_INVALID), &tool_error));
    assert(tool_error.get("jsonrpc") == NULL && tool_error.get("error")->get("code")->raw == "-32602");
    assert(tool_error.get("error")->get("data")->get("error_id"));
    assert(AgentNeedsManagedDebugTask(L"\u8c03\u8bd5 C:\\app.exe \u89c2\u5bdf\u65ad\u70b9\u547d\u4e2d"));
    assert(AgentNeedsManagedDebugTask(L"\u5206\u6790 C:\\app.exe \u8bfb\u53d6\u7684\u6587\u4ef6"));
    assert(!AgentNeedsManagedDebugTask(L"\u4ec0\u4e48\u662f\u65ad\u70b9"));
    unsigned __int64 sample_address = 0;
    unsigned sample_hits = 0, sample_seconds = 0;
    assert(AgentParseBreakpointSample("{\"address\":\"0x401000\",\"max_hits\":4,\"timeout_seconds\":30}",
        &sample_address, &sample_hits, &sample_seconds));
    assert(sample_address == 0x401000 && sample_hits == 4 && sample_seconds == 30);
    assert(!AgentParseBreakpointSample("{\"address\":\"0x401000\",\"max_hits\":17,\"timeout_seconds\":30}",
        &sample_address, &sample_hits, &sample_seconds));
    assert(!AgentParseBreakpointSample("{\"address\":\"0xZZ\",\"max_hits\":1,\"timeout_seconds\":30}",
        &sample_address, &sample_hits, &sample_seconds));
    ModelJson breakpoint_stop;
    assert(ModelJson::parse("{\"exceptionCode\":2147483651,\"exceptionAddress\":\"0x401000\"}", &breakpoint_stop));
    assert(AgentBreakpointStopMatches(&breakpoint_stop, 0x401000));
    assert(!AgentBreakpointStopMatches(&breakpoint_stop, 0x401001));
    assert(AgentDebugObservationSummary("get_debug_context",
        "{\"result\":{\"process_id\":42,\"status\":18,\"sequence\":9,\"last_stop\":{\"exceptionAddress\":\"0x401000\"}}}")
        .find("exceptionAddress=0x401000") != std::string::npos);
    ModelJson root;
    assert(ModelJson::parse("{\"choices\":[{\"message\":{\"content\":\"\\u4f60\\u597d\",\"tool_calls\":[{\"function\":{\"name\":\"read_memory\",\"arguments\":\"{\\\"address\\\":\\\"0x401000\\\"}\"}}]}}]}", &root));
    const ModelJson* choices = root.get("choices");
    assert(choices && choices->kind == ModelJson::ARRAY && choices->items.size() == 1);
    const ModelJson* message = choices->items[0].get("message");
    assert(message && message->get("content")->value == "\xe4\xbd\xa0\xe5\xa5\xbd");
    assert(message->get("tool_calls")->items[0].get("function")->get("name")->value == "read_memory");
    ModelJson args;
    assert(ModelJson::parse(message->get("tool_calls")->items[0].get("function")->get("arguments")->value, &args));
    assert(args.get("address")->value == "0x401000");
    assert(!ModelJson::parse("{\"name\":\"x\",}", &root));
    assert(!ModelJson::parse("{\"name\":\"\\uD800\"}", &root));
    std::string body;
    ModelRequestOptions options;
    options.reasoning_effort = "high";
    AppendProviderOptions(MODEL_QWEN, "qwen-plus", options, &body);
    assert(body == ",\"enable_thinking\":false");
    body.clear();
    AppendProviderOptions(MODEL_QWEN, "other-model", options, &body);
    assert(body.empty());
    body.clear();
    options.reasoning_effort = "medium";
    AppendProviderOptions(MODEL_GLM, "glm-4.5", options, &body);
    assert(body == ",\"reasoning_effort\":\"medium\"");
    body.clear();
    options.reasoning_effort = "high";
    AppendProviderOptions(MODEL_DEEPSEEK, "deepseek-chat", options, &body);
    assert(body.empty());
    assert(SupportsReasoningEffort(MODEL_COMPATIBLE, "custom-chat"));
    assert(SupportsReasoningEffort(MODEL_GLM, "glm-4.5"));
    assert(!SupportsReasoningEffort(MODEL_DEEPSEEK, "deepseek-chat"));
    ModelJson response;
    assert(ModelJson::parse("{\"content\":null,\"reasoning_content\":\"think\",\"tool_calls\":[{\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"read_memory\",\"arguments\":\"{}\"}}]}", &response));
    std::string next;
    std::vector<ModelToolCall> normalized_calls;
    std::string error;
    assert(ReadModelToolCalls(response, 0, &normalized_calls, &error));
    assert(BuildAssistantToolMessage(MODEL_DEEPSEEK, response, normalized_calls, &next));
    assert(next.find("\"reasoning_content\":\"think\"") != std::string::npos);
    assert(ModelJson::parse(next, &root));
    assert(BuildAssistantToolMessage(MODEL_QWEN, response, normalized_calls, &next));
    assert(next.find("\"content\":\"\"") != std::string::npos);
    assert(next.find("reasoning_content") == std::string::npos);

    std::vector<std::string> messages;
    messages.push_back("{\"role\":\"user\",\"content\":\"status\"}");
    const std::string tools = "[{\"type\":\"function\",\"function\":{\"name\":\"get_status\",\"parameters\":{\"type\":\"object\"}}}]";
    ModelJson request;
    assert(ModelJson::parse(BuildModelRequest(MODEL_QWEN, "qwen-plus", messages, tools, options), &request));
    assert(request.get("enable_thinking") && request.get("enable_thinking")->value == "false");
    assert(request.get("reasoning_effort") == NULL);
    assert(ModelJson::parse(BuildModelRequest(MODEL_GLM, "glm-4.5", messages, tools, options), &request));
    assert(request.get("reasoning_effort") && request.get("reasoning_effort")->value == "high");
    assert(request.get("enable_thinking") == NULL);
    options.reasoning_effort = "auto";
    assert(ModelJson::parse(BuildModelRequest(MODEL_GLM, "glm-4.5", messages, tools, options), &request));
    assert(request.get("reasoning_effort") == NULL);
    assert(ModelJson::parse(BuildModelRequest(MODEL_GLM, "glm-5.3", messages, tools, options), &request));
    assert(request.get("reasoning_effort") && request.get("reasoning_effort")->value == "low");
    assert(request.get("enable_thinking") == NULL);
    options.reasoning_effort = "medium";
    assert(ModelJson::parse(BuildModelRequest(MODEL_GLM, "glm-5.3", messages, tools, options), &request));
    assert(request.get("reasoning_effort")->value == "low");
    options.reasoning_effort = "max";
    assert(ModelJson::parse(BuildModelRequest(MODEL_GLM, "glm-5.3", messages, tools, options), &request));
    assert(request.get("reasoning_effort")->value == "max");
    assert(ModelJson::parse(BuildModelRequest(MODEL_QWEN, "glm-5.3", messages, tools, options), &request));
    assert(request.get("reasoning_effort")->value == "max" && request.get("enable_thinking") == NULL);
    options.reasoning_effort = "medium";
    assert(ModelJson::parse(BuildModelRequest(MODEL_COMPATIBLE, "custom-chat", messages, tools, options), &request));
    assert(request.get("reasoning_effort") && request.get("reasoning_effort")->value == "medium");
    options.reasoning_effort = "high";
    assert(ModelJson::parse(BuildModelRequest(MODEL_DEEPSEEK, "deepseek-chat", messages, tools, options), &request));
    assert(request.get("enable_thinking") == NULL && request.get("reasoning_effort") == NULL);
    assert(request.get("tools") && request.get("tool_choice"));
    options = ModelRequestOptions();
    assert(ModelJson::parse(BuildModelRequest(MODEL_OPENAI, "gpt-6-sol", messages, tools, options), &request));
    assert(request.get("max_completion_tokens") == NULL && request.get("temperature") == NULL &&
        request.get("top_p") == NULL && request.get("tool_choice")->value == "auto");
    options.max_output_tokens = 4096;
    options.temperature = "0.7";
    options.top_p = "0.9";
    options.tool_choice = "required";
    assert(ModelJson::parse(BuildModelRequest(MODEL_OPENAI, "gpt-6-sol", messages, tools, options), &request));
    assert(request.get("max_completion_tokens")->value == "4096" && request.get("max_tokens") == NULL);
    assert(request.get("temperature")->value == "0.7" && request.get("top_p")->value == "0.9");
    assert(request.get("tool_choice")->value == "required");
    assert(ModelJson::parse(BuildModelRequest(MODEL_DEEPSEEK, "deepseek-chat", messages, tools, options), &request));
    assert(request.get("max_tokens")->value == "4096" && request.get("max_completion_tokens") == NULL);
    options.tool_choice = "none";
    assert(ModelJson::parse(BuildModelRequest(MODEL_OPENAI, "gpt-6-sol", messages, "[]", options), &request));
    assert(request.get("tools") == NULL && request.get("tool_choice") == NULL);
    options.temperature = "NaN";
    options.top_p = "1.2";
    assert(ModelJson::parse(BuildModelRequest(MODEL_OPENAI, "gpt-6-sol", messages, "[]", options), &request));
    assert(request.get("temperature") == NULL && request.get("top_p") == NULL);
    options.stream = true;
    assert(ModelJson::parse(BuildModelRequest(MODEL_OPENAI, "gpt-6-sol", messages, "[]", options), &request));
    assert(request.get("stream") && request.get("stream")->value == "true");

    ModelStream stream;
    const std::string first = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\r\n\r\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n"
        "data: [DONE]\n\n";
    assert(stream.feed(first.data(), 7));
    assert(stream.feed(first.data() + 7, first.size() - 7));
    assert(stream.complete() && stream.content == "Hello");
    assert(ModelJson::parse(stream.response(), &response));
    assert(response.get("choices")->items[0].get("message")->get("content")->value == "Hello");
    ModelStream tool_stream;
    const std::string tool_events =
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"get_status\",\"arguments\":\"{\\\"a\\\":\"}}]}}]}\n\n"
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n"
        "data: [DONE]\n\n";
    assert(tool_stream.feed(tool_events.data(), tool_events.size()));
    assert(tool_stream.complete());
    assert(ModelJson::parse(tool_stream.response(), &response));
    const ModelJson* streamed_message = response.get("choices")->items[0].get("message");
    assert(ReadModelToolCalls(*streamed_message, 0, &normalized_calls, &error));
    assert(normalized_calls.size() == 1 && normalized_calls[0].arguments_json == "{\"a\":1}");
    ModelStream unfinished;
    const std::string partial_event =
        "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n";
    assert(unfinished.feed(partial_event.data(), partial_event.size()));
    assert(!unfinished.complete());
    ModelStream invalid_tool_stream;
    const std::string invalid_event =
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":8}]}}]}\n\n";
    assert(!invalid_tool_stream.feed(invalid_event.data(), invalid_event.size()));

    const ModelJson* parsed_message = NULL;
    assert(ModelJson::parse("{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":null,\"reasoning_content\":\"step\",\"tool_calls\":[{\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_status\",\"arguments\":\"{}\"}}]}}]}", &response));
    assert(ExtractModelMessage(MODEL_DEEPSEEK, response, &parsed_message));
    assert(ReadModelToolCalls(*parsed_message, 0, &normalized_calls, &error));
    assert(BuildAssistantToolMessage(MODEL_DEEPSEEK, *parsed_message, normalized_calls, &next));
    assert(next.find("\"reasoning_content\":\"step\"") != std::string::npos);
    assert(ModelJson::parse("{\"choices\":[{\"message\":{\"content\":\"done\",\"reasoning_content\":\"summary step\"}}]}", &response));
    assert(ExtractModelMessage(MODEL_DEEPSEEK, response, &parsed_message));
    next = BuildAssistantFinalMessage(MODEL_DEEPSEEK, *parsed_message, "done");
    assert(next.find("\"reasoning_content\":\"summary step\"") != std::string::npos);
    assert(ModelJson::parse("{\"choices\":[{\"message\":{\"content\":null,\"tool_calls\":[{\"id\":\"call_2\",\"type\":\"function\",\"function\":{\"name\":\"get_status\",\"arguments\":\"{}\"}}]}}]}", &response));
    assert(ExtractModelMessage(MODEL_QWEN, response, &parsed_message));
    assert(ReadModelToolCalls(*parsed_message, 1, &normalized_calls, &error));
    assert(BuildAssistantToolMessage(MODEL_QWEN, *parsed_message, normalized_calls, &next));
    assert(next.find("\"content\":\"\"") != std::string::npos);
    assert(ExtractModelMessage(MODEL_GLM, response, &parsed_message));
    std::string formatted = ModelJson::pretty("{\"a\":[1,{\"b\":\"x\"}]}");
    assert(formatted.find("\r\n  \"a\": [") != std::string::npos);
    assert(formatted.find("\r\n    {") != std::string::npos);
    assert(ModelJson::parse(formatted, &root));
    assert(ModelJson::pretty("invalid") == "invalid");

    std::string tool_json;
    std::vector<ModelToolBinding> bindings;
    assert(BuildModelTools("{\"tools\":[{\"name\":\"debug.read-memory\",\"description\":\"Read memory\",\"inputSchema\":{\"properties\":{\"address\":{\"type\":\"string\"}},\"required\":[\"address\"]}},{\"name\":\"get_status\",\"inputSchema\":{\"type\":\"object\"}}]}",
        &tool_json, &bindings, &error));
    assert(bindings.size() == 2 && bindings[0].model_name != bindings[0].mcp_name);
    std::string original_name;
    assert(ResolveModelTool(bindings, bindings[0].model_name, &original_name));
    assert(original_name == "debug.read-memory");
    assert(ModelJson::parse(tool_json, &root));
    assert(root.items[0].get("function")->get("parameters")->get("type")->value == "object");
    assert(!BuildModelTools("{\"tools\":[{\"name\":\"bad\",\"inputSchema\":{\"type\":\"array\"}}]}",
        &tool_json, &bindings, &error));
    assert(!BuildModelTools("{\"tools\":[{\"name\":\"same\"},{\"name\":\"same\"}]}",
        &tool_json, &bindings, &error));
    assert(!BuildModelTools("{\"tools\":[{\"name\":\"bad\",\"inputSchema\":{\"required\":[\"address\"]}}]}",
        &tool_json, &bindings, &error));

    assert(ModelJson::parse("{\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"tool_calls\":[{\"function\":{\"name\":\"get_status\",\"arguments\":{\"count\":2}}}]}", &response));
    std::string content;
    assert(ModelMessageText(response, &content) && content == "done");
    assert(ReadModelToolCalls(response, 2, &normalized_calls, &error));
    assert(normalized_calls.size() == 1 && normalized_calls[0].id == "call_mcp_2_1");
    assert(normalized_calls[0].arguments_json == "{\"count\":2}");
    assert(BuildAssistantToolMessage(MODEL_GLM, response, normalized_calls, &next));
    assert(ModelJson::parse(next, &root));
    assert(root.get("tool_calls")->items[0].get("function")->get("arguments")->kind == ModelJson::STRING);
    assert(ModelJson::parse("{\"tool_calls\":[{\"id\":\"same\",\"function\":{\"name\":\"a\",\"arguments\":\"{}\"}},{\"id\":\"same\",\"function\":{\"name\":\"b\",\"arguments\":\"{}\"}}]}", &response));
    assert(!ReadModelToolCalls(response, 0, &normalized_calls, &error));
    assert(ModelJson::parse("{\"tool_calls\":[{\"function\":{\"name\":\"a\",\"arguments\":\"not json\"}}]}", &response));
    assert(!ReadModelToolCalls(response, 0, &normalized_calls, &error));

    assert(ModelRetryDelayMs(429, 5000, 0) == 5000);
    assert(ModelRetryDelayMs(503, 0, 1) == 2000);
    assert(ModelRetryDelayMs(401, 0, 0) == 0);
    assert(ModelRetryDelayMs(429, 0, 2) == 0);
    assert(ModelErrorText(401, "{\"error\":{\"message\":\"invalid key\"}}")
        .find("invalid key") != std::string::npos);
    assert(ToolSupportForModel(MODEL_QWEN, "qwen-plus") == MODEL_TOOLS_SUPPORTED);
    assert(ToolSupportForModel(MODEL_DEEPSEEK, "deepseek-chat") == MODEL_TOOLS_SUPPORTED);
    assert(ToolSupportForModel(MODEL_GLM, "glm-4.5") == MODEL_TOOLS_SUPPORTED);
    assert(ToolSupportForModel(MODEL_GLM, "glm-4.6") == MODEL_TOOLS_SUPPORTED);
    assert(ToolSupportForModel(MODEL_QWEN, "text-embedding-v4") == MODEL_TOOLS_UNAVAILABLE);
    assert(ToolSupportForModel(MODEL_QWEN, "qwen-embedding-helper") == MODEL_TOOLS_UNVERIFIED);
    assert(ToolSupportForModel(MODEL_COMPATIBLE, "custom-chat") == MODEL_TOOLS_UNVERIFIED);
    std::vector<std::string> history;
    history.push_back("{\"role\":\"user\",\"content\":\"old\"}");
    history.push_back("{\"role\":\"assistant\",\"tool_calls\":[{\"id\":\"c1\"}]}");
    history.push_back("{\"role\":\"tool\",\"tool_call_id\":\"c1\",\"content\":\"ok\"}");
    history.push_back("{\"role\":\"user\",\"content\":\"new\"}");
    assert(FitModelHistory(MODEL_COMPATIBLE, "custom-chat",
        "{\"role\":\"system\",\"content\":\"x\"}", "[]", &history, 2, 4096, options));
    assert(history.size() == 1 && history[0].find("new") != std::string::npos);
    assert(!FitModelHistory(MODEL_COMPATIBLE, "custom-chat",
        "{\"role\":\"system\",\"content\":\"x\"}", "[]", &history, 2, 10, options));
    return 0;
}
