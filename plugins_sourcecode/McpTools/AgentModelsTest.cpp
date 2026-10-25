#include "McpServerApp.cpp"
#include <assert.h>
#include <stdio.h>
#include <crtdbg.h>

enum FakeMode { NORMAL, PRIMARY_FAILS, ALL_FAIL, BAD_PRIMARY, UNKNOWN_TOOL,
    REVIEW_FAILS, REVIEW_CALLS_TOOL, CANCEL_REQUEST, CANCEL_REVIEW };
static FakeMode g_fake_mode;
struct FakeAttempt {
    std::wstring model;
    std::vector<std::string> messages;
    std::string tools;
    std::wstring choice;
};
static std::vector<FakeAttempt> g_fake_attempts;
static std::string EmptyMemoryRetrieve(const ServerConfig&, const std::string&, ChatJob*) { return ""; }
static bool g_confirm_allow = true, g_audit_allow = true;
static int g_confirm_count = 0;
static std::vector<std::string> g_audit_events;
static bool FakeConfirmation(ChatJob*, const ModelToolBinding&, const std::string&)
{
    ++g_confirm_count; return g_confirm_allow;
}
static bool FakeAudit(ChatJob*, const std::string& id, const ModelToolBinding& binding,
    const std::string&, const std::string& decision, const std::string& outcome)
{
    assert(!id.empty());
    g_audit_events.push_back(std::string(McpRiskName(binding.risk)) + ":" + decision + ":" + outcome);
    return g_audit_allow;
}

static bool FakeModelRequest(const ServerConfig& cfg, const std::vector<std::string>& messages,
    const std::string& tools, ModelJson* response, std::string* error,
    std::string* request_json, std::string* response_json, ChatJob*, int round)
{
    FakeAttempt attempt;
    attempt.model = cfg.model_name;
    attempt.messages = messages;
    attempt.tools = tools;
    attempt.choice = cfg.tool_choice;
    g_fake_attempts.push_back(attempt);
    *request_json = "{}";
    bool primary = lstrcmpW(cfg.model_name, L"primary") == 0;
    if (g_fake_mode == CANCEL_REQUEST || (g_fake_mode == CANCEL_REVIEW && round == -1)) {
        InterlockedExchange(&g_chat_cancel, 1);
        *error = "cancelled";
        return false;
    }
    if (g_fake_mode == ALL_FAIL || (g_fake_mode == PRIMARY_FAILS && primary) ||
        (g_fake_mode == REVIEW_FAILS && round == -1)) {
        *error = "HTTP 503";
        return false;
    }
    if ((g_fake_mode == BAD_PRIMARY && primary) ||
        (g_fake_mode == UNKNOWN_TOOL && primary) ||
        (g_fake_mode == REVIEW_CALLS_TOOL && round == -1)) {
        *response_json = g_fake_mode == BAD_PRIMARY ? "{}" :
            "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,"
            "\"tool_calls\":[{\"id\":\"c1\",\"type\":\"function\",\"function\":{"
            "\"name\":\"unknown_tool\",\"arguments\":\"{}\"}}]}}]}";
    }
    else {
        *response_json = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
        ModelJson::quote(response_json, round == -1 ? "review conclusion" : "primary answer");
        *response_json += "}}]}";
    }
    return ModelJson::parse(*response_json, response);
}

static ServerConfig TestConfig()
{
    ServerConfig cfg;
    SetDefaultConfig(&cfg);
    cfg.debug_guard = false;
    cfg.sensitive_guard = false;
    StringCchCopyW(cfg.model_url, _countof(cfg.model_url), L"https://primary.test/chat/completions");
    StringCchCopyW(cfg.model_name, _countof(cfg.model_name), L"primary");
    StringCchCopyW(cfg.tool_choice, _countof(cfg.tool_choice), L"none");
    for (int i = 0; i < 3; ++i) {
        AgentModelProfile& profile = cfg.agent.profiles[i];
        StringCchPrintfW(profile.url, _countof(profile.url), L"https://model%d.test/chat/completions", i + 1);
        StringCchPrintfW(profile.name, _countof(profile.name), L"model%d", i + 1);
        profile.enabled = true;
    }
    return cfg;
}

static void Reset(FakeMode mode)
{
    g_fake_mode = mode;
    g_fake_attempts.clear();
    InterlockedExchange(&g_chat_cancel, 0);
    g_agent_model_request = FakeModelRequest;
}

static bool Request(ChatJob* job, const std::vector<std::string>& messages, int round = 0)
{
    ModelJson response;
    ServerConfig selected;
    std::vector<ModelToolBinding> bindings;
    return AgentRequest(job, messages, "[]", bindings, &response, &selected, round);
}

static void TestTerminalSettings()
{
    ServerConfig cfg = TestConfig();
    assert(SelectTerminalModel(cfg, L"MODEL2") == 3);
    assert(SelectTerminalModel(cfg, L"primary") == 1);
    assert(SelectTerminalModel(cfg, L"auto") == 0);
    assert(SelectTerminalModel(cfg, L"unknown") == -1);
    cfg.agent.profiles[1].enabled = false;
    assert(SelectTerminalModel(cfg, L"2") == -1);
    assert(SelectTerminalModel(cfg, L"model2") == -1);
    cfg.agent.profiles[1].enabled = true;
    StringCchCopyW(cfg.agent.profiles[2].name, 128, L"model2");
    assert(SelectTerminalModel(cfg, L"model2") == -1);
    assert(SelectTerminalModel(cfg, L"2") == 3);

    TerminalSettingsChanges changes;
    std::wstring error;
    assert(SetTerminalSetting(&cfg, 2, L"effort", L"HIGH", &changes, &error));
    assert(lstrcmpW(cfg.agent.profiles[1].effort, L"high") == 0);
    assert(lstrcmpW(cfg.reasoning_effort, L"auto") == 0);
    assert(SetTerminalSetting(&cfg, 2, L"timeout", L"120", &changes, &error));
    assert(cfg.agent.profiles[1].timeout_seconds == 120 && cfg.model_timeout_seconds == 120);
    assert(SetTerminalSetting(&cfg, 0, L"tokens", L"65536", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"temperature", L"0.7", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"top_p", L"0.9", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"temperature", L"default", &changes, &error));
    assert(cfg.temperature[0] == 0);
    assert(SetTerminalSetting(&cfg, 0, L"stream", L"off", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"auto_route", L"on", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"failover", L"true", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"review", L"1", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"tool_choice", L"required", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"tool_rounds", L"50", &changes, &error));
    assert(cfg.max_tool_rounds == 50);
    assert(SetTerminalSetting(&cfg, 0, L"round_warning", L"5", &changes, &error));
    assert(cfg.round_warning == 5);
    assert(SetTerminalSetting(&cfg, 0, L"time_warning_seconds", L"90", &changes, &error));
    assert(cfg.time_warning_seconds == 90);
    assert(SetTerminalSetting(&cfg, 0, L"history", L"2", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"task_mode", L"on", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"task_retries", L"3", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"task_error_mode", L"ignore", &changes, &error));
    assert(cfg.task_error_mode == 1);
    assert(SetTerminalSetting(&cfg, 0, L"task_replans", L"3", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"task_rounds", L"48", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"task_rounds", L"0", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"task_timeout_seconds", L"0", &changes, &error));
    assert(cfg.task_rounds == 0 && cfg.task_timeout_seconds == 0);
    assert(SetTerminalSetting(&cfg, 0, L"task_rounds", L"48", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"task_timeout_seconds", L"3600", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"parallel_workers", L"3", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"event_wait_seconds", L"45", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"debug_guard", L"on", &changes, &error));
    assert(cfg.task_mode && cfg.task_retries == 3);
    assert(SetTerminalSetting(&cfg, 0, L"collaboration", L"on", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"coordinator", L"2", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"context_auto", L"off", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"context_budget_kb", L"32", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"context_recent", L"4", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"tool_result_kb", L"2", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"context_summary_kb", L"3", &changes, &error));
    assert(cfg.collaboration && cfg.coordinator == 2 && !cfg.context_auto && cfg.context_budget_kb == 32);
    assert(SetTerminalSetting(&cfg, 0, L"permission_mode", L"readonly", &changes, &error));
    assert(cfg.permission_mode == 0);
    assert(SetTerminalSetting(&cfg, 0, L"memory_enabled", L"off", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"memory_project", L"project-test", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"memory_hits", L"3", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"memory_context_kb", L"4", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"evaluation_enabled", L"off", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"stream_usage", L"on", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"primary.input_price", L"2", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"1.input_price", L"3", &changes, &error));
    assert(lstrcmpW(cfg.input_price, L"2") == 0 && lstrcmpW(cfg.agent.profiles[0].input_price, L"3") == 0);
    assert(SetTerminalSetting(&cfg, 0, L"1.name", L"new-priced-model", &changes, &error));
    assert(cfg.agent.profiles[0].input_price[0] == 0 && lstrcmpW(cfg.input_price, L"2") == 0);
    assert(!cfg.stream_output && cfg.agent.auto_route && cfg.agent.failover && cfg.agent.review);
    ServerConfig before = cfg;
    const wchar_t* invalid[][2] = {
        { L"effort", L"ultra" }, { L"tokens", L"99999999999999999" },
        { L"tokens", L"12abc" }, { L"timeout", L"4" }, { L"timeout", L"301" },
        { L"top_p", L"0" }, { L"temperature", L"NaN" }, { L"history", L"1" },
        { L"tool_rounds", L"1001" }, { L"round_warning", L"21" },
        { L"time_warning_seconds", L"9" }, { L"tool_choice", L"invalid" },
        { L"stream", L"invalid" }, { L"unknown", L"on" }, { L"task_retries", L"6" },
        { L"coordinator", L"4" }, { L"context_budget_kb", L"15" }, { L"context_recent", L"1" },
        { L"tool_result_kb", L"33" }, { L"context_summary_kb", L"0" }, { L"permission_mode", L"allow_all" },
        { L"memory_hits", L"11" }, { L"memory_context_kb", L"1" }, { L"input_price", L"NaN" },
        { L"output_price", L"-1" }, { L"price_currency", L"EUR" },
        { L"task_replans", L"6" }, { L"task_rounds", L"1001" }, { L"task_timeout_seconds", L"9" },
        { L"parallel_workers", L"5" }, { L"event_wait_seconds", L"0" }
    };
    size_t changed = changes.size();
    for (size_t i = 0; i < _countof(invalid); ++i) {
        assert(!SetTerminalSetting(&cfg, 0, invalid[i][0], invalid[i][1], &changes, &error));
        assert(memcmp(&cfg, &before, sizeof(cfg)) == 0 && changes.size() == changed);
    }
    wchar_t temp[MAX_PATH], path[MAX_PATH], value[64];
    assert(GetTempPathW(_countof(temp), temp));
    assert(GetTempFileNameW(temp, L"mcp", 0, path));
    assert(WritePrivateProfileStringW(L"remote", L"url", L"keep-existing", path));
    assert(SaveTerminalSettings(changes, path));
    GetPrivateProfileStringW(L"agent_model_2", L"reasoning_effort", L"", value, 64, path);
    assert(lstrcmpW(value, L"high") == 0);
    assert(GetPrivateProfileIntW(L"agent_model_2", L"timeout_seconds", 0, path) == 120);
    assert(GetPrivateProfileIntW(L"model", L"round_warning", 0, path) == 5);
    assert(GetPrivateProfileIntW(L"model", L"time_warning_seconds", 0, path) == 90);
    GetPrivateProfileStringW(L"remote", L"url", L"", value, 64, path);
    assert(lstrcmpW(value, L"keep-existing") == 0);
    assert(GetPrivateProfileIntW(L"model", L"max_output_tokens", 0, path) == 65536);
    assert(GetPrivateProfileIntW(L"agent", L"task_mode", 0, path) == 1);
    assert(GetPrivateProfileIntW(L"agent", L"task_retries", 0, path) == 3);
    assert(GetPrivateProfileIntW(L"agent", L"collaboration", 0, path) == 1);
    assert(GetPrivateProfileIntW(L"agent", L"coordinator", 0, path) == 2);
    assert(GetPrivateProfileIntW(L"context", L"context_budget_kb", 0, path) == 32);
    assert(GetPrivateProfileIntW(L"permissions", L"mode", 2, path) == 0);
    assert(!SaveTerminalSettings(changes, (std::wstring(path) + L"\\bad.ini").c_str()));
    assert(DeleteFileW(path));
}

static void TestExtendedTerminalSettings()
{
    ServerConfig cfg;
    SetDefaultConfig(&cfg);
    ServerConfig initial = cfg;
    TerminalSettingsChanges changes;
    std::wstring error;
    assert(!SetTerminalSetting(&cfg, 0, L"1.enabled", L"on", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"1.model_name", L"qwen-plus", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"1.model_url", L"https://model.test/v1", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"1.api_key", L"test-secret", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"1.enabled", L"on", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"1.reviewer", L"on", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"1.keywords", L"crash, asm", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"auto_route", L"on", &changes, &error));
    assert(SelectTerminalModel(cfg, L"qwen-plus") == 2 && AgentRouteModel(cfg.agent, L"asm") == 1);
    assert(SetTerminalSetting(&cfg, 0, L"1.url", L"https://model.test/v1", &changes, &error));
    assert(lstrcmpW(cfg.agent.profiles[0].key, L"test-secret") == 0);
    assert(SetTerminalSetting(&cfg, 0, L"1.url", L"https://other.test/v1", &changes, &error));
    assert(cfg.agent.profiles[0].key[0] == 0);
    assert(changes[std::make_pair(std::wstring(L"agent_model_1"), std::wstring(L"api_key"))].empty());
    assert(SetTerminalSetting(&cfg, 1, L"primary.name", L"main-model", &changes, &error));
    assert(lstrcmpW(cfg.model_name, L"main-model") == 0);
    assert(SetTerminalSetting(&cfg, 0, L"mcp_url", L"https://mcp.test/tools", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"mcp_token", L"test-token", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"mcp_transport", L"sse", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"mcp_timeout", L"45000", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"mcp_retry_interval", L"1000", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"mcp_max_retries", L"3", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"mcp_verify_tls", L"off", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"cache_enabled", L"on", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"cache_ttl", L"90", &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"cache_max_kb", L"2048", &changes, &error));
    assert(IsTerminalSecretSetting(L"1.API_KEY") && IsTerminalSecretSetting(L"mcp_token"));
    assert(!IsTerminalSecretSetting(L"name"));
    ServerConfig before = cfg;
    size_t count = changes.size();
    const wchar_t* invalid[][2] = {
        { L"4.name", L"bad" }, { L"1.tokens", L"100" }, { L"primary.enabled", L"off" },
        { L"primary.keywords", L"crash" }, { L"1.url", L"http://public.test/v1" },
        { L"name", L"one\ntwo" }, { L"mcp_url", L"ftp://mcp.test" },
        { L"mcp_transport", L"bad" }, { L"mcp_timeout", L"99" },
        { L"mcp_retry_interval", L"300001" }, { L"cache_ttl", L"86401" },
        { L"cache_max_kb", L"0" }, { L"mcp_max_retries", L"9999999999999" }
    };
    for (size_t i = 0; i < _countof(invalid); ++i) {
        assert(!SetTerminalSetting(&cfg, 0, invalid[i][0], invalid[i][1], &changes, &error));
        assert(memcmp(&before, &cfg, sizeof(cfg)) == 0 && changes.size() == count);
    }
    assert(!SetTerminalSetting(&cfg, 0, L"api_key", std::wstring(256, L'x'), &changes, &error));
    assert(SetTerminalSetting(&cfg, 0, L"mcp_token", L"clear", &changes, &error));
    assert(!cfg.remote_token[0]);
    wchar_t temp[MAX_PATH], path[MAX_PATH], value[128];
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"mcp", 0, path));
    assert(WritePrivateProfileStringW(L"http", L"port", L"12345", path));
    assert(SaveTerminalSettings(changes, path));
    GetPrivateProfileStringW(L"agent_model_1", L"name", L"", value, _countof(value), path);
    assert(lstrcmpW(value, L"qwen-plus") == 0);
    assert(GetPrivateProfileIntW(L"agent_model_1", L"enabled", 0, path) == 1);
    assert(GetPrivateProfileIntW(L"remote", L"timeout_ms", 0, path) == 45000);
    assert(GetPrivateProfileIntW(L"cache", L"ttl_seconds", 0, path) == 90);
    assert(GetPrivateProfileIntW(L"http", L"port", 0, path) == 12345);
    assert(DeleteFileW(path));

    InitializeCriticalSection(&g_config_cs);
    InitializeCriticalSection(&g_remote_cs);
    InitializeCriticalSection(&g_sse_cs);
    g_config = initial;
    g_remote_tools_result = "stale tools";
    InterlockedExchange(&g_remote_connected, 1);
    ApplyTerminalConfig(initial, cfg);
    assert(g_remote_tools_result.empty() && g_remote_connected == 0);
    assert(CopyConfig().remote_timeout_ms == 45000);
    DeleteCriticalSection(&g_sse_cs);
    DeleteCriticalSection(&g_remote_cs);
    DeleteCriticalSection(&g_config_cs);
    puts("PASS: CLI slot setup, secret clearing, endpoint validation, MCP/cache settings and runtime refresh");
}

enum TaskFakeMode { TASK_OK, TASK_RECOVER, TASK_NO_OBSERVATION, TASK_BAD_PLAN,
    TASK_FAKE_EVIDENCE, TASK_CANCEL_CHECK, TASK_WRITE_DURING_VERIFY, TASK_READ_FAIL, TASK_MULTISTEP };
static TaskFakeMode g_task_fake;
static int g_task_writes, g_task_reads, g_task_value;

static bool FakeTaskTools(const ServerConfig&, std::string* result, bool)
{
    *result = "{\"tools\":[{\"name\":\"write_memory\",\"inputSchema\":{\"type\":\"object\"}},"
        "{\"name\":\"read_memory\",\"annotations\":{\"readOnlyHint\":true},\"inputSchema\":{\"type\":\"object\"}}]}";
    return true;
}

static bool FakeTaskTool(const ServerConfig&, const std::string& request, const std::string&, std::string* result)
{
    ModelJson json;
    assert(ModelJson::parse(request, &json));
    std::string name = json.get("params")->get("name")->value;
    if (name == "write_memory") {
        ++g_task_writes;
        if (g_task_fake == TASK_RECOVER && g_task_writes == 1) {
            *result = "{\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"write failed\"}}";
            return true;
        }
        g_task_value = 42;
        *result = "{\"jsonrpc\":\"2.0\",\"result\":{\"ok\":true}}";
    }
    else {
        assert(name == "read_memory");
        ++g_task_reads;
        *result = g_task_fake == TASK_READ_FAIL ?
            "{\"jsonrpc\":\"2.0\",\"result\":{\"isError\":true}}" :
            "{\"jsonrpc\":\"2.0\",\"result\":{\"value\":" + TaskNumber(g_task_value) + "}}";
    }
    return true;
}

static int g_sample_runs = 0, g_sample_status = 18, g_sample_sequence = 1;
static bool g_sample_wrong_stop = false;

static bool FakeSampleTools(const ServerConfig&, std::string* result, bool)
{
    *result = "{\"tools\":[{\"name\":\"run\",\"inputSchema\":{\"type\":\"object\"}},"
        "{\"name\":\"wait_debug_event\",\"annotations\":{\"readOnlyHint\":true},\"inputSchema\":{\"type\":\"object\"}},"
        "{\"name\":\"get_debug_context\",\"annotations\":{\"readOnlyHint\":true},\"inputSchema\":{\"type\":\"object\"}}]}";
    return true;
}

static bool FakeSampleTool(const ServerConfig&, const std::string& request,
    const std::string&, std::string* result)
{
    ModelJson rpc;
    assert(ModelJson::parse(request, &rpc));
    const std::string name = rpc.get("params")->get("name")->value;
    if (name == "run") {
        assert(g_sample_status == 18);
        ++g_sample_runs; g_sample_status = 19; ++g_sample_sequence;
        *result = "{\"result\":{\"ok\":true}}";
    } else if (name == "wait_debug_event") {
        assert(g_sample_status == 19);
        g_sample_status = 18; ++g_sample_sequence;
        *result = "{\"result\":{\"cursor\":" + TaskNumber(g_sample_sequence) +
            ",\"gap\":false,\"events\":[{\"event\":{\"exceptionCode\":2147483651,"
            "\"exceptionAddress\":\"" + std::string(g_sample_wrong_stop ? "0x402000" : "0x401000") + "\"}}]}}";
    } else {
        assert(name == "get_debug_context");
        *result = "{\"result\":{\"session\":\"sample-session\",\"process_id\":123,"
            "\"thread_id\":7,\"status\":" + TaskNumber(g_sample_status) +
            ",\"revision\":\"7:" + TaskNumber(g_sample_status) + ":" + TaskNumber(g_sample_runs) +
            "\",\"sequence\":" + TaskNumber(g_sample_sequence) + ",\"last_stop\":" +
            (g_sample_runs && g_sample_status == 18 ?
                std::string("{\"exceptionCode\":2147483651,\"exceptionAddress\":\"") +
                    (g_sample_wrong_stop ? "0x402000" : "0x401000") + "\"}" : "null") + "}}";
    }
    return true;
}

static bool FakeTaskModel(const ServerConfig& cfg, const std::vector<std::string>& messages,
    const std::string& tools, ModelJson* response, std::string* error,
    std::string* request_json, std::string* response_json, ChatJob* job, int round)
{
    assert(!messages.empty());
    *request_json = "{}";
    std::string content, call;
    if (round == -2) {
        assert(tools == "[]" && lstrcmpW(cfg.tool_choice, L"none") == 0 && !cfg.stream_output);
        content = g_task_fake == TASK_BAD_PLAN ? "not JSON" :
            "{\"title\":\"Set test cell\",\"steps\":[{\"title\":\"Set cell\","
            "\"criterion\":\"Cell reads 42\",\"kind\":\"mutation\"}]}";
        if (g_task_fake == TASK_MULTISTEP)
            content = "{\"title\":\"Two steps\",\"steps\":[{\"title\":\"Set cell\",\"criterion\":\"Cell reads 42\","
                "\"kind\":\"mutation\"},{\"title\":\"Recheck\",\"criterion\":\"Cell still reads 42\",\"kind\":\"observation\"}]}";
    }
    else if (round == -3) {
        assert(tools == "[]" && lstrcmpW(cfg.tool_choice, L"none") == 0 && !cfg.stream_output);
        if (g_task_fake == TASK_CANCEL_CHECK) {
            InterlockedExchange(&g_chat_cancel, 1);
            *error = "cancelled"; return false;
        }
        size_t count = job->task.evidence.size();
        bool read = count && job->task.evidence.back().read_only;
        std::string status = read ? "verified" : "needs_verification";
        std::string ids = read ? TaskNumber((int)count) : "";
        if (g_task_fake == TASK_NO_OBSERVATION) { status = "verified"; ids.clear(); }
        if (g_task_fake == TASK_FAKE_EVIDENCE) { status = "verified"; ids = "999"; }
        if (g_task_fake == TASK_RECOVER && g_task_value != 42) { status = "retry"; ids.clear(); }
        content = "{\"step\":" + TaskNumber(TaskCurrentStep(job->task) + 1) + ",\"status\":\"" + status + "\",\"evidence\":[" + ids +
            "],\"reason\":\"Check actual cell value\",\"adjustment\":\"Read cell or correct failed write\"}";
    }
    else if (TaskCurrentStep(job->task) < 0) content = "Cell is 42, verified by read_memory.";
    else if (g_task_fake == TASK_NO_OBSERVATION && g_task_writes) content = "Everything is done.";
    else if (g_task_fake == TASK_WRITE_DURING_VERIFY) call = "write_memory";
    else if (job->verification_only || job->task.recovering || job->task.steps[TaskCurrentStep(job->task)].status == "verifying" ||
        job->task.steps[TaskCurrentStep(job->task)].kind == "observation") call = "read_memory";
    else call = "write_memory";
    if (call.empty()) {
        *response_json = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
        ModelJson::quote(response_json, content);
        *response_json += "}}]}";
    }
    else {
        *response_json = "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,"
            "\"tool_calls\":[{\"id\":\"call_" + TaskNumber(round) + "\",\"type\":\"function\","
            "\"function\":{\"name\":\"" + call + "\",\"arguments\":\"{}\"}}]}}]}";
    }
    return ModelJson::parse(*response_json, response);
}

static ChatJob TaskTestJob(TaskFakeMode mode)
{
    g_task_fake = mode; g_task_writes = 0; g_task_reads = 0; g_task_value = 0;
    InterlockedExchange(&g_chat_cancel, 0);
    g_agent_model_request = FakeTaskModel;
    g_agent_tools_list = FakeTaskTools;
    g_agent_tool_call = FakeTaskTool;
    ChatJob job = {};
    job.cfg = TestConfig();
    StringCchCopyW(job.cfg.tool_choice, 16, L"auto");
    job.cfg.max_tool_rounds = 6;
    job.prompt = "Set cell to 42 and verify it";
    job.task_enabled = true;
    job.streamed_round = job.final_round = -1;
    return job;
}

static bool ChainedTools(const ServerConfig&, std::string* result, bool)
{
    *result = "{\"tools\":[{\"name\":\"register_get\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}},"
        "{\"name\":\"stack_read\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"integer\"},\"size\":{\"type\":\"integer\"}},\"required\":[\"address\",\"size\"]}},"
        "{\"name\":\"register_set\",\"inputSchema\":{\"type\":\"object\"}}]}";
    return true;
}

static bool ChainedTool(const ServerConfig&, const std::string& request, const std::string&, std::string* result)
{
    ModelJson rpc; assert(ModelJson::parse(request, &rpc));
    const ModelJson* params = rpc.get("params");
    std::string name = params->get("name")->value;
    if (name == "register_get") {
        assert(params->get("arguments")->get("name")->value == "rsp");
        *result = "{\"result\":{\"registers\":{\"rsp\":\"0x1000\"}}}";
    } else if (name == "register_set") {
        *result = "{\"result\":{\"ok\":true}}";
    } else {
        assert(name == "stack_read" && params->get("arguments")->get("address")->raw == "4096");
        *result = "{\"result\":{\"hex\":\"2A000000\",\"read\":4}}";
    }
    return true;
}

static bool BatchDecisionModel(const ServerConfig&, const std::vector<std::string>& messages,
    const std::string&, ModelJson* response, std::string*, std::string* request_json,
    std::string* response_json, ChatJob*, int round)
{
    *request_json = "{}";
    if (!round) {
        *response_json = "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,\"tool_calls\":["
            "{\"id\":\"read_first\",\"type\":\"function\",\"function\":{\"name\":\"register_get\",\"arguments\":\"{\\\"name\\\":\\\"rsp\\\"}\"}},"
            "{\"id\":\"write_second\",\"type\":\"function\",\"function\":{\"name\":\"register_set\",\"arguments\":\"{}\"}}]}}]}";
    } else {
        bool read_seen = false, deferred_seen = false;
        for (size_t i = 0; i < messages.size(); ++i) {
            ModelJson item;
            if (!ModelJson::parse(messages[i], &item) || !item.get("tool_call_id")) continue;
            if (item.get("tool_call_id")->value == "read_first") read_seen = item.get("content")->value.find("0x1000") != std::string::npos;
            if (item.get("tool_call_id")->value == "write_second") deferred_seen = item.get("content")->value.find("-32008") != std::string::npos;
        }
        assert(read_seen && deferred_seen);
        *response_json = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":\"Write was deferred\"}}]}";
    }
    return ModelJson::parse(*response_json, response);
}

static bool ChainedModel(const ServerConfig&, const std::vector<std::string>& messages,
    const std::string&, ModelJson* response, std::string*, std::string* request_json,
    std::string* response_json, ChatJob*, int round)
{
    *request_json = "{}";
    if (round == 1 || round == 2) {
        bool matched = false;
        for (size_t i = 0; i < messages.size(); ++i) {
            ModelJson item;
            if (!ModelJson::parse(messages[i], &item) || !item.get("role") ||
                item.get("role")->value != "tool") continue;
            const ModelJson* id = item.get("tool_call_id"), *content = item.get("content");
            if (id && content && id->value == (round == 1 ? "register_call" : "stack_call") &&
                content->value.find(round == 1 ? "0x1000" : "2A000000") != std::string::npos) matched = true;
        }
        assert(matched);
    }
    if (round < 2) {
        *response_json = "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,\"tool_calls\":[{\"id\":\"";
        *response_json += round == 0 ? "register_call" : "stack_call";
        *response_json += "\",\"type\":\"function\",\"function\":{\"name\":\"";
        *response_json += round == 0 ? "register_get" : "stack_read";
        *response_json += "\",\"arguments\":\"";
        *response_json += round == 0 ? "{\\\"name\\\":\\\"rsp\\\"}" : "{\\\"address\\\":4096,\\\"size\\\":4}";
        *response_json += "\"}}]}}]}";
    } else {
        *response_json = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":\"Stack value is 42\"}}]}";
    }
    return ModelJson::parse(*response_json, response);
}

static int g_truncated_model_calls = 0;
static bool TruncatedModel(const ServerConfig&, const std::vector<std::string>& messages,
    const std::string&, ModelJson* response, std::string*, std::string* request_json,
    std::string* response_json, ChatJob*, int)
{
    ++g_truncated_model_calls;
    if (g_truncated_model_calls == 2) {
        ModelJson instruction;
        assert(!messages.empty() && ModelJson::parse(messages.back(), &instruction));
        assert(instruction.get("content") && instruction.get("content")->value.find("one concise tool call") != std::string::npos);
    }
    *request_json = "{}";
    *response_json = g_truncated_model_calls == 1 ?
        "{\"choices\":[{\"finish_reason\":\"length\",\"message\":{\"content\":\"partial\"}}]}" :
        "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":\"Concise result\"}}]}";
    return ModelJson::parse(*response_json, response);
}

static bool ContinuationModel(const ServerConfig&, const std::vector<std::string>& messages,
    const std::string&, ModelJson* response, std::string*, std::string* request_json,
    std::string* response_json, ChatJob*, int)
{
    *request_json = "{}";
    bool observed = false;
    for (size_t i = 0; i < messages.size(); ++i) {
        ModelJson item;
        if (ModelJson::parse(messages[i], &item) && item.get("role") &&
            item.get("role")->value == "tool") observed = true;
    }
    *response_json = observed ?
        "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":\"Recovered from saved observation\"}}]}" :
        "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,\"tool_calls\":[{\"id\":\"read_1\",\"type\":\"function\",\"function\":{\"name\":\"register_get\",\"arguments\":\"{\\\"name\\\":\\\"rsp\\\"}\"}}]}}]}";
    return ModelJson::parse(*response_json, response);
}

static bool g_recovery_write;
static bool RecoveryModel(const ServerConfig&, const std::vector<std::string>&,
    const std::string&, ModelJson* response, std::string*, std::string* request_json,
    std::string* response_json, ChatJob*, int round)
{
    *request_json = "{}";
    if (round == 0) {
        *response_json = "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,\"tool_calls\":[{\"id\":\"recovery_read\",\"type\":\"function\",\"function\":{\"name\":\"";
        *response_json += g_recovery_write ? "register_set" : "register_get";
        *response_json += "\",\"arguments\":\"";
        *response_json += g_recovery_write ? "{}" : "{\\\"name\\\":\\\"rsp\\\"}";
        *response_json += "\"}}]}}]}";
    } else {
        *response_json = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":\"Recovery checked\"}}]}";
    }
    return ModelJson::parse(*response_json, response);
}

static bool UncertainTool(const ServerConfig&, const std::string&, const std::string&, std::string*)
{
    return false;
}

static bool UncertainModel(const ServerConfig&, const std::vector<std::string>&,
    const std::string&, ModelJson* response, std::string*, std::string* request_json,
    std::string* response_json, ChatJob*, int)
{
    *request_json = "{}";
    *response_json = "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,\"tool_calls\":["
        "{\"id\":\"write\",\"type\":\"function\",\"function\":{\"name\":\"register_set\",\"arguments\":\"{}\"}},"
        "{\"id\":\"later\",\"type\":\"function\",\"function\":{\"name\":\"register_get\",\"arguments\":\"{\\\"name\\\":\\\"rsp\\\"}\"}}]}}]}";
    return ModelJson::parse(*response_json, response);
}

static bool RemoveMemoryTestTree(const std::wstring& directory);
static void TestChatContinuation()
{
    LONG previous_quota = InterlockedExchange(&g_storage_quota_mb, 512);
    wchar_t temp[MAX_PATH], root[MAX_PATH], previous[32768];
    DWORD previous_length = GetEnvironmentVariableW(L"LOCALAPPDATA", previous, _countof(previous));
    assert(previous_length < _countof(previous));
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"cht", 0, root));
    assert(DeleteFileW(root) && CreateDirectoryW(root, NULL));
    assert(SetEnvironmentVariableW(L"LOCALAPPDATA", root));
    g_agent_tools_list = ChainedTools;
    g_agent_tool_call = ChainedTool;
    g_agent_model_request = ContinuationModel;
    std::wstring path = LocalMcpDataDirectory() + L"\\terminal-test-" + ChatWide(AgentOperationId()) + L".json";
    ChatJob first = {}; first.cfg = TestConfig();
    StringCchCopyW(first.cfg.tool_choice, 16, L"auto");
    first.cfg.max_tool_rounds = 1;
    first.prompt = first.chat_goal = "Read the stack pointer";
    first.chat_history_path = path;
    assert(!RunChat(&first) && first.history_consistent && first.calls.size() == 1 &&
        first.chat_paused && first.answer.find("Partial findings") != std::string::npos);
    ChatContinuation saved;
    assert(LoadChatContinuation(path, &saved) && saved.reason == "round_limit" && saved.goal == first.prompt);
    std::vector<std::string> history; std::string skill;
    assert(LoadTerminalHistory(path, &history, &skill) && history == first.history);
    ChatJob resumed = {}; resumed.cfg = first.cfg;
    resumed.prompt = "Continue the saved request"; resumed.chat_goal = saved.goal;
    resumed.chat_history_path = path; resumed.history = history;
    assert(RunChat(&resumed) && resumed.answer == "Recovered from saved observation");
    assert(!LoadChatContinuation(path, &saved));
    resumed.chat_pending_tool = "register_set";
    resumed.chat_pending_arguments = "{}";
    resumed.chat_pending_target = "old-session:123";
    assert(SaveChatContinuation(&resumed, "operation_pending"));
    assert(LoadChatContinuation(path, &saved) && saved.tool == "register_set" &&
        saved.reason == "operation_pending" && saved.target == "old-session:123");
    assert(!ChatContinuationTargetMatches(first.cfg, saved.target));
    resumed.chat_pending_target.clear();
    assert(SaveChatContinuation(&resumed, "operation_pending"));
    assert(LoadChatContinuation(path, &saved) && saved.target.empty());
    g_agent_model_request = RecoveryModel;
    g_recovery_write = true;
    ChatJob rejected = {}; rejected.cfg = first.cfg; rejected.cfg.max_tool_rounds = 3;
    rejected.prompt = "Verify without changes"; rejected.chat_goal = saved.goal;
    rejected.chat_history_path = path; rejected.history = resumed.history;
    rejected.verification_only = rejected.chat_recovery_verify = true;
    rejected.chat_pending_tool = saved.tool; rejected.chat_pending_arguments = saved.arguments;
    assert(RunChat(&rejected) && !rejected.chat_recovery_observed &&
        rejected.evaluation.tool_denied == 1 && rejected.evaluation.tool_dispatched == 0);
    assert(LoadChatContinuation(path, &saved) && saved.reason == "verification_required" && saved.tool == "register_set");
    g_recovery_write = false;
    ChatJob verified = {}; verified.cfg = first.cfg; verified.cfg.max_tool_rounds = 3;
    verified.prompt = "Read current state"; verified.chat_goal = saved.goal;
    verified.chat_history_path = path; verified.history = rejected.history;
    verified.verification_only = verified.chat_recovery_verify = true;
    verified.chat_pending_tool = saved.tool; verified.chat_pending_arguments = saved.arguments;
    assert(RunChat(&verified) && verified.chat_recovery_observed && verified.evaluation.tool_success == 1);
    assert(LoadChatContinuation(path, &saved) && saved.reason == "verified_review");
    Reset(CANCEL_REQUEST);
    ChatJob retry_cancel = {}; retry_cancel.cfg = TestConfig();
    retry_cancel.prompt = "Resume after review"; retry_cancel.chat_goal = saved.goal;
    retry_cancel.chat_history_path = path; retry_cancel.history = verified.history;
    retry_cancel.chat_resume_authorized = true;
    retry_cancel.chat_pending_tool = saved.tool; retry_cancel.chat_pending_arguments = saved.arguments;
    assert(!RunChat(&retry_cancel) && retry_cancel.chat_paused);
    assert(LoadChatContinuation(path, &saved) && saved.reason == "operation_pending" && saved.tool == "register_set");
    InterlockedExchange(&g_chat_cancel, 0);
    g_agent_model_request = UncertainModel;
    g_agent_tool_call = UncertainTool;
    ChatJob uncertain = {}; uncertain.cfg = first.cfg;
    uncertain.prompt = uncertain.chat_goal = "Change a register";
    uncertain.chat_history_path = path; uncertain.history = verified.history;
    uncertain.chat_resume_authorized = true;
    assert(!RunChat(&uncertain) && uncertain.history_consistent && uncertain.evaluation.tool_uncertain == 1);
    assert(uncertain.calls.size() == 1);
    assert(LoadChatContinuation(path, &saved) && saved.reason == "operation_pending" && saved.tool == "register_set");
    std::vector<ContextBlock> blocks;
    assert(ContextBlocks(uncertain.history, &blocks) && blocks.back().complete);
    Reset(CANCEL_REQUEST);
    ChatJob interrupted = {}; interrupted.cfg = TestConfig();
    interrupted.prompt = interrupted.chat_goal = "Continue reading";
    interrupted.chat_history_path = path; interrupted.history = uncertain.history;
    assert(!RunChat(&interrupted) && interrupted.answer.find("unknown outcome") != std::string::npos);
    assert(LoadChatContinuation(path, &saved) && saved.reason == "operation_pending");
    assert(ClearChatContinuation(&uncertain));
    assert(!RunChat(&interrupted) && interrupted.chat_paused);
    assert(LoadChatContinuation(path, &saved) && saved.reason == "ready");
    InterlockedExchange(&g_chat_cancel, 0);
    assert(ClearChatContinuation(&resumed));
    assert(DeleteFileW(path.c_str()));
    SetEnvironmentVariableW(L"LOCALAPPDATA", previous_length ? previous : NULL);
    assert(RemoveMemoryTestTree(root));
    InterlockedExchange(&g_storage_quota_mb, previous_quota);
    g_agent_tools_list = RemoteToolsList;
    g_agent_tool_call = RemoteToolCall;
    g_agent_model_request = FakeModelRequest;
    puts("PASS: chat round checkpoints, disk reload, continuation and pending-operation marker");
}

static void TestChainedToolResults()
{
    g_agent_tools_list = ChainedTools;
    g_agent_tool_call = ChainedTool;
    g_agent_model_request = ChainedModel;
    ChatJob job = {}; job.cfg = TestConfig();
    StringCchCopyW(job.cfg.tool_choice, 16, L"auto");
    job.prompt = "Read the stack value";
    HANDLE progress_read = NULL, progress_write = NULL;
    assert(CreatePipe(&progress_read, &progress_write, NULL, 0));
    job.console_output = progress_write;
    assert(RunChat(&job) && job.answer == "Stack value is 42" && job.calls.size() == 2);
    CloseHandle(progress_write);
    std::string progress;
    char chunk[1024]; DWORD count = 0;
    while (ReadFile(progress_read, chunk, sizeof(chunk), &count, NULL) && count)
        progress.append(chunk, count);
    CloseHandle(progress_read);
    assert(progress.find("Model request (round 1)") != std::string::npos);
    assert(progress.find("tool  register_get") != std::string::npos);
    assert(progress.find("result  {\"result\":{\"registers\":") != std::string::npos);
    assert(progress.find("tool  stack_read") > progress.find("tool  register_get"));
    std::vector<ContextBlock> blocks;
    assert(ContextBlocks(job.history, &blocks));
    g_agent_model_request = BatchDecisionModel;
    ChatJob batch = {}; batch.cfg = TestConfig();
    StringCchCopyW(batch.cfg.tool_choice, 16, L"auto");
    batch.prompt = "Read and then change a register";
    assert(RunChat(&batch) && batch.answer == "Write was deferred" && batch.calls.size() == 2);
    assert(ContextBlocks(batch.history, &blocks));
    g_agent_model_request = TruncatedModel; g_truncated_model_calls = 0;
    ChatJob retried = {}; retried.cfg = TestConfig(); retried.prompt = "Summarize the evidence";
    bool retried_ok = RunChat(&retried);
    if (!retried_ok || retried.answer != "Concise result" || g_truncated_model_calls != 2 || !retried.calls.empty())
        fprintf(stderr, "Truncated retry: ok=%d calls=%d tools=%u answer=%s\n", retried_ok,
            g_truncated_model_calls, (unsigned)retried.calls.size(), retried.answer.c_str());
    assert(retried_ok && retried.answer == "Concise result" && g_truncated_model_calls == 2 && retried.calls.empty());
    g_agent_tools_list = RemoteToolsList;
    g_agent_tool_call = RemoteToolCall;
    g_agent_model_request = FakeModelRequest;
}

static void TestDebugPythonDispatch()
{
    if (AgentPythonExecutable().empty() || AgentPythonRunnerPath().empty()) return;
    g_agent_tools_list = ChainedTools;
    g_agent_tool_call = ChainedTool;
    std::string remote, catalog, error;
    std::vector<ModelToolBinding> bindings;
    assert(ChainedTools(TestConfig(), &remote, true));
    assert(BuildModelTools(remote, &catalog, &bindings, &error));
    assert(AddDebugPythonTools(&catalog, &bindings, &error));
    ModelJson page;
    assert(ModelJson::parse("{}", &page));
    assert(DebugPythonApi(bindings, page).find("register_get") != std::string::npos);
    std::string capped_catalog;
    std::vector<ModelToolBinding> capped_bindings;
    assert(BuildModelTools(remote, &capped_catalog, &capped_bindings, &error, 1));
    assert(capped_bindings.size() == 1);
    ChatJob job = {}; job.cfg = TestConfig(); job.capabilities = bindings;
    StringCchCopyW(job.cfg.tool_choice, 16, L"auto");
    std::string result; bool dispatched = false;
    assert(ExecuteDebugPython(&job, bindings,
        "{\"code\":\"state = dbg.register_get(name='rsp')\\nprint(state['registers']['rsp'])\"}",
        &result, &dispatched));
    assert(TaskToolSucceeded(result) && result.find("0x1000") != std::string::npos && !dispatched);
    assert(ExecuteDebugPython(&job, bindings,
        "{\"code\":\"dbg.register_set(name='rsp', value=1)\\nint('invalid')\"}",
        &result, &dispatched));
    assert(!TaskToolSucceeded(result) && dispatched && result.find("\"mutated\":true") != std::string::npos);
    job.task_enabled = true;
    job.task.state = "running";
    job.task.steps.push_back(AgentTaskStep());
    assert(ExecuteDebugPython(&job, bindings,
        "{\"code\":\"dbg.register_get(name='rsp')\"}",
        &result, &dispatched));
    assert(TaskToolSucceeded(result) && job.task.evidence.size() == 1 &&
        job.task.evidence[0].tool == "register_get" && job.task.evidence[0].read_only);
    job.task_enabled = false;
    job.cfg.permission_mode = 0;
    g_audit_events.clear();
    assert(ExecuteDebugPython(&job, bindings,
        "{\"code\":\"dbg.register_set(name='rsp', value=1)\"}",
        &result, &dispatched));
    assert(!TaskToolSucceeded(result) && !dispatched);
    bool denied = false;
    for (size_t i = 0; i < g_audit_events.size(); ++i)
        if (g_audit_events[i].find("deny_read_only") != std::string::npos) denied = true;
    assert(denied);
    g_agent_tools_list = RemoteToolsList;
    g_agent_tool_call = RemoteToolCall;
}

static void TestExecutableToolDirectory()
{
    ServerConfig cfg = TestConfig();
    StringCchCopyW(cfg.debugger_path, _countof(cfg.debugger_path), L"C:\\Tools\\Debugger.exe");
    const std::string configured = "{\"tools\":[{\"name\":\"trace_analyzer\","
        "\"path\":\"C:\\\\Tools\\\\Trace.exe\",\"description\":\"Analyze a saved trace\","
        "\"parameters\":[{\"name\":\"--input\",\"description\":\"Trace file path\",\"required\":true}],"
        "\"mcp_tools\":[\"analyze_trace\"]},{\"name\":\"bad\",\"path\":\"x\","
        "\"description\":\"Invalid argument schema\",\"parameters\":[{}]}]}";
    std::string catalog = AgentExecutableCatalog(cfg, configured);
    ModelJson parsed;
    assert(ModelJson::parse(catalog, &parsed) && parsed.kind == ModelJson::ARRAY && parsed.items.size() == 3);
    assert(parsed.items[0].get("available") && parsed.items[0].get("available")->value == "true");
    assert(parsed.items[1].get("available") && parsed.items[1].get("available")->value == "false");
    assert(catalog.find("C:\\\\Tools\\\\Debugger.exe") != std::string::npos);
    assert(catalog.find("-ida <file.exe>") != std::string::npos);
    assert(catalog.find("without starting or attaching a debug process") != std::string::npos);
    assert(catalog.find("does not return file bytes or disassembly to the model") != std::string::npos);
    assert(catalog.find("Trace file path") != std::string::npos);
    assert(catalog.find("Invalid argument schema") == std::string::npos);
    Reset(NORMAL);
    ChatJob normal = {}; normal.cfg = cfg; normal.prompt = "Inspect the debugger";
    assert(RunChat(&normal) && !g_fake_attempts.empty());
    ModelJson system;
    assert(ModelJson::parse(g_fake_attempts.back().messages[0], &system));
    assert(system.get("content")->value.find("C:\\\\Tools\\\\Debugger.exe") != std::string::npos);
    if (AgentPythonExecutable().empty() || AgentPythonRunnerPath().empty()) return;
    ChatJob python = {}; python.cfg = cfg; python.prompt = "Inspect the debugger"; python.python_mode = true;
    assert(RunChat(&python) && !g_fake_attempts.empty());
    assert(ModelJson::parse(g_fake_attempts.back().messages[0], &system));
    assert(system.get("content")->value.find("C:\\\\Tools\\\\Debugger.exe") != std::string::npos);
}

static void TestAgentTasks()
{
    std::string model_tools, binding_error;
    std::vector<ModelToolBinding> binding;
    assert(BuildModelTools("{\"tools\":[{\"name\":\"get_status\",\"annotations\":{\"readOnlyHint\":false}},"
        "{\"name\":\"custom_observation\",\"annotations\":{\"readOnlyHint\":true}}]}", &model_tools, &binding, &binding_error));
    assert(!binding[0].read_only && binding[1].read_only);
    assert(!TaskToolSucceeded("{\"error\":{}}"));
    assert(!TaskToolSucceeded("{\"result\":{\"isError\":true}}"));
    assert(!TaskToolSucceeded("{\"result\":{\"ok\":false}}"));
    assert(!TaskToolSucceeded("not JSON"));
    assert(AgentToolPermissionRefused(McpToolErrorResult(MCP_RPC_TOOL_IS_DISABLED_BY_MCP_TOOLS_PERMISSIONS)));
    assert(!AgentToolPermissionRefused(McpToolErrorResult(MCP_RPC_TOOL_PROVIDER_TIMEOUT)));
    const std::string missing_import = "{\"result\":{\"ok\":false,\"address\":\"0x0\"}}";
    assert(TaskObservationSucceeded("find_import_by_name", missing_import));
    assert(TaskObservationSucceeded("resolve_symbol", missing_import));
    assert(!TaskObservationSucceeded("read_memory", missing_import));
    assert(!TaskObservationSucceeded("find_import_by_name", "{\"error\":{\"code\":-32005},\"result\":{\"ok\":false,\"address\":\"0x0\"}}"));
    AgentAssertion absent_import;
    absent_import.tool = "find_import_by_name";
    absent_import.arguments = "{\"name\":\"WTSEnumerateProcesses\"}";
    absent_import.expected = "{\"ok\":false,\"address\":\"0x0\"}";
    assert(AssertionReceipt(absent_import, absent_import.arguments, missing_import));
    AgentTask malformed;
    assert(!ParseTaskPlan("{\"title\":\"x\",\"steps\":[]}", &malformed));

    ChatJob good = TaskTestJob(TASK_OK);
    wchar_t temp[MAX_PATH], path[MAX_PATH];
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"tsk", 0, path));
    good.task_record_path = path;
    assert(RunChat(&good));
    assert(good.task.state == "completed" && good.task.steps[0].status == "done");
    assert(g_task_writes == 1 && g_task_reads == 1 && good.task.evidence.size() == 2);
    assert(good.history_consistent && !good.task.id.empty());
    ModelJson record;
    assert(ModelJson::parse(TaskJson(good.task), &record));
    assert(record.get("state")->value == "completed");
    assert(ModelJson::parse(TaskJson(good.task, true), &record));
    HANDLE saved = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(saved != INVALID_HANDLE_VALUE);
    DWORD size = GetFileSize(saved, NULL), read = 0;
    assert(size && size < 1024 * 1024);
    std::string contents(size, '\0');
    assert(ReadFile(saved, &contents[0], size, &read, NULL) && read == size);
    CloseHandle(saved);
    assert(contents.compare(0, 8, "Z0DPAPI1") == 0 &&
        contents.find("read_memory") == std::string::npos);
    std::string clear;
    assert(AgentUnprotectRecord(contents, 8 * 1024 * 1024, &clear) &&
        ModelJson::parse(clear, &record) && record.get("state")->value == "completed");
    assert(DeleteFileW(path));
    AgentTask expanded = good.task, restored_evidence;
    while (expanded.evidence.size() < 65) expanded.evidence.push_back(good.task.evidence[0]);
    assert(ParseAgentCheckpoint(TaskJson(expanded), &restored_evidence));
    assert(restored_evidence.evidence.size() == 65 &&
        restored_evidence.evidence[64].tool == good.task.evidence[0].tool);
    while (expanded.evidence.size() < kAgentTaskEvidenceLimit)
        expanded.evidence.push_back(good.task.evidence[0]);
    assert(ParseAgentCheckpoint(TaskJson(expanded), &restored_evidence) &&
        restored_evidence.evidence.size() == kAgentTaskEvidenceLimit);
    expanded.evidence.push_back(good.task.evidence[0]);
    assert(!ParseAgentCheckpoint(TaskJson(expanded), &restored_evidence));

    ChatJob multi = TaskTestJob(TASK_MULTISTEP);
    assert(RunChat(&multi) && multi.task.state == "completed");
    assert(multi.task.steps.size() == 2 && multi.task.steps[1].status == "done");
    assert(g_task_writes == 1 && g_task_reads == 2 && multi.task.evidence[2].step == 1);

    AgentTask stale = good.task;
    stale.steps[0].status = "running";
    stale.steps[0].last_mutation = 1;
    assert(ApplyTaskCheck("{\"step\":1,\"status\":\"verified\",\"evidence\":[2],\"reason\":\"stale\"}", "", &stale, 2));
    assert(stale.steps[0].status == "verifying" && stale.steps[0].retries == 0);

    AgentTask old_verifier = good.task;
    old_verifier.state = "blocked";
    old_verifier.steps[0].status = "blocked";
    old_verifier.steps[0].failure = "verification";
    old_verifier.steps[0].reason.clear();
    size_t old_receipts = old_verifier.operations.size();
    size_t old_evidence = old_verifier.evidence.size();
    assert(PrepareInvalidVerifierContinuation(&old_verifier));
    assert(old_verifier.state == "verifying" && old_verifier.steps[0].status == "verifying");
    assert(old_verifier.operations.size() == old_receipts && old_verifier.evidence.size() == old_evidence);
    assert(!PrepareInvalidVerifierContinuation(&old_verifier));
    AgentTask external_block = good.task;
    external_block.state = "blocked";
    external_block.steps[0].status = "blocked";
    external_block.steps[0].failure = "verification";
    external_block.steps[0].reason = "Authorization required";
    external_block.last_feedback.clear();
    assert(!PrepareInvalidVerifierContinuation(&external_block));
    external_block.steps[0].reason.clear();
    external_block.steps[0].failure = "invalid_verifier";
    assert(PrepareInvalidVerifierContinuation(&external_block));
    AgentTask model_failure = good.task;
    model_failure.state = "failed";
    model_failure.steps[0].status = "failed";
    model_failure.steps[0].failure = "model_response";
    assert(PrepareInvalidVerifierContinuation(&model_failure));
    assert(model_failure.recovering && model_failure.steps[0].status == "verifying");
    assert(model_failure.evidence.size() == good.task.evidence.size());
    assert(model_failure.operations.size() == good.task.operations.size());

    ChatJob recovered = TaskTestJob(TASK_RECOVER);
    assert(!RunChat(&recovered) && recovered.task.state == "blocked" && g_task_writes == 1);
    assert(recovered.task.recovering && recovered.task.operations[0].state == "uncertain");
    assert(PrepareAuthorizedTaskRetry(&recovered.task));
    assert(RunChat(&recovered) && recovered.task.state == "completed" && g_task_writes == 2);
    assert(!recovered.task.evidence[0].success);

    ChatJob limited = TaskTestJob(TASK_RECOVER);
    limited.cfg.task_retries = 0;
    assert(!RunChat(&limited) && limited.task.state == "blocked" && g_task_writes == 1);
    int writes_before = g_task_writes;
    assert(!RunChat(&limited) && g_task_writes == writes_before);

    ChatJob unverified = TaskTestJob(TASK_NO_OBSERVATION);
    assert(!RunChat(&unverified) && unverified.task.state != "completed");
    assert(g_task_writes == 1 && g_task_reads == 0 && unverified.task.steps[0].status != "done");

    ChatJob bad = TaskTestJob(TASK_BAD_PLAN);
    assert(!RunChat(&bad) && bad.task.state == "blocked" && g_task_writes == 0);
    ChatJob fabricated = TaskTestJob(TASK_FAKE_EVIDENCE);
    assert(!RunChat(&fabricated) && fabricated.task.state != "completed" &&
        fabricated.task.steps[0].status != "done");
    ChatJob cancelled = TaskTestJob(TASK_CANCEL_CHECK);
    assert(!RunChat(&cancelled) && cancelled.task.state == "cancelled");

    ChatJob verify = TaskTestJob(TASK_OK);
    verify.task = good.task;
    verify.task.evidence.clear(); verify.task.state = "running";
    verify.task.steps[0].status = "verifying"; verify.task.steps[0].last_mutation = -1;
    verify.verification_only = true; g_task_value = 42;
    assert(RunChat(&verify) && g_task_writes == 0 && g_task_reads == 1);
    ChatJob unsafe = TaskTestJob(TASK_WRITE_DURING_VERIFY);
    unsafe.task = verify.task; unsafe.task.evidence.clear();
    unsafe.task.steps[0].status = "verifying"; unsafe.task.steps[0].last_mutation = -1;
    unsafe.verification_only = true;
    assert(!RunChat(&unsafe) && g_task_writes == 0 && unsafe.task.state != "completed");
    ChatJob read_fail = TaskTestJob(TASK_READ_FAIL);
    read_fail.task = verify.task; read_fail.task.evidence.clear();
    read_fail.task.steps[0].status = "verifying"; read_fail.task.steps[0].last_mutation = -1;
    read_fail.verification_only = true;
    assert(!RunChat(&read_fail) && read_fail.task.state != "completed" && g_task_writes == 0);

    g_agent_model_request = FakeModelRequest;
    g_agent_tools_list = RemoteToolsList; g_agent_tool_call = RemoteToolCall;
    InterlockedExchange(&g_chat_cancel, 0);
    puts("PASS: task planning, verified read-back, failed-action recovery, retry limits, invalid evidence and read-only re-verification");
}

static bool g_summary_fail, g_summary_cancel, g_summary_fenced, g_summary_invalid;
static int g_summary_count;
static bool FakeContextModel(const ServerConfig& cfg, const std::vector<std::string>& messages,
    const std::string& tools, ModelJson* response, std::string* error,
    std::string* request, std::string* reply, ChatJob* job, int round)
{
    for (size_t i = 0; i < messages.size(); ++i)
        assert(messages[i].find("_agent_summary") == std::string::npos);
    assert(AgentContextBytes(cfg, messages, tools) <= (size_t)cfg.context_budget_kb * 1024);
    if (round != -5) return FakeModelRequest(cfg, messages, tools, response, error, request, reply, job, round);
    ++g_summary_count;
    assert(tools == "[]" && lstrcmpW(cfg.tool_choice, L"none") == 0 && !cfg.stream_output);
    if (g_summary_cancel) InterlockedExchange(&g_chat_cancel, 1);
    if (g_summary_fail || g_summary_cancel) { *error = "summary failed/cancelled"; return false; }
    std::string content = "{\"observations\":\"static_disassemble @0x4563EF returned instructions\","
        "\"inferences\":\"color branch meaning is unverified\",\"pending\":\"reread branch before pseudocode\"}";
    if (g_summary_fenced) content = "```json\n" + content + "\n```";
    if (g_summary_invalid) content = "summary unavailable";
    *reply = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
    ModelJson::quote(reply, content); *reply += "}}]}";
    return ModelJson::parse(*reply, response);
}

static std::vector<std::string> LongContext()
{
    std::vector<std::string> messages;
    messages.push_back(ChatMessage("system", "debugger assistant"));
    for (int i = 0; i < 12; ++i) {
        messages.push_back(ChatMessage("user", "old request " + TaskNumber(i) + std::string(2400, 'x')));
        messages.push_back(ChatMessage("assistant", "old answer " + TaskNumber(i)));
    }
    messages.push_back(ChatMessage("user", "latest actual request"));
    messages.push_back("{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"read_memory\",\"arguments\":\"{}\"}}]}");
    std::string reply = "{\"role\":\"tool\",\"tool_call_id\":\"c1\",\"content\":";
    ModelJson::quote(&reply, "real raw result " + std::string(18000, 'y'));
    messages.push_back(reply + "}");
    return messages;
}

static void TestContextManagement()
{
    Reset(NORMAL); g_summary_fail = g_summary_cancel = g_summary_fenced = g_summary_invalid = false; g_summary_count = 0;
    g_agent_model_request = FakeContextModel;
    ChatJob job = {}; job.cfg = TestConfig(); job.cfg.context_budget_kb = 16;
    job.cfg.context_recent = 2; job.cfg.tool_result_kb = 1; job.prompt = "latest actual request";
    std::vector<std::string> messages = LongContext();
    job.history.assign(messages.begin() + 1, messages.end());
    std::string raw = job.history.back();
    assert(Request(&job, messages));
    assert(g_summary_count == 1 && ContextIsSummary(job.history[0]));
    assert(job.history[0].find("Model inferences (unverified)") != std::string::npos);
    g_summary_fenced = true;
    std::vector<std::string> fenced = LongContext();
    std::string fenced_error;
    assert(PrepareAgentContext(&job, job.cfg, &fenced, "[]", 0, &fenced_error, true));
    assert(ContextIsSummary(fenced[1]));
    std::string impossible;
    assert(ContextImpossibleMaskComparison("```c\nif ((seglen & 0xF) > 0x14) draw();\n```", &impossible));
    assert(!ContextImpossibleMaskComparison("```c\nif ((seglen & 0xF) > 0xA) draw();\n```", &impossible));
    assert(!ContextImpossibleMaskComparison("The expression (x & 0xF) > 0x14 is impossible.", &impossible));
    g_summary_fenced = false;
    assert(job.history.back() == raw);
    const std::vector<std::string>& sent = g_fake_attempts.back().messages;
    assert(sent[sent.size() - 3].find("latest actual request") != std::string::npos);
    assert(sent.back().find("context_excerpt") != std::string::npos);
    assert(sent.back().find("18016") != std::string::npos);
    std::vector<ContextBlock> blocks;
    assert(ContextBlocks(job.history, &blocks) && blocks.back().end - blocks.back().first == 2);
    std::vector<std::string> incomplete(job.history.begin(), job.history.end() - 1);
    assert(ContextBlocks(incomplete, &blocks) && !blocks.back().complete);
    incomplete.push_back(ChatMessage("user", "invalid interruption"));
    assert(!ContextBlocks(incomplete, &blocks));
    std::string saved = "{\"version\":2,\"active_skill\":\"\",\"messages\":[";
    for (size_t i = 0; i < job.history.size(); ++i) { if (i) saved += ','; saved += job.history[i]; }
    std::vector<std::string> decoded; std::string skill;
    assert(DecodeTerminalHistory(saved + "]}", &decoded, &skill) && decoded == job.history);
    for (int failure = 0; failure < 2; ++failure) {
        job.history.assign(messages.begin() + 1, messages.end());
        std::vector<std::string> original = job.history;
        g_summary_fail = failure == 0; g_summary_cancel = failure == 1;
        assert(!Request(&job, messages) && job.history == original);
        InterlockedExchange(&g_chat_cancel, 0);
    }
    g_summary_fail = g_summary_cancel = false;
    g_summary_invalid = true;
    job.history.assign(messages.begin() + 1, messages.end());
    assert(Request(&job, messages));
    assert(ContextIsSummary(job.history[0]));
    assert(job.history[0].find("Older conversation messages were omitted") != std::string::npos);
    g_summary_invalid = false;
    job.cfg.context_auto = false;
    assert(!Request(&job, messages));
    std::string error;
    assert(PrepareAgentContext(&job, job.cfg, &messages, "[]", 0, &error, true));
    assert(ContextIsSummary(messages[1]));
    messages.clear(); messages.push_back(ChatMessage("system", "debug"));
    messages.push_back(ChatMessage("user", std::string(20000, 'z')));
    assert(!PrepareAgentContext(&job, job.cfg, &messages, "[]", 0, &error, true));
    assert(!PrepareAgentContext(&job, job.cfg, &messages, "[]", -3, &error));
    Reset(NORMAL);
    puts("PASS: bounded requests, automatic/manual summaries, raw tool retention, complete tool blocks, history persistence and summary failure/cancellation");
}

static bool g_worker_fail;
static std::vector<std::wstring> g_worker_models;
static bool FakeTeamModel(const ServerConfig& cfg, const std::vector<std::string>& messages,
    const std::string& tools, ModelJson* response, std::string* error,
    std::string* request, std::string* reply, ChatJob* job, int round)
{
    if (round == -2 || round == -3) assert(lstrcmpW(cfg.model_name, L"model3") == 0);
    if (round >= 0) {
        int step = TaskCurrentStep(job->task);
        if (step < 0) assert(lstrcmpW(cfg.model_name, L"model3") == 0 && tools == "[]");
        else {
            g_worker_models.push_back(cfg.model_name);
            if (step == 1) {
                assert(messages[0].find("Verified shared results") != std::string::npos);
                assert(messages[0].find("Check actual cell value") != std::string::npos);
                assert(messages[0].find("observations") != std::string::npos);
                assert(messages[0].find("42") != std::string::npos);
                assert(!job->task.steps[0].evidence_ids.empty());
            }
            if (g_worker_fail && lstrcmpW(cfg.model_name, L"model1") == 0) {
                *error = "worker offline"; return false;
            }
        }
    }
    bool ok = FakeTaskModel(cfg, messages, tools, response, error, request, reply, job, round);
    if (round == -2) {
        std::string content = "{\"title\":\"Team task\",\"steps\":[{\"title\":\"Set cell\",\"criterion\":\"Cell reads 42\","
            "\"kind\":\"mutation\",\"model_slot\":1,\"depends_on\":[]},{\"title\":\"Recheck\","
            "\"criterion\":\"Still 42\",\"kind\":\"observation\",\"model_slot\":2,\"depends_on\":[1]}]}";
        *reply = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
        ModelJson::quote(reply, content); *reply += "}}]}";
        ok = ModelJson::parse(*reply, response);
    }
    return ok;
}

static void TestCollaboration()
{
    g_worker_fail = false; g_worker_models.clear();
    ChatJob job = TaskTestJob(TASK_MULTISTEP);
    job.cfg.collaboration = true; job.cfg.coordinator = 3;
    g_agent_model_request = FakeTeamModel;
    assert(RunChat(&job) && g_task_writes == 1 && g_task_reads == 2);
    assert(job.task.steps[0].actual_model == 1 && job.task.steps[1].actual_model == 2);
    assert(job.task.steps[1].depends_on.size() == 1 && job.task.steps[1].depends_on[0] == 0);
    assert(g_worker_models.size() == 3 && g_worker_models[0] == L"model1" && g_worker_models[2] == L"model2");
    job = TaskTestJob(TASK_MULTISTEP); job.cfg.collaboration = true; job.cfg.coordinator = 3;
    job.cfg.agent.failover = true; g_worker_fail = true; g_worker_models.clear();
    g_agent_model_request = FakeTeamModel;
    assert(RunChat(&job) && g_task_writes == 1 && g_task_reads == 2);
    assert(job.task.steps[0].assigned_model == 1 && job.task.steps[0].actual_model == 0);
    assert(g_worker_models[0] == L"model1" && g_worker_models[1] == L"primary" && g_worker_models[2] == L"primary");
    g_worker_fail = false;
    job = TaskTestJob(TASK_MULTISTEP); job.cfg.collaboration = true; job.cfg.coordinator = 3;
    job.cfg.agent.profiles[0].enabled = false; g_agent_model_request = FakeTeamModel;
    assert(!RunChat(&job) && g_task_writes == 0 && job.task.state == "blocked");
    job = TaskTestJob(TASK_OK); job.cfg.collaboration = true; job.cfg.coordinator = 3;
    job.cfg.agent.profiles[2].enabled = false;
    assert(!RunChat(&job) && g_task_writes == 0);
    job = TaskTestJob(TASK_CANCEL_CHECK); job.cfg.collaboration = true; job.cfg.coordinator = 3;
    g_agent_model_request = FakeTeamModel;
    assert(!RunChat(&job) && job.task.state == "cancelled" && g_task_writes == 1);
    AgentTask malformed;
    assert(!ParseTaskPlan("{\"title\":\"x\",\"steps\":[{\"title\":\"s\",\"criterion\":\"c\",\"kind\":\"analysis\",\"depends_on\":[1]}]}", &malformed));
    assert(!ParseTaskPlan("{\"title\":\"x\",\"steps\":[{\"title\":\"s\",\"criterion\":\"c\",\"kind\":\"analysis\",\"model_slot\":4}]}", &malformed));
    Reset(NORMAL); g_agent_tools_list = RemoteToolsList; g_agent_tool_call = RemoteToolCall;
    puts("PASS: coordinator planning/verification, worker assignment, dependencies, verified result sharing, sticky failover, disabled models and collaboration cancellation");
}

static int g_safety_calls;
static bool g_safety_transport;
static ChatJob* g_safety_job;
static AgentTask g_crash_checkpoint;
static bool SafetyTool(const ServerConfig&, const std::string&, const std::string&, std::string* result)
{
    ++g_safety_calls;
    assert(!g_audit_events.empty() && g_audit_events.back().find(":dispatching") != std::string::npos);
    if (g_safety_job && !g_safety_job->task_record_path.empty()) {
        assert(LoadTaskCheckpoint(g_safety_job->task_record_path, &g_crash_checkpoint));
        assert(!g_crash_checkpoint.operations.empty());
        assert(g_crash_checkpoint.operations.back().state == "uncertain");
    }
    *result = "{\"jsonrpc\":\"2.0\",\"id\":100,\"result\":{\"value\":42}}";
    return g_safety_transport;
}

static bool PermissionRefusedTool(const ServerConfig&, const std::string&,
    const std::string&, std::string* result)
{
    *result = McpToolErrorResult(MCP_RPC_TOOL_IS_DISABLED_BY_MCP_TOOLS_PERMISSIONS);
    return true;
}

static ModelToolBinding SafetyBinding(const char* tool)
{
    std::string tools, error;
    std::vector<ModelToolBinding> bindings;
    assert(BuildModelTools(std::string("{\"tools\":[{\"name\":\"") + tool + "\"}]}", &tools, &bindings, &error));
    return bindings[0];
}

static void TestPermissionsAndRecovery()
{
    g_confirm_allow = g_audit_allow = g_safety_transport = true;
    g_safety_calls = 0; g_safety_job = NULL; g_confirm_count = 0;
    g_agent_tool_call = SafetyTool;
    std::string tools, error, result;
    std::vector<ModelToolBinding> bindings;
    std::string large_catalog = "{\"tools\":[";
    for (int i = 0; i < 140; ++i) {
        if (i) large_catalog += ',';
        large_catalog += "{\"name\":\"optional_" + TaskNumber(i) + "\"}";
    }
    large_catalog += ",{\"name\":\"register_get\"},{\"name\":\"debug_stop\"}]}";
    assert(BuildModelTools(large_catalog, &tools, &bindings, &error) && bindings.size() == 128);
    bool has_register = false, has_stop = false;
    for (size_t i = 0; i < bindings.size(); ++i) {
        if (bindings[i].mcp_name == "register_get") has_register = bindings[i].risk == MCP_READ_ONLY;
        if (bindings[i].mcp_name == "debug_stop") has_stop = bindings[i].risk == MCP_DANGEROUS;
    }
    assert(has_register && has_stop);
    ModelToolBinding direct;
    assert(FindRemoteToolBinding(large_catalog, "optional_139", &direct, &error) && direct.mcp_name == "optional_139");
    assert(!FindRemoteToolBinding(large_catalog, "missing_tool", &direct, &error));
    assert(ModelVisibleToolResult(std::string(8193, 'A'), 8192).find("-32007") != std::string::npos);
    assert(ModelVisibleToolResult("{\"result\":1}", 8192) == "{\"result\":1}");
    assert(BuildModelTools("{\"tools\":[{\"name\":\"write_memory\",\"annotations\":{\"readOnlyHint\":true}},"
        "{\"name\":\"custom_execute\"},{\"name\":\"custom_read\",\"annotations\":{\"readOnlyHint\":true}},"
        "{\"name\":\"custom_delete\",\"annotations\":{\"readOnlyHint\":true,\"destructiveHint\":true}}]}", &tools, &bindings, &error));
    assert(bindings[0].risk == MCP_DANGEROUS && !bindings[0].read_only);
    assert(bindings[1].risk == MCP_DANGEROUS && bindings[2].risk == MCP_READ_ONLY && bindings[3].risk == MCP_DANGEROUS);
    ModelToolBinding read = SafetyBinding("read_memory"), symbol = SafetyBinding("resolve_symbol"),
        modify = SafetyBinding("set_software_breakpoint"), danger = SafetyBinding("write_memory");
    assert(read.risk == MCP_READ_ONLY && modify.risk == MCP_MODIFY && danger.risk == MCP_DANGEROUS);
    assert(symbol.risk == MCP_READ_ONLY && symbol.read_only && PriorityDebuggerTool("resolve_symbol"));
    AgentTaskOperation run_op;
    run_op.step = 0; run_op.risk = MCP_MODIFY; run_op.tool = "run";
    run_op.arguments = "{}"; run_op.state = "completed"; run_op.context_revision = "pause:1";
    assert(TaskOperationMatches(run_op, 0, "run", "{}", "pause:1"));
    assert(!TaskOperationMatches(run_op, 0, "run", "{}", "pause:2"));
    run_op.state = "uncertain";
    assert(TaskOperationMatches(run_op, 0, "run", "{}", "pause:2"));
    run_op.state = "completed"; run_op.tool = "set_software_breakpoint";
    assert(TaskOperationMatches(run_op, 0, "set_software_breakpoint", "{}", "pause:2"));
    ChatJob job = {}; job.cfg = TestConfig();
    bool sent = false;
    job.cfg.permission_mode = 0;
    assert(ExecuteAgentTool(&job, read, "{}", "{}", "100", &result, &sent) && sent && g_safety_calls == 1);
    assert(ExecuteAgentTool(&job, modify, "{}", "{}", "100", &result, &sent) && !sent && g_confirm_count == 0);
    job.cfg.permission_mode = 1;
    assert(ExecuteAgentTool(&job, modify, "{}", "{}", "100", &result, &sent) && sent && g_confirm_count == 0);
    job.cfg.permission_mode = 2;
    assert(ExecuteAgentTool(&job, modify, "{}", "{}", "100", &result, &sent) && sent && g_confirm_count == 0);
    g_confirm_allow = false;
    assert(ExecuteAgentTool(&job, danger, "{}", "{}", "100", &result, &sent) && sent && g_confirm_count == 0);
    g_confirm_allow = true; g_audit_allow = false;
    int count = g_safety_calls;
    assert(!ExecuteAgentTool(&job, danger, "{}", "{}", "100", &result, &sent) && !sent && count == g_safety_calls);
    g_audit_allow = true;
    g_agent_tool_call = PermissionRefusedTool;
    ChatJob denied = {}; denied.cfg = TestConfig();
    assert(ExecuteAgentTool(&denied, modify, "{}", "{}", "100", &result, &sent) &&
        sent && !TaskToolSucceeded(result) && !denied.chat_operation_uncertain &&
        denied.evaluation.tool_uncertain == 0);
    g_agent_tool_call = SafetyTool;
    ModelJson secrets;
    assert(ModelJson::parse("{\"api_key\":\"private_key\",\"nested\":{\"password\":\"private_password\"},\"address\":42}", &secrets));
    std::string redacted = AgentAuditRedact(secrets);
    assert(redacted.find("private_") == std::string::npos && redacted.find("42") != std::string::npos);

    wchar_t temp[MAX_PATH], path[MAX_PATH];
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"rcv", 0, path));
    job = TaskTestJob(TASK_OK); job.task_record_path = path;
    job.task.id = "recovery-test"; job.task.goal = job.prompt; job.task.server_binding = AgentServerBinding(job.cfg);
    assert(ParseTaskPlan("{\"title\":\"Recover write\",\"steps\":[{\"title\":\"Set cell\",\"criterion\":\"Reads 42\",\"kind\":\"mutation\"}]}", &job.task));
    job.history.push_back(ChatMessage("user", job.prompt));
    job.history.push_back("{\"role\":\"assistant\",\"tool_calls\":[{\"id\":\"pending_call\"}],\"content\":null}");
    g_safety_job = &job; g_agent_tool_call = SafetyTool;
    assert(ExecuteAgentTool(&job, danger, "{\"address\":1,\"value\":42}", "{}", "100", &result, &sent) && sent);
    assert(g_crash_checkpoint.operations[0].state == "uncertain" && g_crash_checkpoint.recovering);
    assert(g_crash_checkpoint.checkpoint_history.size() == 1);
    count = g_safety_calls;
    assert(ExecuteAgentTool(&job, danger, "{ \"value\" : 42, \"address\" : 1 }", "{}", "100", &result, &sent) && !sent && g_safety_calls == count);
    assert(g_audit_events.back().find("reuse_completed") != std::string::npos);
    AgentTask receipt;
    assert(LoadTaskCheckpoint(path, &receipt) && receipt.operations[0].state == "completed");
    assert(receipt.recovering && receipt.steps[0].status == "verifying");
    {
        TaskCheckpointLease first, second;
        assert(first.acquire(&job) && !second.acquire(&job));
    }
    ChatJob recovered = TaskTestJob(TASK_OK);
    recovered.task = g_crash_checkpoint; recovered.task_record_path = path;
    recovered.task.checkpoint_stamp = receipt.checkpoint_stamp;
    recovered.history = recovered.task.checkpoint_history;
    g_task_value = 42; g_safety_job = NULL;
    assert(RunChat(&recovered) && recovered.task.state == "completed" && g_task_writes == 0 && g_task_reads == 1);
    assert(!recovered.task.recovering && recovered.task.operations[0].state == "resolved");
    assert(LoadTaskCheckpoint(path, &receipt) && TaskCurrentStep(receipt) < 0);
    std::string saved = TaskJson(receipt);
    AgentTask decoded;
    assert(ParseAgentCheckpoint(saved, &decoded));
    assert(!ParseAgentCheckpoint("{\"version\":1}", &decoded));
    size_t risk = saved.find("\"risk\":2");
    assert(risk != std::string::npos); saved.replace(risk, 8, "\"risk\":9");
    assert(!ParseAgentCheckpoint(saved, &decoded));
    AgentTask sequential;
    sequential.id = "multi-recovery"; sequential.goal = "two steps"; sequential.server_binding = job.task.server_binding;
    assert(ParseTaskPlan("{\"title\":\"Two steps\",\"steps\":[{\"title\":\"Observe\",\"criterion\":\"42\",\"kind\":\"observation\"},"
        "{\"title\":\"Set bp\",\"criterion\":\"bp exists\",\"kind\":\"mutation\"}]}", &sequential));
    AgentTask operation_task = sequential;
    run_op.id = "run-1"; run_op.tool = "run"; run_op.result = "{\"result\":{\"ok\":true}}";
    operation_task.operations.push_back(run_op);
    assert(ParseAgentCheckpoint(TaskJson(operation_task), &decoded) &&
        decoded.operations[0].context_revision == "pause:1");
    AgentTaskEvidence observed;
    observed.step = 0; observed.tool = "read_memory"; observed.arguments = "{}";
    observed.result = "{\"result\":{\"value\":42}}"; observed.success = observed.read_only = true; observed.truncated = false;
    sequential.evidence.push_back(observed); sequential.steps[0].status = "done"; sequential.steps[0].evidence_ids.push_back(1);
    assert(ParseAgentCheckpoint(TaskJson(sequential), &decoded) && decoded.steps[0].status == "done");
    assert(ParseAgentCheckpoint(TaskJson(decoded), &sequential) && sequential.steps[0].evidence_ids.size() == 1);

    job = TaskTestJob(TASK_OK); job.task = g_crash_checkpoint; job.task.recovering = false;
    job.task.steps[0].status = "running"; job.task.operations.clear(); job.task.checkpoint_stamp.clear();
    job.task_record_path = std::wstring(path) + L"\\missing\\task.json";
    g_agent_tool_call = SafetyTool; g_safety_job = NULL;
    count = g_safety_calls;
    assert(!ExecuteAgentTool(&job, danger, "{}", "{}", "100", &result, &sent) && !sent && count == g_safety_calls);

    job.task_record_path.clear(); job.task.operations.clear();
    g_safety_transport = false;
    assert(ExecuteAgentTool(&job, danger, "{}", "{}", "100", &result, &sent) && sent && job.task.recovering);
    assert(job.task.operations[0].state == "uncertain");
    count = g_safety_calls;
    assert(ExecuteAgentTool(&job, danger, "{}", "{}", "100", &result, &sent) && !sent && count == g_safety_calls);
    assert(g_audit_events.back().find("deny_uncertain") != std::string::npos);
    assert(PrepareAuthorizedTaskRetry(&job.task) && !job.task.recovering);
    g_safety_transport = true;
    assert(ExecuteAgentTool(&job, danger, "{}", "{}", "100", &result, &sent) && sent);
    ChatJob stale = TaskTestJob(TASK_OK); stale.task = receipt; stale.task_record_path = path;
    stale.task.checkpoint_stamp = "stale";
    assert(!RunChat(&stale) && stale.answer.find("locked") != std::string::npos);
    stale.task.checkpoint_stamp.clear(); StringCchCopyW(stale.cfg.remote_url, 512, L"https://different.test/mcp");
    assert(!RunChat(&stale) && stale.answer.find("different") != std::string::npos);
    assert(DeleteFileW(path));
    wchar_t audit_root[MAX_PATH], previous_data[32768];
    DWORD previous_length = GetEnvironmentVariableW(L"LOCALAPPDATA", previous_data, _countof(previous_data));
    assert(GetTempFileNameW(temp, L"adt", 0, audit_root) && DeleteFileW(audit_root) && CreateDirectoryW(audit_root, NULL));
    assert(SetEnvironmentVariableW(L"LOCALAPPDATA", audit_root));
    ChatJob audited = {}; audited.cfg = TestConfig();
    assert(WriteAgentAudit(&audited, "audit-test", danger, "{\"api_key\":\"private_key\",\"address\":42}", "confirmed", "dispatching"));
    assert(WriteAgentAudit(&audited, "audit-test", danger, "{}", "confirmed", "completed"));
    std::wstring audit_directory = std::wstring(audit_root) + L"\\McpServer\\audit";
    WIN32_FIND_DATAW entry;
    HANDLE search = FindFirstFileW((audit_directory + L"\\*.jsonl").c_str(), &entry);
    assert(search != INVALID_HANDLE_VALUE); FindClose(search);
    std::wstring audit_file = audit_directory + L"\\" + entry.cFileName;
    HANDLE log = CreateFileW(audit_file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(log != INVALID_HANDLE_VALUE);
    DWORD log_size = GetFileSize(log, NULL), log_read = 0;
    std::string lines(log_size, '\0');
    assert(ReadFile(log, &lines[0], log_size, &log_read, NULL) && log_read == log_size); CloseHandle(log);
    assert(lines.find("private_key") == std::string::npos);
    size_t first_line = lines.find("\r\n"); ModelJson audit_json;
    assert(ModelJson::parse(lines.substr(0, first_line), &audit_json));
    assert(audit_json.get("risk")->value == "dangerous" && audit_json.get("outcome")->value == "dispatching");
    assert(ModelJson::parse(lines.substr(first_line + 2), &audit_json) && audit_json.get("outcome")->value == "completed");
    assert(SetEnvironmentVariableW(L"LOCALAPPDATA", previous_length ? previous_data : NULL));
    assert(DeleteFileW(audit_file.c_str()) && RemoveDirectoryW(audit_directory.c_str()) &&
        RemoveDirectoryW((std::wstring(audit_root) + L"\\McpServer").c_str()) && RemoveDirectoryW(audit_root));
    g_agent_tool_call = RemoteToolCall; g_agent_tools_list = RemoteToolsList;
    Reset(NORMAL);
    puts("PASS: risk levels, automatic tool dispatch, mandatory audit, checkpoint-before-dispatch, canonical receipt reuse, uncertain-operation blocking, fresh recovery observations, retry authorization and checkpoint locking");
}

static bool FakeMemoryEvaluationModel(const ServerConfig& cfg, const std::vector<std::string>& messages,
    const std::string& tools, ModelJson* response, std::string* error,
    std::string* request, std::string* reply, ChatJob* job, int round)
{
    if (round == -2 || round >= 0) {
        bool found = false;
        for (size_t i = 0; i < messages.size(); ++i) if (messages[i].find("LOCAL_PROJECT_KNOWLEDGE_42") != std::string::npos) found = true;
        assert(found);
    }
    if (round == -3) {
        for (size_t i = 0; i < messages.size(); ++i) assert(messages[i].find("LOCAL_PROJECT_KNOWLEDGE_42") == std::string::npos);
    }
    bool result = FakeTaskModel(cfg, messages, tools, response, error, request, reply, job, round);
    if (!result) return false;
    reply->resize(reply->size() - 1);
    *reply += ",\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":300,\"prompt_tokens_details\":{\"cached_tokens\":200},"
        "\"completion_tokens_details\":{\"reasoning_tokens\":40}}}";
    return ModelJson::parse(*reply, response);
}

static bool RemoveMemoryTestTree(const std::wstring& directory)
{
    WIN32_FIND_DATAW entry;
    HANDLE search = FindFirstFileW((directory + L"\\*").c_str(), &entry);
    bool ok = true;
    if (search != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = entry.cFileName;
            if (name == L"." || name == L"..") continue;
            std::wstring path = directory + L"\\" + name;
            if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                ok = (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT ? RemoveDirectoryW(path.c_str()) != FALSE : RemoveMemoryTestTree(path)) && ok;
            else ok = DeleteFileW(path.c_str()) != FALSE && ok;
        } while (FindNextFileW(search, &entry));
        FindClose(search);
    }
    return RemoveDirectoryW(directory.c_str()) != FALSE && ok;
}

static void TestMemoryAndEvaluation()
{
    ModelJson response;
    assert(ModelJson::parse("{\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":300,\"prompt_cache_hit_tokens\":200}}", &response));
    AgentModelMeasurement measurement; measurement.currency = "USD"; measurement.finished = measurement.valid = true;
    ReadEvaluationUsage(response, "2", "8", "0.5", &measurement);
    assert(measurement.usage_known && measurement.cost_known && fabs(measurement.estimated_cost - 0.0041) < 0.00000001);
    AgentModelMeasurement unknown;
    ReadEvaluationUsage(response, "2", "8", "", &unknown);
    assert(unknown.usage_known && !unknown.cost_known);
    assert(ModelJson::parse("{\"usage\":{\"input_tokens\":100,\"output_tokens\":20}}", &response));
    ReadEvaluationUsage(response, "0", "0", "", &unknown);
    assert(unknown.usage_known && unknown.cost_known && unknown.estimated_cost == 0);
    unknown = AgentModelMeasurement();
    assert(ModelJson::parse("{\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20,\"prompt_cache_hit_tokens\":200}}", &response));
    ReadEvaluationUsage(response, "2", "8", "0.5", &unknown);
    assert(!unknown.usage_known && !unknown.cost_known);
    double price;
    assert(!EvaluationPrice("NaN", &price) && !EvaluationPrice("-1", &price));
    ModelStream stream;
    std::string chunks = "data: {\"choices\":[{\"delta\":{\"content\":\"answer\"},\"finish_reason\":\"stop\"}]}\n\n"
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20}}\n\n"
        "data: [DONE]\n\n";
    assert(stream.feed(chunks.data(), chunks.size()) && stream.complete());
    assert(ModelJson::parse(stream.response(), &response) && response.get("usage"));
    ModelRequestOptions options; options.stream = options.stream_usage = true;
    std::vector<std::string> no_messages;
    assert(BuildModelRequest(MODEL_COMPATIBLE, "test", no_messages, "[]", options).find("include_usage") != std::string::npos);

    AgentMemoryEntry preference; preference.id = "p"; preference.project = "global"; preference.kind = "preference";
    preference.text = "Prefer concise Chinese responses"; preference.source = "user";
    AgentMemoryEntry knowledge; knowledge.id = "k"; knowledge.project = "project-a"; knowledge.kind = "knowledge";
    knowledge.text = "RIP crash access violation module"; knowledge.source = "README";
    AgentMemoryEntry historical = knowledge; historical.id = "r"; historical.kind = "result"; historical.verified = false;
    std::vector<AgentMemoryEntry> entries; entries.push_back(preference); entries.push_back(knowledge); entries.push_back(historical);
    std::vector<MemoryMatch> found = RankMemory(entries, "RIP crash", "project-a", 5);
    assert(found.size() == 2 && found[0].entry.id == "k");
    assert(RankMemory(entries, "RIP crash", "project-b", 5).size() == 1);
    knowledge.text = "\xe5\xb4\xa9\xe6\xba\x83 RIP";
    entries.clear(); entries.push_back(knowledge);
    assert(RankMemory(entries, "\xe5\xb4\xa9\xe6\xba\x83", "project-a", 5).size() == 1);
    std::string context = MemoryContext(found, 2048);
    assert(context.size() <= 2048 && context.find("not fresh evidence") != std::string::npos);

    AgentEvaluation first;
    first.id = "001"; first.project = "project-a"; first.task_id = "task-one"; first.managed = true; first.outcome = "failed";
    first.elapsed_ms = 1000; first.requests.push_back(measurement);
    AgentEvaluation later = first; later.id = "002"; later.outcome = "verified"; later.elapsed_ms = 2000;
    AgentEvaluation rated_chat; rated_chat.id = "003"; rated_chat.project = first.project; rated_chat.outcome = "unrated"; rated_chat.feedback = "failure";
    AgentEvaluation unfinished = first; unfinished.id = "004"; unfinished.task_id = "task-two"; unfinished.outcome = "running";
    unfinished.requests.clear(); unfinished.requests.push_back(AgentModelMeasurement()); unfinished.tool_dispatched = 1;
    std::vector<AgentEvaluation> samples; samples.push_back(first); samples.push_back(later); samples.push_back(rated_chat); samples.push_back(unfinished);
    EvaluationTotals totals = SummarizeEvaluations(samples);
    assert(totals.tasks == 1 && totals.task_success == 1 && totals.task_unfinished == 1 && totals.rated_chats == 1 && totals.chat_success == 0);
    assert(totals.pending_requests == 1 && totals.pending_tools == 1 && totals.missing_cost == 1);
    AgentEvaluation decoded;
    assert(ParseEvaluation(EvaluationJson(later), &decoded));
    assert(decoded.requests[0].cost_known && fabs(decoded.requests[0].estimated_cost - 0.0041) < 0.00000001);
    assert(ParseEvaluation(EvaluationJson(unfinished), &decoded) && !decoded.requests[0].usage_known);
    unfinished.requests[0].valid = true;
    assert(!ParseEvaluation(EvaluationJson(unfinished), &decoded));

    wchar_t temp[MAX_PATH], root[MAX_PATH], previous[32768];
    DWORD previous_length = GetEnvironmentVariableW(L"LOCALAPPDATA", previous, _countof(previous));
    assert(previous_length < _countof(previous));
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"mem", 0, root));
    assert(DeleteFileW(root) && CreateDirectoryW(root, NULL) && SetEnvironmentVariableW(L"LOCALAPPDATA", root));
    ServerConfig cfg = TestConfig(); StringCchCopyW(cfg.memory_project, 128, L"memory-test");
    assert(HandleMemoryCommand(L"/memory add preference Prefer concise Chinese answers", NULL, cfg));
    assert(HandleMemoryCommand(L"/memory add knowledge Set cell to 42: LOCAL_PROJECT_KNOWLEDGE_42 requires fresh read-back.", NULL, cfg));
    assert(ReadAgentMemories(cfg).size() == 2);
    std::wstring document = std::wstring(root) + L"\\README.md";
    assert(AgentWriteJson(document, "MCP_INDEX_MARKER explains RIP crash analysis."));
    assert(ImportMemoryDocument(cfg, document) == 1);
    assert(RetrieveAgentMemory(cfg, "MCP_INDEX_MARKER").find("MCP_INDEX_MARKER") != std::string::npos);
    assert(AgentWriteJson(document, "changed source document"));
    assert(RetrieveAgentMemory(cfg, "MCP_INDEX_MARKER").find("MCP_INDEX_MARKER") == std::string::npos);
    assert(ReadAgentMemories(cfg, true).size() == 3 && ReadAgentMemories(cfg).size() == 2);
    assert(ImportMemoryDocument(cfg, document) == 1);
    assert(ReadAgentMemories(cfg).size() == 3);
    ServerConfig different = cfg; StringCchCopyW(different.memory_project, 128, L"different-project");
    assert(RetrieveAgentMemory(different, "LOCAL_PROJECT_KNOWLEDGE_42").find("LOCAL_PROJECT_KNOWLEDGE_42") == std::string::npos);

    ChatJob job = TaskTestJob(TASK_OK); job.cfg = cfg;
    StringCchCopyW(job.cfg.tool_choice, 16, L"auto"); job.cfg.max_tool_rounds = 6;
    StringCchCopyW(job.cfg.input_price, 32, L"2"); StringCchCopyW(job.cfg.output_price, 32, L"8"); StringCchCopyW(job.cfg.cached_input_price, 32, L"0.5");
    job.hwnd = (HWND)1;
    g_agent_memory_retrieve = RetrieveAgentMemory; g_agent_model_request = FakeMemoryEvaluationModel;
    assert(RunChat(&job) && g_task_writes == 1 && g_task_reads == 1);
    assert(job.evaluation.managed && job.evaluation.outcome == "verified" && job.evaluation.tool_dispatched == 2 && job.evaluation.tool_success == 2);
    assert(job.evaluation.requests.size() == 6 && !job.evaluation_path.empty());
    for (size_t i = 0; i < job.evaluation.requests.size(); ++i)
        assert(job.evaluation.requests[i].finished && job.evaluation.requests[i].cost_known);
    std::vector<AgentEvaluation> saved = ReadAgentEvaluations(cfg);
    assert(saved.size() == 1 && saved[0].requests.size() == 6);
    entries = ReadAgentMemories(cfg);
    int result_memories = 0;
    for (size_t i = 0; i < entries.size(); ++i) if (entries[i].kind == "result") { ++result_memories; assert(entries[i].verified); }
    assert(result_memories == 1);
    AgentTask old_task = job.task; old_task.id = "old-result-task";
    std::wstring tasks_folder = AgentTaskFolder(cfg);
    assert(AgentWriteJson(tasks_folder + L"\\old-result-task.json", TaskJson(old_task)));
    AgentTask other_server = old_task; other_server.id = "other-server-task"; other_server.server_binding.assign(64, '0');
    assert(AgentWriteJson(tasks_folder + L"\\other-server-task.json", TaskJson(other_server)));
    assert(HandleMemoryCommand(L"/memory sync", NULL, cfg));
    assert(ReadAgentMemories(cfg).size() == entries.size() + 1);
    AgentEvaluation rejected = job.evaluation; rejected.id = "999999999999999999";
    rejected.task_id = "rejected-task"; rejected.feedback = "failure";
    assert(AgentWriteJson(AgentDataFolder(L"evaluations", rejected.project) + L"\\" + ChatWide(rejected.id) + L".json", EvaluationJson(rejected)));
    old_task.id = rejected.task_id;
    assert(AgentWriteJson(tasks_folder + L"\\rejected-task.json", TaskJson(old_task)));
    assert(HandleMemoryCommand(L"/memory sync", NULL, cfg));
    assert(ReadAgentMemories(cfg).size() == entries.size() + 1);
    assert(DeleteFileW((AgentDataFolder(L"evaluations", rejected.project) + L"\\" + ChatWide(rejected.id) + L".json").c_str()));
    assert(DeleteFileW((tasks_folder + L"\\rejected-task.json").c_str()));
    assert(HandleMemoryCommand(L"/memory sync", NULL, cfg));
    assert(ReadAgentMemories(cfg).size() == entries.size() + 1);
    assert(HandleEvaluationCommand(L"/rate failure", NULL, cfg, &job.evaluation, job.evaluation_path));
    saved = ReadAgentEvaluations(cfg);
    assert(SummarizeEvaluations(saved).task_success == 0);
    std::string remembered = RetrieveAgentMemory(cfg, "Cell is 42 verified");
    assert(remembered.find("verified task " + job.task.id) == std::string::npos);
    assert(HandleEvaluationCommand(L"/rate success", NULL, cfg, &job.evaluation, job.evaluation_path));
    assert(RetrieveAgentMemory(cfg, "Cell is 42 verified").find("verified task " + job.task.id) != std::string::npos);
    std::wstring export_path = std::wstring(root) + L"\\evaluation-export.json";
    assert(HandleEvaluationCommand(L"/eval export " + export_path, NULL, cfg, &job.evaluation, job.evaluation_path));
    std::string exported;
    assert(AgentReadJson(export_path, 16 * 1024 * 1024, &exported) && ModelJson::parse(exported, &response));
    assert(response.get("runs")->items.size() == 1);
    ChatJob no_archive = job; no_archive.task.state = "failed";
    assert(RememberAgentTask(&no_archive));
    cfg.memory_enabled = false;
    g_agent_memory_retrieve = EmptyMemoryRetrieve;
    Reset(NORMAL);
    ChatJob disabled = {}; disabled.cfg = cfg; disabled.prompt = "chat";
    assert(RunChat(&disabled) && disabled.retrieved_memory.empty());
    assert(SetEnvironmentVariableW(L"LOCALAPPDATA", previous_length ? previous : NULL));
    assert(RemoveMemoryTestTree(root));
    g_agent_tools_list = RemoteToolsList; g_agent_tool_call = RemoteToolCall;
    Reset(NORMAL);
    puts("PASS: scoped memory retrieval, Chinese matching, stale document exclusion, verified-only result recall, rating correction, phase/token/cache-cost accounting, interrupted runs, task deduplication and JSON export");
}

static std::string g_runtime_session = "session-a", g_runtime_revision = "revision-a";
static int g_runtime_pid = 123;
static int g_runtime_status = 18;
static int g_runtime_catalog = 0, g_runtime_dispatches = 0, g_runtime_waits = 0, g_runtime_context_failures = 0;
static bool g_runtime_last_stop = false;
static bool FakeRuntimeTools(const ServerConfig&, std::string* result, bool)
{
    *result = "{\"tools\":[{\"name\":\"get_debug_context\"},{\"name\":\"wait_debug_event\"},"
        "{\"name\":\"write_memory\"}";
    if (g_runtime_catalog != 1) *result += std::string(",{\"name\":\"read_memory\",\"inputSchema\":") +
        (g_runtime_catalog == 2 ? "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"integer\"}},\"required\":[\"address\"]}" : "{\"type\":\"object\"}") + "}";
    *result += "]}"; return true;
}
static bool FakeRuntimeTool(const ServerConfig&, const std::string& request, const std::string&, std::string* result)
{
    ModelJson json; assert(ModelJson::parse(request, &json));
    std::string name = json.get("params")->get("name")->value;
    if (name == "get_debug_context") {
        if (g_runtime_context_failures > 0) { --g_runtime_context_failures; return false; }
        *result = "{\"result\":{\"ok\":true,\"session\":\"" + g_runtime_session + "\",\"revision\":\"" + g_runtime_revision +
            "\",\"process_id\":" + TaskNumber(g_runtime_pid) + ",\"thread_id\":456,\"status\":" + TaskNumber(g_runtime_status) + ",\"sequence\":0,\"last_stop\":" +
            (g_runtime_last_stop ? "{\"event\":\"breakpoint\",\"exceptionAddress\":\"0x1234\"}" : "null") + "}}";
    }
    else if (name == "wait_debug_event") { ++g_runtime_waits; *result = "{\"result\":{\"ok\":true,\"cursor\":1,\"gap\":false,\"events\":[{\"event\":" +
        std::string(g_runtime_last_stop ? "{\"event\":\"breakpoint\",\"exceptionAddress\":\"0x1234\"}" : "\"breakpoint\"") + "}]}}"; }
    else {
        ++g_runtime_dispatches;
        assert(json.get("params")->get("_meta") && json.get("params")->get("_meta")->get("z0dbg/target"));
        *result = "{\"result\":{\"ok\":true}}";
    }
    return true;
}

static int g_replans_requested = 0;
static bool g_replan_bad = false, g_replan_repeat = false;
static bool FakeReplanModel(const ServerConfig& cfg, const std::vector<std::string>& messages, const std::string& tools,
    ModelJson* response, std::string* error, std::string* request, std::string* reply, ChatJob* job, int round)
{
    std::string content;
    if (round == -6) {
        ++g_replans_requested;
        content = "{\"title\":\"Alternative\",\"steps\":[{\"title\":\"Read cell using a different approach\",\"criterion\":\"" +
            std::string(g_replan_bad ? "Weaker goal" : "Cell reads 42") + "\",\"kind\":\"mutation\"}]}";
    }
    else if (round == -3 && (g_replan_repeat || (!g_task_reads && g_task_writes)))
        content = "{\"step\":1,\"status\":\"replan\",\"reason\":\"Need a different observation strategy\",\"adjustment\":\"Use read_memory\"}";
    else if (round >= 0 && g_replans_requested && !g_task_reads) {
        *request = "{}";
        *reply = "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,\"tool_calls\":[{\"id\":\"alternative\",\"type\":\"function\",\"function\":{\"name\":\"read_memory\",\"arguments\":\"{}\"}}]}}]}";
        return ModelJson::parse(*reply, response);
    }
    else return FakeTaskModel(cfg, messages, tools, response, error, request, reply, job, round);
    *request = "{}"; *reply = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
    ModelJson::quote(reply, content); *reply += "}}]}"; return ModelJson::parse(*reply, response);
}

static volatile LONG g_parallel_active = 0, g_parallel_peak = 0;
static HANDLE g_parallel_barrier = NULL;
static bool g_parallel_cancel = false;
static bool g_parallel_disagree = false;
static bool FakeParallelModel(const ServerConfig& cfg, const std::vector<std::string>&, const std::string& tools,
    ModelJson* response, std::string* error, std::string* request, std::string* reply, ChatJob* job, int round)
{
    assert(tools == "[]"); std::string content = "Analysis result";
    if (round == -7) {
        LONG active = InterlockedIncrement(&g_parallel_active);
        LONG peak = InterlockedCompareExchange(&g_parallel_peak, 0, 0);
        while (active > peak) { LONG old = InterlockedCompareExchange(&g_parallel_peak, active, peak); if (old == peak) break; peak = old; }
        if (active >= 2) SetEvent(g_parallel_barrier);
        assert(WaitForSingleObject(g_parallel_barrier, 2000) == WAIT_OBJECT_0);
        if (g_parallel_cancel && lstrcmpW(cfg.model_name, L"model1") == 0) SetEvent(job->cancel_event);
        InterlockedDecrement(&g_parallel_active);
        if (AgentJobCancelled(job)) { *error = "cancelled"; return false; }
        if (g_parallel_disagree) content = lstrcmpW(cfg.model_name, L"model1") == 0 ? "{\"claims\":{\"access\":\"read\"}}" : "{\"claims\":{\"access\":\"write\"}}";
    }
    else if (round == -3)
        content = "{\"step\":" + TaskNumber(TaskCurrentStep(job->task) + 1) + ",\"status\":\"verified\",\"evidence\":[],\"reason\":\"Candidate satisfies analysis criterion\"}";
    *request = "{}"; *reply = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
    ModelJson::quote(reply, content); *reply += "}}]}"; return ModelJson::parse(*reply, response);
}

struct ResourceTest { ChatJob job; bool acquired; };
static DWORD WINAPI ResourceTestThread(LPVOID value)
{
    ResourceTest* test = (ResourceTest*)value; AgentResourceLease lease; test->acquired = lease.acquire(&test->job); return 0;
}

static void TestAgentRuntime()
{
    Reset(NORMAL);
    ChatJob* empty = NewChatJob();
    assert(!empty->task_enabled && !empty->verification_only && !empty->cancel_event && !empty->event_cursor_known && !empty->console_output && !empty->hwnd);
    delete empty;
    DebugRuntimeFeed feed; feed.update(123, 456, 18);
    ModelJson initial; assert(ModelJson::parse(feed.context(), &initial));
    ModelJson compact_context;
    assert(ModelJson::parse(ModelDebugContext("{\"session\":\"s\",\"status\":18,\"last_stop\":{\"exceptionAddress\":\"0x1234\"},\"modules\":[{\"path\":\"C:\\\\Windows\\\\kernel32.dll\"}]}"), &compact_context));
    assert(compact_context.get("last_stop") && compact_context.get("last_stop")->get("exceptionAddress") &&
        compact_context.get("module_count") && compact_context.get("module_count")->raw == "1" && !compact_context.get("modules"));
    unsigned __int64 cursor = _strtoui64(initial.get("sequence")->raw.c_str(), NULL, 10);
    std::string identity = initial.get("session")->value;
    ModelJson events; assert(ModelJson::parse(feed.wait(cursor, 0), &events) && events.get("events")->items.empty());
    feed.push("{\"event\":\"breakpoint\"}", false, true);
    assert(ModelJson::parse(feed.wait(cursor, 0), &events) && events.get("events")->items.size() == 1);
    for (int i = 0; i < 300; ++i) feed.push("{\"event\":\"module\"}", true, false);
    assert(ModelJson::parse(feed.wait(cursor, 0), &events) && events.get("gap")->value == "true" && events.get("events")->items.size() == 256);
    feed.update(124, 456, 18);
    assert(ModelJson::parse(feed.context(), &initial) && initial.get("session")->value != identity);

    ChatJob job = TaskTestJob(TASK_OK); job.cfg.debug_guard = true;
    job.task.id = "runtime-test"; job.task.goal = job.prompt;
    assert(ParseTaskPlan("{\"title\":\"Runtime\",\"steps\":[{\"title\":\"Read\",\"criterion\":\"Current state\",\"kind\":\"observation\"}]}", &job.task));
    g_agent_tools_list = FakeRuntimeTools; g_agent_tool_call = FakeRuntimeTool;
    g_runtime_catalog = g_runtime_dispatches = g_runtime_waits = 0;
    g_runtime_session = "session-a"; g_runtime_revision = "revision-a";
    std::string remote, catalog, error;
    assert(FakeRuntimeTools(job.cfg, &remote, true) && BuildModelTools(remote, &catalog, &job.capabilities, &error));
    ChatJob bootstrap = TaskTestJob(TASK_OK);
    bootstrap.cfg.debug_guard = true; bootstrap.capabilities = job.capabilities;
    g_agent_tool_call = FakeRuntimeTool;
    g_agent_tools_list = FakeRuntimeTools;
    g_runtime_pid = 0;
    assert(RefreshDebugContext(&bootstrap));
    g_runtime_pid = 123; g_runtime_session = "new-target";
    g_runtime_context_failures = 1;
    assert(AwaitDebugEvent(&bootstrap, "debug_open_process") &&
        bootstrap.task.target_identity == "new-target:123");
    g_runtime_session = "session-a";
    assert(RefreshDebugContext(&job) && !job.task.target_identity.empty());
    g_runtime_status = 19;
    assert(RefreshDebugContext(&job, true) && job.task.target_identity == "session-a:123");
    g_runtime_status = 18;
    assert(RefreshDebugContext(&job));
    ModelToolBinding constrained; constrained.input_schema = "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"integer\",\"string\"]},\"size\":{\"type\":\"integer\",\"minimum\":1}},\"required\":[\"address\",\"size\"],\"additionalProperties\":false}";
    assert(ValidateToolArguments(constrained, "{\"address\":\"0x100000001\",\"size\":4}"));
    assert(!ValidateToolArguments(constrained, "{\"address\":true,\"size\":4}") && !ValidateToolArguments(constrained, "{\"address\":1,\"size\":0}"));
    assert(!ValidateToolArguments(constrained, "{\"address\":1,\"size\":4,\"extra\":1}"));
    ModelToolBinding read = *RuntimeTool(job, "read_memory"), write;
    write.mcp_name = write.model_name = "write_memory"; write.risk = MCP_DANGEROUS;
    std::string result; bool dispatched;
    assert(ExecuteAgentTool(&job, read, "{}", "{\"id\":1,\"params\":{}}", "1", &result, &dispatched) && dispatched && g_runtime_dispatches == 1);
    AgentTaskEvidence evidence; evidence.step = 0; evidence.tool = "read_memory"; evidence.result = result;
    evidence.success = evidence.read_only = true; evidence.truncated = false; evidence.context_revision = job.task.context_revision;
    job.task.evidence.push_back(evidence);
    g_runtime_revision = "revision-b";
    assert(ExecuteAgentTool(&job, write, "{}", "{}", "1", &result, &dispatched) && !dispatched && !job.task.evidence[0].success);
    assert(result.find("context changed") != std::string::npos);
    g_runtime_last_stop = true;
    assert(AwaitDebugEvent(&job, "run") && g_runtime_waits == 1);
    assert(job.task.evidence.back().tool == "wait_debug_event" &&
        job.task.evidence.back().result.find("0x1234") != std::string::npos);
    AgentTask compact_task = job.task;
    compact_task.evidence.back().context = "full-debugger-module-list-sentinel";
    assert(TaskJson(compact_task, true).find("full-debugger-module-list-sentinel") == std::string::npos &&
        TaskJson(compact_task).find("full-debugger-module-list-sentinel") != std::string::npos);
    g_runtime_last_stop = false;
    g_runtime_catalog = 2;
    assert(ExecuteAgentTool(&job, read, "{}", "{}", "1", &result, &dispatched) && !dispatched && result.find("inputSchema") != std::string::npos);
    g_runtime_catalog = 1;
    assert(ExecuteAgentTool(&job, read, "{}", "{}", "1", &result, &dispatched) && !dispatched && result.find("removed") != std::string::npos);
    g_runtime_catalog = 0; g_runtime_session = "session-b";
    assert(!ExecuteAgentTool(&job, write, "{}", "{}", "1", &result, &dispatched) && !dispatched && job.task.state == "blocked" && g_runtime_dispatches == 1);
    job.cfg.task_mode = false; job.task_enabled = false;
    assert(HandleRuntimeCommand(L"/debug", NULL, job.cfg) && HandleRuntimeCommand(L"/events", NULL, job.cfg));

    ResourceTest resource = {}; resource.job.cfg = TestConfig(); resource.job.cfg.remote_timeout_ms = 100;
    StringCchCopyW(resource.job.cfg.remote_url, 512, L"https://resource.test/mcp");
    {
        AgentResourceLease held; assert(held.acquire(&resource.job));
        StringCchCopyW(resource.job.cfg.remote_token, 256, L"different-credentials");
        HANDLE thread = CreateThread(NULL, 0, ResourceTestThread, &resource, 0, NULL);
        assert(thread && WaitForSingleObject(thread, 2000) == WAIT_OBJECT_0 && !resource.acquired); CloseHandle(thread);
    }
    AgentResourceLease free_resource; assert(free_resource.acquire(&resource.job));

    g_replans_requested = 0; g_replan_bad = g_replan_repeat = false;
    job = TaskTestJob(TASK_OK); g_agent_model_request = FakeReplanModel;
    assert(RunChat(&job) && job.task.replans == 1 && g_task_writes == 1 && g_task_reads == 1);
    g_replans_requested = 0; g_replan_bad = true;
    job = TaskTestJob(TASK_OK); g_agent_model_request = FakeReplanModel;
    assert(!RunChat(&job) && job.task.state == "blocked" && g_task_writes == 1 && !g_task_reads);
    g_replans_requested = 0; g_replan_bad = false; g_replan_repeat = true;
    job = TaskTestJob(TASK_OK); job.cfg.task_replans = 1; g_agent_model_request = FakeReplanModel;
    assert(!RunChat(&job) && job.task.replans == 1 && job.task.state == "blocked");
    g_replan_repeat = false;

    for (int cancel = 0; cancel < 2; ++cancel) {
        ChatJob fresh = {};
        job = fresh; job.cfg = TestConfig(); job.cfg.collaboration = true; job.cfg.parallel_workers = 2;
        job.task_enabled = true; job.task.id = "parallel-test"; job.task.goal = "Independent analysis";
        assert(ParseTaskPlan("{\"title\":\"Parallel\",\"steps\":[{\"title\":\"Analysis A\",\"criterion\":\"Explain A\",\"kind\":\"analysis\",\"model_slot\":0},"
            "{\"title\":\"Analysis B\",\"criterion\":\"Explain B\",\"kind\":\"analysis\",\"model_slot\":1}]}", &job.task));
        g_agent_model_request = FakeParallelModel; g_parallel_cancel = cancel != 0;
        g_parallel_active = g_parallel_peak = 0; g_parallel_barrier = CreateEventW(NULL, TRUE, FALSE, NULL); assert(g_parallel_barrier);
        bool ok = RunParallelAnalysis(&job);
        assert(g_parallel_peak == 2 && g_parallel_active == 0 && job.evaluation.tool_dispatched == 0);
        if (cancel) assert(!ok && job.task.state == "cancelled");
        else assert(ok && TaskCurrentStep(job.task) < 0 && job.evaluation.requests.size() == 4);
        CloseHandle(g_parallel_barrier); g_parallel_barrier = NULL;
    }
    Reset(NORMAL);
    puts("PASS: target/session guard, stale evidence invalidation, capability removal/schema changes, event cursor/gaps, resource conflicts, bounded replanning, parallel child analysis and cancellation");
}

static std::string g_semantic_id;
static std::string g_conflict_a, g_conflict_b;
static int g_semantic_pages = 0;
static bool FakePagedMemoryModel(const ServerConfig&, const std::vector<std::string>& messages,
    const std::string&, ModelJson* response, std::string*, std::string* request, std::string* reply, ChatJob*, int round)
{
    assert(round == -8); ++g_semantic_pages;
    ModelJson message; assert(ModelJson::parse(messages.back(), &message));
    std::string data = message.get("content")->value, selection;
    if (!g_conflict_a.empty()) selection = "{\"conflicts\":[{\"a\":\"" + g_conflict_a + "\",\"b\":\"" + g_conflict_b + "\"}]}";
    else selection = data.find(g_semantic_id) == std::string::npos ? "{\"ids\":[]}" : "{\"ids\":[\"" + g_semantic_id + "\"]}";
    *request = "{}"; *reply = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
    ModelJson::quote(reply, selection); *reply += "}}]}"; return ModelJson::parse(*reply, response);
}
static bool FakeOversizedTool(const ServerConfig&, const std::string&, const std::string&, std::string* result)
{
    *result = "{\"result\":{\"ok\":true,\"text\":\"" + std::string(2048, 'x') + "\"}}"; return true;
}
static bool FakeSemanticModel(const ServerConfig& cfg, const std::vector<std::string>& messages,
    const std::string& tools, ModelJson* response, std::string*, std::string* request, std::string* reply, ChatJob*, int round)
{
    assert(round == -8 && tools == "[]" && !cfg.stream_output && wcscmp(cfg.tool_choice, L"none") == 0);
    assert(messages.back().find("SECRET_OTHER_PROJECT") == std::string::npos);
    std::string selection = "{\"ids\":[\"" + g_semantic_id + "\"]}";
    *request = "{}"; *reply = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
    ModelJson::quote(reply, selection); *reply += "}}]}";
    return ModelJson::parse(*reply, response);
}

static bool FakeBenchmarkTools(const ServerConfig&, std::string* result, bool)
{
    *result = "{\"tools\":[{\"name\":\"get_debug_context\"},{\"name\":\"get_status\"},{\"name\":\"get_cpu_thread_id\"}]}";
    return true;
}
static bool FakeBenchmarkTool(const ServerConfig& cfg, const std::string& request, const std::string& id, std::string* result)
{
    ModelJson rpc; assert(ModelJson::parse(request, &rpc));
    std::string name = rpc.get("params")->get("name")->value;
    if (name == "get_debug_context") return FakeRuntimeTool(cfg, request, id, result);
    if (name == "get_status") *result = "{\"result\":{\"ok\":true,\"return\":18}}";
    else { assert(name == "get_cpu_thread_id"); *result = "{\"result\":{\"ok\":true,\"threadId\":\"0x1C8\"}}"; }
    return true;
}
static bool FakeBenchmarkModel(const ServerConfig&, const std::vector<std::string>&, const std::string&,
    ModelJson* response, std::string*, std::string* request, std::string* reply, ChatJob* job, int round)
{
    std::string text, tool;
    if (round == -2) text = "{\"title\":\"Observe\",\"steps\":[{\"title\":\"Read\",\"criterion\":\"Fresh observation\",\"kind\":\"observation\"}]}";
    else if (round == -3) text = "{\"step\":1,\"status\":\"verified\",\"evidence\":[1],\"reason\":\"Observed\"}";
    else if (job->task.evidence.empty()) tool = job->prompt.find("Use get_status") != std::string::npos ? "get_status" :
        job->prompt.find("Use get_cpu_thread_id") != std::string::npos ? "get_cpu_thread_id" : "get_debug_context";
    else text = "Observed live state.";
    *request = "{}";
    if (tool.empty()) {
        *reply = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":";
        ModelJson::quote(reply, text); *reply += "}}]}";
    }
    else *reply = "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"content\":null,\"tool_calls\":[{\"id\":\"observe\",\"type\":\"function\",\"function\":{\"name\":\"" + tool + "\",\"arguments\":\"{}\"}}]}}]}";
    return ModelJson::parse(*reply, response);
}

static void TestRetrievalBenchmarkIsolation()
{
    wchar_t temp[MAX_PATH], root[MAX_PATH], previous[32768];
    DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", previous, _countof(previous));
    assert(length < _countof(previous));
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"iso", 0, root));
    assert(DeleteFileW(root) && CreateDirectoryW(root, NULL) && SetEnvironmentVariableW(L"LOCALAPPDATA", root));
    ServerConfig cfg = TestConfig(); StringCchCopyW(cfg.memory_project, 128, L"new-agent-tests");
    AgentMemoryEntry first; first.id = AgentDigest("fact-a"); first.project = AgentProjectScope(cfg);
    first.kind = "knowledge"; first.fact_key = "build-mode"; first.text = "compile debug symbols"; first.source = "source-a";
    AgentMemoryEntry second = first; second.id = AgentDigest("fact-b"); second.text = "compile stripped binaries";
    assert(SaveMemoryEntry(first) && SaveMemoryEntry(second));
    assert(RankMemory(ReadAgentMemories(cfg), "compile", first.project, 5).empty());
    assert(HandleMemoryCommand(L"/memory resolve " + ChatWide(first.id), NULL, cfg));
    assert(RankMemory(ReadAgentMemories(cfg), "compile", first.project, 5).size() == 1);
    assert(!MemoryDateValid("2026-02-30") && MemoryDateValid("2028-02-29"));
    assert(HandleMemoryCommand(L"/memory expire " + ChatWide(first.id) + L" 2000-01-01", NULL, cfg));
    assert(RankMemory(ReadAgentMemories(cfg), "compile", first.project, 5).empty());
    assert(HandleMemoryCommand(L"/memory expire " + ChatWide(first.id) + L" clear", NULL, cfg));
    AgentMemoryEntry secret = first; secret.id = AgentDigest("secret"); secret.project = "other-project"; secret.text = "SECRET_OTHER_PROJECT";
    assert(SaveMemoryEntry(secret));
    cfg.memory_semantic = true; g_agent_model_request = FakeSemanticModel; g_semantic_id = first.id;
    ChatJob owner = {}; owner.cfg = cfg;
    assert(RetrieveAgentMemory(cfg, "how to inspect runtime failures", &owner).find(first.id) != std::string::npos);
    assert(owner.evaluation.requests.size() == 1 && owner.evaluation.requests[0].phase == "retrieval");
    g_semantic_id = secret.id;
    assert(RetrieveAgentMemory(cfg, "unrelated-query").empty());
    cfg.memory_semantic = false;
    std::vector<MemoryMatch> all, ranked;
    for (int i = 0; i < 70; ++i) {
        MemoryMatch candidate; candidate.entry = first; candidate.entry.id = AgentDigest(TaskNumber(i)); candidate.score = 0;
        all.push_back(candidate);
    }
    g_semantic_id = all.back().entry.id; g_agent_model_request = FakePagedMemoryModel; g_semantic_pages = 0;
    assert(SemanticMemoryRank(cfg, "different terminology", all, &ranked, NULL) && ranked.size() == 1 &&
        ranked[0].entry.id == all.back().entry.id && g_semantic_pages == 4);
    AgentMemoryEntry prose_a = first, prose_b = first;
    prose_a.id = AgentDigest("prose-a"); prose_a.fact_key.clear(); prose_a.text = "The module uses cdecl and the caller restores its stack.";
    prose_b.id = AgentDigest("prose-b"); prose_b.fact_key.clear(); prose_b.text = "The same module uses stdcall; the callee restores the stack.";
    assert(SaveMemoryEntry(prose_a) && SaveMemoryEntry(prose_b));
    g_conflict_a = prose_a.id; g_conflict_b = prose_b.id; cfg.memory_semantic = true;
    assert(AuditMemoryConflicts(cfg, NULL));
    std::vector<AgentMemoryEntry> prose = ReadAgentMemories(cfg); bool flagged = false;
    for (size_t i = 0; i < prose.size(); ++i) if (prose[i].id == prose_a.id) flagged = MemoryConflict(prose, i);
    assert(flagged && HandleMemoryCommand(L"/memory resolve " + ChatWide(prose_a.id), NULL, cfg));
    prose = ReadAgentMemories(cfg);
    for (size_t i = 0; i < prose.size(); ++i) if (prose[i].id == prose_a.id) assert(!MemoryConflict(prose, i));
    g_conflict_a.clear(); g_conflict_b.clear(); cfg.memory_semantic = false;
    ServerConfig other = cfg; StringCchCopyW(other.project_path, 512, root);
    assert(AgentTaskFolder(cfg) != AgentTaskFolder(other) && TerminalHistoryPath(cfg) != TerminalHistoryPath(other));
    assert(ReadAgentMemories(other).empty());
    TerminalSettingsChanges changes; std::wstring setting_error;
    assert(SetTerminalSetting(&other, 0, L"memory_semantic", L"on", &changes, &setting_error) && other.memory_semantic);
    assert(SetTerminalSetting(&other, 0, L"isolation_tools", L"get_status,read_memory", &changes, &setting_error));
    assert(SetTerminalSetting(&other, 0, L"isolation_target", L"on", &changes, &setting_error) && other.isolation_target);
    assert(SetTerminalSetting(&other, 0, L"isolation_calls", L"24", &changes, &setting_error) && other.isolation_calls == 24);
    assert(!SetTerminalSetting(&other, 0, L"isolation_calls", L"0", &changes, &setting_error));
    assert(!SetTerminalSetting(&other, 0, L"isolation_result_kb", L"10241", &changes, &setting_error));
    ChatJob gate = {}; gate.cfg = cfg; gate.cfg.isolation_calls = 1;
    ModelToolBinding read; read.mcp_name = "read_memory"; read.risk = MCP_READ_ONLY; read.read_only = true;
    assert(IsolationGate(&gate, read, "{}")); gate.isolation_dispatched = 1;
    assert(!IsolationGate(&gate, read, "{}") && gate.isolation_call_budget_exhausted);
    assert(gate.answer.find("/resume <task-id>") != std::string::npos);
    gate.task.steps.resize(2);
    gate.task.steps[0].status = "done";
    gate.task.steps[1].status = "running";
    PauseTaskForIsolationBudget(&gate);
    assert(gate.task.state == "paused" && gate.task.steps[0].status == "done" &&
        gate.task.steps[1].status == "pending" && gate.task.steps[1].failure == "budget");
    gate.isolation_dispatched = 0;
    StringCchCopyW(gate.cfg.isolation_tools, 1024, L"get_status, read_memory");
    ModelToolBinding write = read; write.mcp_name = "write_memory";
    assert(IsolationGate(&gate, read, "{}") && !IsolationGate(&gate, write, "{}"));
    gate.cfg.isolation_argument_kb = 1;
    assert(!IsolationGate(&gate, read, std::string(1025, 'x')));
    cfg.permission_mode = 0; cfg.isolation_target = true;
    StringCchCopyW(cfg.isolation_tools, 1024, L"get_debug_context,read_memory");
    assert(HandleIsolationCommand(L"/isolation save", NULL, cfg));
    gate.isolation_loaded = false; gate.cfg = cfg; gate.cfg.permission_mode = 2; gate.cfg.isolation_tools[0] = 0;
    assert(IsolationGate(&gate, read, "{}") && gate.cfg.permission_mode == 0 && !IsolationGate(&gate, write, "{}"));
    assert(gate.cfg.isolation_tools[0] != 0);
    g_agent_tools_list = FakeRuntimeTools; g_agent_tool_call = FakeRuntimeTool;
    g_runtime_session = "bound-target"; g_runtime_revision = "stable";
    std::wstring unbound_history = TerminalHistoryPath(cfg);
    assert(HandleIsolationCommand(L"/isolation bind", NULL, cfg));
    assert(TerminalHistoryPath(cfg) != unbound_history);
    std::string remote, catalog, error;
    // Aggregate initialization is required for MSVC v100 scalar members.
    ChatJob fresh = {}; gate = fresh; gate.cfg = cfg;
    assert(FakeRuntimeTools(cfg, &remote, true) && BuildModelTools(remote, &catalog, &gate.capabilities, &error));
    assert(RefreshDebugContext(&gate)); g_runtime_session = "replaced-target";
    assert(!RefreshDebugContext(&gate));
    ChatJob limited = {}; limited.cfg = TestConfig(); limited.cfg.isolation_result_kb = 1;
    g_agent_tool_call = FakeOversizedTool;
    ModelToolBinding mutation; mutation.mcp_name = "write_memory"; mutation.risk = MCP_MODIFY;
    std::string limited_result; bool sent = false;
    assert(ExecuteAgentTool(&limited, mutation, "{}", "{}", "1", &limited_result, &sent) && sent);
    assert(limited_result.find(std::string(100, 'x')) == std::string::npos && limited.evaluation.tool_uncertain == 1);
    ServerConfig bench = TestConfig(); StringCchCopyW(bench.memory_project, 128, L"benchmark-tests");
    StringCchCopyW(bench.tool_choice, 16, L"auto");
    g_agent_tools_list = FakeBenchmarkTools; g_agent_tool_call = FakeBenchmarkTool; g_agent_model_request = FakeBenchmarkModel;
    g_runtime_session = "benchmark-target"; g_runtime_revision = "stable";
    assert(HandleBenchmarkCommand(L"/bench run v1 fixture-a 2", NULL, bench, 1));
    WIN32_FIND_DATAW found; std::wstring folder = AgentDataFolder(L"benchmarks", AgentProjectScope(bench));
    HANDLE search = FindFirstFileW((folder + L"\\*.json").c_str(), &found); assert(search != INVALID_HANDLE_VALUE); FindClose(search);
    std::string report; ModelJson json;
    assert(AgentReadJson(folder + L"\\" + found.cFileName, 8 * 1024 * 1024, &report) && ModelJson::parse(report, &json));
    assert(json.get("sample")->value == "simulated" && json.get("cases")->items.size() == 6);
    for (size_t i = 0; i < json.get("cases")->items.size(); ++i) assert(json.get("cases")->items[i].get("passed")->value == "true");
    assert(HandleBenchmarkCommand(L"/bench compare " + ChatWide(json.get("id")->value) + L" " + ChatWide(json.get("id")->value), NULL, bench, 1));
    AgentTask false_success; false_success.state = "completed";
    AgentTaskEvidence bad = {}; bad.tool = "get_status"; bad.success = bad.read_only = true;
    bad.result = "{\"result\":{\"ok\":true,\"return\":17}}"; false_success.evidence.push_back(bad);
    ModelJson context; assert(ModelJson::parse("{}", &context));
    assert(!BenchmarkEvidencePass(false_success, 1, context));
    AgentBenchmarkSuite custom;
    const std::string suite_text = "{\"id\":\"checks\",\"cases\":[{\"name\":\"cell\",\"goal\":\"Read cell\",\"checks\":[{\"tool\":\"read_memory\",\"arguments\":{\"address\":4096,\"size\":4},\"expected\":{\"hex\":\"2A000000\",\"read\":4}}]}]}";
    assert(ParseBenchmarkSuite(suite_text, &custom));
    std::wstring suite_path = std::wstring(root) + L"\\custom-suite.json";
    const std::string runner_suite = "{\"id\":\"custom-status\",\"cases\":[{\"name\":\"paused\",\"goal\":\"Use get_status to verify the paused state.\",\"checks\":[{\"tool\":\"get_status\",\"arguments\":{},\"expected\":{\"return\":18}}]}]}";
    assert(AgentWriteJson(suite_path, runner_suite));
    assert(HandleBenchmarkCommand(L"/bench run custom fixture-a 2 " + suite_path, NULL, bench, 1) && g_benchmark_exit == 0);
    search = FindFirstFileW((folder + L"\\*.json").c_str(), &found); assert(search != INVALID_HANDLE_VALUE);
    bool custom_report = false;
    do {
        assert(AgentReadJson(folder + L"\\" + found.cFileName, 8 * 1024 * 1024, &report) && ModelJson::parse(report, &json));
        if (json.get("suite")->value == "custom-status") {
            assert(json.get("cases")->items.size() == 2 && !json.get("suite_fingerprint")->value.empty());
            for (size_t i = 0; i < json.get("cases")->items.size(); ++i) assert(json.get("cases")->items[i].get("passed")->value == "true");
            custom_report = true;
        }
    } while (FindNextFileW(search, &found));
    FindClose(search); assert(custom_report);
    std::wstring report_id = ChatWide(json.get("id")->value);
    assert(HandleBenchmarkCommand(L"/bench gate " + report_id + L" " + report_id, NULL, bench, 1) && g_benchmark_exit == 1);
    assert(HandleBenchmarkCommand(L"/bench gate " + report_id + L" " + report_id + L" -1 25 25", NULL, bench, 1) && g_benchmark_exit == 2);
    AgentTask matched; matched.state = "completed"; AgentTaskEvidence cell = {};
    cell.tool = "read_memory"; cell.arguments = "{\"size\":4,\"address\":4096}";
    cell.result = "{\"result\":{\"read\":4,\"ok\":true,\"hex\":\"2A000000\"}}"; cell.success = cell.read_only = true;
    matched.evidence.push_back(cell);
    assert(BenchmarkCaseEvidencePass(matched, custom.cases[0]));
    matched.evidence[0].arguments = "{\"size\":4,\"address\":8192}";
    assert(!BenchmarkCaseEvidencePass(matched, custom.cases[0]));
    assert(!ParseBenchmarkSuite("{\"id\":\"unsafe\",\"cases\":[{\"name\":\"write\",\"goal\":\"change target\",\"checks\":[{\"tool\":\"write_memory\",\"arguments\":{},\"expected\":{\"read\":4}}]}]}", &custom));
    assert(SetEnvironmentVariableW(L"LOCALAPPDATA", length ? previous : NULL));
    assert(RemoveMemoryTestTree(root));
    g_agent_tools_list = RemoteToolsList; g_agent_tool_call = RemoteToolCall; Reset(NORMAL);
    puts("PASS: semantic recall with scoped IDs, citations, conflict resolution/expiry, project isolation, intersected permissions, tool/argument/call budgets, pinned targets and repeatable benchmark evidence checks");
}

static int g_budget_calls = 0;
static bool g_budget_overrun = false;
static bool BudgetModel(const ServerConfig& cfg, const std::vector<std::string>&, const std::string&,
    ModelJson* response, std::string*, std::string* request, std::string* reply, ChatJob*, int)
{
    ++g_budget_calls; assert(cfg.max_output_tokens > 0);
    *request = "{}";
    *reply = "{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"content\":\"answer\"}}],\"usage\":{\"prompt_tokens\":" +
        std::string(g_budget_overrun ? "20000" : "40") + ",\"completion_tokens\":10}}";
    return ModelJson::parse(*reply, response);
}
struct BudgetWriter { std::string data; bool allow; };
static bool TestBudgetWriter(const std::string& data, void* context)
{
    BudgetWriter* writer = (BudgetWriter*)context;
    if (!writer->allow) return false;
    writer->data = data; return true;
}
struct BudgetWorker { AgentBudgetLedger* ledger; HANDLE start; bool reserved; };
static DWORD WINAPI BudgetReservationThread(LPVOID context)
{
    BudgetWorker* worker = (BudgetWorker*)context; WaitForSingleObject(worker->start, INFINITE);
    int output = 300; AgentBudgetReservation reservation; std::string error;
    worker->reserved = worker->ledger->reserve(200, &output, -1, -1, "USD", &reservation, &error);
    return 0;
}
static void TestAgentHardening()
{
    AgentTask contract;
    std::string contract_json = "{\"title\":\"Paused target\",\"goal\":\"Use get_status to verify the paused target.\",\"steps\":[{\"title\":\"Observe\",\"criterion\":\"Status is 18\",\"kind\":\"observation\",\"checks\":[{\"tool\":\"get_status\",\"arguments\":{},\"expected\":{\"return\":18}}]}]}";
    assert(ParseTaskContract(contract_json, &contract));
    AgentTaskEvidence evidence = {}; evidence.step = 0; evidence.success = evidence.read_only = true;
    evidence.tool = "get_status"; evidence.arguments = "{}"; evidence.result = "{\"result\":{\"return\":18,\"ok\":true}}";
    contract.evidence.push_back(evidence);
    ChatJob checked = {}; checked.cfg = TestConfig(); checked.task = contract;
    Reset(ALL_FAIL);
    assert(CheckTaskStep(&checked, "Paused") && checked.task.steps[0].status == "done" && g_fake_attempts.empty());
    contract.steps[0].status = "pending"; evidence.result = "{\"result\":{\"return\":17}}"; contract.evidence.push_back(evidence);
    assert(TaskAssertionEvidence(contract, 0, contract.steps[0].checks[0]) < 0);
    assert(ApplyTaskCheck("{\"step\":1,\"status\":\"verified\",\"evidence\":[1],\"reason\":\"old match\"}", "Paused", &contract, 2));
    assert(contract.steps[0].status != "done");
    contract.evidence.back().truncated = true; assert(TaskAssertionEvidence(contract, 0, contract.steps[0].checks[0]) < 0);
    AgentTask restored; checked.task.id = "assertions-test"; checked.task.server_binding = AgentDigest("server"); checked.task.state = "completed";
    assert(ParseAgentCheckpoint(TaskJson(checked.task), &restored) && restored.steps[0].checks.size() == 1);
    checked.task.evidence[0].result = "{\"result\":{\"return\":17}}";
    assert(!ParseAgentCheckpoint(TaskJson(checked.task), &restored));
    AgentBenchmarkSuite suite;
    std::string suite_json = "{\"id\":\"diagnosis\",\"cases\":[{\"name\":\"reason\",\"goal\":\"Derive stop reason\",\"checks\":[{\"tool\":\"get_status\",\"arguments\":{},\"expected\":{\"return\":18}}],\"expected_answer\":{\"diagnosis\":\"hidden-ground-truth\"}}]}";
    assert(ParseBenchmarkSuite(suite_json, &suite));
    assert(BenchmarkCasePrompt(suite.cases[0]).find("hidden-ground-truth") == std::string::npos);
    checked.task.evidence[0].result = "{\"result\":{\"return\":18}}";
    assert(!BenchmarkCaseEvidencePass(checked.task, suite.cases[0], "{\"diagnosis\":\"wrong\"}"));
    assert(BenchmarkCaseEvidencePass(checked.task, suite.cases[0], "{\"diagnosis\":\"hidden-ground-truth\"}"));

    AgentBudgetLedger ledger; BudgetWriter writer; writer.allow = true;
    assert(ledger.initialize(10000, 0, "USD", "", TestBudgetWriter, &writer));
    ChatJob budget = {}; budget.cfg = TestConfig(); budget.cfg.evaluation_enabled = false; budget.budget = &ledger;
    std::vector<std::string> messages; messages.push_back(ChatMessage("user", "hello"));
    std::vector<ModelToolBinding> bindings; ModelJson response; std::string error, request, reply;
    g_agent_model_request = BudgetModel; g_budget_calls = 0; g_budget_overrun = false;
    assert(TrackedAgentModelRequest(budget.cfg, messages, "[]", &response, &error, &request, &reply, &budget, 0, bindings) && g_budget_calls == 1);
    ModelJson usage; assert(ModelJson::parse(writer.data, &usage) && usage.get("tokens")->value == "50");
    AgentBudgetLedger recovered;
    assert(recovered.initialize(10000, 0, "USD", writer.data));
    g_budget_overrun = true;
    assert(!TrackedAgentModelRequest(budget.cfg, messages, "[]", &response, &error, &request, &reply, &budget, 1, bindings) && budget.budget_stopped);
    assert(!TrackedAgentModelRequest(budget.cfg, messages, "[]", &response, &error, &request, &reply, &budget, 2, bindings) && g_budget_calls == 2);
    AgentBudgetLedger fees; assert(fees.initialize(0, .01, "CNY", ""));
    int output = 4096; AgentBudgetReservation reservation;
    assert(!fees.reserve(500, &output, -1, 2, "CNY", &reservation, &error));
    assert(!fees.reserve(500, &output, 2, 2, "USD", &reservation, &error));
    assert(fees.reserve(500, &output, 2, 10, "CNY", &reservation, &error) && output < 4096);
    AgentModelMeasurement unknown; assert(fees.settle(reservation, unknown));
    assert(!fees.reserve(500, &output, 2, 10, "CNY", &reservation, &error));
    AgentBudgetLedger failed; writer.allow = false; assert(!failed.initialize(1000, 0, "USD", "", TestBudgetWriter, &writer));
    AgentBudgetLedger concurrent; assert(concurrent.initialize(500, 0, "USD", ""));
    HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL); assert(start);
    BudgetWorker workers[2] = {}; HANDLE threads[2];
    for (int i = 0; i < 2; ++i) { workers[i].ledger = &concurrent; workers[i].start = start; threads[i] = CreateThread(NULL, 0, BudgetReservationThread, &workers[i], 0, NULL); assert(threads[i]); }
    SetEvent(start); assert(WaitForMultipleObjects(2, threads, TRUE, 5000) == WAIT_OBJECT_0);
    assert((int)workers[0].reserved + (int)workers[1].reserved == 1);
    for (int i = 0; i < 2; ++i) CloseHandle(threads[i]); CloseHandle(start);

    std::vector<AgentRouteCandidate> routes(2);
    for (int i = 0; i < 2; ++i) { routes[i].slot = i; routes[i].eligible = true; routes[i].currency = "USD"; routes[i].capability.tool_calls = true; }
    routes[0].capability.quality = 95; routes[0].capability.latency_ms = 30000; routes[0].input_price = routes[0].output_price = 10;
    routes[1].capability.quality = 40; routes[1].capability.latency_ms = 500; routes[1].input_price = routes[1].output_price = .1;
    assert(AgentBestRoute(routes, 2, true, "USD") == 0);
    assert(AgentBestRoute(routes, 3, false, "USD") == 1 && AgentBestRoute(routes, 4, false, "USD") == 1);
    routes[1].eligible = false; assert(AgentBestRoute(routes, 3, false, "USD") == 0);
    routes[0].eligible = false; assert(AgentBestRoute(routes, 1, false, "USD") == -1);
    ServerConfig settings = TestConfig(); TerminalSettingsChanges changes; std::wstring setting_error;
    assert(SetTerminalSetting(&settings, 0, L"routing_mode", L"balanced", &changes, &setting_error));
    assert(SetTerminalSetting(&settings, 0, L"task_token_budget", L"25000", &changes, &setting_error));
    assert(SetTerminalSetting(&settings, 0, L"task_cost_budget", L"0.25", &changes, &setting_error));
    assert(SetTerminalSetting(&settings, 0, L"1.context_tokens", L"32000", &changes, &setting_error));
    assert(SetTerminalSetting(&settings, 0, L"1.tool_calls", L"off", &changes, &setting_error));
    assert(!SetTerminalSetting(&settings, 0, L"routing_mode", L"magic", &changes, &setting_error));
    assert(!SetTerminalSetting(&settings, 0, L"task_cost_budget", L"NaN", &changes, &setting_error));
    ChatJob gated = {}; gated.cfg = TestConfig(); gated.cfg.context_budget_tokens = 1;
    g_budget_calls = 0; g_budget_overrun = false;
    assert(!TrackedAgentModelRequest(gated.cfg, messages, "[]", &response, &error, &request, &reply, &gated, 0, bindings) && !g_budget_calls);
    gated.cfg.context_budget_tokens = 0; gated.cfg.evaluation_enabled = true;
    gated.evaluation.requests.resize(512); gated.budget = &recovered;
    std::string unchanged = recovered.snapshot();
    assert(!TrackedAgentModelRequest(gated.cfg, messages, "[]", &response, &error, &request, &reply, &gated, 0, bindings));
    assert(recovered.snapshot() == unchanged && !g_budget_calls);
    wchar_t journal_path[MAX_PATH]; GetTempPathW(_countof(journal_path), journal_path);
    std::wstring disk_journal = std::wstring(journal_path) + L"agent-budget-" + ChatWide(AgentOperationId()) + L".json";
    AgentBudgetLedger disk; assert(disk.initialize(1000, 0, "USD", "", SaveBudgetJournal, &disk_journal));
    output = 300; assert(disk.reserve(200, &output, -1, -1, "USD", &reservation, &error));
    std::string saved_budget; assert(AgentReadJson(disk_journal, 4096, &saved_budget));
    AgentBudgetLedger restart; assert(restart.initialize(1000, 0, "USD", saved_budget));
    assert(restart.snapshot() == disk.snapshot()); DeleteFileW(disk_journal.c_str());
    Reset(NORMAL);
    ChatJob adaptive = {}; adaptive.cfg = TestConfig(); adaptive.cfg.agent.auto_route = true; adaptive.cfg.agent.routing_mode = 2;
    adaptive.cfg.agent.profiles[0].capability.quality = 100;
    adaptive.prompt = "Choose the best model";
    assert(RunChat(&adaptive) && !g_fake_attempts.empty() && g_fake_attempts[0].model == L"model1");
    Reset(NORMAL); adaptive.requested_model = 3;
    assert(RunChat(&adaptive) && g_fake_attempts[0].model == L"model2");
    AgentRouteCandidate historical; historical.name = "worker"; historical.endpoint = "digest";
    AgentEvaluation run; run.id = "run1"; run.task_id = "task1"; run.outcome = "verified";
    AgentModelMeasurement measure; measure.model = "worker"; measure.endpoint = "digest";
    measure.phase = "execution"; measure.finished = measure.valid = true; measure.elapsed_ms = 100;
    run.requests.push_back(measure); std::vector<AgentEvaluation> history(2, run);
    AgentRouteHistory(history, &historical);
    assert(historical.samples == 2 && historical.task_samples == 1 && historical.task_success == 1);
    Reset(NORMAL);
    puts("PASS: deterministic verification without model approval, newest-receipt enforcement, checkpoint checks, hidden diagnosis references, shared token/cost reservation, usage settlement, currency/rate refusal and adaptive routing policies");
}

static bool g_queue_running = false;
static bool g_queue_event_payload = false;
static bool FakeQueueTools(const ServerConfig&, std::string* result, bool) {
    *result = "{\"tools\":[{\"name\":\"get_debug_context\"},{\"name\":\"get_status\"},{\"name\":\"get_cpu_thread_id\"},{\"name\":\"wait_debug_event\"}]}"; return true;
}
static bool FakeQueueTool(const ServerConfig& cfg, const std::string& request, const std::string& id, std::string* result) {
    ModelJson rpc; assert(ModelJson::parse(request, &rpc));
    if (rpc.get("params")->get("name")->value == "wait_debug_event") {
        ++g_runtime_waits;
        *result = g_queue_event_payload
            ? "{\"result\":{\"cursor\":2,\"gap\":false,\"events\":[{\"event\":\"breakpoint\"}]}}"
            : "{\"result\":{\"cursor\":1,\"gap\":false,\"events\":[]}}";
        return true;
    }
    bool ok = FakeBenchmarkTool(cfg, request, id, result);
    size_t status = result->find("\"status\":18");
    if (g_queue_running && status != std::string::npos) result->replace(status, 11, "\"status\":16"); return ok;
}
static bool g_policy_match = true;
static bool FakePolicyTool(const ServerConfig& cfg, const std::string&, const std::string&, std::string* result)
{
    *result = "{\"result\":{\"version\":1,\"enforcement\":\"mcp-dispatch-v1\",\"strict\":true,\"require_target\":true,\"scope\":";
    ModelJson::quote(result, g_policy_match ? AgentDigest(AgentProjectScope(cfg)) : "other-scope");
    *result += ",\"files\":"; ModelJson::quote(result, WideToUtf8(cfg.isolation_files));
    *result += ",\"network\":"; ModelJson::quote(result, WideToUtf8(cfg.isolation_network)); *result += "}}"; return true;
}

static void TestAgentScaleFeatures()
{
    std::vector<AgentMemoryEntry> corpus;
    for (int i = 0; i < 300; ++i) {
        AgentMemoryEntry entry; entry.id = AgentDigest(TaskNumber(i)); entry.project = "scale"; entry.kind = "knowledge";
        entry.text = "debugger unique_symbol_" + TaskNumber(i); corpus.push_back(entry);
    }
    AgentKnowledgeIndex index; index.update(corpus, AgentDigest); assert(index.changed == 300);
    AgentKnowledgeIndex loaded; assert(loaded.load(index.json())); loaded.update(corpus, AgentDigest); assert(loaded.changed == 0);
    std::vector<MemoryMatch> found = loaded.search(corpus, "unique_symbol_299", 5);
    assert(!found.empty() && found[0].entry.id == corpus[299].id);
    corpus[299].text = "replacement content"; loaded.update(corpus, AgentDigest); assert(loaded.changed == 1);
    corpus.erase(corpus.begin()); loaded.update(corpus, AgentDigest); assert(loaded.changed == 1);
    ModelJson malformed; assert(ModelJson::parse("[[65536,1]]", &malformed)); AgentSparseVector vector; assert(!ParseKnowledgeVector(malformed, &vector));

    wchar_t temp[MAX_PATH], root[MAX_PATH], previous[32768]; DWORD previous_length = GetEnvironmentVariableW(L"LOCALAPPDATA", previous, _countof(previous));
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"scf", 0, root));
    assert(DeleteFileW(root) && CreateDirectoryW(root, NULL) && SetEnvironmentVariableW(L"LOCALAPPDATA", root));
    ServerConfig cfg = TestConfig(); StringCchCopyW(cfg.memory_project, 128, L"scale-features");
    std::wstring document = std::wstring(root) + L"\\document.md";
    assert(AgentWriteJson(document, "unique_knowledge_marker debugger knowledge"));
    assert(ImportMemoryDocument(cfg, document) == 1);
    std::vector<AgentMemoryEntry> entries = ReadAgentMemories(cfg); assert(entries.size() == 1);
    std::string first_stamp = entries[0].updated;
    assert(ImportMemoryDocument(cfg, document) == 1 && ReadAgentMemories(cfg)[0].updated == first_stamp);
    assert(RetrieveAgentMemory(cfg, "unique_knowledge_marker").find("unique_knowledge_marker") != std::string::npos);
    cfg.memory_semantic = true; g_semantic_id = entries[0].id; g_semantic_pages = 0; g_conflict_a.clear();
    g_agent_model_request = FakePagedMemoryModel;
    std::string memory = RetrieveAgentMemory(cfg, "unique_knowledge_marker"); assert(g_semantic_pages == 1);
    assert(RetrieveAgentMemory(cfg, "unique_knowledge_marker") == memory && g_semantic_pages == 1);
    entries[0].text = "unique_knowledge_marker changed knowledge"; assert(SaveMemoryEntry(entries[0]));
    assert(RetrieveAgentMemory(cfg, "unique_knowledge_marker").find("changed knowledge") != std::string::npos && g_semantic_pages == 2);
    assert(AccessFileAllowed(document, root));
    assert(!AccessFileAllowed(std::wstring(root) + L"\\..\\outside.md", root));
    assert(!AccessFileAllowed(std::wstring(root) + L"-other\\file.md", root));
    assert(!AccessFileAllowed(std::wstring(root) + L"\\NUL", root));
    assert(!AccessFileAllowed(document + L":stream", root));
    assert(!AccessFileAllowed(L"\\\\server\\share\\file", root));
    assert(AccessNetworkAllowed(L"https://allowed.test/a", L"https://allowed.test"));
    assert(!AccessNetworkAllowed(L"https://allowed.test.evil/a", L"https://allowed.test"));
    assert(!AccessNetworkAllowed(L"https://allowed.test:444/a", L"https://allowed.test"));
    assert(!AccessNetworkAllowed(L"https://user:secret@allowed.test/a", L"https://allowed.test"));
    ModelJson arguments; assert(ModelJson::parse("{\"nested\":[{\"url\":\"https://evil.test\"}]}", &arguments));
    assert(!AccessArgumentsAllowed(arguments, root, L"https://allowed.test"));
    ChatJob remote = {}; remote.cfg = cfg; remote.cfg.isolation_require_remote = true;
    ModelToolBinding policy; policy.mcp_name = policy.model_name = "get_isolation_policy"; policy.read_only = true; policy.risk = MCP_READ_ONLY; policy.input_schema = "{\"type\":\"object\"}";
    remote.capabilities.push_back(policy); g_agent_tool_call = FakePolicyTool; g_policy_match = true;
    assert(VerifyRemoteIsolation(&remote)); g_policy_match = false; assert(!VerifyRemoteIsolation(&remote));
    remote.capabilities.clear(); assert(!VerifyRemoteIsolation(&remote));
    ServerConfig pinned = cfg; pinned.isolation_strict = true;
    StringCchCopyW(pinned.isolation_files, 2048, root); StringCchCopyW(pinned.isolation_network, 2048, L"https://allowed.test");
    assert(HandleIsolationCommand(L"/isolation save", NULL, pinned));
    ChatJob reduced = {}; reduced.cfg = cfg;
    ApplyAgentProjectPolicy(&reduced);
    assert(reduced.cfg.isolation_strict && AccessNetworkAllowed(L"https://allowed.test", reduced.cfg.isolation_network));
    reduced = remote; reduced.cfg = cfg; reduced.cfg.isolation_strict = true;
    StringCchCopyW(reduced.cfg.isolation_network, 2048, L"https://other.test");
    StringCchCopyW(reduced.cfg.isolation_files, 2048, root); reduced.isolation_loaded = false;
    ApplyAgentProjectPolicy(&reduced); assert(!reduced.cfg.isolation_network[0]);
    std::wstring pin_path = AgentDataFolder(L"policies", AgentProjectScope(cfg)) + L"\\" + ChatWide(AgentServerBinding(cfg)) + L".ini";
    assert(DeleteFileW(pin_path.c_str()));

    AgentTask task; task.id = "disagreement-test"; task.server_binding = AgentDigest("server"); task.goal = "Compare analyses"; task.title = "Agreement"; task.state = "blocked";
    task.steps.resize(2);
    for (int i = 0; i < 2; ++i) { task.steps[i].kind = "analysis"; task.steps[i].title = "Diagnosis"; task.steps[i].criterion = "Determine fault"; task.steps[i].agreement_group = "fault"; }
    task.steps[0].proposal = "{\"claims\":{\"access\":\"write\",\"address\":0},\"answer\":\"A\"}";
    task.steps[1].proposal = "{\"claims\":{\"address\":0,\"access\":\"read\"},\"answer\":\"B\"}";
    assert(!AnalysisAgreement(task, "fault"));
    RecordTaskTimeline(&task, AgentUtc(), "disagreement", 0, 1, "Conflicting fault diagnoses");
    AgentTask restored; assert(ParseAgentCheckpoint(TaskJson(task), &restored, false) && restored.state == "blocked" && restored.timeline.size() == 1);
    assert(restored.steps[1].proposal == task.steps[1].proposal && !ResolveAnalysisAgreement(&restored, "fault", 2));
    assert(ResolveAnalysisAgreement(&restored, "fault", 0) && TaskCurrentStep(restored) < 0 && restored.steps[1].output == task.steps[0].proposal);
    task.steps[1].proposal = "{\"claims\":{\"address\":0,\"access\":\"write\"},\"answer\":\"Different explanation\"}";
    assert(AnalysisAgreement(task, "fault"));
    ChatJob competing = {}; competing.cfg = cfg; competing.cfg.collaboration = true; competing.cfg.parallel_workers = 2;
    competing.task_enabled = true; competing.task = task; competing.task.timeline.clear(); competing.task.state = "running";
    for (int i = 0; i < 2; ++i) { competing.task.steps[i].status = "pending"; competing.task.steps[i].proposal.clear(); competing.task.steps[i].assigned_model = i; }
    g_agent_model_request = FakeParallelModel; g_parallel_disagree = true; g_parallel_cancel = false;
    g_parallel_active = g_parallel_peak = 0; g_parallel_barrier = CreateEventW(NULL, TRUE, FALSE, NULL);
    assert(!RunParallelAnalysis(&competing) && competing.task.state == "blocked" && competing.task.steps[0].failure == "disagreement");
    assert(competing.task.steps[0].output.empty() && !competing.task.steps[1].proposal.empty());
    assert(ParseAgentCheckpoint(TaskJson(competing.task), &restored) && restored.state == "blocked" && !restored.recovering);
    assert(ResolveAnalysisAgreement(&restored, "fault", 1));
    CloseHandle(g_parallel_barrier); g_parallel_barrier = NULL; g_parallel_disagree = false;
    assert(AgentFailureClass("HTTP transport failed") == "transport" && AgentFailureClass("Task token budget exhausted") == "budget");
    for (int i = 0; i < 300; ++i) RecordTaskTimeline(&task, AgentUtc(), "task", 0, 0, "bounded timeline"); assert(task.timeline.size() == 256);

    InitializeCriticalSection(&g_remote_cs); InitializeCriticalSection(&g_sse_cs);
    InitializeCriticalSection(&g_config_cs); g_config = cfg; g_config.memory_enabled = false;
    StringCchCopyW(g_config.tool_choice, 16, L"auto");
    g_agent_tools_list = FakeBenchmarkTools; g_agent_tool_call = FakeBenchmarkTool; g_agent_model_request = FakeBenchmarkModel;
    g_runtime_session = "queue-target"; g_runtime_revision = "stable"; InterlockedExchange(&g_chat_cancel, 0);
    AgentQueuedTask queued; queued.id = AgentOperationId(); queued.project = AgentProjectScope(g_config); queued.server = AgentServerBinding(g_config); queued.prompt = "Use get_status to verify paused state";
    assert(WriteQueue(g_config, &queued)); AgentQueuedTask parsed; assert(ParseQueuedTask(QueueJson(queued), &parsed));
    std::wstring base = QueueFolder(g_config) + L"\\" + ChatWide(queued.id);
    assert(AgentWriteJson(base + L".pause", "{}"));
    assert(RunAgentQueue(AgentDigest(queued.project), AgentDigest(queued.server), 1, false) == 0);
    assert(ReadQueue(g_config)[0].state == "queued");
    assert(HandleQueueCommand(L"/queue continue " + ChatWide(queued.id), NULL, g_config, 0, ""));
    assert(RunAgentQueue(AgentDigest(queued.project), AgentDigest(queued.server), 1, false) == 0);
    assert(ReadQueue(g_config)[0].state == "completed");
    AgentTask completed; assert(LoadTaskCheckpoint(AgentTaskFolder(g_config) + L"\\" + ChatWide(queued.id) + L".json", &completed) && completed.state == "completed");
    assert(!completed.evidence.empty() && !completed.evidence[0].observed.empty() &&
        completed.evidence[0].target == completed.target_identity && !completed.evidence[0].context.empty() &&
        completed.evidence[0].source_digest == AgentDigest(completed.evidence[0].result) &&
        completed.evidence[0].project_scope == AgentDigest(AgentProjectScope(g_config)));
    queued.id = AgentOperationId(); queued.state = "queued"; assert(WriteQueue(g_config, &queued));
    assert(HandleQueueCommand(L"/queue cancel " + ChatWide(queued.id), NULL, g_config, 0, ""));
    assert(RunAgentQueue(AgentDigest(queued.project), AgentDigest(queued.server), 1, false) == 0);
    std::vector<AgentQueuedTask> queue = ReadQueue(g_config); bool cancelled = false;
    for (size_t i = 0; i < queue.size(); ++i) if (queue[i].id == queued.id) cancelled = queue[i].state == "cancelled"; assert(cancelled);
    assert(RunAgentQueue("other-project", AgentDigest(queued.server), 1, false) == 2);
    ChatJob waiting = {}; waiting.cfg = g_config; waiting.task_enabled = true;
    waiting.task.id = AgentOperationId(); waiting.task.goal = "Use get_status to verify paused state"; waiting.task.server_binding = queued.server;
    assert(ParseTaskPlan("{\"title\":\"Waiting target\",\"steps\":[{\"title\":\"Read status\",\"kind\":\"observation\",\"criterion\":\"Fresh paused status\"}]}", &waiting.task));
    waiting.task.waiting_event = true; waiting.task.wait_cursor = "0"; waiting.task.target_identity = "queue-target:123";
    waiting.task_record_path = AgentTaskFolder(g_config) + L"\\" + ChatWide(waiting.task.id) + L".json";
    assert(SaveAgentTaskRecord(&waiting));
    assert(HandleQueueCommand(L"/queue resume " + ChatWide(waiting.task.id), NULL, g_config, 0, ""));
    HANDLE wake = CreateEventW(NULL, FALSE, FALSE, QueueWakeSignal(g_config).c_str()); assert(wake);
    assert(ExecuteMcpRequest("{\"jsonrpc\":\"2.0\",\"method\":\"z0dbg/event\",\"params\":{\"source\":\"Z0BDbg\",\"plugin\":\"MCP Tools\",\"event\":\"debug_event\"}}") == "{}");
    assert(WaitForSingleObject(wake, 0) == WAIT_OBJECT_0);
    assert(ExecuteMcpRequest("{\"jsonrpc\":\"2.0\",\"method\":\"z0dbg/event\",\"params\":{\"source\":\"other\",\"plugin\":\"MCP Tools\",\"event\":\"debug_event\"}}") != "{}");
    assert(WaitForSingleObject(wake, 0) == WAIT_TIMEOUT); CloseHandle(wake);
    g_agent_tools_list = FakeQueueTools; g_agent_tool_call = FakeQueueTool; g_queue_running = true; g_runtime_waits = 0;
    assert(RunAgentQueue(AgentDigest(queued.project), AgentDigest(queued.server), 1, false) == 0 && g_runtime_waits == 1);
    assert(LoadTaskCheckpoint(waiting.task_record_path, &completed) && completed.waiting_event && completed.wait_cursor == "1");
    g_runtime_session = "other-target";
    ChatJob changed = {}; changed.cfg = g_config; changed.task = completed; changed.task_record_path = waiting.task_record_path; changed.task_enabled = true;
    assert(!QueueTargetReady(&changed) && changed.answer.find("target/session changed") != std::string::npos && g_runtime_waits == 1);
    g_runtime_session = "queue-target"; g_queue_running = false; g_queue_event_payload = true;
    assert(RunAgentQueue(AgentDigest(queued.project), AgentDigest(queued.server), 1, false) == 0);
    assert(LoadTaskCheckpoint(waiting.task_record_path, &completed) && completed.state == "completed" && !completed.waiting_event);
    bool event_seen = false;
    for (size_t i = 0; i < completed.checkpoint_history.size(); ++i)
        if (completed.checkpoint_history[i].find("breakpoint") != std::string::npos) event_seen = true;
    assert(event_seen); g_queue_event_payload = false;
    DeleteCriticalSection(&g_config_cs); DeleteCriticalSection(&g_remote_cs); DeleteCriticalSection(&g_sse_cs);
    SetEnvironmentVariableW(L"LOCALAPPDATA", previous_length ? previous : NULL); Reset(NORMAL);
    puts("PASS: incremental vector index/cache invalidation, directory/origin boundaries, remote-policy refusal, durable queue pause/continue/cancel, scoped execution, disagreement persistence/resolution and bounded timeline");
}

static std::string g_undo_memory;
static int g_undo_writes;
static bool g_undo_short_read, g_undo_transport_failure;
static int g_undo_retry_read;
static bool FakeUndoTools(const ServerConfig&, std::string* result, bool) {
    *result = "{\"tools\":[{\"name\":\"get_debug_context\"},{\"name\":\"read_memory\"},"
        "{\"name\":\"write_memory\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"integer\"},"
        "\"hex\":{\"type\":\"string\"},\"expected_hex\":{\"type\":\"string\"}},\"required\":[\"address\",\"hex\"]}}]}";
    return true;
}
static bool FakeUndoTool(const ServerConfig& cfg, const std::string& request, const std::string& id, std::string* result) {
    ModelJson rpc; assert(ModelJson::parse(request, &rpc));
    const ModelJson* params = rpc.get("params"), *args = params->get("arguments");
    if (params->get("name")->value == "get_debug_context") return FakeRuntimeTool(cfg, request, id, result);
    if (params->get("name")->value == "read_memory") {
        if (g_undo_retry_read == 2) { --g_undo_retry_read; return false; }
        if (g_undo_retry_read == 1) { --g_undo_retry_read; g_runtime_revision = "new-stop"; }
        *result = "{\"result\":{\"ok\":true,\"read\":" + TaskNumber(g_undo_short_read ? 1 : (int)g_undo_memory.size() / 2) +
            ",\"hex\":\"" + g_undo_memory + "\"}}"; return true;
    }
    assert(params->get("name")->value == "write_memory");
    assert(params->get("_meta")->get("z0dbg/target"));
    const ModelJson* expected = args->get("expected_hex");
    if (expected && expected->value != g_undo_memory) { *result = "{\"error\":{\"message\":\"conditional mismatch\"}}"; return true; }
    ++g_undo_writes; g_undo_memory = args->get("hex")->value;
    *result = "{\"result\":{\"ok\":true,\"written\":2}}"; return !g_undo_transport_failure;
}

static void TestAgentRecoveryDepth()
{
    AgentServiceRegistry health; DWORD remaining;
    for (int i = 0; i < 3; ++i) { assert(health.acquire("a", i, &remaining)); health.finish("a", i, false, true); }
    assert(!health.acquire("a", 100, &remaining) && remaining > 0);
    assert(health.acquire("b", 100, &remaining)); health.finish("b", 100, true, false);
    assert(health.acquire("a", 15002, &remaining) && !health.acquire("a", 15002, &remaining));
    health.finish("a", 15002, false, false); // Cancelled probe releases its slot.
    assert(health.acquire("a", 15003, &remaining)); health.finish("a", 15003, false, true);
    assert(!health.acquire("a", 45002, &remaining) && health.acquire("a", 45003, &remaining));
    health.finish("a", 45003, true, false); assert(health.acquire("a", 45004, &remaining));
    AgentServiceRegistry rollover;
    for (int i = 0; i < 3; ++i) { assert(rollover.acquire("wrap", 0xFFFFFF00UL, &remaining)); rollover.finish("wrap", 0xFFFFFF00UL, false, true); }
    assert(!rollover.acquire("wrap", 100, &remaining) && rollover.acquire("wrap", 15000, &remaining));
    assert(AgentReadBackoff(0) == 250 && AgentReadBackoff(99) == 4000);
    std::string observation, expected, address;
    assert(AgentMemoryChange("{\"address\":4096,\"hex\":\"ab cd\"}", &observation, &expected, &address) && expected == "ABCD");
    assert(!AgentMemoryChange("{\"address\":4096,\"hex\":\"aZ\"}", &observation, &expected, &address));

    wchar_t directory[MAX_PATH], path[MAX_PATH];
    assert(GetTempPathW(MAX_PATH, directory) && GetTempFileNameW(directory, L"und", 0, path));
    g_agent_tools_list = FakeUndoTools; g_agent_tool_call = FakeUndoTool;
    g_runtime_session = "undo-target"; g_runtime_revision = "undo-stop"; g_runtime_catalog = 0;
    g_confirm_allow = g_audit_allow = true; g_undo_short_read = g_undo_transport_failure = false;
    g_undo_memory = "1122"; g_undo_writes = 0; InterlockedExchange(&g_chat_cancel, 0);
    ChatJob job = {}; job.cfg = TestConfig(); job.cfg.permission_mode = 2;
    job.cfg.debug_guard = true; job.cfg.isolation_target = true;
    job.task_enabled = true; job.task_record_path = path; job.task.id = "undo-test";
    job.task.goal = "Set memory then undo"; job.task.server_binding = AgentServerBinding(job.cfg);
    assert(ParseTaskPlan("{\"title\":\"Memory transaction\",\"steps\":[{\"title\":\"Set cell\",\"criterion\":\"Cell reads ABCD\",\"kind\":\"mutation\"}]}", &job.task));
    std::string remote, catalog, error, result;
    assert(FakeUndoTools(job.cfg, &remote, true));
    if (!BuildModelTools(remote, &catalog, &job.capabilities, &error)) { printf("Undo tools error: %s\n", error.c_str()); assert(false); }
    ModelToolBinding write = job.capabilities[2]; assert(write.mcp_name == "write_memory");
    const std::string arguments = "{\"address\":4096,\"hex\":\"ABCD\"}";
    const std::string request = "{\"id\":100,\"params\":{\"name\":\"write_memory\",\"arguments\":" + arguments + "}}";
    bool sent = false;
    ChatJob reconnected = job; reconnected.cfg.read_retries = 1;
    ModelToolBinding read = *RuntimeTool(reconnected, "read_memory");
    g_undo_retry_read = 2;
    assert(ExecuteAgentTool(&reconnected, read, "{\"address\":4096,\"size\":2}",
        "{\"id\":100,\"params\":{\"name\":\"read_memory\",\"arguments\":{\"address\":4096,\"size\":2}}}", "100", &result, &sent));
    assert(result.find("changed during reconnect") != std::string::npos && !TaskToolSucceeded(result));
    g_undo_short_read = true;
    assert(!ExecuteAgentTool(&job, write, arguments, request, "100", &result, &sent) && !sent && g_undo_writes == 0);
    g_undo_short_read = false;
    bool wrote = ExecuteAgentTool(&job, write, arguments, request, "100", &result, &sent);
    if (!wrote || !sent) printf("Snapshot write error: %s; %s\n", job.answer.c_str(), result.c_str());
    assert(wrote && sent && g_undo_writes == 1);
    assert(job.task.operations[0].rollback_state == "available" && job.task.operations[0].rollback_expected == "ABCD");
    std::string id = job.task.operations[0].id;
    AgentTask restored; assert(ParseAgentCheckpoint(TaskJson(job.task), &restored, false));
    assert(restored.operations[0].rollback_arguments.find("1122") != std::string::npos);
    g_undo_memory = "EEFF";
    assert(!UndoAgentOperation(&job, id) && g_undo_writes == 1);
    g_undo_memory = "ABCD"; g_runtime_session = "different-target";
    assert(!UndoAgentOperation(&job, id) && g_undo_writes == 1);
    g_runtime_session = "undo-target";
    g_confirm_allow = false;
    assert(UndoAgentOperation(&job, id) && g_undo_writes == 2 && g_undo_memory == "1122");
    g_confirm_allow = true;
    assert(job.task.operations[0].rollback_state == "undone" && job.task.state == "blocked");
    assert(!UndoAgentOperation(&job, id) && g_undo_writes == 2);
    assert(ParseAgentCheckpoint(TaskJson(job.task), &restored, false) && restored.operations[0].rollback_state == "undone");
    job.task.operations[0].rollback_state = "dispatching";
    assert(ParseAgentCheckpoint(TaskJson(job.task), &restored) && restored.operations[0].rollback_state == "uncertain");
    job.task.operations[0].rollback_state = "available"; job.task.operations[0].state = "completed";
    g_undo_memory = "ABCD"; g_undo_transport_failure = true;
    assert(!UndoAgentOperation(&job, id) && job.task.operations[0].rollback_state == "uncertain" && g_undo_memory == "1122");
    int writes = g_undo_writes; g_undo_transport_failure = false;
    assert(!UndoAgentOperation(&job, id) && g_undo_writes == writes);
    assert(DeleteFileW(path));

    AgentEvaluation evaluation; evaluation.elapsed_ms = 1000;
    evaluation.id = "gate-test"; evaluation.project = "gate-project"; evaluation.outcome = "verified";
    AgentModelMeasurement measurement; measurement.valid = measurement.finished = measurement.cost_known = true;
    measurement.usage_known = true;
    measurement.currency = "USD"; measurement.estimated_cost = 0.01; evaluation.requests.push_back(measurement);
    std::string report = "{\"state\":\"completed\",\"suite\":\"fixture\",\"suite_fingerprint\":\"same\",\"fixture\":\"sample\",\"sample\":\"simulated\",\"requested_cases\":1,"
        "\"cases\":[{\"repeat\":1,\"case\":1,\"passed\":true,\"evaluation\":" + EvaluationJson(evaluation) + "}]}";
    ModelJson baseline, candidate; assert(ModelJson::parse(report, &baseline));
    AgentBenchmarkMetrics a, b; assert(BenchmarkMetrics(baseline, &a)); b = a;
    assert(BenchmarkRegression(a, b, 0, 25, 25).empty());
    b.passed = 0; assert(BenchmarkRegression(a, b, 0, 25, 25).find("success rate") != std::string::npos); b = a;
    b.elapsed = 1251; assert(BenchmarkRegression(a, b, 0, 25, 25).find("elapsed") != std::string::npos); b = a;
    b.cost = 0.02; assert(BenchmarkRegression(a, b, 0, 25, 25).find("estimated cost") != std::string::npos); b = a;
    b.cost_known = false; assert(BenchmarkRegression(a, b, 0, 25, 25).find("unavailable") != std::string::npos);
    assert(BenchmarkComparable(baseline, baseline));
    size_t key = report.find("\"repeat\":1"); report.replace(key, 10, "\"repeat\":2");
    assert(ModelJson::parse(report, &candidate) && !BenchmarkComparable(baseline, candidate));
    g_agent_tools_list = RemoteToolsList; g_agent_tool_call = RemoteToolCall; Reset(NORMAL);
    puts("PASS: circuit cooldown/probe/rollover, complete snapshots, target/conflict guarded undo, durable undo receipts and success/time/cost regression gates");
}

static int g_dense_requests;
static bool FakeDenseEmbeddings(const ServerConfig&, const std::vector<std::string>& input, std::vector<AgentDenseVector>* output, ChatJob*) {
    ++g_dense_requests; output->clear();
    for (size_t i = 0; i < input.size(); ++i) { AgentDenseVector v(2, 0); v[0] = 1; output->push_back(v); }
    return true;
}
static void TestBreakpointSampling()
{
    g_sample_runs = 0; g_sample_status = 18; g_sample_sequence = 1; g_sample_wrong_stop = false;
    InterlockedExchange(&g_chat_cancel, 0);
    g_agent_tools_list = FakeSampleTools;
    g_agent_tool_call = FakeSampleTool;
    ChatJob job = {};
    job.cfg = TestConfig(); job.cfg.debug_guard = true;
    job.cfg.permission_mode = 1;
    StringCchCopyW(job.cfg.tool_choice, _countof(job.cfg.tool_choice), L"auto");
    job.task_enabled = true; job.task.id = "sample-test"; job.task.goal = "Collect three breakpoint hits";
    job.task.server_binding = AgentServerBinding(job.cfg);
    assert(ParseTaskPlan("{\"title\":\"Sample\",\"steps\":[{\"title\":\"Hits\",\"criterion\":\"Three hits\",\"kind\":\"mutation\"}]}", &job.task));
    std::string remote, catalog, error;
    assert(FakeSampleTools(job.cfg, &remote, false));
    assert(BuildModelTools(remote, &catalog, &job.capabilities, &error, 127));
    assert(AddBreakpointSamplingTool(&catalog, &job.capabilities, &error));
    wchar_t folder[MAX_PATH], record[MAX_PATH];
    assert(GetTempPathW(_countof(folder), folder) && GetTempFileNameW(folder, L"sam", 0, record));
    job.task_record_path = record;
    std::string result; bool dispatched = false;
    assert(SampleBreakpointHits(&job,
        "{\"address\":\"0x401000\",\"max_hits\":3,\"timeout_seconds\":10}",
        &result, &dispatched));
    ModelJson output;
    assert(ModelJson::parse(result, &output) && output.get("result")->get("ok")->value == "true");
    assert(output.get("result")->get("count")->raw == "3");
    assert(g_sample_runs == 3 && g_sample_status == 18 && dispatched);
    assert(job.task.operations.size() == 3);
    assert(job.task.operations[0].context_revision != job.task.operations[1].context_revision);
    assert(job.task.operations[1].context_revision != job.task.operations[2].context_revision);
    assert(DeleteFileW(record));
    g_sample_runs = 0; g_sample_status = 18; g_sample_sequence = 1; g_sample_wrong_stop = true;
    ChatJob mismatch = {};
    mismatch.cfg = job.cfg; mismatch.task_enabled = true;
    mismatch.task.id = "sample-other"; mismatch.task.goal = "Stop on another breakpoint";
    mismatch.task.server_binding = AgentServerBinding(mismatch.cfg);
    assert(ParseTaskPlan("{\"title\":\"Sample\",\"steps\":[{\"title\":\"Hits\",\"criterion\":\"Three hits\",\"kind\":\"mutation\"}]}", &mismatch.task));
    mismatch.capabilities = job.capabilities;
    assert(GetTempFileNameW(folder, L"sam", 0, record));
    mismatch.task_record_path = record;
    assert(SampleBreakpointHits(&mismatch,
        "{\"address\":\"0x401000\",\"max_hits\":3,\"timeout_seconds\":10}",
        &result, &dispatched));
    assert(ModelJson::parse(result, &output) && output.get("result")->get("reason")->value == "different_stop");
    assert(g_sample_runs == 1 && g_sample_status == 18);
    assert(DeleteFileW(record));
    g_sample_wrong_stop = false;
    puts("PASS: bounded breakpoint sampling continues each fresh stop and preserves operation receipts");
}

static void TestFairnessKnowledgeSecurityManagement() {
    AgentQueuedTask a, b; a.id = "a"; b.id = "b"; a.project = b.project = "project";
    a.server = b.server = "server"; a.prompt = b.prompt = "inspect";
    a.created = b.created = "2026-09-29T00:00:00Z";
    b.priority = 5; QueueFairLess order(QueueTime(b.created)); assert(order(b, a));
    a.created = "2026-09-28T23:40:00Z"; assert(order(a, b));
    a.slices = 10; assert(order(b, a));
    AgentQueuedTask parsed; assert(ParseQueuedTask(QueueJson(a), &parsed) && parsed.slices == 10);
    assert(!QueueTime("2026-65537-01T00:00:00Z"));

    std::wstring encrypted, clear;
    assert(AgentProtectSecret(L"private-test-key", &encrypted) && encrypted.find(L"private-test-key") == std::wstring::npos);
    assert(AgentUnprotectSecret(encrypted, &clear) && clear == L"private-test-key");
    assert(!AgentUnprotectSecret(L"dpapi:v1:XX", &clear) && clear.empty());
    assert(!AgentUnprotectSecret(L"dpapi:v2:00", &clear));
    std::vector<std::string> secrets(1, "private-test-key");
    std::string safe = AgentRedactText("private-test-key Bearer other-token token=unknown&ok=1", secrets);
    assert(safe.find("private-test-key") == std::string::npos && safe.find("other-token") == std::string::npos && safe.find("unknown") == std::string::npos);
    ChatJob guard = {}; guard.cfg = TestConfig(); guard.cfg.permission_mode = 2; guard.cfg.sensitive_guard = true;
    g_agent_tool_call = SafetyTool; g_confirm_allow = false; g_audit_allow = true;
    int calls = g_safety_calls; bool sent = false; std::string result;
    assert(ExecuteAgentTool(&guard, SafetyBinding("set_software_breakpoint"), "{}", "{}", "100", &result, &sent) && sent && g_safety_calls == calls + 1);
    g_confirm_allow = true;

    std::vector<AgentDenseVector> vectors;
    assert(ParseEmbeddingResponse("{\"data\":[{\"index\":1,\"embedding\":[0,2]},{\"index\":0,\"embedding\":[3,0]}]}", 2, &vectors));
    assert(vectors[0][0] == 1 && vectors[1][1] == 1);
    assert(!ParseEmbeddingResponse("{\"data\":[{\"index\":0,\"embedding\":[0,0]}]}", 1, &vectors));
    assert(!ParseEmbeddingResponse("{\"data\":[{\"index\":0,\"embedding\":[1]},{\"index\":0,\"embedding\":[1]}]}", 2, &vectors));

    wchar_t temp[MAX_PATH], root[MAX_PATH], previous[32768]; DWORD previous_length = GetEnvironmentVariableW(L"LOCALAPPDATA", previous, _countof(previous));
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"fkm", 0, root));
    assert(DeleteFileW(root) && CreateDirectoryW(root, NULL) && SetEnvironmentVariableW(L"LOCALAPPDATA", root));
    ServerConfig cfg = TestConfig(); StringCchCopyW(cfg.memory_project, 128, L"fair-quality");
    StringCchCopyW(cfg.embedding_url, 512, L"https://embedding.test/v1/embeddings");
    StringCchCopyW(cfg.embedding_model, 128, L"dense-test");
    AgentEmbeddingFunction original = g_agent_embeddings; g_agent_embeddings = FakeDenseEmbeddings; g_dense_requests = 0;
    std::vector<AgentMemoryEntry> entries(1); entries[0].id = AgentDigest("semantic-item"); entries[0].text = "different words";
    AgentEmbeddingIndex index;
    assert(BuildEmbeddingIndex(cfg, entries, &index, NULL, 1) && g_dense_requests == 1);
    assert(BuildEmbeddingIndex(cfg, entries, &index, NULL, 1) && g_dense_requests == 1);
    entries[0].text = "changed words";
    assert(BuildEmbeddingIndex(cfg, entries, &index, NULL, 1) && g_dense_requests == 2);
    StringCchCopyW(cfg.embedding_revision, 64, L"v2");
    assert(BuildEmbeddingIndex(cfg, entries, &index, NULL, 1) && g_dense_requests == 3);
    AgentEmbeddingIndex loaded; assert(loaded.load(index.json(), index.identity) && !loaded.load(index.json(), "other-model"));
    AgentDenseVector query(2, 0); query[0] = 1;
    assert(index.search(entries, query, 2).size() == 1);
    g_agent_embeddings = original;

    std::wstring managed = LocalMcpDataDirectory(), file = managed + L"\\quota.json", path;
    const std::string sensitive = "C:\\private\\sample.exe memory=0x12345678";
    assert(AgentWriteJson(file, sensitive));
    HANDLE raw_file = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(raw_file != INVALID_HANDLE_VALUE);
    DWORD raw_size = GetFileSize(raw_file, NULL), raw_read = 0;
    std::string raw(raw_size, '\0');
    assert(raw_size > 8 && ReadFile(raw_file, &raw[0], raw_size, &raw_read, NULL) && raw_read == raw_size);
    CloseHandle(raw_file);
    assert(raw.compare(0, 8, "Z0DPAPI1") == 0 && raw.find(sensitive) == std::string::npos);
    std::string recovered;
    assert(AgentReadJson(file, 1024, &recovered) && recovered == sensitive);
    assert(AgentUnprotectRecord(sensitive, 1024, &recovered) && recovered == sensitive);
    std::wstring history_file = managed + L"\\test-history.json";
    std::vector<std::string> history(1, "{\"role\":\"user\",\"content\":\"C:\\\\private\\\\sample.exe\"}");
    assert(SaveTerminalHistory(history_file, history, ""));
    history.clear(); std::string skill;
    assert(LoadTerminalHistory(history_file, &history, &skill) && history.size() == 1);
    DeleteFileW(history_file.c_str());
    { AgentStorageReservation quota; assert(!quota.acquire(managed, file, 2 * 1024 * 1024, 1)); }
    { AgentStorageReservation quota; assert(quota.acquire(managed, file, raw_size, 1)); }
    { AgentStorageReservation quota; assert(quota.acquire(managed, managed + L"\\stop", 1, 0)); }
    assert(!ManagementPath(cfg, file, &path, true));
    std::wstring exported = std::wstring(root) + L"\\portable.json";
    assert(ManagementPath(cfg, exported, &path, true));
    TerminalSettingsChanges changes; ServerConfig portable = cfg;
    assert(HandleManagementCommand(L"/config export " + exported, NULL, &portable, &changes));
    std::string data; assert(AgentReadJson(exported, 65536, &data) && data.find("api_key") == std::string::npos);
    portable.queue_workers = 4;
    InitializeCriticalSection(&g_config_cs);
    assert(HandleManagementCommand(L"/config import " + exported, NULL, &portable, &changes) && portable.queue_workers == cfg.queue_workers);
    DeleteCriticalSection(&g_config_cs);
    entries[0].project = AgentProjectScope(cfg); entries[0].kind = "knowledge"; entries[0].source = "first"; entries[0].confidence = 90;
    assert(SaveMemoryEntry(entries[0]));
    AgentMemoryEntry duplicate = entries[0]; duplicate.id = AgentDigest("duplicate"); duplicate.text = " CHANGED   WORDS "; duplicate.source = "second"; duplicate.confidence = 30;
    assert(SaveMemoryEntry(duplicate));
    assert(HandleMemoryCommand(L"/memory dedupe", NULL, cfg));
    std::vector<AgentMemoryEntry> deduped = ReadAgentMemories(cfg, true); int winners = 0;
    for (size_t n = 0; n < deduped.size(); ++n) if (deduped[n].superseded_by.empty()) {
        ++winners; assert(deduped[n].confidence == 30 && deduped[n].sources.size() == 2);
    }
    assert(winners == 1);
    AgentQueuedTask finished; finished.id = "cleanup-test"; finished.project = AgentProjectScope(cfg); finished.server = AgentServerBinding(cfg); finished.prompt = "done"; finished.state = "completed";
    assert(WriteQueue(cfg, &finished));
    HANDLE old_file = CreateFileW((QueueFolder(cfg) + L"\\cleanup-test.json").c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(old_file != INVALID_HANDLE_VALUE); unsigned __int64 old_time = QueueTime("2026-01-01T00:00:00Z");
    FILETIME old_stamp = { (DWORD)old_time, (DWORD)(old_time >> 32) }; assert(SetFileTime(old_file, NULL, NULL, &old_stamp)); CloseHandle(old_file);
    int eligible = 0, removed = 0;
    assert(CleanAgentRecords(cfg, 0, false, &eligible, &removed) && eligible == 1 && removed == 0);
    eligible = removed = 0; assert(CleanAgentRecords(cfg, 0, true, &eligible, &removed) && removed == 1);
    assert(AgentWriteJson(exported, "{\"version\":2,\"settings\":[{\"key\":\"queue_workers\",\"value\":\"4\"},{\"key\":\"api_key\",\"value\":\"bad\"}]}"));
    int workers = portable.queue_workers;
    assert(HandleManagementCommand(L"/config import " + exported, NULL, &portable, &changes) && portable.queue_workers == workers);
    SetEnvironmentVariableW(L"LOCALAPPDATA", previous_length ? previous : NULL);
    assert(RemoveMemoryTestTree(root)); Reset(NORMAL);
    puts("PASS: queue aging/slice fairness, DPAPI, redaction, sensitive authorization, dense validation/incremental migration, quota and atomic portable import");
}

static void TestOpenProcessAutoRunOption()
{
    ModelJson tools;
    assert(ModelJson::parse(DebuggerBootstrapToolJson(), &tools) && tools.kind == ModelJson::ARRAY);
    const ModelJson* open = NULL;
    for (size_t i = 0; i < tools.items.size(); ++i) {
        const ModelJson* name = tools.items[i].get("name");
        if (name && name->value == "debug_open_process") open = &tools.items[i];
    }
    assert(open && open->get("inputSchema"));
    const ModelJson* properties = open->get("inputSchema")->get("properties");
    assert(properties && properties->get("auto_run") &&
        properties->get("auto_run")->get("type") &&
        properties->get("auto_run")->get("type")->value == "boolean");

    ServerConfig cfg = {};
    cfg.port = 3000;
    bool auto_run = false;
    std::vector<wchar_t> paused = DebuggerLocalEnvironment(cfg, &auto_run);
    auto_run = true;
    std::vector<wchar_t> running = DebuggerLocalEnvironment(cfg, &auto_run);
    std::vector<wchar_t> idle = DebuggerLocalEnvironment(cfg, NULL);
    bool saw_paused = false, saw_running = false, saw_idle = false;
    for (size_t i = 0; i < paused.size() && paused[i]; i += wcslen(&paused[i]) + 1)
        if (wcscmp(&paused[i], L"Z0B_MCP_OPEN_AUTO_RUN=0") == 0) saw_paused = true;
    for (size_t i = 0; i < running.size() && running[i]; i += wcslen(&running[i]) + 1)
        if (wcscmp(&running[i], L"Z0B_MCP_OPEN_AUTO_RUN=1") == 0) saw_running = true;
    for (size_t i = 0; i < idle.size() && idle[i]; i += wcslen(&idle[i]) + 1)
        if (wcsncmp(&idle[i], L"Z0B_MCP_OPEN_AUTO_RUN=", 22) == 0) saw_idle = true;
    assert(saw_paused && saw_running && !saw_idle);

    const std::wstring target = L"D:\\tools\\procexp64.exe";
    assert(!LocalTargetContextMatches("{\"result\":{\"process_id\":0,\"modules\":[]}}", target));
    assert(!LocalTargetContextMatches("{\"result\":{\"process_id\":42,\"modules\":[{\"path\":\"D:\\\\tools\\\\other.exe\"}]}}", target));
    assert(LocalTargetContextMatches("{\"result\":{\"process_id\":42,\"modules\":[{\"path\":\"D:\\\\tools\\\\procexp64.exe\"}]}}", target));
}

static void TestVerificationToolVisibility()
{
    assert(!AgentToolRequiresPausedTarget("static_pe_info"));
    assert(!AgentToolRequiresPausedTarget("static_list_imports"));
    assert(!AgentToolRequiresPausedTarget("thread_list"));
    assert(!AgentToolRequiresPausedTarget("thread_get"));
    assert(!AgentToolRequiresPausedTarget("module_list"));
    assert(!AgentToolRequiresPausedTarget("module_get"));
    assert(!AgentToolRequiresPausedTarget("resolve_symbol"));
    assert(!AgentToolRequiresPausedTarget("find_import_by_name"));
    assert(!AgentToolRequiresPausedTarget("get_breakpoint_type"));
    assert(!AgentToolRequiresPausedTarget("get_breakpoint_type_count"));
    assert(!AgentToolRequiresPausedTarget("get_next_breakpoint"));
    assert(!AgentToolRequiresPausedTarget("breakpoint_list"));
    assert(!AgentToolRequiresPausedTarget("get_cpu_thread_id"));
    assert(!AgentToolRequiresPausedTarget("read_memory"));
    assert(AgentToolRequiresPausedTarget("register_list"));
    assert(AgentToolRequiresPausedTarget("stack_read"));
    assert(AgentToolRequiresPausedTarget("evaluate"));
    assert(AgentToolRequiresPausedTarget("set_software_breakpoint"));
    ChatJob job = {};
    job.task_enabled = true;
    job.task.steps.push_back(AgentTaskStep());
    job.task.steps[0].kind = "mutation";
    job.task.steps[0].status = "verifying";
    assert(!TaskReadOnlyVerification(job));

    AgentTaskOperation attempted;
    attempted.step = 0;
    attempted.state = "completed";
    job.task.operations.push_back(attempted);
    assert(TaskReadOnlyVerification(job));
    job.task.operations.clear();
    job.task.recovering = true;
    assert(TaskReadOnlyVerification(job));
    job.task.recovering = false;
    job.task.steps[0].kind = "observation";
    assert(TaskReadOnlyVerification(job));

    std::vector<ModelToolBinding> tools(2), allowed;
    tools[0].model_name = tools[0].mcp_name = "get_debug_context";
    tools[0].risk = MCP_READ_ONLY;
    tools[1].model_name = tools[1].mcp_name = "debugger_start";
    tools[1].risk = MCP_DANGEROUS;
    std::string filtered;
    assert(ReadOnlyModelCatalog("[{\"type\":\"function\",\"function\":{\"name\":\"get_debug_context\"}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"debugger_start\"}}]",
        tools, &filtered, &allowed));
    assert(allowed.size() == 1 && allowed[0].mcp_name == "get_debug_context");
    assert(filtered.find("debugger_start") == std::string::npos);
}

int main(int argc, char** argv)
{
    TestOpenProcessAutoRunOption();
    TestVerificationToolVisibility();
    setvbuf(stdout, NULL, _IONBF, 0);
    _set_error_mode(_OUT_TO_STDERR); _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 2 && strcmp(argv[1], "--continuation") == 0) {
        g_agent_confirm = FakeConfirmation;
        g_agent_audit = FakeAudit;
        g_agent_memory_retrieve = EmptyMemoryRetrieve;
        TestChatContinuation();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--python") == 0) {
        g_agent_confirm = FakeConfirmation;
        g_agent_audit = FakeAudit;
        g_agent_memory_retrieve = EmptyMemoryRetrieve;
        TestDebugPythonDispatch();
        TestExecutableToolDirectory();
        puts("PASS: Python debugger catalog, dispatch, mutation and permissions");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--probe-mcp") == 0) {
        InitializeCriticalSection(&g_config_cs); InitializeCriticalSection(&g_remote_cs);
        ServerConfig cfg; SetDefaultConfig(&cfg);
        std::wstring url = ChatWide(argv[2]);
        StringCchCopyW(cfg.remote_url, _countof(cfg.remote_url), url.c_str());
        std::string raw, tools;
        DWORD status = 0;
        bool http = RemoteHttpRequest(cfg, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}", &raw, &status);
        bool listed = http && ExtractJsonObjectMember(raw, "result", tools);
        printf("http=%d status=%lu bytes=%zu listed=%d\n", http ? 1 : 0, status, raw.size(), listed ? 1 : 0);
        CloseAgentHttpSession(); DeleteCriticalSection(&g_remote_cs); DeleteCriticalSection(&g_config_cs);
        return listed ? 0 : 1;
    }
    if (argc == 2) {
        std::string data; AgentBenchmarkSuite suite;
        assert(AgentReadJson(ChatWide(argv[1]), 64 * 1024, &data) && ParseBenchmarkSuite(data, &suite));
        assert(suite.cases.size() == 5 && suite.cases[2].checks.size() == 2 && !suite.cases[3].expected_answer.empty());
        puts("PASS: generated debugger fixture suite is accepted by the benchmark parser");
        return 0;
    }
    g_agent_confirm = FakeConfirmation;
    g_agent_audit = FakeAudit;
    g_agent_memory_retrieve = EmptyMemoryRetrieve;
    TestContextManagement();
    TestCollaboration();
    TestPermissionsAndRecovery();
    TestBreakpointSampling();
    TestChainedToolResults();
    TestChatContinuation();
    TestDebugPythonDispatch();
    TestMemoryAndEvaluation();
    TestAgentRuntime();
    TestRetrievalBenchmarkIsolation();
    TestAgentTasks();
    TestTerminalSettings();
    TestExtendedTerminalSettings();
    TestAgentHardening();
    TestAgentScaleFeatures();
    TestAgentRecoveryDepth();
    TestFairnessKnowledgeSecurityManagement();
    ServerConfig cfg = TestConfig();
    cfg.agent.auto_route = true;
    StringCchCopyW(cfg.agent.profiles[0].keywords, 512, L"asm; ANALYZE");
    StringCchCopyW(cfg.agent.profiles[1].keywords, 512, L"analyze crash, crash");
    assert(AgentRouteModel(cfg.agent, L"ANALYZE crash") == 2);
    assert(AgentRouteModel(cfg.agent, L"asm") == 1);
    assert(AgentRouteModel(cfg.agent, L"hello") == 0);
    cfg.agent.profiles[1].enabled = false;
    assert(AgentRouteModel(cfg.agent, L"analyze crash") == 1);
    cfg.agent.auto_route = false;
    assert(AgentRouteModel(cfg.agent, L"asm") == 0);

    ServerConfig adapted_cfg = TestConfig();
    std::vector<std::string> vendor_messages;
    vendor_messages.push_back("{\"role\":\"assistant\",\"content\":null,\"reasoning_content\":\"reason\","
        "\"tool_calls\":[{\"id\":\"done\",\"type\":\"function\",\"function\":{\"name\":\"get_status\",\"arguments\":\"{}\"}}]}");
    StringCchCopyW(adapted_cfg.model_url, 512, L"https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions");
    std::vector<std::string> adapted_messages = AgentMessagesForModel(adapted_cfg, vendor_messages);
    ModelJson adapted_json;
    assert(ModelJson::parse(adapted_messages[0], &adapted_json));
    assert(!adapted_json.get("reasoning_content"));
    assert(adapted_json.get("content")->kind == ModelJson::STRING);
    StringCchCopyW(adapted_cfg.model_url, 512, L"https://api.deepseek.com/chat/completions");
    StringCchCopyW(adapted_cfg.model_name, 128, L"deepseek-reasoner");
    adapted_messages = AgentMessagesForModel(adapted_cfg, adapted_messages);
    assert(ModelJson::parse(adapted_messages[0], &adapted_json));
    assert(adapted_json.get("reasoning_content") && adapted_json.get("reasoning_content")->value.empty());

    std::vector<std::string> messages;
    messages.push_back(ChatMessage("system", "debugger"));
    messages.push_back(ChatMessage("user", "analyze"));
    messages.push_back("{\"role\":\"assistant\",\"tool_calls\":[{\"id\":\"done\","
        "\"type\":\"function\",\"function\":{\"name\":\"get_status\",\"arguments\":\"{}\"}}]}");
    messages.push_back("{\"role\":\"tool\",\"tool_call_id\":\"done\",\"content\":\"already executed\"}");

    ChatJob job = {};
    job.cfg = TestConfig();
    job.cfg.agent.failover = true;
    Reset(PRIMARY_FAILS);
    assert(Request(&job, messages));
    assert(job.active_model == 1 && g_fake_attempts.size() == 2);
    assert(g_fake_attempts[0].messages == messages && g_fake_attempts[1].messages == messages);
    assert(Request(&job, messages, 1));
    assert(g_fake_attempts.size() == 3 && g_fake_attempts.back().model == L"model1");

    Reset(ALL_FAIL);
    job.active_model = 0;
    assert(!Request(&job, messages) && g_fake_attempts.size() == 4);
    assert(job.answer.find("HTTP 503") != std::string::npos);

    Reset(PRIMARY_FAILS);
    job.cfg.agent.failover = false;
    assert(!Request(&job, messages) && g_fake_attempts.size() == 1);

    Reset(BAD_PRIMARY);
    job.cfg.agent.failover = true;
    assert(Request(&job, messages) && job.active_model == 1);

    Reset(UNKNOWN_TOOL);
    job.active_model = 0;
    assert(Request(&job, messages) && job.active_model == 1);

    Reset(PRIMARY_FAILS);
    job.active_model = 0;
    job.cfg.agent.profiles[0].enabled = false;
    assert(Request(&job, messages) && job.active_model == 2);
    assert(g_fake_attempts.size() == 2);

    Reset(ALL_FAIL);
    job.cfg = TestConfig();
    job.cfg.agent.failover = true;
    job.active_model = 0;
    StringCchCopyW(job.cfg.agent.profiles[0].url, 512, job.cfg.model_url);
    StringCchCopyW(job.cfg.agent.profiles[0].name, 128, job.cfg.model_name);
    assert(!Request(&job, messages) && g_fake_attempts.size() == 3);

    Reset(PRIMARY_FAILS);
    StringCchCopyW(job.cfg.agent.profiles[0].key, 256, L"alternate-account");
    assert(Request(&job, messages) && g_fake_attempts.size() == 3 && job.active_model == 2);

    Reset(NORMAL);
    job.cfg = TestConfig();
    job.cfg.agent.failover = true;
    StringCchCopyW(job.cfg.tool_choice, 16, L"auto");
    StringCchCopyW(job.cfg.model_name, 128, L"embedding-main");
    job.active_model = 0;
    assert(Request(&job, messages) && g_fake_attempts.size() == 1 && job.active_model == 1);

    Reset(CANCEL_REQUEST);
    job.cfg = TestConfig();
    job.cfg.agent.failover = true;
    assert(!Request(&job, messages) && g_fake_attempts.size() == 1);

    Reset(NORMAL);
    ChatJob reviewed = {};
    reviewed.cfg = TestConfig();
    reviewed.cfg.agent.review = true;
    reviewed.cfg.agent.profiles[0].reviewer = true;
    reviewed.prompt = "analyze";
    assert(RunChat(&reviewed));
    assert(g_fake_attempts.size() == 2);
    assert(g_fake_attempts[1].tools == "[]" && g_fake_attempts[1].choice == L"none");
    assert(reviewed.answer.find("primary answer") != std::string::npos);
    assert(reviewed.answer.find("review conclusion") != std::string::npos);
    assert(reviewed.history.back().find("review conclusion") != std::string::npos);
    assert(reviewed.calls.empty());

    Reset(REVIEW_CALLS_TOOL);
    ChatJob blocked = {};
    blocked.cfg = reviewed.cfg;
    blocked.prompt = "analyze";
    assert(RunChat(&blocked));
    assert(blocked.answer == "primary answer" && blocked.calls.empty());
    assert(blocked.model_events.back().find("Review unavailable") == 0);

    Reset(REVIEW_FAILS);
    ChatJob failed_review = {};
    failed_review.cfg = reviewed.cfg;
    failed_review.prompt = "analyze";
    assert(RunChat(&failed_review) && failed_review.answer == "primary answer");

    Reset(CANCEL_REVIEW);
    ChatJob cancelled_review = {};
    cancelled_review.cfg = reviewed.cfg;
    cancelled_review.prompt = "analyze";
    assert(!RunChat(&cancelled_review) && cancelled_review.history_consistent);
    assert(cancelled_review.history.back().find("primary answer") != std::string::npos);

    Reset(NORMAL);
    ChatJob manual = {};
    manual.cfg = TestConfig();
    manual.requested_model = 3;
    manual.prompt = "analyze";
    assert(RunChat(&manual) && g_fake_attempts[0].model == L"model2");

    Reset(NORMAL);
    ChatJob routed = {};
    routed.cfg = cfg;
    routed.cfg.agent.auto_route = true;
    routed.prompt = "asm";
    assert(RunChat(&routed) && g_fake_attempts[0].model == L"model1");
    Reset(NORMAL);
    routed.cfg.agent.review = true;
    routed.cfg.agent.profiles[0].reviewer = true;
    routed.history.clear();
    assert(RunChat(&routed) && g_fake_attempts.size() == 1);
    assert(routed.model_events.back().find("Review skipped") == 0);

    InitializeCriticalSection(&g_config_cs);
    ServerConfig saved = TestConfig();
    saved.agent.routing_mode = 3; saved.context_budget_tokens = 32000; saved.task_token_budget = 100000;
    saved.memory_vector = false; saved.memory_candidates = 128; saved.memory_cache_seconds = 600;
    saved.isolation_strict = true; saved.isolation_require_remote = true;
    StringCchCopyW(saved.isolation_network, 2048, L"https://allowed.test");
    StringCchCopyW(saved.task_cost_budget, 32, L"0.25"); StringCchCopyW(saved.budget_currency, 8, L"CNY");
    saved.model_capability.context_tokens = 64000; saved.model_capability.quality = 80;
    saved.agent.profiles[0].capability.latency_ms = 1500; saved.agent.profiles[0].capability.tool_calls = false;
    saved.task_mode = true; saved.task_retries = 4;
    saved.task_timeout_seconds = 75; saved.read_retries = 3;
    saved.task_replans = 3; saved.task_rounds = 48; saved.parallel_workers = 3; saved.event_wait_seconds = 45; saved.debug_guard = true;
    saved.collaboration = true; saved.coordinator = 2;
    saved.context_auto = false; saved.context_budget_kb = 64;
    saved.context_recent = 3; saved.tool_result_kb = 2; saved.context_summary_kb = 5;
    saved.permission_mode = 0;
    saved.memory_enabled = false; saved.evaluation_enabled = false; saved.stream_usage = true;
    saved.memory_hits = 3; saved.memory_context_kb = 4;
    saved.memory_semantic = true; saved.isolation_target = true;
    saved.isolation_calls = 48; saved.isolation_argument_kb = 12; saved.isolation_result_kb = 64;
    StringCchCopyW(saved.isolation_tools, 1024, L"get_debug_context,read_memory");
    StringCchCopyW(saved.memory_project, 128, L"config-project");
    StringCchCopyW(saved.input_price, 32, L"2.5");
    StringCchCopyW(saved.agent.profiles[0].output_price, 32, L"8");
    StringCchCopyW(saved.agent.profiles[0].price_currency, 8, L"CNY");
    saved.agent.auto_route = saved.agent.failover = saved.agent.review = true;
    saved.agent.profiles[0].reviewer = true;
    StringCchCopyW(saved.agent.profiles[0].keywords, 512, L"crash; asm");
    StringCchCopyW(saved.agent.profiles[0].key, 256, L"test-key");
    StringCchCopyW(saved.agent.profiles[0].effort, 16, L"high");
    saved.agent.profiles[0].timeout_seconds = 45;
    g_config = saved;
    SaveConfig();
    SetDefaultConfig(&g_config);
    LoadConfig();
    ServerConfig loaded = CopyConfig();
    assert(!loaded.memory_vector && loaded.memory_candidates == 128 && loaded.memory_cache_seconds == 600);
    assert(loaded.isolation_strict && loaded.isolation_require_remote && wcscmp(loaded.isolation_network, L"https://allowed.test") == 0);
    assert(loaded.agent.routing_mode == 3 && loaded.context_budget_tokens == 32000 && loaded.task_token_budget == 100000);
    assert(wcscmp(loaded.task_cost_budget, L"0.25") == 0 && wcscmp(loaded.budget_currency, L"CNY") == 0);
    assert(loaded.model_capability.context_tokens == 64000 && loaded.model_capability.quality == 80);
    assert(loaded.agent.profiles[0].capability.latency_ms == 1500 && !loaded.agent.profiles[0].capability.tool_calls);
    assert(loaded.agent.auto_route && loaded.agent.failover && loaded.agent.review);
    assert(loaded.task_mode && loaded.task_retries == 4);
    assert(loaded.task_timeout_seconds == 75 && loaded.read_retries == 3);
    assert(loaded.task_replans == 3 && loaded.task_rounds == 48 && loaded.parallel_workers == 3 && loaded.event_wait_seconds == 45 && loaded.debug_guard);
    assert(loaded.collaboration && loaded.coordinator == 2 && !loaded.context_auto);
    assert(loaded.context_budget_kb == 64 && loaded.context_recent == 3 &&
        loaded.tool_result_kb == 2 && loaded.context_summary_kb == 5);
    assert(loaded.permission_mode == 0);
    assert(!loaded.memory_enabled && !loaded.evaluation_enabled && loaded.stream_usage);
    assert(loaded.memory_hits == 3 && loaded.memory_context_kb == 4 && lstrcmpW(loaded.memory_project, L"config-project") == 0);
    assert(loaded.memory_semantic && loaded.isolation_target && loaded.isolation_calls == 48 &&
        loaded.isolation_argument_kb == 12 && loaded.isolation_result_kb == 64 &&
        wcscmp(loaded.isolation_tools, L"get_debug_context,read_memory") == 0);
    assert(lstrcmpW(loaded.input_price, L"2.5") == 0 && lstrcmpW(loaded.agent.profiles[0].output_price, L"8") == 0);
    assert(lstrcmpW(loaded.agent.profiles[0].price_currency, L"CNY") == 0);
    assert(loaded.agent.profiles[0].enabled && loaded.agent.profiles[0].reviewer);
    assert(lstrcmpW(loaded.agent.profiles[0].key, L"test-key") == 0);
    assert(lstrcmpW(loaded.agent.profiles[0].keywords, L"crash; asm") == 0);
    assert(lstrcmpW(loaded.agent.profiles[0].effort, L"high") == 0);
    assert(loaded.agent.profiles[0].timeout_seconds == 45);
    DeleteCriticalSection(&g_config_cs);
    puts("PASS: routing, failover, preserved tool history, cancellation, review isolation and manual selection");
    return 0;
}
