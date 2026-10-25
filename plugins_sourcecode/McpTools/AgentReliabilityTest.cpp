#include "McpServerApp.cpp"
#include <assert.h>
#include <stdio.h>
#include <crtdbg.h>

struct SlowRequest {
    SOCKET listener;
    HANDLE ready, release;
    ChatJob job;
    bool received;
};
static DWORD WINAPI SlowServer(LPVOID pointer)
{
    SlowRequest* test = (SlowRequest*)pointer;
    SOCKET client = accept(test->listener, NULL, NULL); assert(client != INVALID_SOCKET);
    std::string request; char buffer[2048];
    while (request.find("\r\n\r\n") == std::string::npos) {
        int read = recv(client, buffer, sizeof(buffer), 0); assert(read > 0); request.append(buffer, read);
    }
    const char* headers = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n";
    assert(send(client, headers, (int)strlen(headers), 0) == (int)strlen(headers));
    SetEvent(test->ready);
    assert(WaitForSingleObject(test->release, 5000) == WAIT_OBJECT_0);
    send(client, "{}", 2, 0); closesocket(client); return 0;
}
static DWORD WINAPI SlowClient(LPVOID pointer)
{
    SlowRequest* test = (SlowRequest*)pointer; std::string response; DWORD status = 0;
    test->received = RemoteHttpRequest(test->job.cfg, "{}", &response, &status, false, NULL, NULL, NULL, true, &test->job);
    return 0;
}
static void PrepareSlowRequest(SlowRequest* test)
{
    ChatJob fresh = {}; test->job = fresh;
    test->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(test->listener != INVALID_SOCKET);
    sockaddr_in address = {}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(test->listener, (sockaddr*)&address, sizeof(address)) == 0 && listen(test->listener, 1) == 0);
    int size = sizeof(address); assert(getsockname(test->listener, (sockaddr*)&address, &size) == 0);
    SetDefaultConfig(&test->job.cfg);
    StringCchPrintfW(test->job.cfg.remote_url, 512, L"http://127.0.0.1:%u/test", ntohs(address.sin_port));
    test->job.cfg.remote_timeout_ms = 4000;
    test->ready = CreateEventW(NULL, TRUE, FALSE, NULL); test->release = CreateEventW(NULL, TRUE, FALSE, NULL);
    test->job.cancel_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    assert(test->ready && test->release && test->job.cancel_event);
}
static bool TestAudit(ChatJob*, const std::string&, const ModelToolBinding&, const std::string&, const std::string&, const std::string&) { return true; }
static int g_attempts = 0, g_failures = 0;
static bool FlakyTool(const ServerConfig&, const std::string&, const std::string&, std::string* result)
{
    ++g_attempts; if (g_failures-- > 0) return false; *result = "{\"result\":{\"ok\":true}}"; return true;
}
struct LocalCallTest {
    ServerConfig cfg;
    bool ok;
    std::string response;
};
static DWORD WINAPI LocalCallClient(LPVOID pointer)
{
    LocalCallTest* test = (LocalCallTest*)pointer;
    test->ok = RemoteHttpRequest(test->cfg,
        "{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"tools/call\",\"params\":{\"name\":\"get_status\",\"arguments\":{}}}",
        &test->response, NULL, false);
    return 0;
}
static void TestLocalPluginRoundTrip()
{
    InitializeCriticalSection(&g_config_cs);
    InitializeCriticalSection(&g_remote_cs);
    ServerConfig cfg; SetDefaultConfig(&cfg);
    SOCKET reserved = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(reserved != INVALID_SOCKET);
    sockaddr_in address = {}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(reserved, (sockaddr*)&address, sizeof(address)) == 0);
    int address_size = sizeof(address); assert(getsockname(reserved, (sockaddr*)&address, &address_size) == 0);
    cfg.port = ntohs(address.sin_port); closesocket(reserved);
    g_config = cfg;
    assert(StartServer());
    DWORD start = GetTickCount();
    while (!InterlockedCompareExchange(&g_server_running, 0, 0) && GetTickCount() - start < 3000) Sleep(10);
    assert(InterlockedCompareExchange(&g_server_running, 0, 0));
    StringCchPrintfW(cfg.remote_url, _countof(cfg.remote_url), L"http://127.0.0.1:%d/mcp", cfg.port);
    cfg.remote_timeout_ms = 5000;
    std::string response;
    assert(RemoteHttpRequest(cfg,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"z0dbg/register_tools\",\"params\":{\"tools\":[{\"name\":\"get_status\"}]}}",
        &response, NULL, false));
    InterlockedExchange(&g_server_running, 0);
    ServerConfig local = g_config;
    assert(LocalListenerToolsRegistered(local, &response) && response.find("get_status") != std::string::npos);
    assert(LocalToolsList(local, &response, false) && response.find("get_status") != std::string::npos &&
        response.find("debugger_start") == std::string::npos);
    EnterCriticalSection(&g_remote_cs);
    g_local_tools_registered_at = GetTickCount() - 8000;
    LeaveCriticalSection(&g_remote_cs);
    assert(!LocalListenerToolsRegistered(local, NULL));
    assert(LocalToolsList(local, &response, false) && response.find("debugger_start") != std::string::npos);
    EnterCriticalSection(&g_remote_cs);
    g_local_tools_registered_at = GetTickCount();
    LeaveCriticalSection(&g_remote_cs);
    InterlockedExchange(&g_server_running, 1);
    LocalCallTest calls[2] = {}; HANDLE callers[2];
    for (int i = 0; i < 2; ++i) {
        calls[i].cfg = cfg;
        callers[i] = CreateThread(NULL, 0, LocalCallClient, &calls[i], 0, NULL);
        assert(callers[i]);
    }
    for (int i = 0; i < 2; ++i) {
        std::string pending;
        start = GetTickCount();
        do {
            assert(RemoteHttpRequest(cfg,
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"z0dbg/poll\",\"params\":{}}",
                &pending, NULL, false));
            if (pending.find("\"pending\":true") != std::string::npos) break;
            Sleep(10);
        } while (GetTickCount() - start < 3000);
        assert(pending.find("\"pending\":true") != std::string::npos);
        assert(pending.find("get_status") != std::string::npos);
        ModelJson poll_result;
        assert(ModelJson::parse(pending, &poll_result));
        const ModelJson* request_id = poll_result.get("result")->get("request_id");
        assert(request_id && request_id->kind == ModelJson::STRING);
        std::string submit = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"z0dbg/result\",\"params\":{\"request_id\":";
        ModelJson::quote(&submit, request_id->value);
        submit += ",\"response\":\"{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":77,\\\"result\\\":{\\\"ok\\\":true}}\"}}";
        assert(RemoteHttpRequest(cfg, submit, &response, NULL, false));
    }
    for (int i = 0; i < 2; ++i) {
        assert(WaitForSingleObject(callers[i], 3000) == WAIT_OBJECT_0 && calls[i].ok);
        assert(calls[i].response.find("\"ok\":true") != std::string::npos);
        CloseHandle(callers[i]);
    }
    StopServer();
    {
        ConsoleLocalListener cli_listener(local);
        assert(InterlockedCompareExchange(&g_server_running, 0, 0));
    }
    assert(!InterlockedCompareExchange(&g_server_running, 0, 0));
    g_local_tools_result.clear();
    DeleteCriticalSection(&g_remote_cs);
    DeleteCriticalSection(&g_config_cs);
    puts("PASS: local CLI catalog, concurrent plugin poll and tool result round-trip");
}
int main()
{
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    wchar_t temp[MAX_PATH], root[MAX_PATH], previous[32768];
    DWORD previous_length = GetEnvironmentVariableW(L"LOCALAPPDATA", previous, _countof(previous));
    assert(previous_length < _countof(previous));
    assert(GetTempPathW(_countof(temp), temp) && GetTempFileNameW(temp, L"rel", 0, root));
    assert(DeleteFileW(root) && CreateDirectoryW(root, NULL) && SetEnvironmentVariableW(L"LOCALAPPDATA", root));
    WSADATA sockets; assert(WSAStartup(MAKEWORD(2, 2), &sockets) == 0);
    TestLocalPluginRoundTrip();
    DWORD warm_handles = 0;
    for (int repeat = 0; repeat < 6; ++repeat) {
        SlowRequest tests[2] = {};
        HANDLE servers[2], clients[2];
        for (int i = 0; i < 2; ++i) {
            PrepareSlowRequest(&tests[i]);
            servers[i] = CreateThread(NULL, 0, SlowServer, &tests[i], 0, NULL);
            clients[i] = CreateThread(NULL, 0, SlowClient, &tests[i], 0, NULL);
            assert(servers[i] && clients[i]);
        }
        for (int i = 0; i < 2; ++i) assert(WaitForSingleObject(tests[i].ready, 3000) == WAIT_OBJECT_0);
        DWORD started = GetTickCount(); SetEvent(tests[0].job.cancel_event);
        assert(WaitForSingleObject(clients[0], 1500) == WAIT_OBJECT_0 && !tests[0].received && GetTickCount() - started < 1500);
        assert(WaitForSingleObject(clients[1], 75) == WAIT_TIMEOUT);
        SetEvent(tests[1].release);
        assert(WaitForSingleObject(clients[1], 2000) == WAIT_OBJECT_0 && tests[1].received);
        SetEvent(tests[0].release);
        for (int i = 0; i < 2; ++i) {
            assert(WaitForSingleObject(servers[i], 2000) == WAIT_OBJECT_0);
            CloseHandle(clients[i]); CloseHandle(servers[i]); CloseHandle(tests[i].ready);
            CloseHandle(tests[i].release); CloseHandle(tests[i].job.cancel_event); closesocket(tests[i].listener);
        }
        Sleep(100);
        DWORD handles = 0; assert(GetProcessHandleCount(GetCurrentProcess(), &handles));
        printf("Loopback cleanup iteration %d: %lu handles\n", repeat + 1, handles); fflush(stdout);
        if (!repeat) warm_handles = handles;
        else assert(handles <= warm_handles + 8);
    }
    g_agent_audit = TestAudit; g_agent_tool_call = FlakyTool;
    ChatJob job = {}; SetDefaultConfig(&job.cfg); job.cfg.evaluation_enabled = false;
    ModelToolBinding read; read.mcp_name = "read_memory"; read.read_only = true; read.risk = MCP_READ_ONLY;
    std::string response; g_attempts = 0; g_failures = 1;
    assert(DispatchAgentTransport(&job, read, "{}", "{}", "1", &response) && g_attempts == 2 && job.evaluation.tool_failed == 1);
    ModelToolBinding write = read; write.mcp_name = "write_memory"; write.risk = MCP_DANGEROUS; write.read_only = false;
    g_attempts = 0; g_failures = 3;
    assert(!DispatchAgentTransport(&job, write, "{}", "{}", "1", &response) && g_attempts == 1);
    job.run_clock_started = true; job.run_started = GetTickCount() - 10000; job.cfg.task_timeout_seconds = 10;
    g_attempts = 0;
    assert(AgentJobTimedOut(&job) && !DispatchAgentTransport(&job, read, "{}", "{}", "1", &response) && !g_attempts);
    job.cfg.task_timeout_seconds = 0;
    assert(!AgentJobTimedOut(&job));
    std::wstring policy = AgentDataFolder(L"policies", AgentProjectScope(job.cfg));
    assert(RemoveDirectoryW(policy.c_str()) && RemoveDirectoryW((std::wstring(root) + L"\\McpServer\\policies").c_str()) &&
        RemoveDirectoryW((std::wstring(root) + L"\\McpServer").c_str()));
    assert(SetEnvironmentVariableW(L"LOCALAPPDATA", previous_length ? previous : NULL) && RemoveDirectoryW(root));
    CloseAgentHttpSession();
    WSACleanup();
    puts("PASS: real loopback HTTP cancellation, concurrent request independence, repeated handle cleanup, read-only reconnection retry, no mutation retry and task deadline gates");
    return 0;
}
