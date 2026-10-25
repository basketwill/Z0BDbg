#include "McpTools.cpp"
#include <assert.h>
#include <stdio.h>
#include <crtdbg.h>

static int g_reads = 0;
static int g_writes = 0;
static ulong __cdecl TestNextBreakpoint(ulong previous, ulong* type, int* command)
{
    if (type) *type = 1;
    if (command) *command = 0;
    return previous < 0x1000 ? 0x1000 : previous < 0x2000 ? 0x2000 :
        previous < 0x3000 ? 0x3000 : 0;
}
static int g_target_bits = 64;
static int __cdecl TestTargetBits(void) { return g_target_bits; }
static unsigned long __cdecl TestActiveProcessId(void) { return GetCurrentProcessId(); }
static int __cdecl TestDebugState(void) { return STAT_PAUSED; }
static ulong __cdecl TestStaticDisasm(uchar* bytes, ulong size, ulong, uchar*,
    HostDisasm* decoded, int, ulong)
{
    if (!bytes || !size || !decoded) return 0;
    StringCchCopyA(decoded->result, _countof(decoded->result), "nop");
    return 1;
}
static int __cdecl TestRegister(const char* name, unsigned __int64* value)
{
    if (!strcmp(name, "rax")) *value = 0x123456789ABCDEF0ULL;
    else if (!strcmp(name, "rsp")) *value = 0x1234567880000000ULL;
    else if (!strcmp(name, "esp")) *value = 0x80000000ULL;
    else if (!strcmp(name, "ebp")) *value = 0x80000100ULL;
    else return 0;
    return 1;
}
static bool g_partial_write = false;
static ulong __cdecl TestWrite(const void*, ulong, ulong size, int) {
    ++g_writes; return g_partial_write ? size - 1 : size;
}
static std::string g_inserted_name;
static int __cdecl TestInsert(ulong, int, char* name) { g_inserted_name = name; return 0; }
static ulong __cdecl TestRead(void* data, ulong, ulong size, int)
{
    ++g_reads; memset(data, 42, (size_t)size); return size;
}
static BOOL __cdecl TestStaticQuery(Z0B_StaticQuery* query)
{
    if (!query || !GetModuleFileNameW(NULL, query->path, _countof(query->path))) return FALSE;
    if (query->operation == Z0B_STATIC_QUERY_ACTIVE) return TRUE;
    if (query->operation != Z0B_STATIC_QUERY_DISASSEMBLE) return FALSE;
    StringCchCopyW(query->bytes, _countof(query->bytes), L"90");
    StringCchCopyW(query->text, _countof(query->text), L"nop");
    query->instruction_size = 1;
    return TRUE;
}
static DWORD WINAPI EmitStop(LPVOID)
{
    Sleep(50);
    DEBUG_EVENT event; ZeroMemory(&event, sizeof(event));
    event.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    event.dwProcessId = GetCurrentProcessId(); event.dwThreadId = GetCurrentThreadId();
    event.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
    QueueDebuggerEvent(&event);
    return 0;
}
static std::string ScopedRequest(const char* tool, const char* arguments, const char* scope)
{
    ModelJson context; assert(ModelJson::parse(g_debug_feed.context(), &context));
    std::string request = "{\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":";
    ModelJson::quote(&request, tool); request += ",\"arguments\":" + std::string(arguments) + ",\"_meta\":{\"z0dbg/scope\":";
    ModelJson::quote(&request, scope); request += ",\"z0dbg/target\":";
    ModelJson::quote(&request, context.get("session")->value + ":" + context.get("process_id")->raw); return request + "}}}";
}
int main()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC query_system = ntdll ? GetProcAddress(ntdll, "NtQuerySystemInformation") : NULL;
    assert(query_system && ResolveLoadedModuleExport(GetCurrentProcessId(),
        "ntdll!NtQuerySystemInformation") == (unsigned __int64)(ULONG_PTR)query_system);
    assert(ResolveLoadedModuleExport(GetCurrentProcessId(),
        "ntdll.dll!NtQuerySystemInformation") == (unsigned __int64)(ULONG_PTR)query_system);
    assert(!ResolveLoadedModuleExport(GetCurrentProcessId(), "ntdll!Z0B_NotAnExport"));
    wchar_t self_path[MAX_PATH] = {};
    assert(GetModuleFileNameW(NULL, self_path, _countof(self_path)));
    StaticPeImage self_image;
    assert(self_image.open(self_path));
    ModelJson imports;
    assert(ModelJson::parse(self_image.imports(0, 64), &imports));
    bool checked_import = false;
    for (size_t i = 0; i < imports.get("imports")->items.size(); ++i) {
        const ModelJson& item = imports.get("imports")->items[i];
        const ModelJson* import_name = item.get("name");
        if (!import_name || import_name->value.empty()) continue;
        unsigned __int64 preferred = _strtoui64(item.get("iat_address")->value.c_str(), NULL, 16);
        unsigned __int64 actual = (unsigned __int64)(ULONG_PTR)GetModuleHandleW(NULL) +
            preferred - self_image.image_base();
        assert(FindLoadedMainImport(GetCurrentProcessId(), import_name->value) == actual);
        assert(!FindLoadedMainImport(GetCurrentProcessId(), import_name->value, actual + 8, 8));
        checked_import = true;
        break;
    }
    assert(checked_import && !FindLoadedMainImport(GetCurrentProcessId(), "Z0B_NotAnImport"));
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    InitializeCriticalSection(&g_config_cs);
    SetDefaultConfig(&g_config); g_config.send_debug_events = FALSE;
    wchar_t previous_url[512], previous_token[512];
    DWORD url_length = GetEnvironmentVariableW(L"Z0B_MCP_LOCAL_URL", previous_url, _countof(previous_url));
    DWORD token_length = GetEnvironmentVariableW(L"Z0B_MCP_LOCAL_TOKEN", previous_token, _countof(previous_token));
    assert(url_length < _countof(previous_url) && token_length < _countof(previous_token));
    assert(SetEnvironmentVariableW(L"Z0B_MCP_LOCAL_URL", L"http://127.0.0.1:8765/mcp"));
    assert(SetEnvironmentVariableW(L"Z0B_MCP_LOCAL_TOKEN", L"test-token"));
    McpConfig local; SetDefaultConfig(&local); local.enabled = FALSE;
    StringCchCopyW(local.http_method, _countof(local.http_method), L"GET");
    ApplyLocalServerEnvironment(&local);
    assert(local.enabled && local.auto_connect && local.mcp_initialize &&
        local.allow_breakpoint && local.allow_execute && local.allow_high_risk &&
        wcscmp(local.transport, L"http") == 0 && wcscmp(local.http_method, L"POST") == 0 &&
        wcscmp(local.url, L"http://127.0.0.1:8765/mcp") == 0 &&
        wcscmp(local.auth_token, L"test-token") == 0);
    assert(g_auto_confirm_local_server && ConfirmHighRiskTool(local, "run"));
    g_auto_confirm_local_server = FALSE;
    assert(ConfirmHighRiskTool(local, "run", true) && IsToolAllowed(local, "run", true));
    local.allow_high_risk = FALSE;
    assert(!ConfirmHighRiskTool(local, "run", true) && !IsToolAllowed(local, "run", true));
    g_auto_confirm_local_server = TRUE;
    assert(SetEnvironmentVariableW(L"Z0B_MCP_LOCAL_URL", url_length ? previous_url : NULL));
    assert(SetEnvironmentVariableW(L"Z0B_MCP_LOCAL_TOKEN", token_length ? previous_token : NULL));
    pReadmemory = TestRead;
    pGetnextbreakpoint = TestNextBreakpoint;
    pMcpGetRegister = TestRegister; pMcpTargetBits = TestTargetBits;
    assert(McpReadOnlyTool("register_get") && McpReadOnlyTool("stack_read") &&
        McpReadOnlyTool("get_event_capabilities"));
    ModelJson capabilities;
    ModelJson tool_list;
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/list\"}"), &tool_list));
    bool event_tool_listed = false, static_without_target = false;
    const ModelJson* listed = tool_list.get("result")->get("tools");
    for (size_t i = 0; i < listed->items.size(); ++i)
        if (listed->items[i].get("name")->value == "get_event_capabilities") event_tool_listed = true;
        else if (listed->items[i].get("name")->value == "static_pe_info") static_without_target = true;
    assert(event_tool_listed && !static_without_target);
    pMcpStaticQuery = TestStaticQuery;
    assert(ModelJson::parse(ToolListJson(), &tool_list));
    bool static_info_listed = false, static_disassemble_listed = false;
    for (size_t i = 0; i < tool_list.items.size(); ++i) {
        std::string name = tool_list.items[i].get("name")->value;
        if (name == "static_pe_info") static_info_listed = true;
        if (name == "static_disassemble") static_disassemble_listed = true;
    }
    assert(static_info_listed && static_disassemble_listed);
    ModelJson static_reply;
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"static_pe_info\",\"arguments\":{}}}"), &static_reply));
    assert(static_reply.get("result") && static_reply.get("result")->get("entry_point"));
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"static_list_sections\",\"arguments\":{}}}"), &static_reply));
    assert(static_reply.get("result") && static_reply.get("result")->get("sections"));
    pMcpStaticQuery = NULL;
    pMcpActiveProcessId = TestActiveProcessId;
    assert(ModelJson::parse(ToolListJson(), &tool_list));
    static_info_listed = false;
    for (size_t i = 0; i < tool_list.items.size(); ++i)
        if (tool_list.items[i].get("name")->value == "static_pe_info") static_info_listed = true;
    assert(static_info_listed);
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"static_pe_info\",\"arguments\":{}}}"), &static_reply));
    assert(static_reply.get("result") && static_reply.get("result")->get("entry_point"));
    std::string entry = static_reply.get("result")->get("entry_point")->value;
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"static_list_imports\",\"arguments\":{}}}"), &static_reply));
    assert(static_reply.get("result") && static_reply.get("result")->get("imports"));
    std::string byte_call = "{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"static_read_bytes\",\"arguments\":{\"address\":\"" + entry + "\",\"size\":1}}}";
    assert(ModelJson::parse(ExecuteToolCommand(byte_call), &static_reply));
    assert(static_reply.get("result") && static_reply.get("result")->get("hex") &&
        static_reply.get("result")->get("hex")->value.size() == 2);
    pDisasm = TestStaticDisasm;
    std::string disasm_call = "{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"static_disassemble\",\"arguments\":{\"address\":\"" + entry + "\",\"count\":1}}}";
    assert(ModelJson::parse(ExecuteToolCommand(disasm_call), &static_reply));
    assert(static_reply.get("result") && static_reply.get("result")->get("instructions") &&
        static_reply.get("result")->get("instructions")->items.size() == 1);
    assert(static_reply.get("result")->get("instructions")->items[0].get("text") &&
        static_reply.get("result")->get("instructions")->items[0].get("text")->value == "nop");
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"static_disassemble\",\"arguments\":{\"address\":\"0x7FFAC4F82400\",\"count\":1}}}"), &static_reply));
    assert(static_reply.get("error") && static_reply.get("error")->get("message") &&
        static_reply.get("error")->get("message")->value.find("runtime VA") != std::string::npos);
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"resolve_symbol\",\"arguments\":{\"name\":\"ntdll!UnlikelyMissingExportForTest\"}}}"), &static_reply));
    assert(static_reply.get("result") && static_reply.get("result")->get("address_space") &&
        static_reply.get("result")->get("address_space")->value == "runtime_va");
    pDisasm = NULL;
    pMcpActiveProcessId = NULL;
    pMcpStaticQuery = TestStaticQuery;
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event_capabilities\",\"arguments\":{}}}"), &capabilities));
    assert(capabilities.get("result") && capabilities.get("result")->get("feed") &&
        capabilities.get("result")->get("feed")->get("kinds") &&
        capabilities.get("result")->get("feed")->get("kinds")->items.size() == 11 &&
        capabilities.get("result")->get("server_notifications") &&
        capabilities.get("result")->get("server_notifications")->get("enabled")->value == "false");
    g_config.send_debug_events = TRUE;
    g_config.event_exception = FALSE;
    g_config.agent_require_target = TRUE;
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event_capabilities\",\"arguments\":{}}}"), &capabilities));
    assert(capabilities.get("result")->get("server_notifications")->get("enabled")->value == "true" &&
        capabilities.get("result")->get("server_notifications")->get("categories")->get("exception")->value == "false" &&
        capabilities.get("result")->get("server_notifications")->get("categories")->get("thread")->value == "true");
    g_config.send_debug_events = FALSE;
    g_config.event_exception = TRUE;
    g_config.agent_require_target = FALSE;
    assert(McpKnownDangerousTool("register_set") && McpKnownDangerousTool("debug_stop") && McpKnownDangerousTool("dump_memory_region"));
    ModelJson register_reply;
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"register_get\",\"arguments\":{\"name\":\"rax\"}}}"), &register_reply));
#ifdef _WIN64
    assert(register_reply.get("result") && register_reply.get("result")->get("registers")->get("rax")->value == "0x123456789ABCDEF0");
    g_target_bits = 32;
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"stack_get_pointers\",\"arguments\":{}}}"), &register_reply));
    assert(register_reply.get("result") && register_reply.get("result")->get("registers")->get("esp"));
#else
    assert(register_reply.get("error"));
    g_target_bits = 32;
#endif
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"stack_read\",\"arguments\":{\"address\":\"0xFFFFFFFFFFFFFFFF\",\"size\":2}}}"), &register_reply));
    assert(register_reply.get("error") && g_reads == 0);
    std::string page_reply = ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"breakpoint_list\",\"arguments\":{\"offset\":1,\"limit\":1}}}");
    assert(ModelJson::parse(page_reply, &register_reply));
    if (!register_reply.get("result") || !register_reply.get("result")->get("breakpoints") ||
        register_reply.get("result")->get("breakpoints")->items.size() != 1 ||
        register_reply.get("result")->get("next_offset")->raw != "2") fprintf(stderr, "Page reply: %s\n", page_reply.c_str());
    assert(register_reply.get("result") && register_reply.get("result")->get("breakpoints") &&
        register_reply.get("result")->get("breakpoints")->items.size() == 1 &&
        register_reply.get("result")->get("next_offset")->raw == "2");
    assert(register_reply.get("result") && register_reply.get("result")->get("breakpoints")->items.size() == 1 &&
        register_reply.get("result")->get("next_offset")->raw == "2");
    pInsertnameA = TestInsert; g_config.allow_write = TRUE;
    g_debug_feed.update(0, 0, 0);
    pMcpActiveProcessId = TestActiveProcessId; pMcpDebugState = TestDebugState;
    ModelJson refreshed;
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_debug_context\",\"arguments\":{}}}"), &refreshed) &&
        refreshed.get("result") && refreshed.get("result")->get("process_id")->raw == DebugRuntimeFeed::number(GetCurrentProcessId()) &&
        refreshed.get("result")->get("status")->raw == "18");
    pMcpActiveProcessId = NULL; pMcpDebugState = NULL;
    g_debug_feed.update(GetCurrentProcessId(), GetCurrentThreadId(), STAT_PAUSED);
    ModelJson root;
    assert(ModelJson::parse(ExecuteToolCommand("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_debug_context\",\"arguments\":{}}}"), &root));
    const ModelJson* context = root.get("result");
    assert(context && context->get("status")->raw == "18" && context->get("modules_known")->value == "true" && !context->get("modules")->items.empty());
    std::string identity = context->get("session")->value + ":" + context->get("process_id")->raw;
    std::string revision = context->get("revision")->value;
    std::string request = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_memory\",\"arguments\":{\"address\":4096,\"size\":4},\"_meta\":{\"z0dbg/target\":";
    ModelJson::quote(&request, identity); request += ",\"z0dbg/revision\":"; ModelJson::quote(&request, revision); request += "}}}";
    std::string reply = ExecuteToolCommand(request);
    if (!g_reads) fprintf(stderr, "Plugin reply: %s\n", reply.c_str());
    assert(ModelJson::parse(reply, &root) && root.get("result") && g_reads == 1);
    unsigned __int64 parsed = 7;
    assert(JsonFindUInt64("{\"address\":18446744073709551615,\"next\":\"text\"}", "address", parsed) && parsed == ~(unsigned __int64)0);
    assert(!JsonFindUInt64("{\"address\":-1}", "address", parsed) && parsed == ~(unsigned __int64)0);
    assert(JsonFindUInt64("{\"address\":\"0x100000001\"}", "address", parsed) && parsed == 0x100000001ULL);
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"insert_name\",\"arguments\":{\"address\":4096,\"name\":\"Label \\u4e2d\"}}}"), &root));
    assert(root.get("result") && g_inserted_name == "Label \xe4\xb8\xad");
    g_debug_feed.update(GetCurrentProcessId(), GetCurrentThreadId() + 1, STAT_PAUSED);
    assert(ModelJson::parse(ExecuteToolCommand(request), &root) && root.get("error")->get("code")->raw == "-32004" && g_reads == 1);
    assert(ModelJson::parse(g_debug_feed.context(), &root));
    std::string cursor = root.get("sequence")->raw;
    HANDLE thread = CreateThread(NULL, 0, EmitStop, NULL, 0, NULL); assert(thread);
    DWORD start = GetTickCount();
    request = "{\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"wait_debug_event\",\"arguments\":{\"cursor\":" + cursor + ",\"timeout_ms\":1000}}}";
    assert(ModelJson::parse(ExecuteToolCommand(request), &root) && !root.get("result")->get("events")->items.empty());
    assert(GetTickCount() - start < 1000 && WaitForSingleObject(thread, 1000) == WAIT_OBJECT_0); CloseHandle(thread);
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"wait_debug_event\",\"arguments\":{\"cursor\":-1}}}"), &root) && root.get("error"));
    assert(ModelJson::parse(ToolListJson(), &root));
    bool read_found = false, missing_write = true, wait_found = false;
    for (size_t i = 0; i < root.items.size(); ++i) {
        std::string name = root.items[i].get("name")->value;
        if (name == "read_memory") read_found = true;
        if (name == "write_memory") missing_write = false;
        if (name == "wait_debug_event") wait_found = root.items[i].get("inputSchema")->get("required") != NULL;
    }
    assert(read_found && missing_write && wait_found);
    pWritememory = TestWrite;
    g_config.allow_patch = g_config.allow_high_risk = TRUE; g_config.confirm_high_risk = FALSE;
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("write_memory", "{\"address\":4096,\"hex\":\"1122\",\"expected_hex\":\"FFFF\"}", "")), &root) && root.get("error") && g_writes == 0);
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("write_memory", "{\"address\":4096,\"hex\":\"1122\",\"expected_hex\":\"2AZA\"}", "")), &root) && root.get("error") && g_writes == 0);
    std::string conditional = ExecuteToolCommand(ScopedRequest("write_memory", "{\"address\":4096,\"hex\":\"1122\",\"expected_hex\":\"2A2A\"}", ""));
    if (!g_writes) fprintf(stderr, "Conditional write reply: %s\n", conditional.c_str());
    assert(ModelJson::parse(conditional, &root) && root.get("result") && root.get("result")->get("ok")->raw == "true" && g_writes == 1);
    g_partial_write = true;
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("write_memory", "{\"address\":4096,\"hex\":\"1122\"}", "")), &root) && root.get("result")->get("ok")->raw == "false" && g_writes == 2);
    g_partial_write = false;
    assert(ModelJson::parse(g_debug_feed.context(), &root) && root.get("last_stop") &&
        root.get("last_stop")->get("exceptionCode")->raw == "2147483651");
    DEBUG_EVENT access; ZeroMemory(&access, sizeof(access));
    access.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    access.dwProcessId = GetCurrentProcessId(); access.dwThreadId = GetCurrentThreadId();
    access.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    access.u.Exception.ExceptionRecord.NumberParameters = 2;
    access.u.Exception.ExceptionRecord.ExceptionInformation[0] = 1;
    access.u.Exception.ExceptionRecord.ExceptionInformation[1] = 0;
    QueueDebuggerEvent(&access);
    assert(ModelJson::parse(g_debug_feed.context(), &root) &&
        root.get("last_stop")->get("accessType")->raw == "1" &&
        root.get("last_stop")->get("faultAddress")->value == "0x0");
    g_config.agent_readonly = g_config.agent_require_target = TRUE;
    StringCchCopyW(g_config.agent_scope, 128, L"test-project");
    StringCchCopyW(g_config.agent_tools, 1024, L"read_memory,get_debug_context");
    StringCchCopyW(g_config.agent_address_min, 32, L"0x1000"); StringCchCopyW(g_config.agent_address_max, 32, L"0x100F");
    g_config.agent_max_read_bytes = 8;
    int before_reads = g_reads;
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("read_memory", "{\"address\":4096,\"size\":4}", "wrong-project")), &root) && root.get("error"));
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("read_memory", "{\"address\":4108,\"size\":8}", "test-project")), &root) && root.get("error"));
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("read_memory", "{\"address\":4096,\"size\":9}", "test-project")), &root) && root.get("error"));
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("insert_name", "{\"address\":4096,\"name\":\"blocked\"}", "test-project")), &root) && root.get("error"));
    assert(g_reads == before_reads);
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("read_memory", "{\"address\":4096,\"size\":4}", "test-project")), &root) && root.get("result") && g_reads == before_reads + 1);
    assert(root.get("result")->get("hex")->value == "2A2A2A2A");
    assert(ModelJson::parse(ExecuteToolCommand("{\"id\":10,\"method\":\"z0dbg.read_memory\",\"address\":4096,\"size\":4}"), &root) && root.get("error"));
    g_config.agent_strict = TRUE; StringCchCopyW(g_config.agent_tools, 1024, L"read_memory,get_debug_context,get_isolation_policy");
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("get_isolation_policy", "{}", "test-project")), &root));
    assert(root.get("result") && root.get("result")->get("strict")->raw == "true" && root.get("result")->get("scope")->value == "test-project");
    int strict_reads = g_reads;
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("read_memory", "{\"address\":4096,\"size\":4,\"path\":\"C:\\\\outside\\\\data\"}", "test-project")), &root) && root.get("error"));
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("read_memory", "{\"address\":4096,\"size\":4,\"nested\":{\"url\":\"https://outside.test\"}}", "test-project")), &root) && root.get("error") && g_reads == strict_reads);
    assert(ModelJson::parse(ExecuteToolCommand(ScopedRequest("read_memory", "{\"address\":4096,\"size\":4}", "test-project")), &root) && root.get("result"));
    HANDLE job = CreateAgentProcessJob(64, 30);
    if (!job) fprintf(stderr, "Job setup error: %lu; structure bytes: %u\n", GetLastError(), (unsigned)sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
    assert(job);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
    assert(QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits), NULL));
    assert(limits.BasicLimitInformation.ActiveProcessLimit == 4 && limits.JobMemoryLimit == 64 * 1024 * 1024 &&
        (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE));
    CloseHandle(job);
    wchar_t system[MAX_PATH]; assert(GetSystemDirectoryW(system, _countof(system)));
    std::wstring command = L"\"" + std::wstring(system) + L"\\cmd.exe\" /d /c exit 0";
    HANDLE null = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    assert(null != INVALID_HANDLE_VALUE); STARTUPINFOW startup = {}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = startup.hStdOutput = startup.hStdError = null;
    PROCESS_INFORMATION child = {}; HANDLE child_job = NULL;
    bool launched = CreateIsolatedAgentProcess(&command[0], NULL, NULL, CREATE_NO_WINDOW, startup, 64, 30, &child, &child_job);
    if (launched) {
        BOOL contained = FALSE;
        assert(IsProcessInJob(child.hProcess, child_job, &contained) && contained && WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0);
        CloseHandle(child.hThread); CloseHandle(child.hProcess); CloseHandle(child_job);
        puts("PASS: restricted-token child launch with selective handle inheritance and Windows Job Object containment");
    }
    else { assert(!child.hProcess && !child.hThread && !child_job); puts("PASS: isolated child startup fails closed when Windows denies token/job setup"); }
    command = L"\"" + std::wstring(system) + L"\\cmd.exe\" /d /c exit 0";
    assert(!CreateIsolatedAgentProcess(&command[0], NULL, NULL, CREATE_NO_WINDOW, startup, 64, 30, &child, &child_job, L"") && !child.hProcess && !child_job);
    CloseHandle(null);
    DeleteCriticalSection(&g_config_cs);
    puts("PASS: native plugin runtime, stop evidence, mandatory project/target checks, range/read quotas, unscoped alias refusal, read-only policy and job limits");
    return 0;
}
