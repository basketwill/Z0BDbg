#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string>
#include "../ModelJson.h"

extern "C" __declspec(dllexport) volatile LONG AgentCell = 42;
extern "C" __declspec(dllexport) volatile LONG* AgentPointer = &AgentCell;
extern "C" __declspec(dllexport) volatile LONG** AgentPointerRoot = &AgentPointer;
extern "C" __declspec(dllexport) unsigned char AgentCode[64];
unsigned char AgentCode[64];
extern "C" __declspec(dllexport) __declspec(noinline) int AgentCall(int input) { return input + AgentCell; }
extern "C" __declspec(dllexport) __declspec(noinline) void AgentFault() { volatile LONG* missing = NULL; *missing = 1; }

static std::string Address(const void* pointer)
{
    char text[32]; sprintf_s(text, sizeof(text), "0x%I64X", (unsigned __int64)(ULONG_PTR)pointer); return text;
}
static std::string Check(const char* tool, const std::string& args, const std::string& expected)
{
    std::string out = "{\"tool\":"; ModelJson::quote(&out, tool);
    return out + ",\"arguments\":" + args + ",\"expected\":" + expected + "}";
}
static std::string Case(const char* name, const char* goal, const std::string& checks, const std::string& answer = "")
{
    std::string out = "{\"name\":"; ModelJson::quote(&out, name); out += ",\"goal\":"; ModelJson::quote(&out, goal);
    return out + ",\"checks\":[" + checks + "]" + (answer.empty() ? "" : ",\"expected_answer\":" + answer) + "}";
}
static std::string PointerCheck(const void* location, const void* value)
{
    ULONG_PTR address = (ULONG_PTR)value; std::string hex;
    for (size_t i = 0; i < sizeof(address); ++i) { char byte[3]; sprintf_s(byte, 3, "%02X", (unsigned)((address >> (i * 8)) & 0xff)); hex += byte; }
    char size[16]; sprintf_s(size, 16, "%u", (unsigned)sizeof(address));
    return Check("read_memory", "{\"address\":\"" + Address(location) + "\",\"size\":" + size + "}", "{\"read\":" + std::string(size) + ",\"hex\":\"" + hex + "\"}");
}
int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) { puts("DebugAgentFixture.exe <suite.json> [--crash|--describe|--breakpoint|--repeat-breakpoints]"); return 1; }
    memset(AgentCode, 0x90, sizeof(AgentCode));
    for (int offset = 0; offset <= 32; offset += 16) {
        AgentCode[offset] = 0xe8;
        ULONG_PTR target = offset == 32 ? (ULONG_PTR)&AgentCall : (ULONG_PTR)(AgentCode + offset + 16);
        LONG relative = (LONG)(target - ((ULONG_PTR)AgentCode + offset + 5)); memcpy(AgentCode + offset + 1, &relative, 4);
        AgentCode[offset + 5] = 0xc3;
    }
    bool crash = argc > 2 && wcscmp(argv[2], L"--crash") == 0;
    bool describe = argc > 2 && wcscmp(argv[2], L"--describe") == 0;
    bool breakpoint = argc > 2 && wcscmp(argv[2], L"--breakpoint") == 0;
    bool repeat_breakpoints = argc > 2 && wcscmp(argv[2], L"--repeat-breakpoints") == 0;
    std::string cell = "{\"address\":\"" + Address((const void*)&AgentCell) + "\",\"size\":4}";
    std::string code = "{\"address\":\"" + Address(AgentCode) + "\"}";
    std::string suite = "{\"id\":\"debug-fixture-v2" + std::string(crash ? "-crash" : breakpoint ? "-breakpoint" : "") + "\",\"cases\":[";
    suite += Case("known-cell", "Inspect the fixture cell and confirm its 32-bit little-endian value is 42.", Check("read_memory", cell, "{\"read\":4,\"hex\":\"2A000000\"}"));
    suite += ',' + Case("expression", "Evaluate 1+2 in the debugger and verify the numerical result.", Check("evaluate", "{\"expression\":\"1+2\"}", "{\"number\":\"0x3\"}"));
    suite += ',' + Case("call-analysis", "Inspect the synthetic CALL instruction, decode its length, and resolve the called function address.",
        Check("disassemble", code, "{\"size\":5}") + ',' + Check("follow_call", code, "{\"address\":\"" + Address(AgentCode + 16) + "\"}"));
    std::string chain;
    for (int offset = 0; offset <= 32; offset += 16) {
        if (!chain.empty()) chain += ',';
        const void* target = offset == 32 ? (const void*)&AgentCall : AgentCode + offset + 16;
        chain += Check("follow_call", "{\"address\":\"" + Address(AgentCode + offset) + "\"}", "{\"address\":\"" + Address(target) + "\"}");
    }
    suite += ',' + Case("call-chain", "Resolve all three synthetic CALL destinations in order. Return call_chain as an array of hexadecimal destination strings.", chain,
        "{\"call_chain\":[\"" + Address(AgentCode + 16) + "\",\"" + Address(AgentCode + 32) + "\",\"" + Address((const void*)&AgentCall) + "\"]}");
    suite += ',' + Case("pointer-chain", "Follow the supplied two-level pointer chain and read its final 32-bit value. Return resolved_value as a decimal integer.",
        PointerCheck(&AgentPointerRoot, &AgentPointer) + ',' + PointerCheck(&AgentPointer, (const void*)&AgentCell) + ',' + Check("read_memory", cell, "{\"read\":4,\"hex\":\"2A000000\"}"),
        "{\"resolved_value\":42}");
    if (crash) suite += ',' + Case("access-violation", "Identify the paused exception code using current stop evidence.",
        Check("get_debug_context", "{}", "{\"last_stop\":{\"exceptionCode\":3221225477,\"accessType\":1,\"faultAddress\":\"0x0\"}}"),
        "{\"exception_code\":3221225477,\"access\":\"write\",\"fault_address\":\"0x0\"}");
    if (breakpoint || repeat_breakpoints) suite += ',' + Case("breakpoint-stop", "Identify the current paused stop reason. Return stop_type as breakpoint and exception_code as a decimal integer.",
        Check("get_debug_context", "{}", "{\"last_stop\":{\"exceptionCode\":2147483651}}"), "{\"stop_type\":\"breakpoint\",\"exception_code\":2147483651}");
    suite += "]}";
    FILE* file = NULL;
    if (_wfopen_s(&file, argv[1], L"wb") || !file) return 2;
    bool saved = fwrite(suite.data(), 1, suite.size(), file) == suite.size(); saved = fclose(file) == 0 && saved;
    if (!saved) return 2;
    printf("Fixture PID %lu; suite emitted. Addresses are valid only in this process.\n", GetCurrentProcessId()); fflush(stdout);
    if (describe) return 0;
    if (!IsDebuggerPresent()) { puts("Start this executable under the debugger; no debug break executed."); return 3; }
    DebugBreak();
    if (repeat_breakpoints) {
        for (int hit = 1; hit <= 30; ++hit) {
            printf("Fixture breakpoint %d/30\n", hit); fflush(stdout);
            Sleep(100);
            DebugBreak();
        }
    }
    if (crash) AgentFault();
    return AgentCall(1) == 43 ? 0 : 4;
}
