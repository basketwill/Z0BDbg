#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>
#include <wchar.h>
#include "plugin.h"

extern "C" int __cdecl AgentPluginRun(HINSTANCE instance);
extern "C" int __cdecl AgentPluginRunQueue(HINSTANCE instance, const char* arguments);
extern "C" int __cdecl AgentPluginRunConfig(HINSTANCE instance);
extern "C" int __cdecl AgentPluginRunInternal(HINSTANCE instance);
#ifdef _M_IX86
#pragma comment(linker, "/EXPORT:AgentTerminal=_AgentTerminal@16")
#pragma comment(linker, "/EXPORT:AgentQueue=_AgentQueue@16")
#pragma comment(linker, "/EXPORT:AgentConfig=_AgentConfig@16")
#pragma comment(linker, "/EXPORT:AgentInternal=_AgentInternal@16")
#endif
static HINSTANCE g_agent_instance = NULL;
static volatile LONG g_internal_running = 0;

static void OpenAgent(const wchar_t* entry, bool terminal)
{
    wchar_t module[MAX_PATH], system[MAX_PATH], rundll[MAX_PATH], command[MAX_PATH * 2];
    DWORD length = GetModuleFileNameW(g_agent_instance, module, MAX_PATH);
    if (!length || length >= MAX_PATH || !GetSystemDirectoryW(system, MAX_PATH) ||
        FAILED(StringCchPrintfW(rundll, MAX_PATH, L"%s\\rundll32.exe", system)) ||
        FAILED(StringCchPrintfW(command, MAX_PATH * 2, L"\"%s\" \"%s\",%s", rundll, module, entry))) {
        MessageBoxW(GetActiveWindow(), L"Could not locate the Agent plugin.",
            L"Z0bDbgAgent", MB_OK | MB_ICONERROR);
        return;
    }
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(rundll, command, NULL, NULL, FALSE,
            terminal ? CREATE_NEW_CONSOLE : 0, NULL, NULL,
            &startup, &process)) {
        wchar_t error[160];
        StringCchPrintfW(error, 160, L"Failed to open Agent window (error %lu).",
            GetLastError());
        MessageBoxW(GetActiveWindow(), error, L"Z0bDbgAgent", MB_OK | MB_ICONERROR);
        return;
    }
    if (WaitForSingleObject(process.hProcess, 1500) == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(process.hProcess, &code);
        wchar_t error[160];
        StringCchPrintfW(error, 160, L"Agent window exited during startup (code 0x%08lX).", code);
        MessageBoxW(GetActiveWindow(), error, L"Z0bDbgAgent", MB_OK | MB_ICONERROR);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

static DWORD WINAPI RunTerminalThread(LPVOID)
{
    return (DWORD)AgentPluginRun(g_agent_instance);
}

static DWORD WINAPI RunQueueThread(LPVOID arguments)
{
    return (DWORD)AgentPluginRunQueue(g_agent_instance, (const char*)arguments);
}

static DWORD WINAPI RunConfigThread(LPVOID)
{
    return (DWORD)AgentPluginRunConfig(g_agent_instance);
}

static DWORD WINAPI RunInternalThread(LPVOID)
{
    DWORD result = (DWORD)AgentPluginRunInternal(g_agent_instance);
    InterlockedExchange(&g_internal_running, 0);
    return result;
}

static void OpenInternalAgent(void)
{
    if (InterlockedCompareExchange(&g_internal_running, 1, 0) != 0)
        return;
    HANDLE thread = CreateThread(NULL, 8 * 1024 * 1024, RunInternalThread, NULL,
        STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!thread) {
        InterlockedExchange(&g_internal_running, 0);
        MessageBoxW(GetActiveWindow(), L"Could not create the Agent thread.",
            L"Z0bDbgAgent", MB_OK | MB_ICONERROR);
        return;
    }
    CloseHandle(thread);
}

static void RunWithAgentStack(LPTHREAD_START_ROUTINE entry, LPVOID argument)
{
    HANDLE thread = CreateThread(NULL, 8 * 1024 * 1024, entry, argument,
        STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!thread) {
        MessageBoxW(NULL, L"Could not create the Agent thread.", L"Z0bDbgAgent", MB_OK | MB_ICONERROR);
        return;
    }
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
}

extern "C" __declspec(dllexport) void CALLBACK AgentTerminal(HWND, HINSTANCE, LPSTR, int)
{
    RunWithAgentStack(RunTerminalThread, NULL);
}

extern "C" __declspec(dllexport) void CALLBACK AgentQueue(HWND, HINSTANCE, LPSTR arguments, int)
{
    RunWithAgentStack(RunQueueThread, arguments);
}

extern "C" __declspec(dllexport) void CALLBACK AgentConfig(HWND, HINSTANCE, LPSTR, int)
{
    RunWithAgentStack(RunConfigThread, NULL);
}

extern "C" __declspec(dllexport) void CALLBACK AgentInternal(HWND, HINSTANCE, LPSTR, int)
{
    RunWithAgentStack(RunInternalThread, NULL);
}

static int __cdecl MenuStart(t_table*, wchar_t*, ulong, int mode)
{
    if (mode == MENU_VERIFY) return MENU_NORMAL;
    if (mode == MENU_EXECUTE) OpenAgent(L"AgentTerminal", true);
    return MENU_NOREDRAW;
}

static int __cdecl MenuConfig(t_table*, wchar_t*, ulong, int mode)
{
    if (mode == MENU_VERIFY) return MENU_NORMAL;
    if (mode == MENU_EXECUTE) OpenAgent(L"AgentConfig", false);
    return MENU_NOREDRAW;
}

static int __cdecl MenuInternal(t_table*, wchar_t*, ulong, int mode)
{
    if (mode == MENU_VERIFY) return MENU_NORMAL;
    if (mode == MENU_EXECUTE) OpenInternalAgent();
    return MENU_NOREDRAW;
}

static t_menu g_menu[] = {
    { L"\x5185\x90E8\x52A9\x624B", L"\x6253\x5F00\x5185\x7F6E\x52A9\x624B", K_NONE, MenuInternal, NULL, 0 },
    { L"\x7EC8\x7AEF\x6A21\x5F0F", L"\x6253\x5F00\x7EC8\x7AEF\x6A21\x5F0F", K_NONE, MenuStart, NULL, 0 },
    { L"\x914D\x7F6E", L"\x914D\x7F6E AI Agent", K_NONE, MenuConfig, NULL, 0 },
    { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

static void UpdateMenuLanguage(void)
{
    HMODULE host = GetModuleHandleW(NULL);
    typedef BOOL (__cdecl *LanguageQuery)(void);
    LanguageQuery query = host ? (LanguageQuery)GetProcAddress(host, "Z0B_IsUiLanguageEnglish") : NULL;
    if (!query && host) query = (LanguageQuery)GetProcAddress(host, "IsUiLanguageEnglish");
    bool english = query ? query() != FALSE :
        PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_ENGLISH;
    if (english) {
        g_menu[0].name = L"Internal Assistant";
        g_menu[0].help = L"Open internal AI assistant";
        g_menu[1].name = L"Terminal Mode";
        g_menu[1].help = L"Open AI Agent terminal";
        g_menu[2].name = L"Configure";
        g_menu[2].help = L"Configure AI Agent";
    } else {
        g_menu[0].name = L"\x5185\x90E8\x52A9\x624B";
        g_menu[0].help = L"\x6253\x5F00\x5185\x7F6E\x52A9\x624B";
        g_menu[1].name = L"\x7EC8\x7AEF\x6A21\x5F0F";
        g_menu[1].help = L"\x6253\x5F00\x7EC8\x7AEF\x6A21\x5F0F";
        g_menu[2].name = L"\x914D\x7F6E";
        g_menu[2].help = L"\x914D\x7F6E AI Agent";
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_agent_instance = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) int __cdecl ODBG2_Pluginquery(int version, ulong*,
    wchar_t name[SHORTNAME], wchar_t pluginversion[SHORTNAME])
{
    if (version < 201) return 0;
    StringCchCopyW(name, SHORTNAME, L"Z0bDbgAgent");
    StringCchCopyW(pluginversion, SHORTNAME, L"1.0");
    return 201;
}

extern "C" __declspec(dllexport) int __cdecl ODBG2_Plugininit(void)
{
    return 0;
}

extern "C" __declspec(dllexport) t_menu* __cdecl ODBG2_Pluginmenu(wchar_t* type)
{
    if (type && lstrcmpiW(type, PWM_MAIN) == 0) {
        UpdateMenuLanguage();
        return g_menu;
    }
    return NULL;
}
