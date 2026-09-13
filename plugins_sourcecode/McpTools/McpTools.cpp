#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <winhttp.h>
#include <strsafe.h>
#include <deque>
#include <string>
#include <vector>
#include <cctype>
#include "plugin.h"

struct Z0B_RESULT {
    int type;
    int dtype;
    unsigned char data[16];
    char value[TEXTLEN];
    ulong lvaddr;
};

struct Z0B_MODULE {
    ulong base;
    ulong size;
    ulong type;
    ulong codebase;
    ulong codesize;
    ulong resbase;
    ulong ressize;
    void* stringtable;
    int nstringtable;
    int maxstringtable;
    ulong entry;
    ulong database;
    ulong idatatable;
    ulong idatabase;
    ulong edatatable;
    ulong edatasize;
    ulong reloctable;
    ulong relocsize;
    char name[32];
    char path[MAX_PATH];
};

typedef int (__cdecl* PFN_FindnameA)(ulong addr, int type, char* name);
typedef int (__cdecl* PFN_Getstatus)(void);
typedef int (__cdecl* PFN_Setbreakpoint)(ulong addr, ulong type, uchar cmd);
typedef int (__cdecl* PFN_Setbreakpointext)(ulong addr, ulong type, char cmd, ulong passcount);
typedef void (__cdecl* PFN_Deletebreakpoints)(ulong addr0, ulong addr1, int silent);
typedef int (__cdecl* PFN_Sethardwarebreakpoint)(ulong addr, int size, int type);
typedef int (__cdecl* PFN_Deletehardwarebreakbyaddr)(ulong addr);
typedef int (__cdecl* PFN_Deletehardwarebreakpoint)(int index);
typedef int (__cdecl* PFN_Suspendprocess)(int processevents);
typedef int (__cdecl* PFN_Go)(ulong threadid, ulong tilladdr, int stepmode, int givechance, int backupregs);
typedef ulong (__cdecl* PFN_Readmemory)(void* buf, ulong addr, ulong size, int mode);
typedef ulong (__cdecl* PFN_Writememory)(const void* buf, ulong addr, ulong size, int mode);
typedef int (__cdecl* PFN_Listmemory)(void);
typedef ulong (__cdecl* PFN_Disasm)(uchar* cmd, ulong cmdsize, ulong ip, uchar* dec, t_disasm* da, int mode, t_reg* reg, t_predict* predict);
typedef ulong (__cdecl* PFN_Assemble)(wchar_t* src, ulong ip, uchar* buf, ulong nbuf, int mode, wchar_t* errtxt);
typedef int (__cdecl* PFN_Removemembreakpoint)(ulong addr);
typedef ulong (__cdecl* PFN_Getcputhreadid)(void);
typedef void (__cdecl* PFN_Setcpu)(ulong threadid, ulong asmaddr, ulong dumpaddr, ulong selsize, ulong stackaddr, int mode);
typedef ulong (__cdecl* PFN_Followcall)(ulong addr);
typedef int (__cdecl* PFN_Run)(t_status status, int pass);
typedef int (__cdecl* PFN_InsertnameA)(ulong addr, int type, char* name);
typedef int (__cdecl* PFN_DecodeaddressA)(ulong addr, ulong base, int addrmode, char* s, int nsymb, char* comment);
typedef int (__cdecl* PFN_ExpressionA)(Z0B_RESULT* result, char* expression, int a, int b, uchar* data, ulong database, ulong datasize, ulong threadid);
typedef ulong (__cdecl* PFN_FinddataA)(ulong addr, int type, void* data, ulong datasize);
typedef ulong (__cdecl* PFN_Getbreakpointtype)(ulong addr);
typedef ulong (__cdecl* PFN_Getnextbreakpoint)(ulong addr, ulong* type, int* cmd);
typedef void (__cdecl* PFN_Tempbreakpoint)(ulong addr, int mode);
typedef void (__cdecl* PFN_VoidVoid)(void);
typedef HWND (__cdecl* PFN_WindowVoid)(void);
typedef void (__cdecl* PFN_SettraceconditionA)(char* cond, int onsuspicious, ulong in0, ulong in1, ulong out0, ulong out1);
typedef void (__cdecl* PFN_Settracecount)(ulong count);
typedef void (__cdecl* PFN_SettracepauseoncommandsA)(char* cmdset);
typedef int (__cdecl* PFN_Isprefix)(int prefix);
typedef int (__cdecl* PFN_SetmembreakpointSimple)(int type, ulong addr, ulong size);
typedef t_memory* (__cdecl* PFN_Findmemory)(ulong addr);
typedef void (__cdecl* PFN_Setdisasm)(ulong asmaddr, ulong selsize, int mode);
typedef int (__cdecl* PFN_FindlabelA)(ulong addr, char* name);
typedef Z0B_MODULE* (__cdecl* PFN_Findmodule)(ulong addr);
typedef ulong (__cdecl* PFN_Findfileoffset)(Z0B_MODULE* pmod, ulong addr);
typedef ulong (__cdecl* PFN_FindimportbynameA)(char* name, ulong addr0, ulong addr1);
typedef int (__cdecl* PFN_FindstringsA)(ulong base, ulong size, ulong origin, char* title);
typedef int (__cdecl* PFN_FindreferencesA)(ulong base, ulong size, ulong addr0, ulong addr1, ulong origin, int recurseonjump, char* title);
typedef int (__cdecl* PFN_Hardbreakpoints)(int closeondelete);
typedef void (__cdecl* PFN_Setdumptype)(void* pd, ulong dumptype);
typedef void (__cdecl* PFN_Dumpbackup)(void* pd, int action);
typedef void* (__cdecl* PFN_Findthread)(ulong threadid);
typedef ulong (__cdecl* PFN_Getbreakpointtypecount)(ulong addr, ulong* passcount);
typedef void* (__cdecl* PFN_Finddataptr)(ulong addr, int type, ulong* datasize);
typedef void (__cdecl* PFN_Pluginmodulechanged)(ulong addr);
typedef int (__cdecl* PFN_DecodenameA)(ulong addr, int type, char* name);
typedef char* (__cdecl* PFN_FinddecodeA)(ulong addr, ulong* psize);
typedef int (__cdecl* PFN_CommentaddressW)(ulong addr, int typelist, wchar_t* comment, int ncomment);
typedef int (__cdecl* PFN_SimpleaddressW)(wchar_t* text, ulong addr, uchar* mask, int* select);
typedef int (__cdecl* PFN_GetlasterrorW)(void* pthr, ulong* error, wchar_t* s);
typedef t_dump* (__cdecl* PFN_Getcpudisasmdump)(void);
typedef t_table* (__cdecl* PFN_Getcpudisasmtable)(void);
typedef ulong (__cdecl* PFN_Walkreference)(int dir);
typedef ulong (__cdecl* PFN_Walkreferenceex)(int dir, ulong* size);
typedef int (__cdecl* PFN_Plugintempbreakpoint)(ulong addr, int mode, int type, int size, int force);
typedef int (__cdecl* PFN_Pluginwriteinttoini)(HINSTANCE dllinst, char* key, int value);
typedef int (__cdecl* PFN_Pluginwritestringtoini)(HINSTANCE dllinst, char* key, char* s);
typedef int (__cdecl* PFN_Pluginreadintfromini)(HINSTANCE dllinst, char* key, int def);
typedef int (__cdecl* PFN_Pluginreadstringfromini)(HINSTANCE dllinst, char* key, char* s, char* def);
typedef BOOL (__cdecl* PFN_IsUiLanguageEnglish)(void);

static PFN_FindnameA pFindnameA = NULL;
static PFN_Getstatus pGetstatus = NULL;
static PFN_Setbreakpoint pSetbreakpoint = NULL;
static PFN_Setbreakpointext pSetbreakpointext = NULL;
static PFN_Deletebreakpoints pDeletebreakpoints = NULL;
static PFN_Sethardwarebreakpoint pSethardwarebreakpoint = NULL;
static PFN_Deletehardwarebreakbyaddr pDeletehardwarebreakbyaddr = NULL;
static PFN_Deletehardwarebreakpoint pDeletehardwarebreakpoint = NULL;
static PFN_Suspendprocess pSuspendprocess = NULL;
static PFN_Go pGo = NULL;
static PFN_Readmemory pReadmemory = NULL;
static PFN_Writememory pWritememory = NULL;
static PFN_Listmemory pListmemory = NULL;
static PFN_Disasm pDisasm = NULL;
static PFN_Assemble pAssemble = NULL;
static PFN_Removemembreakpoint pRemovemembreakpoint = NULL;
static PFN_Getcputhreadid pGetcputhreadid = NULL;
static PFN_Setcpu pSetcpu = NULL;
static PFN_Followcall pFollowcall = NULL;
static PFN_Run pRun = NULL;
static PFN_InsertnameA pInsertnameA = NULL;
static PFN_DecodeaddressA pDecodeaddressA = NULL;
static PFN_ExpressionA pExpressionA = NULL;
static PFN_FinddataA pFinddataA = NULL;
static PFN_Getbreakpointtype pGetbreakpointtype = NULL;
static PFN_Getnextbreakpoint pGetnextbreakpoint = NULL;
static PFN_Tempbreakpoint pTempbreakpoint = NULL;
static PFN_VoidVoid pRedrawcpudisasm = NULL;
static PFN_VoidVoid pRedrawcpureg = NULL;
static PFN_VoidVoid pRedrawlist = NULL;
static PFN_VoidVoid pSuspendallthreads = NULL;
static PFN_VoidVoid pResumeallthreads = NULL;
static PFN_WindowVoid pCreatethreadwindow = NULL;
static PFN_WindowVoid pCreatertracewindow = NULL;
static PFN_WindowVoid pCreatewinwindow = NULL;
static PFN_WindowVoid pCreatepatchwindow = NULL;
static PFN_WindowVoid pCreatewatchwindow = NULL;
static PFN_SettraceconditionA pSettraceconditionA = NULL;
static PFN_Settracecount pSettracecount = NULL;
static PFN_SettracepauseoncommandsA pSettracepauseoncommandsA = NULL;
static PFN_Isprefix pIsprefix = NULL;
static PFN_SetmembreakpointSimple pSetmembreakpointSimple = NULL;
static PFN_Findmemory pFindmemory = NULL;
static PFN_Setdisasm pSetdisasm = NULL;
static PFN_FindlabelA pFindlabelA = NULL;
static PFN_Findmodule pFindmodule = NULL;
static PFN_Findfileoffset pFindfileoffset = NULL;
static PFN_FindimportbynameA pFindimportbynameA = NULL;
static PFN_FindstringsA pFindstringsA = NULL;
static PFN_FindreferencesA pFindreferencesA = NULL;
static PFN_Hardbreakpoints pHardbreakpoints = NULL;
static PFN_Setdumptype pSetdumptype = NULL;
static PFN_Dumpbackup pDumpbackup = NULL;
static PFN_Findthread pFindthread = NULL;
static PFN_Getbreakpointtypecount pGetbreakpointtypecount = NULL;
static PFN_Finddataptr pFinddataptr = NULL;
static PFN_Pluginmodulechanged pPluginmodulechanged = NULL;
static PFN_DecodenameA pDecodenameA = NULL;
static PFN_FinddecodeA pFinddecodeA = NULL;
static PFN_CommentaddressW pCommentaddressW = NULL;
static PFN_SimpleaddressW pSimpleaddressW = NULL;
static PFN_GetlasterrorW pGetlasterrorW = NULL;
static PFN_Getcpudisasmdump pGetcpudisasmdump = NULL;
static PFN_Getcpudisasmtable pGetcpudisasmtable = NULL;
static PFN_Walkreference pWalkreference = NULL;
static PFN_Walkreferenceex pWalkreferenceex = NULL;
static PFN_Plugintempbreakpoint pPlugintempbreakpoint = NULL;
static PFN_Pluginwriteinttoini pPluginwriteinttoini = NULL;
static PFN_Pluginwritestringtoini pPluginwritestringtoini = NULL;
static PFN_Pluginreadintfromini pPluginreadintfromini = NULL;
static PFN_Pluginreadstringfromini pPluginreadstringfromini = NULL;
static PFN_IsUiLanguageEnglish pIsUiLanguageEnglish = NULL;

#define PLUGIN_NAME L"MCP Tools"
#define PLUGIN_VERSION_TEXT L"1.0"

#define IDC_ENABLE        1001
#define IDC_NAME          1002
#define IDC_TRANSPORT     1003
#define IDC_URL           1004
#define IDC_COMMAND       1005
#define IDC_ARGUMENTS     1006
#define IDC_WORKDIR       1007
#define IDC_ENV           1008
#define IDC_TIMEOUT       1009
#define IDC_BROWSE_CMD    1010
#define IDC_BROWSE_DIR    1011
#define IDC_SAVE          IDOK
#define IDC_CANCEL        IDCANCEL

struct McpConfig {
    BOOL enabled;
    wchar_t name[128];
    wchar_t transport[32];
    wchar_t url[512];
    wchar_t command[512];
    wchar_t arguments[1024];
    wchar_t workdir[MAX_PATH];
    wchar_t env[2048];
    int timeout_ms;
};

static HINSTANCE g_instance = NULL;
static McpConfig g_config;
static CRITICAL_SECTION g_config_cs;
static CRITICAL_SECTION g_queue_cs;
static CRITICAL_SECTION g_stdio_cs;
static std::deque<std::string> g_queue;
static HANDLE g_queue_event = NULL;
static HANDLE g_stop_event = NULL;
static HANDLE g_worker_thread = NULL;
static HANDLE g_stdio_process = NULL;
static HANDLE g_stdio_stdin = NULL;
static HANDLE g_stdio_stdout = NULL;
static HANDLE g_stdio_reader_thread = NULL;
static volatile LONG g_runtime_ready = 0;
static const size_t MCP_MAX_QUEUE = 512;

static DWORD WINAPI StdioReaderThreadProc(LPVOID);
static std::string ExecuteToolCommand(const std::string& json);

static void GetPluginDirectory(wchar_t* path, size_t cch)
{
    if (!path || cch == 0)
        return;
    path[0] = L'\0';
    GetModuleFileNameW(g_instance, path, (DWORD)cch);
    wchar_t* slash = wcsrchr(path, L'\\');
    if (slash)
        slash[1] = L'\0';
}

static void GetConfigPath(wchar_t* path, size_t cch)
{
    GetPluginDirectory(path, cch);
    StringCchCatW(path, cch, L"McpTools.ini");
}

static void SetDefaultConfig(McpConfig* cfg)
{
    ZeroMemory(cfg, sizeof(*cfg));
    cfg->enabled = FALSE;
    StringCchCopyW(cfg->name, _countof(cfg->name), L"local-mcp");
    StringCchCopyW(cfg->transport, _countof(cfg->transport), L"stdio");
    StringCchCopyW(cfg->url, _countof(cfg->url), L"http://127.0.0.1:3000/mcp");
    cfg->timeout_ms = 30000;
}

template<typename T>
static void ResolveHostExport(T* target, const char* name)
{
    HMODULE host = GetModuleHandleW(NULL);
    *target = host ? (T)GetProcAddress(host, name) : NULL;
}

static void ResolveHostExports(void)
{
    ResolveHostExport(&pFindnameA, "Findname");
    ResolveHostExport(&pGetstatus, "Getstatus");
    ResolveHostExport(&pSetbreakpoint, "Setbreakpoint");
    ResolveHostExport(&pSetbreakpointext, "Setbreakpointext");
    ResolveHostExport(&pDeletebreakpoints, "Deletebreakpoints");
    ResolveHostExport(&pSethardwarebreakpoint, "Sethardwarebreakpoint");
    ResolveHostExport(&pDeletehardwarebreakbyaddr, "Deletehardwarebreakbyaddr");
    ResolveHostExport(&pDeletehardwarebreakpoint, "Deletehardwarebreakpoint");
    ResolveHostExport(&pSuspendprocess, "Suspendprocess");
    ResolveHostExport(&pGo, "Go");
    ResolveHostExport(&pReadmemory, "Readmemory");
    ResolveHostExport(&pWritememory, "Writememory");
    ResolveHostExport(&pListmemory, "Listmemory");
    ResolveHostExport(&pDisasm, "Disasm");
    ResolveHostExport(&pAssemble, "Assemble");
    ResolveHostExport(&pRemovemembreakpoint, "Removemembreakpoint");
    ResolveHostExport(&pGetcputhreadid, "Getcputhreadid");
    ResolveHostExport(&pSetcpu, "Setcpu");
    ResolveHostExport(&pFollowcall, "Followcall");
    ResolveHostExport(&pRun, "Run");
    ResolveHostExport(&pInsertnameA, "Insertname");
    ResolveHostExport(&pDecodeaddressA, "Decodeaddress");
    ResolveHostExport(&pExpressionA, "Expression");
    ResolveHostExport(&pFinddataA, "Finddata");
    ResolveHostExport(&pGetbreakpointtype, "Getbreakpointtype");
    ResolveHostExport(&pGetnextbreakpoint, "Getnextbreakpoint");
    ResolveHostExport(&pTempbreakpoint, "Tempbreakpoint");
    ResolveHostExport(&pRedrawcpudisasm, "Redrawcpudisasm");
    ResolveHostExport(&pRedrawcpureg, "Redrawcpureg");
    ResolveHostExport(&pRedrawlist, "Redrawlist");
    ResolveHostExport(&pSuspendallthreads, "Suspendallthreads");
    ResolveHostExport(&pResumeallthreads, "Resumeallthreads");
    ResolveHostExport(&pCreatethreadwindow, "Createthreadwindow");
    ResolveHostExport(&pCreatertracewindow, "Creatertracewindow");
    ResolveHostExport(&pCreatewinwindow, "Createwinwindow");
    ResolveHostExport(&pCreatepatchwindow, "Createpatchwindow");
    ResolveHostExport(&pCreatewatchwindow, "Createwatchwindow");
    ResolveHostExport(&pSettraceconditionA, "Settracecondition");
    ResolveHostExport(&pSettracecount, "Settracecount");
    ResolveHostExport(&pSettracepauseoncommandsA, "Settracepauseoncommands");
    ResolveHostExport(&pIsprefix, "Isprefix");
    ResolveHostExport(&pSetmembreakpointSimple, "Setmembreakpoint");
    ResolveHostExport(&pFindmemory, "Findmemory");
    ResolveHostExport(&pSetdisasm, "Setdisasm");
    ResolveHostExport(&pFindlabelA, "Findlabel");
    ResolveHostExport(&pFindmodule, "Findmodule");
    ResolveHostExport(&pFindfileoffset, "Findfileoffset");
    ResolveHostExport(&pFindimportbynameA, "Findimportbyname");
    ResolveHostExport(&pFindstringsA, "Findstrings");
    ResolveHostExport(&pFindreferencesA, "Findreferences");
    ResolveHostExport(&pHardbreakpoints, "Hardbreakpoints");
    ResolveHostExport(&pSetdumptype, "Setdumptype");
    ResolveHostExport(&pDumpbackup, "Dumpbackup");
    ResolveHostExport(&pFindthread, "Findthread");
    ResolveHostExport(&pGetbreakpointtypecount, "Getbreakpointtypecount");
    ResolveHostExport(&pFinddataptr, "Finddataptr");
    ResolveHostExport(&pPluginmodulechanged, "Pluginmodulechanged");
    ResolveHostExport(&pDecodenameA, "Decodename");
    ResolveHostExport(&pFinddecodeA, "Finddecode");
    ResolveHostExport(&pCommentaddressW, "Commentaddress");
    ResolveHostExport(&pSimpleaddressW, "Simpleaddress");
    ResolveHostExport(&pGetlasterrorW, "Getlasterror");
    ResolveHostExport(&pGetcpudisasmdump, "Getcpudisasmdump");
    ResolveHostExport(&pGetcpudisasmtable, "Getcpudisasmtable");
    ResolveHostExport(&pWalkreference, "Walkreference");
    ResolveHostExport(&pWalkreferenceex, "Walkreferenceex");
    ResolveHostExport(&pPlugintempbreakpoint, "Plugintempbreakpoint");
    ResolveHostExport(&pPluginwriteinttoini, "Pluginwriteinttoini");
    ResolveHostExport(&pPluginwritestringtoini, "Pluginwritestringtoini");
    ResolveHostExport(&pPluginreadintfromini, "Pluginreadintfromini");
    ResolveHostExport(&pPluginreadstringfromini, "Pluginreadstringfromini");
    ResolveHostExport(&pIsUiLanguageEnglish, "Z0B_IsUiLanguageEnglish");
    if (!pIsUiLanguageEnglish)
        ResolveHostExport(&pIsUiLanguageEnglish, "IsUiLanguageEnglish");
}

static void LoadConfig(void)
{
    wchar_t path[MAX_PATH];
    GetConfigPath(path, _countof(path));
    McpConfig cfg;
    SetDefaultConfig(&cfg);

    cfg.enabled = GetPrivateProfileIntW(L"server", L"enabled", cfg.enabled, path) ? TRUE : FALSE;
    GetPrivateProfileStringW(L"server", L"name", cfg.name, cfg.name, _countof(cfg.name), path);
    GetPrivateProfileStringW(L"server", L"transport", cfg.transport, cfg.transport, _countof(cfg.transport), path);
    GetPrivateProfileStringW(L"server", L"url", cfg.url, cfg.url, _countof(cfg.url), path);
    GetPrivateProfileStringW(L"server", L"command", cfg.command, cfg.command, _countof(cfg.command), path);
    GetPrivateProfileStringW(L"server", L"arguments", cfg.arguments, cfg.arguments, _countof(cfg.arguments), path);
    GetPrivateProfileStringW(L"server", L"workdir", cfg.workdir, cfg.workdir, _countof(cfg.workdir), path);
    GetPrivateProfileStringW(L"server", L"env", cfg.env, cfg.env, _countof(cfg.env), path);
    cfg.timeout_ms = GetPrivateProfileIntW(L"server", L"timeout_ms", cfg.timeout_ms, path);
    if (cfg.timeout_ms <= 0)
        cfg.timeout_ms = 30000;

    EnterCriticalSection(&g_config_cs);
    g_config = cfg;
    LeaveCriticalSection(&g_config_cs);
}

static void WriteIntIni(const wchar_t* path, const wchar_t* section, const wchar_t* key, int value)
{
    wchar_t text[32];
    StringCchPrintfW(text, _countof(text), L"%d", value);
    WritePrivateProfileStringW(section, key, text, path);
}

static McpConfig CopyConfig(void);

static void SaveConfig(void)
{
    McpConfig cfg = CopyConfig();
    wchar_t path[MAX_PATH];
    GetConfigPath(path, _countof(path));
    WriteIntIni(path, L"server", L"enabled", cfg.enabled ? 1 : 0);
    WritePrivateProfileStringW(L"server", L"name", cfg.name, path);
    WritePrivateProfileStringW(L"server", L"transport", cfg.transport, path);
    WritePrivateProfileStringW(L"server", L"url", cfg.url, path);
    WritePrivateProfileStringW(L"server", L"command", cfg.command, path);
    WritePrivateProfileStringW(L"server", L"arguments", cfg.arguments, path);
    WritePrivateProfileStringW(L"server", L"workdir", cfg.workdir, path);
    WritePrivateProfileStringW(L"server", L"env", cfg.env, path);
    WriteIntIni(path, L"server", L"timeout_ms", cfg.timeout_ms);
}

static McpConfig CopyConfig(void)
{
    McpConfig cfg;
    EnterCriticalSection(&g_config_cs);
    cfg = g_config;
    LeaveCriticalSection(&g_config_cs);
    return cfg;
}

static bool McpIsEnglish(void)
{
    if (pIsUiLanguageEnglish)
        return pIsUiLanguageEnglish() != FALSE;
    return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_ENGLISH;
}

static const wchar_t* McpText(const wchar_t* zh, const wchar_t* en)
{
    return McpIsEnglish() ? en : zh;
}

static std::string WideToUtf8(const wchar_t* text)
{
    if (!text)
        return std::string();
    int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (needed <= 1)
        return std::string();
    std::string out;
    out.resize((size_t)needed - 1);
    WideCharToMultiByte(CP_UTF8, 0, text, -1, &out[0], needed, NULL, NULL);
    return out;
}

static void JsonAppendEscaped(std::string& out, const char* text)
{
    out.push_back('"');
    if (text) {
        for (const unsigned char* p = (const unsigned char*)text; *p; ++p) {
            switch (*p) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (*p < 0x20) {
                    char buf[8];
                    StringCchPrintfA(buf, _countof(buf), "\\u%04x", *p);
                    out += buf;
                }
                else {
                    out.push_back((char)*p);
                }
                break;
            }
        }
    }
    out.push_back('"');
}

static void JsonAppendWide(std::string& out, const wchar_t* text)
{
    std::string utf8 = WideToUtf8(text);
    JsonAppendEscaped(out, utf8.c_str());
}

static void JsonAppendHex64(std::string& out, unsigned __int64 value)
{
    char buf[32];
    StringCchPrintfA(buf, _countof(buf), "\"0x%llX\"", value);
    out += buf;
}

static void QueueJsonEvent(const std::string& json)
{
    if (InterlockedCompareExchange(&g_runtime_ready, 0, 0) == 0)
        return;
    EnterCriticalSection(&g_queue_cs);
    if (g_queue.size() >= MCP_MAX_QUEUE)
        g_queue.pop_front();
    g_queue.push_back(json);
    LeaveCriticalSection(&g_queue_cs);
    if (g_queue_event)
        SetEvent(g_queue_event);
}

static std::string BuildBaseEventPrefix(const char* event_name)
{
    std::string json;
    json.reserve(512);
    json += "{\"jsonrpc\":\"2.0\",\"method\":\"z0dbg/event\",\"params\":{\"source\":\"Z0BDbg\",\"plugin\":\"MCP Tools\",\"event\":";
    JsonAppendEscaped(json, event_name);
    json += ",\"tick\":";
    char tick[32];
    StringCchPrintfA(tick, _countof(tick), "%llu", (unsigned long long)GetTickCount64());
    json += tick;
    return json;
}

static bool HttpPostJson(const McpConfig& cfg, const std::string& json)
{
    if (!cfg.url[0])
        return false;

    URL_COMPONENTSW uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = (DWORD)-1;
    uc.dwHostNameLength = (DWORD)-1;
    uc.dwUrlPathLength = (DWORD)-1;
    uc.dwExtraInfoLength = (DWORD)-1;
    if (!WinHttpCrackUrl(cfg.url, 0, 0, &uc))
        return false;

    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength)
        path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    if (path.empty())
        path = L"/";

    DWORD access_type = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
    HINTERNET session = WinHttpOpen(L"Z0BDbg MCP Tools/1.0", access_type,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return false;

    DWORD timeout = (DWORD)cfg.timeout_ms;
    WinHttpSetTimeouts(session, timeout, timeout, timeout, timeout);

    HINTERNET connect = WinHttpConnect(session, host.c_str(), uc.nPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path.c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    const wchar_t* headers = L"Content-Type: application/json\r\n";
    BOOL ok = WinHttpSendRequest(request, headers, (DWORD)-1L,
        (LPVOID)json.data(), (DWORD)json.size(), (DWORD)json.size(), 0);
    if (ok)
        ok = WinHttpReceiveResponse(request, NULL);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return ok ? true : false;
}

static wchar_t* SkipSpaces(wchar_t* p)
{
    while (p && (*p == L' ' || *p == L'\t'))
        ++p;
    return p;
}

static void AppendEnvironmentBlock(std::wstring& env_block, const wchar_t* lines)
{
    if (!lines || !lines[0])
        return;
    const wchar_t* p = lines;
    while (*p) {
        const wchar_t* line = p;
        while (*p && *p != L'\r' && *p != L'\n')
            ++p;
        if (p > line) {
            env_block.append(line, p - line);
            env_block.push_back(L'\0');
        }
        while (*p == L'\r' || *p == L'\n')
            ++p;
    }
}

static std::wstring BuildEnvironmentBlock(const McpConfig& cfg)
{
    std::wstring env_block;
    LPWCH current = GetEnvironmentStringsW();
    if (current) {
        for (LPWCH p = current; *p; p += lstrlenW(p) + 1) {
            env_block.append(p);
            env_block.push_back(L'\0');
        }
        FreeEnvironmentStringsW(current);
    }
    AppendEnvironmentBlock(env_block, cfg.env);
    env_block.push_back(L'\0');
    return env_block;
}

static bool EnsureStdioProcess(const McpConfig& cfg)
{
    if (g_stdio_stdin)
        return true;
    if (!cfg.command[0])
        return false;

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE child_stdin_read = NULL;
    HANDLE child_stdin_write = NULL;
    HANDLE child_stdout_read = NULL;
    HANDLE child_stdout_write = NULL;
    if (!CreatePipe(&child_stdin_read, &child_stdin_write, &sa, 0))
        return false;
    SetHandleInformation(child_stdin_write, HANDLE_FLAG_INHERIT, 0);
    if (!CreatePipe(&child_stdout_read, &child_stdout_write, &sa, 0)) {
        CloseHandle(child_stdin_read);
        CloseHandle(child_stdin_write);
        return false;
    }
    SetHandleInformation(child_stdout_read, HANDLE_FLAG_INHERIT, 0);

    std::wstring cmdline = L"\"";
    cmdline += cfg.command;
    cmdline += L"\"";
    if (cfg.arguments[0]) {
        cmdline += L" ";
        cmdline += cfg.arguments;
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = child_stdin_read;
    si.hStdOutput = child_stdout_write;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.wShowWindow = SW_HIDE;

    std::wstring env = BuildEnvironmentBlock(cfg);
    BOOL ok = CreateProcessW(NULL, &cmdline[0], NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        env.empty() ? NULL : (LPVOID)env.c_str(), cfg.workdir[0] ? cfg.workdir : NULL, &si, &pi);
    CloseHandle(child_stdin_read);
    CloseHandle(child_stdout_write);
    if (!ok) {
        CloseHandle(child_stdin_write);
        CloseHandle(child_stdout_read);
        return false;
    }

    CloseHandle(pi.hThread);
    g_stdio_process = pi.hProcess;
    g_stdio_stdin = child_stdin_write;
    g_stdio_stdout = child_stdout_read;
    g_stdio_reader_thread = CreateThread(NULL, 0, StdioReaderThreadProc, NULL, 0, NULL);
    return true;
}

static void CloseStdioProcess(void)
{
    EnterCriticalSection(&g_stdio_cs);
    HANDLE reader = g_stdio_reader_thread;
    g_stdio_reader_thread = NULL;
    if (g_stdio_stdout) {
        CloseHandle(g_stdio_stdout);
        g_stdio_stdout = NULL;
    }
    if (g_stdio_stdin) {
        CloseHandle(g_stdio_stdin);
        g_stdio_stdin = NULL;
    }
    if (g_stdio_process) {
        CloseHandle(g_stdio_process);
        g_stdio_process = NULL;
    }
    LeaveCriticalSection(&g_stdio_cs);
    if (reader) {
        WaitForSingleObject(reader, 1000);
        CloseHandle(reader);
    }
}

static bool SendStdioJson(const McpConfig& cfg, const std::string& json)
{
    EnterCriticalSection(&g_stdio_cs);
    if (!EnsureStdioProcess(cfg))
    {
        LeaveCriticalSection(&g_stdio_cs);
        return false;
    }
    std::string line = json;
    line += "\n";
    DWORD written = 0;
    BOOL ok = WriteFile(g_stdio_stdin, line.data(), (DWORD)line.size(), &written, NULL);
    if (!ok) {
        if (g_stdio_stdin) {
            CloseHandle(g_stdio_stdin);
            g_stdio_stdin = NULL;
        }
        if (g_stdio_process) {
            CloseHandle(g_stdio_process);
            g_stdio_process = NULL;
        }
        LeaveCriticalSection(&g_stdio_cs);
        return false;
    }
    LeaveCriticalSection(&g_stdio_cs);
    return true;
}

static void SendJsonToServer(const McpConfig& cfg, const std::string& json)
{
    if (!cfg.enabled)
        return;
    if (lstrcmpiW(cfg.transport, L"stdio") == 0)
        SendStdioJson(cfg, json);
    else
        HttpPostJson(cfg, json);
}

static DWORD WINAPI WorkerThreadProc(LPVOID)
{
    HANDLE handles[2] = { g_stop_event, g_queue_event };
    for (;;) {
        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0)
            break;
        for (;;) {
            std::string item;
            EnterCriticalSection(&g_queue_cs);
            if (!g_queue.empty()) {
                item = g_queue.front();
                g_queue.pop_front();
            }
            LeaveCriticalSection(&g_queue_cs);
            if (item.empty())
                break;
            McpConfig cfg = CopyConfig();
            SendJsonToServer(cfg, item);
        }
    }
    CloseStdioProcess();
    return 0;
}

static void StartWorker(void)
{
    if (g_worker_thread)
        return;
    g_queue_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_queue_event && g_stop_event)
        g_worker_thread = CreateThread(NULL, 0, WorkerThreadProc, NULL, 0, NULL);
}

static void StopWorker(void)
{
    InterlockedExchange(&g_runtime_ready, 0);
    if (g_stop_event)
        SetEvent(g_stop_event);
    if (g_worker_thread) {
        WaitForSingleObject(g_worker_thread, 3000);
        CloseHandle(g_worker_thread);
        g_worker_thread = NULL;
    }
    if (g_queue_event) {
        CloseHandle(g_queue_event);
        g_queue_event = NULL;
    }
    if (g_stop_event) {
        CloseHandle(g_stop_event);
        g_stop_event = NULL;
    }
    EnterCriticalSection(&g_queue_cs);
    g_queue.clear();
    LeaveCriticalSection(&g_queue_cs);
}

static const char* DebugEventName(DWORD code)
{
    switch (code) {
    case EXCEPTION_DEBUG_EVENT: return "exception";
    case CREATE_THREAD_DEBUG_EVENT: return "create_thread";
    case CREATE_PROCESS_DEBUG_EVENT: return "create_process";
    case EXIT_THREAD_DEBUG_EVENT: return "exit_thread";
    case EXIT_PROCESS_DEBUG_EVENT: return "exit_process";
    case LOAD_DLL_DEBUG_EVENT: return "load_dll";
    case UNLOAD_DLL_DEBUG_EVENT: return "unload_dll";
    case OUTPUT_DEBUG_STRING_EVENT: return "output_debug_string";
    case RIP_EVENT: return "rip";
    default: return "unknown";
    }
}

static const char* NotifyName(int code)
{
    switch (code) {
    case PN_NEWPROC: return "new_process";
    case PN_ENDPROC: return "end_process";
    case PN_NEWTHR: return "new_thread";
    case PN_ENDTHR: return "end_thread";
    case PN_PREMOD: return "pre_module";
    case PN_NEWMOD: return "new_module";
    case PN_ENDMOD: return "end_module";
    case PN_REMOVE: return "remove_analysis";
    default: return "unknown";
    }
}

static void AppendDebugEventData(std::string& json, const DEBUG_EVENT* ev)
{
    json += ",\"debugEventCode\":";
    char num[64];
    StringCchPrintfA(num, _countof(num), "%lu", ev->dwDebugEventCode);
    json += num;
    json += ",\"debugEventName\":";
    JsonAppendEscaped(json, DebugEventName(ev->dwDebugEventCode));
    StringCchPrintfA(num, _countof(num), "%lu", ev->dwProcessId);
    json += ",\"processId\":";
    json += num;
    StringCchPrintfA(num, _countof(num), "%lu", ev->dwThreadId);
    json += ",\"threadId\":";
    json += num;

    switch (ev->dwDebugEventCode) {
    case EXCEPTION_DEBUG_EVENT:
        StringCchPrintfA(num, _countof(num), "%lu", ev->u.Exception.ExceptionRecord.ExceptionCode);
        json += ",\"exceptionCode\":";
        json += num;
        json += ",\"exceptionAddress\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.Exception.ExceptionRecord.ExceptionAddress);
        json += ",\"firstChance\":";
        json += ev->u.Exception.dwFirstChance ? "true" : "false";
        break;
    case CREATE_THREAD_DEBUG_EVENT:
        json += ",\"threadStartAddress\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.CreateThread.lpStartAddress);
        json += ",\"threadLocalBase\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.CreateThread.lpThreadLocalBase);
        break;
    case CREATE_PROCESS_DEBUG_EVENT:
        json += ",\"imageBase\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.CreateProcessInfo.lpBaseOfImage);
        json += ",\"startAddress\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.CreateProcessInfo.lpStartAddress);
        json += ",\"threadLocalBase\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.CreateProcessInfo.lpThreadLocalBase);
        break;
    case EXIT_THREAD_DEBUG_EVENT:
        StringCchPrintfA(num, _countof(num), "%lu", ev->u.ExitThread.dwExitCode);
        json += ",\"exitCode\":";
        json += num;
        break;
    case EXIT_PROCESS_DEBUG_EVENT:
        StringCchPrintfA(num, _countof(num), "%lu", ev->u.ExitProcess.dwExitCode);
        json += ",\"exitCode\":";
        json += num;
        break;
    case LOAD_DLL_DEBUG_EVENT:
        json += ",\"dllBase\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.LoadDll.lpBaseOfDll);
        json += ",\"imageNameAddress\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.LoadDll.lpImageName);
        json += ",\"unicodeImageName\":";
        json += ev->u.LoadDll.fUnicode ? "true" : "false";
        break;
    case UNLOAD_DLL_DEBUG_EVENT:
        json += ",\"dllBase\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.UnloadDll.lpBaseOfDll);
        break;
    case OUTPUT_DEBUG_STRING_EVENT:
        json += ",\"stringAddress\":";
        JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)ev->u.DebugString.lpDebugStringData);
        StringCchPrintfA(num, _countof(num), "%u", ev->u.DebugString.nDebugStringLength);
        json += ",\"stringLength\":";
        json += num;
        json += ",\"unicodeString\":";
        json += ev->u.DebugString.fUnicode ? "true" : "false";
        break;
    case RIP_EVENT:
        StringCchPrintfA(num, _countof(num), "%lu", ev->u.RipInfo.dwError);
        json += ",\"error\":";
        json += num;
        StringCchPrintfA(num, _countof(num), "%lu", ev->u.RipInfo.dwType);
        json += ",\"type\":";
        json += num;
        break;
    }
}

static void QueueDebuggerEvent(const DEBUG_EVENT* ev)
{
    if (!ev)
        return;
    std::string json = BuildBaseEventPrefix("debug_event");
    AppendDebugEventData(json, ev);
    json += "}}";
    QueueJsonEvent(json);
}

static void QueueNotifyEvent(int code, void* data, ulong parm1, ulong parm2)
{
    std::string json = BuildBaseEventPrefix("notify");
    char num[64];
    StringCchPrintfA(num, _countof(num), "%d", code);
    json += ",\"notifyCode\":";
    json += num;
    json += ",\"notifyName\":";
    JsonAppendEscaped(json, NotifyName(code));
    json += ",\"dataPointer\":";
    JsonAppendHex64(json, (unsigned __int64)(ULONG_PTR)data);
    json += ",\"parm1\":";
    JsonAppendHex64(json, (unsigned __int64)parm1);
    json += ",\"parm2\":";
    JsonAppendHex64(json, (unsigned __int64)parm2);
    json += "}}";
    QueueJsonEvent(json);
}

static void QueueSimpleEvent(const char* event_name)
{
    std::string json = BuildBaseEventPrefix(event_name);
    json += "}}";
    QueueJsonEvent(json);
}

static bool JsonFindString(const std::string& json, const char* key, std::string& value)
{
    std::string pattern = "\"";
    pattern += key;
    pattern += "\"";
    size_t p = json.find(pattern);
    if (p == std::string::npos)
        return false;
    p = json.find(':', p + pattern.size());
    if (p == std::string::npos)
        return false;
    p = json.find('"', p + 1);
    if (p == std::string::npos)
        return false;
    value.clear();
    for (++p; p < json.size(); ++p) {
        char c = json[p];
        if (c == '"')
            return true;
        if (c == '\\' && p + 1 < json.size()) {
            char e = json[++p];
            switch (e) {
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            case '\\': value.push_back('\\'); break;
            case '"': value.push_back('"'); break;
            default: value.push_back(e); break;
            }
        }
        else {
            value.push_back(c);
        }
    }
    return false;
}

static bool JsonFindUInt64(const std::string& json, const char* key, unsigned __int64& value)
{
    std::string text;
    if (JsonFindString(json, key, text)) {
        char* end = NULL;
        value = _strtoui64(text.c_str(), &end, 0);
        return end && end != text.c_str();
    }
    std::string pattern = "\"";
    pattern += key;
    pattern += "\"";
    size_t p = json.find(pattern);
    if (p == std::string::npos)
        return false;
    p = json.find(':', p + pattern.size());
    if (p == std::string::npos)
        return false;
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t'))
        ++p;
    size_t start = p;
    while (p < json.size() && (isalnum((unsigned char)json[p]) || json[p] == 'x' || json[p] == 'X'))
        ++p;
    if (p == start)
        return false;
    std::string num = json.substr(start, p - start);
    char* end = NULL;
    value = _strtoui64(num.c_str(), &end, 0);
    return end && end != num.c_str();
}

static std::wstring Utf8ToWide(const std::string& text)
{
    if (text.empty())
        return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), NULL, 0);
    if (needed <= 0)
        return std::wstring();
    std::wstring out;
    out.resize(needed);
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], needed);
    return out;
}

static int HexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static std::vector<uchar> HexToBytes(const std::string& hex)
{
    std::vector<uchar> bytes;
    int high = -1;
    for (size_t i = 0; i < hex.size(); ++i) {
        int d = HexDigit(hex[i]);
        if (d < 0)
            continue;
        if (high < 0) {
            high = d;
        }
        else {
            bytes.push_back((uchar)((high << 4) | d));
            high = -1;
        }
    }
    return bytes;
}

static std::string BytesToHex(const uchar* data, size_t size)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.resize(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = hex[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[data[i] & 0xF];
    }
    return out;
}

static ulong BreakAccessFromText(const std::string& access, ulong def)
{
    if (access == "read")
        return BP_READ;
    if (access == "write")
        return BP_WRITE;
    if (access == "execute" || access == "exec")
        return BP_EXEC;
    if (access == "readwrite" || access == "rw")
        return BP_READ | BP_WRITE;
    return def;
}

static std::string ToolListJson(void)
{
    const char* tools[] = {
        "get_status", "get_cpu_thread_id", "run", "go", "pause", "step_into", "step_over", "trace_into", "trace_over",
        "auto_step_into", "auto_step_over",
        "read_memory", "write_memory", "list_memory", "find_memory", "find_data_ptr",
        "set_software_breakpoint", "set_software_breakpoint_ext", "delete_software_breakpoint", "delete_breakpoint_range", "delete_all_breakpoints",
        "set_memory_breakpoint", "delete_memory_breakpoint",
        "set_hardware_breakpoint", "delete_hardware_breakpoint",
        "get_breakpoint_type", "get_breakpoint_type_count", "get_next_breakpoint", "set_temp_breakpoint",
        "plugin_temp_breakpoint",
        "disassemble", "assemble", "set_cpu", "set_disasm",
        "evaluate", "find_name", "insert_name", "decode_address", "decode_name", "comment_address", "simple_address", "find_label", "find_module", "find_thread", "find_data", "find_decode", "find_strings", "find_references", "find_import_by_name", "find_file_offset", "follow_call", "walk_reference", "walk_reference_ex", "is_prefix",
        "get_last_error", "get_cpu_disasm_dump", "get_cpu_disasm_table",
        "plugin_read_ini_int", "plugin_write_ini_int", "plugin_read_ini_string", "plugin_write_ini_string",
        "redraw_disasm", "redraw_registers", "redraw_list", "redraw_all",
        "suspend_all_threads", "resume_all_threads",
        "show_memory", "show_breakpoints", "show_hardware_breakpoints", "show_threads", "show_trace", "show_windows", "show_patches", "show_watch",
        "set_trace_condition", "set_trace_count", "set_trace_pause_on_commands",
        "set_dump_type", "dump_backup", "plugin_module_changed"
    };
    std::string out = "[";
    for (size_t i = 0; i < _countof(tools); ++i) {
        if (i)
            out += ",";
        JsonAppendEscaped(out, tools[i]);
    }
    out += "]";
    return out;
}

static std::string JsonRpcResult(const std::string& id, const std::string& result_json)
{
    std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
    if (id.empty())
        out += "null";
    else
        out += id;
    out += ",\"result\":";
    out += result_json;
    out += "}";
    return out;
}

static std::string JsonRpcError(const std::string& id, int code, const char* message)
{
    char num[32];
    StringCchPrintfA(num, _countof(num), "%d", code);
    std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
    if (id.empty())
        out += "null";
    else
        out += id;
    out += ",\"error\":{\"code\":";
    out += num;
    out += ",\"message\":";
    JsonAppendEscaped(out, message);
    out += "}}";
    return out;
}

static std::string ExtractIdJson(const std::string& json)
{
    std::string pattern = "\"id\"";
    size_t p = json.find(pattern);
    if (p == std::string::npos)
        return std::string();
    p = json.find(':', p + pattern.size());
    if (p == std::string::npos)
        return std::string();
    ++p;
    while (p < json.size() && isspace((unsigned char)json[p]))
        ++p;
    if (p >= json.size())
        return std::string();
    if (json[p] == '"') {
        std::string value;
        if (JsonFindString(json, "id", value)) {
            std::string out;
            JsonAppendEscaped(out, value.c_str());
            return out;
        }
        return std::string();
    }
    size_t start = p;
    while (p < json.size() && (isalnum((unsigned char)json[p]) || json[p] == '-' || json[p] == '+'))
        ++p;
    return json.substr(start, p - start);
}

static std::string ExecuteToolCommand(const std::string& json)
{
    std::string id = ExtractIdJson(json);
    std::string method;
    JsonFindString(json, "method", method);

    if (method == "z0dbg.tools" || method == "tools/list")
        return JsonRpcResult(id, ToolListJson());

    std::string tool;
    if (!JsonFindString(json, "tool", tool))
        JsonFindString(json, "name", tool);
    if (tool.empty() && method.find("z0dbg.") == 0)
        tool = method.substr(6);
    if (tool.empty())
        return JsonRpcError(id, -32601, "missing tool name");

    unsigned __int64 address = 0, size = 0, index = 0, type_value = 0, count = 0;
    std::string access, hex, text, name, expression, condition, cmdset, key, value, defvalue;
    JsonFindUInt64(json, "address", address);
    JsonFindUInt64(json, "addr", address);
    JsonFindUInt64(json, "size", size);
    JsonFindUInt64(json, "index", index);
    JsonFindUInt64(json, "type", type_value);
    JsonFindUInt64(json, "count", count);
    JsonFindString(json, "access", access);
    JsonFindString(json, "hex", hex);
    JsonFindString(json, "data", hex);
    JsonFindString(json, "text", text);
    JsonFindString(json, "assembly", text);
    JsonFindString(json, "name", name);
    JsonFindString(json, "expression", expression);
    JsonFindString(json, "condition", condition);
    JsonFindString(json, "cmdset", cmdset);
    JsonFindString(json, "key", key);
    JsonFindString(json, "value", value);
    JsonFindString(json, "default", defvalue);

    int rc = 0;
    if (tool == "get_status") {
        if (!pGetstatus)
            return JsonRpcError(id, -32001, "Getstatus is not available");
        rc = pGetstatus();
    }
    else if (tool == "get_cpu_thread_id") {
        if (!pGetcputhreadid)
            return JsonRpcError(id, -32001, "Getcputhreadid is not available");
        std::string result = "{\"ok\":true,\"threadId\":";
        JsonAppendHex64(result, (unsigned __int64)pGetcputhreadid());
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "run")
    {
        if (!pRun)
            return JsonRpcError(id, -32001, "Run is not available");
        rc = pRun(STAT_RUNNING, 0);
    }
    else if (tool == "go")
    {
        if (!pGo)
            return JsonRpcError(id, -32001, "Go is not available");
        if (!pGetcputhreadid)
            return JsonRpcError(id, -32001, "Getcputhreadid is not available");
        rc = pGo(pGetcputhreadid(), (ulong)address, 0, 0, 0);
    }
    else if (tool == "pause")
    {
        if (!pSuspendprocess)
            return JsonRpcError(id, -32001, "Suspendprocess is not available");
        rc = pSuspendprocess(0);
    }
    else if (tool == "step_into")
    {
        if (!pRun)
            return JsonRpcError(id, -32001, "Run is not available");
        rc = pRun(STAT_STEPIN, 0);
    }
    else if (tool == "step_over")
    {
        if (!pRun)
            return JsonRpcError(id, -32001, "Run is not available");
        rc = pRun(STAT_STEPOVER, 0);
    }
    else if (tool == "trace_into")
    {
        if (!pRun)
            return JsonRpcError(id, -32001, "Run is not available");
        rc = pRun(STAT_TRACEIN, 0);
    }
    else if (tool == "trace_over")
    {
        if (!pRun)
            return JsonRpcError(id, -32001, "Run is not available");
        rc = pRun(STAT_TRACEOVER, 0);
    }
    else if (tool == "auto_step_into")
    {
        if (!pRun)
            return JsonRpcError(id, -32001, "Run is not available");
        rc = pRun(STAT_ANIMIN, 0);
    }
    else if (tool == "auto_step_over")
    {
        if (!pRun)
            return JsonRpcError(id, -32001, "Run is not available");
        rc = pRun(STAT_ANIMOVER, 0);
    }
    else if (tool == "close_process")
        return JsonRpcError(id, -32601, "close_process is not exported by current debugger SDK");
    else if (tool == "list_memory")
    {
        if (!pListmemory)
            return JsonRpcError(id, -32001, "Listmemory is not available");
        rc = pListmemory();
    }
    else if (tool == "find_memory") {
        if (!pFindmemory)
            return JsonRpcError(id, -32001, "Findmemory is not available");
        t_memory* mem = pFindmemory((ulong)address);
        if (!mem)
            return JsonRpcResult(id, "{\"ok\":false}");
        std::string result = "{\"ok\":true,\"base\":";
        JsonAppendHex64(result, (unsigned __int64)mem->base);
        result += ",\"size\":";
        JsonAppendHex64(result, (unsigned __int64)mem->size);
        result += ",\"access\":";
        JsonAppendHex64(result, (unsigned __int64)mem->access);
        result += ",\"initAccess\":";
        JsonAppendHex64(result, (unsigned __int64)mem->initaccess);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_data_ptr") {
        if (!pFinddataptr)
            return JsonRpcError(id, -32001, "Finddataptr is not available");
        ulong datasize = 0;
        void* ptr = pFinddataptr((ulong)address, (int)type_value, &datasize);
        std::string result = "{\"ok\":";
        result += ptr ? "true" : "false";
        result += ",\"pointer\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)ptr);
        result += ",\"size\":";
        JsonAppendHex64(result, (unsigned __int64)datasize);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "read_memory") {
        if (!address || !size || size > 1024 * 1024)
            return JsonRpcError(id, -32602, "read_memory requires address and size <= 1MB");
        std::vector<uchar> buf((size_t)size);
        if (!pReadmemory)
            return JsonRpcError(id, -32001, "Readmemory is not available");
        ulong read = pReadmemory(buf.data(), (ulong)address, (ulong)size, MM_SILENT);
        std::string result = "{\"ok\":true,\"read\":";
        char num[32];
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)read);
        result += num;
        result += ",\"hex\":";
        std::string outhex = BytesToHex(buf.data(), (size_t)read);
        JsonAppendEscaped(result, outhex.c_str());
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "write_memory") {
        if (!address || hex.empty())
            return JsonRpcError(id, -32602, "write_memory requires address and hex/data");
        std::vector<uchar> buf = HexToBytes(hex);
        if (!pWritememory)
            return JsonRpcError(id, -32001, "Writememory is not available");
        ulong written = buf.empty() ? 0 : pWritememory(buf.data(), (ulong)address, (ulong)buf.size(), MM_SILENT);
        char num[32];
        std::string result = "{\"ok\":true,\"written\":";
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)written);
        result += num;
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "set_software_breakpoint") {
        if (!pSetbreakpoint)
            return JsonRpcError(id, -32001, "Setbreakpoint is not available");
        rc = pSetbreakpoint((ulong)address, BP_MANUAL | BP_BREAK, 0);
    }
    else if (tool == "set_software_breakpoint_ext") {
        if (!pSetbreakpointext)
            return JsonRpcError(id, -32001, "Setbreakpointext is not available");
        rc = pSetbreakpointext((ulong)address, BP_MANUAL | BP_BREAK, 0, (ulong)count);
    }
    else if (tool == "delete_software_breakpoint") {
        if (!pDeletebreakpoints)
            return JsonRpcError(id, -32001, "Deletebreakpoints is not available");
        pDeletebreakpoints((ulong)address, (ulong)address + 1, 1);
        rc = 0;
    }
    else if (tool == "delete_breakpoint_range") {
        if (!size)
            return JsonRpcError(id, -32602, "delete_breakpoint_range requires address and size");
        if (!pDeletebreakpoints)
            return JsonRpcError(id, -32001, "Deletebreakpoints is not available");
        pDeletebreakpoints((ulong)address, (ulong)(address + size), 1);
        rc = 0;
    }
    else if (tool == "delete_all_breakpoints") {
        if (!pDeletebreakpoints)
            return JsonRpcError(id, -32001, "Deletebreakpoints is not available");
        pDeletebreakpoints(0, ~(ulong)0, 1);
        rc = 0;
    }
    else if (tool == "set_memory_breakpoint") {
        if (!size)
            size = 1;
        if (!pSetmembreakpointSimple)
            return JsonRpcError(id, -32001, "Setmembreakpoint is not available");
        rc = pSetmembreakpointSimple((int)BreakAccessFromText(access, BP_READ | BP_WRITE), (ulong)address, (ulong)size);
    }
    else if (tool == "delete_memory_breakpoint") {
        if (!pRemovemembreakpoint)
            return JsonRpcError(id, -32001, "Removemembreakpoint is not available");
        rc = pRemovemembreakpoint((ulong)address);
    }
    else if (tool == "set_hardware_breakpoint") {
        if (!size)
            size = 1;
        if (!pSethardwarebreakpoint)
            return JsonRpcError(id, -32001, "Sethardwarebreakpoint is not available");
        rc = pSethardwarebreakpoint((ulong)address, (int)size, (int)(BreakAccessFromText(access, BP_EXEC) | BP_MANUAL | BP_BREAK));
    }
    else if (tool == "delete_hardware_breakpoint") {
        if (address)
        {
            if (!pDeletehardwarebreakbyaddr)
                return JsonRpcError(id, -32001, "Deletehardwarebreakbyaddr is not available");
            rc = pDeletehardwarebreakbyaddr((ulong)address);
        }
        else
        {
            if (!pDeletehardwarebreakpoint)
                return JsonRpcError(id, -32001, "Deletehardwarebreakpoint is not available");
            rc = pDeletehardwarebreakpoint((int)index);
        }
    }
    else if (tool == "get_breakpoint_type") {
        if (!pGetbreakpointtype)
            return JsonRpcError(id, -32001, "Getbreakpointtype is not available");
        ulong typ = pGetbreakpointtype((ulong)address);
        char num[32];
        std::string result = "{\"ok\":true,\"type\":";
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)typ);
        result += num;
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "get_breakpoint_type_count") {
        if (!pGetbreakpointtypecount)
            return JsonRpcError(id, -32001, "Getbreakpointtypecount is not available");
        ulong passcount = 0;
        ulong typ = pGetbreakpointtypecount((ulong)address, &passcount);
        std::string result = "{\"ok\":true,\"type\":";
        JsonAppendHex64(result, (unsigned __int64)typ);
        result += ",\"passCount\":";
        JsonAppendHex64(result, (unsigned __int64)passcount);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "get_next_breakpoint") {
        if (!pGetnextbreakpoint)
            return JsonRpcError(id, -32001, "Getnextbreakpoint is not available");
        ulong typ = 0;
        int cmd = 0;
        ulong next = pGetnextbreakpoint((ulong)address, &typ, &cmd);
        char num[32];
        std::string result = "{\"ok\":true,\"address\":";
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)next);
        result += num;
        result += ",\"type\":";
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)typ);
        result += num;
        result += ",\"cmd\":";
        StringCchPrintfA(num, _countof(num), "%d", cmd);
        result += num;
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "set_temp_breakpoint") {
        if (!pTempbreakpoint)
            return JsonRpcError(id, -32001, "Tempbreakpoint is not available");
        pTempbreakpoint((ulong)address, (int)type_value);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "plugin_temp_breakpoint") {
        if (!pPlugintempbreakpoint)
            return JsonRpcError(id, -32001, "Plugintempbreakpoint is not available");
        rc = pPlugintempbreakpoint((ulong)address, (int)type_value, (int)BreakAccessFromText(access, BP_EXEC), (int)size, 1);
    }
    else if (tool == "disassemble") {
        uchar cmd[32] = { 0 };
        if (!pReadmemory || !pDisasm)
            return JsonRpcError(id, -32001, "Disasm is not available");
        ulong read = pReadmemory(cmd, (ulong)address, sizeof(cmd), MM_SILENT);
        if (!read)
            return JsonRpcError(id, -32000, "failed to read instruction bytes");
        t_disasm da;
        ZeroMemory(&da, sizeof(da));
        ulong len = pDisasm(cmd, read, (ulong)address, NULL, &da, 0, NULL, NULL);
        std::string result = "{\"ok\":true,\"size\":";
        char num[32];
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)len);
        result += num;
        result += ",\"text\":";
        JsonAppendWide(result, da.result);
        result += ",\"dump\":";
        JsonAppendWide(result, da.dump);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "assemble") {
        if (text.empty())
            return JsonRpcError(id, -32602, "assemble requires text/assembly");
        uchar buf[32] = { 0 };
        wchar_t err[TEXTLEN] = { 0 };
        std::wstring wtext = Utf8ToWide(text);
        if (!pAssemble)
            return JsonRpcError(id, -32001, "Assemble is not available");
        ulong n = pAssemble((wchar_t*)wtext.c_str(), (ulong)address, buf, sizeof(buf), 0, err);
        if (!n) {
            std::string e = "assemble failed";
            std::string result = "{\"ok\":false,\"error\":";
            JsonAppendWide(result, err[0] ? err : L"assemble failed");
            result += "}";
            return JsonRpcResult(id, result);
        }
        std::string result = "{\"ok\":true,\"size\":";
        char num[32];
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)n);
        result += num;
        result += ",\"hex\":";
        std::string outhex = BytesToHex(buf, n);
        JsonAppendEscaped(result, outhex.c_str());
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "set_cpu") {
        if (!pSetcpu || !pGetcputhreadid)
            return JsonRpcError(id, -32001, "Setcpu is not available");
        pSetcpu(pGetcputhreadid(), (ulong)address, 0, 0, 0, CPU_ASMHIST | CPU_ASMCENTER | CPU_ASMFOCUS | CPU_REDRAW);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "set_disasm") {
        if (!pSetdisasm)
            return JsonRpcError(id, -32001, "Setdisasm is not available");
        pSetdisasm((ulong)address, (ulong)size, (int)type_value);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "evaluate") {
        if (!pExpressionA)
            return JsonRpcError(id, -32001, "Expression is not available");
        if (expression.empty())
            expression = text;
        if (expression.empty())
            return JsonRpcError(id, -32602, "evaluate requires expression");
        Z0B_RESULT res;
        ZeroMemory(&res, sizeof(res));
        if (!pGetcputhreadid)
            return JsonRpcError(id, -32001, "Getcputhreadid is not available");
        int ok = pExpressionA(&res, (char*)expression.c_str(), 0, 0, NULL, 0, 0, pGetcputhreadid());
        std::string result = "{\"ok\":";
        result += ok ? "true" : "false";
        result += ",\"value\":";
        JsonAppendEscaped(result, res.value);
        result += ",\"number\":";
        JsonAppendHex64(result, *(unsigned __int64*)res.data);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_name") {
        if (!pFindnameA)
            return JsonRpcError(id, -32001, "Findname is not available");
        char buf[TEXTLEN] = { 0 };
        int n = pFindnameA((ulong)address, (int)type_value, buf);
        std::string result = "{\"ok\":";
        result += n ? "true" : "false";
        result += ",\"name\":";
        JsonAppendEscaped(result, buf);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "insert_name") {
        if (!pInsertnameA)
            return JsonRpcError(id, -32001, "Insertname is not available");
        if (name.empty())
            name = text;
        rc = pInsertnameA((ulong)address, (int)type_value, (char*)name.c_str());
    }
    else if (tool == "decode_address") {
        if (!pDecodeaddressA)
            return JsonRpcError(id, -32001, "Decodeaddress is not available");
        char symbol[TEXTLEN] = { 0 };
        char comment[TEXTLEN] = { 0 };
        int n = pDecodeaddressA((ulong)address, 0, (int)type_value, symbol, TEXTLEN, comment);
        std::string result = "{\"ok\":";
        result += n ? "true" : "false";
        result += ",\"text\":";
        JsonAppendEscaped(result, symbol);
        result += ",\"comment\":";
        JsonAppendEscaped(result, comment);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "decode_name") {
        if (!pDecodenameA)
            return JsonRpcError(id, -32001, "Decodename is not available");
        char buf[TEXTLEN] = { 0 };
        int n = pDecodenameA((ulong)address, (int)type_value, buf);
        std::string result = "{\"ok\":";
        result += n ? "true" : "false";
        result += ",\"name\":";
        JsonAppendEscaped(result, buf);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "comment_address") {
        if (!pCommentaddressW)
            return JsonRpcError(id, -32001, "Commentaddress is not available");
        wchar_t buf[TEXTLEN] = { 0 };
        int n = pCommentaddressW((ulong)address, (int)(type_value ? type_value : 0xFFFFFFFF), buf, _countof(buf));
        std::string result = "{\"ok\":";
        result += n ? "true" : "false";
        result += ",\"comment\":";
        JsonAppendWide(result, buf);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "simple_address") {
        if (!pSimpleaddressW)
            return JsonRpcError(id, -32001, "Simpleaddress is not available");
        wchar_t buf[TEXTLEN] = { 0 };
        uchar mask[TEXTLEN] = { 0 };
        int select = 0;
        int n = pSimpleaddressW(buf, (ulong)address, mask, &select);
        std::string result = "{\"ok\":";
        result += n ? "true" : "false";
        result += ",\"text\":";
        JsonAppendWide(result, buf);
        result += ",\"select\":";
        char num[32];
        StringCchPrintfA(num, _countof(num), "%d", select);
        result += num;
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_label") {
        if (!pFindlabelA)
            return JsonRpcError(id, -32001, "Findlabel is not available");
        char buf[TEXTLEN] = { 0 };
        int n = pFindlabelA((ulong)address, buf);
        std::string result = "{\"ok\":";
        result += n ? "true" : "false";
        result += ",\"label\":";
        JsonAppendEscaped(result, buf);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_module") {
        if (!pFindmodule)
            return JsonRpcError(id, -32001, "Findmodule is not available");
        Z0B_MODULE* mod = pFindmodule((ulong)address);
        if (!mod)
            return JsonRpcResult(id, "{\"ok\":false}");
        std::string result = "{\"ok\":true,\"base\":";
        JsonAppendHex64(result, (unsigned __int64)mod->base);
        result += ",\"size\":";
        JsonAppendHex64(result, (unsigned __int64)mod->size);
        result += ",\"entry\":";
        JsonAppendHex64(result, (unsigned __int64)mod->entry);
        result += ",\"name\":";
        JsonAppendEscaped(result, mod->name);
        result += ",\"path\":";
        JsonAppendEscaped(result, mod->path);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_thread") {
        if (!pFindthread)
            return JsonRpcError(id, -32001, "Findthread is not available");
        if (!pGetcputhreadid)
            return JsonRpcError(id, -32001, "Getcputhreadid is not available");
        void* th = pFindthread((ulong)(address ? address : pGetcputhreadid()));
        std::string result = "{\"ok\":";
        result += th ? "true" : "false";
        result += ",\"pointer\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)th);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_data") {
        if (!pFinddataA)
            return JsonRpcError(id, -32001, "Finddata is not available");
        std::vector<uchar> buf = HexToBytes(hex);
        if (buf.empty())
            return JsonRpcError(id, -32602, "find_data requires hex/data");
        ulong found = pFinddataA((ulong)address, (int)type_value, buf.data(), (ulong)buf.size());
        std::string result = "{\"ok\":true,\"address\":";
        JsonAppendHex64(result, found);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_decode") {
        if (!pFinddecodeA)
            return JsonRpcError(id, -32001, "Finddecode is not available");
        ulong decoded_size = 0;
        char* decoded = pFinddecodeA((ulong)address, &decoded_size);
        std::string result = "{\"ok\":";
        result += decoded ? "true" : "false";
        result += ",\"size\":";
        JsonAppendHex64(result, (unsigned __int64)decoded_size);
        result += ",\"text\":";
        JsonAppendEscaped(result, decoded ? decoded : "");
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_strings") {
        if (!pFindstringsA)
            return JsonRpcError(id, -32001, "Findstrings is not available");
        if (!size)
            return JsonRpcError(id, -32602, "find_strings requires base/address and size");
        rc = pFindstringsA((ulong)address, (ulong)size, 0, (char*)(text.empty() ? "MCP strings" : text.c_str()));
    }
    else if (tool == "find_references") {
        if (!pFindreferencesA)
            return JsonRpcError(id, -32001, "Findreferences is not available");
        unsigned __int64 target0 = 0, target1 = 0;
        JsonFindUInt64(json, "target", target0);
        JsonFindUInt64(json, "target0", target0);
        JsonFindUInt64(json, "target1", target1);
        if (!size || !target0)
            return JsonRpcError(id, -32602, "find_references requires base/address, size and target");
        rc = pFindreferencesA((ulong)address, (ulong)size, (ulong)target0, (ulong)target1, 0, 0, (char*)(text.empty() ? "MCP references" : text.c_str()));
    }
    else if (tool == "find_import_by_name") {
        if (!pFindimportbynameA)
            return JsonRpcError(id, -32001, "Findimportbyname is not available");
        if (name.empty())
            name = text;
        ulong found = pFindimportbynameA((char*)name.c_str(), (ulong)address, (ulong)(size ? address + size : 0));
        std::string result = "{\"ok\":";
        result += found ? "true" : "false";
        result += ",\"address\":";
        JsonAppendHex64(result, (unsigned __int64)found);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_file_offset") {
        if (!pFindmodule || !pFindfileoffset)
            return JsonRpcError(id, -32001, "Findmodule/Findfileoffset is not available");
        Z0B_MODULE* mod = pFindmodule((ulong)address);
        ulong off = mod ? pFindfileoffset(mod, (ulong)address) : 0;
        std::string result = "{\"ok\":";
        result += off ? "true" : "false";
        result += ",\"offset\":";
        JsonAppendHex64(result, (unsigned __int64)off);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "follow_call") {
        if (!pFollowcall)
            return JsonRpcError(id, -32001, "Followcall is not available");
        ulong target = pFollowcall((ulong)address);
        std::string result = "{\"ok\":true,\"address\":";
        JsonAppendHex64(result, target);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "walk_reference") {
        if (!pWalkreference)
            return JsonRpcError(id, -32001, "Walkreference is not available");
        ulong ref = pWalkreference((int)type_value);
        std::string result = "{\"ok\":";
        result += ref ? "true" : "false";
        result += ",\"address\":";
        JsonAppendHex64(result, (unsigned __int64)ref);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "walk_reference_ex") {
        if (!pWalkreferenceex)
            return JsonRpcError(id, -32001, "Walkreferenceex is not available");
        ulong refsize = 0;
        ulong ref = pWalkreferenceex((int)type_value, &refsize);
        std::string result = "{\"ok\":";
        result += ref ? "true" : "false";
        result += ",\"address\":";
        JsonAppendHex64(result, (unsigned __int64)ref);
        result += ",\"size\":";
        JsonAppendHex64(result, (unsigned __int64)refsize);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "is_prefix") {
        if (!pIsprefix)
            return JsonRpcError(id, -32001, "Isprefix is not available");
        rc = pIsprefix((int)type_value);
    }
    else if (tool == "get_last_error") {
        if (!pGetlasterrorW)
            return JsonRpcError(id, -32001, "Getlasterror is not available");
        ulong error = 0;
        wchar_t buf[TEXTLEN] = { 0 };
        int ok = pGetlasterrorW(NULL, &error, buf);
        std::string result = "{\"ok\":";
        result += ok ? "true" : "false";
        result += ",\"code\":";
        JsonAppendHex64(result, (unsigned __int64)error);
        result += ",\"text\":";
        JsonAppendWide(result, buf);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "get_cpu_disasm_dump") {
        if (!pGetcpudisasmdump)
            return JsonRpcError(id, -32001, "Getcpudisasmdump is not available");
        t_dump* dump = pGetcpudisasmdump();
        if (!dump)
            return JsonRpcResult(id, "{\"ok\":false}");
        std::string result = "{\"ok\":true,\"pointer\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)dump);
        result += ",\"base\":";
        JsonAppendHex64(result, (unsigned __int64)dump->base);
        result += ",\"size\":";
        JsonAppendHex64(result, (unsigned __int64)dump->size);
        result += ",\"addr\":";
        JsonAppendHex64(result, (unsigned __int64)dump->addr);
        result += ",\"sel0\":";
        JsonAppendHex64(result, (unsigned __int64)dump->sel0);
        result += ",\"sel1\":";
        JsonAppendHex64(result, (unsigned __int64)dump->sel1);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "get_cpu_disasm_table") {
        if (!pGetcpudisasmtable)
            return JsonRpcError(id, -32001, "Getcpudisasmtable is not available");
        t_table* table = pGetcpudisasmtable();
        std::string result = "{\"ok\":";
        result += table ? "true" : "false";
        result += ",\"pointer\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)table);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "plugin_read_ini_int") {
        if (!pPluginreadintfromini)
            return JsonRpcError(id, -32001, "Pluginreadintfromini is not available");
        if (key.empty())
            return JsonRpcError(id, -32602, "plugin_read_ini_int requires key");
        int defint = (int)type_value;
        int got = pPluginreadintfromini(g_instance, (char*)key.c_str(), defint);
        char num[32];
        std::string result = "{\"ok\":true,\"value\":";
        StringCchPrintfA(num, _countof(num), "%d", got);
        result += num;
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "plugin_write_ini_int") {
        if (!pPluginwriteinttoini)
            return JsonRpcError(id, -32001, "Pluginwriteinttoini is not available");
        if (key.empty())
            return JsonRpcError(id, -32602, "plugin_write_ini_int requires key");
        rc = pPluginwriteinttoini(g_instance, (char*)key.c_str(), (int)type_value);
    }
    else if (tool == "plugin_read_ini_string") {
        if (!pPluginreadstringfromini)
            return JsonRpcError(id, -32001, "Pluginreadstringfromini is not available");
        if (key.empty())
            return JsonRpcError(id, -32602, "plugin_read_ini_string requires key");
        char buf[TEXTLEN] = { 0 };
        int n = pPluginreadstringfromini(g_instance, (char*)key.c_str(), buf, (char*)defvalue.c_str());
        std::string result = "{\"ok\":true,\"read\":";
        char num[32];
        StringCchPrintfA(num, _countof(num), "%d", n);
        result += num;
        result += ",\"value\":";
        JsonAppendEscaped(result, buf);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "plugin_write_ini_string") {
        if (!pPluginwritestringtoini)
            return JsonRpcError(id, -32001, "Pluginwritestringtoini is not available");
        if (key.empty())
            return JsonRpcError(id, -32602, "plugin_write_ini_string requires key");
        if (value.empty())
            value = text;
        rc = pPluginwritestringtoini(g_instance, (char*)key.c_str(), (char*)value.c_str());
    }
    else if (tool == "redraw_disasm") {
        if (pRedrawcpudisasm) pRedrawcpudisasm();
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "redraw_registers") {
        if (pRedrawcpureg) pRedrawcpureg();
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "redraw_list") {
        if (pRedrawlist) pRedrawlist();
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "redraw_all") {
        if (pRedrawcpudisasm) pRedrawcpudisasm();
        if (pRedrawcpureg) pRedrawcpureg();
        if (pRedrawlist) pRedrawlist();
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "suspend_all_threads") {
        if (pSuspendallthreads) pSuspendallthreads();
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "resume_all_threads") {
        if (pResumeallthreads) pResumeallthreads();
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "show_threads") {
        HWND h = pCreatethreadwindow ? pCreatethreadwindow() : NULL;
        std::string result = "{\"ok\":true,\"hwnd\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)h);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "show_memory") {
        if (!pListmemory)
            return JsonRpcError(id, -32001, "Listmemory is not available");
        rc = pListmemory();
    }
    else if (tool == "show_breakpoints") {
        if (!pHardbreakpoints)
            return JsonRpcError(id, -32001, "Hardbreakpoints is not available");
        rc = pHardbreakpoints(0);
    }
    else if (tool == "show_hardware_breakpoints") {
        if (!pHardbreakpoints)
            return JsonRpcError(id, -32001, "Hardbreakpoints is not available");
        rc = pHardbreakpoints(0);
    }
    else if (tool == "show_trace") {
        HWND h = pCreatertracewindow ? pCreatertracewindow() : NULL;
        std::string result = "{\"ok\":true,\"hwnd\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)h);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "show_windows") {
        HWND h = pCreatewinwindow ? pCreatewinwindow() : NULL;
        std::string result = "{\"ok\":true,\"hwnd\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)h);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "show_patches") {
        HWND h = pCreatepatchwindow ? pCreatepatchwindow() : NULL;
        std::string result = "{\"ok\":true,\"hwnd\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)h);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "show_watch") {
        HWND h = pCreatewatchwindow ? pCreatewatchwindow() : NULL;
        std::string result = "{\"ok\":true,\"hwnd\":";
        JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)h);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "set_trace_condition") {
        if (!pSettraceconditionA)
            return JsonRpcError(id, -32001, "Settracecondition is not available");
        pSettraceconditionA((char*)condition.c_str(), 0, 0, 0, 0, 0);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "set_trace_count") {
        if (!pSettracecount)
            return JsonRpcError(id, -32001, "Settracecount is not available");
        pSettracecount((ulong)count);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "set_trace_pause_on_commands") {
        if (!pSettracepauseoncommandsA)
            return JsonRpcError(id, -32001, "Settracepauseoncommands is not available");
        pSettracepauseoncommandsA((char*)cmdset.c_str());
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "set_dump_type") {
        if (!pSetdumptype)
            return JsonRpcError(id, -32001, "Setdumptype is not available");
        pSetdumptype(NULL, (ulong)type_value);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "dump_backup") {
        if (!pDumpbackup)
            return JsonRpcError(id, -32001, "Dumpbackup is not available");
        pDumpbackup(NULL, (int)type_value);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "plugin_module_changed") {
        if (!pPluginmodulechanged)
            return JsonRpcError(id, -32001, "Pluginmodulechanged is not available");
        pPluginmodulechanged((ulong)address);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else {
        return JsonRpcError(id, -32601, "unknown tool");
    }

    char num[32];
    StringCchPrintfA(num, _countof(num), "%d", rc);
    std::string result = "{\"ok\":true,\"return\":";
    result += num;
    result += "}";
    return JsonRpcResult(id, result);
}

static DWORD WINAPI StdioReaderThreadProc(LPVOID)
{
    std::string pending;
    char buf[1024];
    for (;;) {
        HANDLE h = g_stdio_stdout;
        if (!h)
            break;
        DWORD read = 0;
        if (!ReadFile(h, buf, sizeof(buf), &read, NULL) || read == 0)
            break;
        pending.append(buf, buf + read);
        for (;;) {
            size_t pos = pending.find('\n');
            if (pos == std::string::npos)
                break;
            std::string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ' || line.back() == '\t'))
                line.pop_back();
            if (line.empty())
                continue;
            std::string response = ExecuteToolCommand(line);
            McpConfig cfg = CopyConfig();
            SendStdioJson(cfg, response);
        }
    }
    return 0;
}

static HWND AddLabel(HWND parent, int x, int y, int w, int h, const wchar_t* text)
{
    return CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
        x, y, w, h, parent, NULL, g_instance, NULL);
}

static HWND AddEdit(HWND parent, int id, int x, int y, int w, int h, DWORD style)
{
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | style,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, g_instance, NULL);
}

static HWND AddButton(HWND parent, int id, int x, int y, int w, int h, const wchar_t* text, DWORD style)
{
    return CreateWindowExW(0, L"BUTTON", text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, g_instance, NULL);
}

static void SetChildFont(HWND parent, HFONT font)
{
    HWND child = GetWindow(parent, GW_CHILD);
    while (child) {
        SendMessageW(child, WM_SETFONT, (WPARAM)font, TRUE);
        child = GetWindow(child, GW_HWNDNEXT);
    }
}

static void BrowseCommand(HWND hwnd)
{
    wchar_t file[MAX_PATH] = { 0 };
    GetDlgItemTextW(hwnd, IDC_COMMAND, file, _countof(file));

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = file;
    ofn.nMaxFile = _countof(file);
    ofn.lpstrFilter = McpIsEnglish() ?
        L"Executable files (*.exe;*.cmd;*.bat)\0*.exe;*.cmd;*.bat\0All files (*.*)\0*.*\0" :
        L"可执行文件 (*.exe;*.cmd;*.bat)\0*.exe;*.cmd;*.bat\0所有文件 (*.*)\0*.*\0";
    ofn.lpstrTitle = McpText(L"选择 MCP Server 命令", L"Select MCP Server command");
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn))
        SetDlgItemTextW(hwnd, IDC_COMMAND, file);
}

static void BrowseWorkdir(HWND hwnd)
{
    wchar_t dir[MAX_PATH] = { 0 };
    GetDlgItemTextW(hwnd, IDC_WORKDIR, dir, _countof(dir));

    BROWSEINFOW bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.hwndOwner = hwnd;
    bi.lpszTitle = McpText(L"选择 MCP Server 工作目录", L"Select MCP Server working directory");
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        if (SHGetPathFromIDListW(pidl, dir))
            SetDlgItemTextW(hwnd, IDC_WORKDIR, dir);
        CoTaskMemFree(pidl);
    }
}

static void FillDialog(HWND hwnd)
{
    McpConfig cfg = CopyConfig();
    CheckDlgButton(hwnd, IDC_ENABLE, cfg.enabled ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(hwnd, IDC_NAME, cfg.name);
    SetDlgItemTextW(hwnd, IDC_URL, cfg.url);
    SetDlgItemTextW(hwnd, IDC_COMMAND, cfg.command);
    SetDlgItemTextW(hwnd, IDC_ARGUMENTS, cfg.arguments);
    SetDlgItemTextW(hwnd, IDC_WORKDIR, cfg.workdir);
    SetDlgItemTextW(hwnd, IDC_ENV, cfg.env);

    HWND combo = GetDlgItem(hwnd, IDC_TRANSPORT);
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"stdio");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"http");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"sse");
    int sel = 0;
    if (lstrcmpiW(cfg.transport, L"http") == 0)
        sel = 1;
    else if (lstrcmpiW(cfg.transport, L"sse") == 0)
        sel = 2;
    SendMessageW(combo, CB_SETCURSEL, sel, 0);

    wchar_t timeout[32];
    StringCchPrintfW(timeout, _countof(timeout), L"%d", cfg.timeout_ms);
    SetDlgItemTextW(hwnd, IDC_TIMEOUT, timeout);
}

static void ReadDialog(HWND hwnd)
{
    McpConfig cfg = CopyConfig();
    cfg.enabled = IsDlgButtonChecked(hwnd, IDC_ENABLE) == BST_CHECKED;
    GetDlgItemTextW(hwnd, IDC_NAME, cfg.name, _countof(cfg.name));
    GetDlgItemTextW(hwnd, IDC_URL, cfg.url, _countof(cfg.url));
    GetDlgItemTextW(hwnd, IDC_COMMAND, cfg.command, _countof(cfg.command));
    GetDlgItemTextW(hwnd, IDC_ARGUMENTS, cfg.arguments, _countof(cfg.arguments));
    GetDlgItemTextW(hwnd, IDC_WORKDIR, cfg.workdir, _countof(cfg.workdir));
    GetDlgItemTextW(hwnd, IDC_ENV, cfg.env, _countof(cfg.env));

    HWND combo = GetDlgItem(hwnd, IDC_TRANSPORT);
    int sel = (int)SendMessageW(combo, CB_GETCURSEL, 0, 0);
    if (sel == 1)
        StringCchCopyW(cfg.transport, _countof(cfg.transport), L"http");
    else if (sel == 2)
        StringCchCopyW(cfg.transport, _countof(cfg.transport), L"sse");
    else
        StringCchCopyW(cfg.transport, _countof(cfg.transport), L"stdio");

    wchar_t timeout[32];
    GetDlgItemTextW(hwnd, IDC_TIMEOUT, timeout, _countof(timeout));
    cfg.timeout_ms = _wtoi(timeout);
    if (cfg.timeout_ms <= 0)
        cfg.timeout_ms = 30000;

    EnterCriticalSection(&g_config_cs);
    g_config = cfg;
    LeaveCriticalSection(&g_config_cs);
}

static LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_CREATE: {
        NONCLIENTMETRICSW ncm;
        ZeroMemory(&ncm, sizeof(ncm));
        ncm.cbSize = sizeof(ncm);
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        HFONT font = CreateFontIndirectW(&ncm.lfMessageFont);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)font);

        AddButton(hwnd, IDC_ENABLE, 14, 14, 210, 22, McpText(L"启用 MCP Server", L"Enable MCP Server"), BS_AUTOCHECKBOX);
        AddLabel(hwnd, 14, 48, 90, 22, McpText(L"名称", L"Name"));
        AddEdit(hwnd, IDC_NAME, 115, 46, 420, 24, 0);
        AddLabel(hwnd, 14, 82, 90, 22, McpText(L"传输类型", L"Transport"));
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            115, 80, 160, 120, hwnd, (HMENU)(INT_PTR)IDC_TRANSPORT, g_instance, NULL);
        AddLabel(hwnd, 14, 116, 90, 22, L"URL");
        AddEdit(hwnd, IDC_URL, 115, 114, 520, 24, 0);
        AddLabel(hwnd, 14, 150, 90, 22, McpText(L"命令", L"Command"));
        AddEdit(hwnd, IDC_COMMAND, 115, 148, 420, 24, 0);
        AddButton(hwnd, IDC_BROWSE_CMD, 545, 147, 90, 26, McpText(L"浏览...", L"Browse..."), BS_PUSHBUTTON);
        AddLabel(hwnd, 14, 184, 90, 22, McpText(L"参数", L"Arguments"));
        AddEdit(hwnd, IDC_ARGUMENTS, 115, 182, 520, 24, 0);
        AddLabel(hwnd, 14, 218, 90, 22, McpText(L"工作目录", L"Work dir"));
        AddEdit(hwnd, IDC_WORKDIR, 115, 216, 420, 24, 0);
        AddButton(hwnd, IDC_BROWSE_DIR, 545, 215, 90, 26, McpText(L"浏览...", L"Browse..."), BS_PUSHBUTTON);
        AddLabel(hwnd, 14, 252, 90, 22, McpText(L"环境变量", L"Environment"));
        AddEdit(hwnd, IDC_ENV, 115, 250, 520, 74, ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL);
        AddLabel(hwnd, 14, 337, 90, 22, McpText(L"超时(ms)", L"Timeout(ms)"));
        AddEdit(hwnd, IDC_TIMEOUT, 115, 335, 120, 24, ES_NUMBER);
        AddLabel(hwnd, 250, 337, 385, 44,
            McpText(L"stdio 使用命令/参数/工作目录；http/sse 使用 URL。环境变量每行一个 NAME=VALUE。",
                    L"stdio uses command/arguments/workdir; http/sse uses URL. One NAME=VALUE per env line."));
        AddButton(hwnd, IDC_SAVE, 445, 395, 90, 28, McpText(L"保存", L"Save"), BS_DEFPUSHBUTTON);
        AddButton(hwnd, IDC_CANCEL, 545, 395, 90, 28, McpText(L"取消", L"Cancel"), BS_PUSHBUTTON);

        SetChildFont(hwnd, font);
        FillDialog(hwnd);
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_BROWSE_CMD:
            BrowseCommand(hwnd);
            return 0;
        case IDC_BROWSE_DIR:
            BrowseWorkdir(hwnd);
            return 0;
        case IDC_SAVE:
            ReadDialog(hwnd);
            SaveConfig();
            CloseStdioProcess();
            MessageBoxW(hwnd, McpText(L"MCP Server 设置已保存。", L"MCP Server settings saved."), PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
            DestroyWindow(hwnd);
            return 0;
        case IDC_CANCEL:
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY: {
        HFONT font = (HFONT)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (font)
            DeleteObject(font);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void ShowSettingsDialog(void)
{
    LoadConfig();

    const wchar_t* cls = L"Z0B_McpTools_Settings";
    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = SettingsWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = cls;
    RegisterClassW(&wc);

    HWND owner = GetActiveWindow();
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, cls, McpText(L"MCP Server 设置", L"MCP Server Settings"),
        WS_CAPTION | WS_SYSMENU | WS_POPUP,
        CW_USEDEFAULT, CW_USEDEFAULT, 665, 470,
        owner, NULL, g_instance, NULL);
    if (!hwnd)
        return;

    RECT rc;
    GetWindowRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    if (owner)
        EnableWindow(owner, FALSE);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (IsWindow(hwnd) && GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (owner)
        EnableWindow(owner, TRUE);
}

static void ShowConfigPath(void)
{
    wchar_t path[MAX_PATH];
    GetConfigPath(path, _countof(path));
    MessageBoxW(GetActiveWindow(), path, McpText(L"MCP Tools 配置文件", L"MCP Tools configuration file"), MB_OK | MB_ICONINFORMATION);
}

static int __cdecl MenuSettings(t_table*, wchar_t*, ulong, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    if (mode == MENU_EXECUTE) {
        ShowSettingsDialog();
        return MENU_NOREDRAW;
    }
    return MENU_ABSENT;
}

static int __cdecl MenuReload(t_table*, wchar_t*, ulong, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    if (mode == MENU_EXECUTE) {
        LoadConfig();
        CloseStdioProcess();
        QueueSimpleEvent("config_reloaded");
        MessageBoxW(GetActiveWindow(), McpText(L"MCP Server 配置已重新读取。", L"MCP Server configuration reloaded."), PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
        return MENU_NOREDRAW;
    }
    return MENU_ABSENT;
}

static int __cdecl MenuConfigPath(t_table*, wchar_t*, ulong, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    if (mode == MENU_EXECUTE) {
        ShowConfigPath();
        return MENU_NOREDRAW;
    }
    return MENU_ABSENT;
}

static int __cdecl MenuSendTest(t_table*, wchar_t*, ulong, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    if (mode == MENU_EXECUTE) {
        QueueSimpleEvent("test");
        MessageBoxW(GetActiveWindow(), McpText(L"测试事件已加入发送队列。", L"Test event queued."), PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
        return MENU_NOREDRAW;
    }
    return MENU_ABSENT;
}

static int __cdecl MenuAbout(t_table*, wchar_t*, ulong, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    if (mode == MENU_EXECUTE) {
        MessageBoxW(GetActiveWindow(),
            McpText(L"MCP Tools 插件\r\n\r\n用于保存和管理 MCP Server 配置，转发调试事件，并提供 81 个 MCP 调试控制工具。\r\n地址参数支持 64 位，x64 构建使用当前调试器的 x64 反汇编/汇编能力。",
                    L"MCP Tools plugin\r\n\r\nSaves and manages MCP Server configuration, forwards debug events, and exposes 81 MCP debugger control tools.\r\nAddress parameters support 64-bit values. x64 builds use the debugger's x64 disassembly/assembly path."),
            PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
        return MENU_NOREDRAW;
    }
    return MENU_ABSENT;
}

static t_menu g_main_menu[] = {
    { L"设置 MCP Server", L"Configure MCP Server", K_NONE, MenuSettings, NULL, 0 },
    { L"重新读取配置", L"Reload MCP Server configuration", K_NONE, MenuReload, NULL, 0 },
    { L"显示配置文件路径", L"Show MCP configuration file path", K_NONE, MenuConfigPath, NULL, 0 },
    { L"发送测试事件", L"Send test event", K_NONE, MenuSendTest, NULL, 0 },
    { L"|关于", L"About MCP Tools", K_NONE, MenuAbout, NULL, 0 },
    { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

static void UpdateMenuLanguage(void)
{
    if (McpIsEnglish()) {
        g_main_menu[0].name = L"Configure MCP Server";
        g_main_menu[1].name = L"Reload MCP Server configuration";
        g_main_menu[2].name = L"Show MCP configuration file path";
        g_main_menu[3].name = L"Send test event";
        g_main_menu[4].name = L"|About MCP Tools";
    }
    else {
        g_main_menu[0].name = L"设置 MCP Server";
        g_main_menu[1].name = L"重新读取配置";
        g_main_menu[2].name = L"显示配置文件路径";
        g_main_menu[3].name = L"发送测试事件";
        g_main_menu[4].name = L"|关于";
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_instance = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) int __cdecl ODBG2_Pluginquery(int ollydbgversion, ulong*,
    wchar_t pluginname[SHORTNAME], wchar_t pluginversion[SHORTNAME])
{
    if (ollydbgversion < 201)
        return 0;
    StringCchCopyW(pluginname, SHORTNAME, PLUGIN_NAME);
    StringCchCopyW(pluginversion, SHORTNAME, PLUGIN_VERSION_TEXT);
    return 201;
}

extern "C" __declspec(dllexport) int __cdecl ODBG2_Plugininit(void)
{
    InitializeCriticalSection(&g_config_cs);
    InitializeCriticalSection(&g_queue_cs);
    InitializeCriticalSection(&g_stdio_cs);
    ResolveHostExports();
    LoadConfig();
    StartWorker();
    InterlockedExchange(&g_runtime_ready, 1);
    QueueSimpleEvent("plugin_init");
    return 0;
}

extern "C" __declspec(dllexport) t_menu* __cdecl ODBG2_Pluginmenu(wchar_t* type)
{
    if (type && lstrcmpiW(type, PWM_MAIN) == 0) {
        UpdateMenuLanguage();
        return g_main_menu;
    }
    return NULL;
}

extern "C" __declspec(dllexport) void __cdecl ODBG2_Pluginmainloop(DEBUG_EVENT* debugevent)
{
    QueueDebuggerEvent(debugevent);
}

extern "C" __declspec(dllexport) void __cdecl ODBG2_Pluginnotify(int code, void* data, ulong parm1, ulong parm2)
{
    QueueNotifyEvent(code, data, parm1, parm2);
}

extern "C" __declspec(dllexport) void __cdecl ODBG2_Plugindestroy(void)
{
    QueueSimpleEvent("plugin_destroy");
    StopWorker();
    DeleteCriticalSection(&g_stdio_cs);
    DeleteCriticalSection(&g_queue_cs);
    DeleteCriticalSection(&g_config_cs);
}
