#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <winhttp.h>
#include <strsafe.h>
#include <deque>
#include <string>
#include <vector>
#include <cctype>
#include <cwctype>
#include <errno.h>
#include "plugin.h"
#include "McpToolTraits.h"
#include "McpRpcError.h"
#include "DebugRuntime.h"
#include "AgentProcessIsolation.h"
#include "StaticPeImage.h"
#include "../../MachOImage.h"
#include "../../StaticViewBridge.h"
#include "../../IdaSymbolCacheFormat.h"

static DebugRuntimeFeed g_debug_feed;
static ulong* g_host_process_id = NULL;
static DWORD g_observed_process_id = 0;

#pragma comment(lib, "ws2_32.lib")

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
typedef int (__cdecl* PFN_McpAttachPid)(unsigned long);
typedef int (__cdecl* PFN_McpOpenProcess)(const wchar_t*, const wchar_t*);
typedef int (__cdecl* PFN_McpOpenProcessEx)(const wchar_t*, const wchar_t*, int);
typedef int (__cdecl* PFN_McpStopDebug)(void);
typedef int (__cdecl* PFN_McpDebugState)(void);
typedef unsigned long (__cdecl* PFN_McpActiveProcessId)(void);
typedef int (__cdecl* PFN_McpTargetBits)(void);
typedef int (__cdecl* PFN_McpGetRegister)(const char*, unsigned __int64*);
typedef int (__cdecl* PFN_McpSetRegister)(const char*, unsigned __int64);
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
struct HostDisasmOperand {
    char optype, opsize, regscale[8], seg;
    ulong opconst;
};

struct HostDisasm {
    ulong ip;
    char dump[TEXTLEN], result[TEXTLEN], comment[TEXTLEN], opinfo[3][TEXTLEN];
    int cmdtype, memtype, nprefix, indexed;
    ulong jmpconst, jmptable, adrconst, immconst;
    int zeroconst, fixupoffset, fixupsize;
    ulong jmpaddr;
    int condition, error, warnings, optype[3], opsize[3], opgood[3];
    ulong opaddr[3], opdata[3];
    HostDisasmOperand op[3];
    ulong regdata[8];
    int regstatus[8];
    ulong addrdata;
    int addrstatus;
    ulong regstack[32];
    int rststatus[32], nregstack;
    ulong reserved[29];
};
typedef ulong (__cdecl* PFN_Disasm)(uchar* cmd, ulong cmdsize, ulong ip, uchar* dec, HostDisasm* da, int mode, ulong threadid);
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
static PFN_McpAttachPid pMcpAttachPid = NULL;
static PFN_McpOpenProcess pMcpOpenProcess = NULL;
static PFN_McpOpenProcessEx pMcpOpenProcessEx = NULL;
static PFN_McpStopDebug pMcpStopDebug = NULL;
static PFN_McpDebugState pMcpDebugState = NULL;
static PFN_McpActiveProcessId pMcpActiveProcessId = NULL;
static PFN_McpTargetBits pMcpTargetBits = NULL;
static PFN_McpGetRegister pMcpGetRegister = NULL;
static PFN_McpSetRegister pMcpSetRegister = NULL;
typedef BOOL (__cdecl* PFN_McpStaticQuery)(Z0B_StaticQuery*);
static PFN_McpStaticQuery pMcpStaticQuery = NULL;
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

#ifdef MCPTOOLS_SERVER_BUILD
#define PLUGIN_NAME L"MCP Tools Server"
#define MCPTOOLS_DEFAULT_ROLE L"server"
#define MCPTOOLS_DEFAULT_ENABLED TRUE
#define MCPTOOLS_DEFAULT_HTTP_SERVER TRUE
#else
#define PLUGIN_NAME L"MCP Tools"
#define MCPTOOLS_DEFAULT_ROLE L"client"
#define MCPTOOLS_DEFAULT_ENABLED FALSE
#define MCPTOOLS_DEFAULT_HTTP_SERVER FALSE
#endif
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
#define IDC_TEST          1012
#define IDC_DEFAULTS      1013
#define IDC_STATUS        1014
#define IDC_PIPE_NAME     1015
#define IDC_PIPE_PROTOCOL 1016
#define IDC_SHARED_KEY    1017
#define IDC_URL_LABEL     1018
#define IDC_COMMAND_LABEL 1019
#define IDC_ARGUMENTS_LABEL 1020
#define IDC_WORKDIR_LABEL 1021
#define IDC_ENV_LABEL     1022
#define IDC_PIPE_NAME_LABEL 1023
#define IDC_PIPE_PROTOCOL_LABEL 1024
#define IDC_SHARED_KEY_LABEL 1025
#define IDC_ROLE            1026
#define IDC_AUTO_CONNECT    1027
#define IDC_AUTO_RECONNECT  1028
#define IDC_RECONNECT_INTERVAL 1029
#define IDC_RECONNECT_MAX   1030
#define IDC_MCP_INITIALIZE  1031
#define IDC_CLIENT_NAME     1032
#define IDC_CLIENT_VERSION  1033
#define IDC_HTTP_HEADERS    1034
#define IDC_AUTH_TOKEN      1035
#define IDC_ALLOW_READ      1036
#define IDC_ALLOW_WRITE     1037
#define IDC_ALLOW_EXECUTE   1038
#define IDC_ALLOW_BREAKPOINT 1039
#define IDC_ALLOW_PATCH     1040
#define IDC_TEST_CONNECT    1041
#define IDC_TEST_INITIALIZE 1042
#define IDC_TEST_TOOLS      1043
#define IDC_ROLE_LABEL      1044
#define IDC_RECONNECT_INTERVAL_LABEL 1045
#define IDC_RECONNECT_MAX_LABEL 1046
#define IDC_CLIENT_NAME_LABEL 1047
#define IDC_CLIENT_VERSION_LABEL 1048
#define IDC_HTTP_HEADERS_LABEL 1049
#define IDC_AUTH_TOKEN_LABEL 1050
#define IDC_PERMISSION_LABEL 1051
#define IDC_ADVANCED         1052
#define IDC_HTTP_METHOD      1053
#define IDC_HTTP_USER_AGENT  1054
#define IDC_HTTP_PROXY       1055
#define IDC_HTTP_VERIFY_TLS  1056
#define IDC_SSE_RETRY        1057
#define IDC_SSE_HEARTBEAT    1058
#define IDC_STDIO_SHELL      1059
#define IDC_STDIO_CONSOLE    1060
#define IDC_STDIO_INHERIT_ENV 1061
#define IDC_STDIO_RESTART    1062
#define IDC_STDIO_ENCODING   1063
#define IDC_STDIO_STDERR     1064
#define IDC_STDIO_MAX_OUTPUT 1065
#define IDC_PIPE_HANDSHAKE  1066
#define IDC_PIPE_READ_TIMEOUT 1067
#define IDC_PIPE_WRITE_TIMEOUT 1068
#define IDC_PIPE_ALLOW_PLAIN 1069
#define IDC_PIPE_RETAIN_QUEUE 1070
#define IDC_ADVANCED_SAVE   1071
#define IDC_ADVANCED_CANCEL 1072
#define IDC_PROTOCOL_VERSION 1073
#define IDC_CONNECT_DEBUG_OPEN 1074
#define IDC_RECONNECT_ON_SAVE 1075
#define IDC_SEND_DEBUG_EVENTS 1076
#define IDC_RECEIVE_COMMANDS 1077
#define IDC_AUTO_REPLY       1078
#define IDC_REQUEST_TIMEOUT  1079
#define IDC_TEST_TOOL_NAME   1080
#define IDC_TEST_TOOL_ARGS   1081
#define IDC_TEST_TOOL        1082
#define IDC_SERVER_INFO      1083
#define IDC_ALLOW_DELETE_BP  1084
#define IDC_ALLOW_REGISTERS  1085
#define IDC_ALLOW_HIGH_RISK  1086
#define IDC_CONFIRM_RISK     1087
#define IDC_EVENT_EXCEPTION  1088
#define IDC_EVENT_THREAD     1089
#define IDC_EVENT_MODULE     1090
#define IDC_EVENT_PROCESS    1091
#define IDC_EVENT_OUTPUT     1092
#define IDC_EVENT_IGNORE_DUP 1093
#define IDC_EVENT_QUEUE_MAX  1094
#define IDC_LOG_LEVEL        1095
#define IDC_LOG_FILE         1096
#define IDC_LOG_RAW_JSON     1097
#define IDC_LOG_TRANSPORT    1098
#define IDC_LOG_REDACT       1099
#define IDC_HTTP_SERVER_ENABLE 1100
#define IDC_HTTP_SERVER_BIND 1101
#define IDC_HTTP_SERVER_PORT 1102
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
    wchar_t pipe_name[512];
    wchar_t pipe_protocol[32];
    wchar_t shared_key[512];
    wchar_t role[32];
    BOOL auto_connect;
    BOOL auto_reconnect;
    BOOL mcp_initialize;
    int reconnect_interval_ms;
    int reconnect_max_attempts;
    wchar_t protocol_version[64];
    wchar_t client_name[128];
    wchar_t client_version[64];
    BOOL connect_on_debug_open;
    BOOL reconnect_on_save;
    BOOL send_debug_events;
    BOOL receive_server_commands;
    BOOL auto_reply_requests;
    int request_timeout_ms;
    wchar_t test_tool_name[128];
    wchar_t test_tool_args[1024];
    wchar_t http_headers[2048];
    wchar_t auth_token[512];
    wchar_t http_method[16];
    wchar_t http_user_agent[128];
    wchar_t http_proxy[512];
    BOOL http_verify_tls;
    int sse_retry_interval_ms;
    int sse_heartbeat_timeout_ms;
    BOOL stdio_shell;
    BOOL stdio_show_console;
    BOOL stdio_inherit_env;
    BOOL stdio_restart_on_exit;
    wchar_t stdio_encoding[32];
    wchar_t stdio_stderr_mode[32];
    int stdio_max_output;
    int pipe_handshake_timeout_ms;
    int pipe_read_timeout_ms;
    int pipe_write_timeout_ms;
    BOOL pipe_allow_unencrypted;
    BOOL pipe_retain_queue;
    BOOL allow_read;
    BOOL allow_write;
    BOOL allow_execute;
    BOOL allow_breakpoint;
    BOOL allow_patch;
    BOOL allow_delete_breakpoint;
    BOOL allow_registers;
    BOOL allow_high_risk;
    BOOL confirm_high_risk;
    BOOL agent_readonly, agent_require_target;
    wchar_t agent_scope[128], agent_tools[1024], agent_address_min[32], agent_address_max[32];
    int agent_max_read_bytes, agent_max_argument_kb;
    BOOL stdio_isolate;
    BOOL stdio_strict, agent_strict;
    wchar_t stdio_files[2048], agent_files[2048], agent_network[2048];
    int stdio_memory_mb, stdio_cpu_seconds;
    BOOL event_exception;
    BOOL event_thread;
    BOOL event_module;
    BOOL event_process;
    BOOL event_output;
    BOOL event_ignore_duplicates;
    int event_queue_max;
    int log_level;
    BOOL log_to_file;
    BOOL log_raw_json;
    BOOL log_transport_data;
    BOOL log_redact_secrets;
    BOOL http_server_enable;
    wchar_t http_server_bind[64];
    int http_server_port;
    int timeout_ms;
};

static HINSTANCE g_instance = NULL;
static McpConfig g_config;
static CRITICAL_SECTION g_config_cs;
static CRITICAL_SECTION g_queue_cs;
static CRITICAL_SECTION g_stdio_cs;
static CRITICAL_SECTION g_pipe_cs;
static CRITICAL_SECTION g_status_cs;
static CRITICAL_SECTION g_response_cs;
static std::deque<std::string> g_queue;

struct PendingResponse {
    std::string id;
    std::string response;
    HANDLE event;
};

static std::vector<PendingResponse> g_pending_responses;
static HANDLE g_queue_event = NULL;
static HANDLE g_stop_event = NULL;
static HANDLE g_worker_thread = NULL;
static HANDLE g_stdio_process = NULL;
static HANDLE g_stdio_job = NULL;
static HANDLE g_stdio_stdin = NULL;
static HANDLE g_stdio_stdout = NULL;
static HANDLE g_stdio_reader_thread = NULL;
static HANDLE g_pipe_handle = NULL;
static HANDLE g_pipe_reader_thread = NULL;
static HANDLE g_http_server_thread = NULL;
static SOCKET g_http_server_socket = INVALID_SOCKET;
static volatile LONG g_http_server_stop = 0;
static bool g_pipe_encrypted = false;
static std::string g_pipe_server_nonce;
static std::string g_pipe_client_nonce;
static volatile LONG g_runtime_ready = 0;
static volatile LONG g_mcp_initialized = 0;
static HANDLE g_local_dispatch_thread = NULL;
static volatile LONG g_local_dispatch_stop = 0;
static BOOL g_auto_confirm_local_server = FALSE;
static volatile LONG g_reconnect_attempts = 0;
static BOOL g_connected = FALSE;
static wchar_t g_last_error[512];
static DWORD g_last_connect_tick = 0;
static const size_t MCP_MAX_QUEUE = 512;
static std::string g_last_event_key;

static DWORD WINAPI StdioReaderThreadProc(LPVOID);
static DWORD WINAPI PipeReaderThreadProc(LPVOID);
static std::string ExecuteToolCommand(const std::string& json, bool internal_direct = false);
static int HexDigit(char c);
static bool JsonFindString(const std::string& json, const char* key, std::string& value);
static std::string WideToUtf8(const wchar_t* text);
static std::wstring Utf8ToWide(const std::string& text);
static bool EnsureTransportReady(const McpConfig& cfg);
static bool EnsureMcpInitialized(const McpConfig& cfg);
static std::string ToolListJson(void);
static std::string BuildInitializeJson(const McpConfig& cfg);
static std::string BuildInitializedJson(void);
static void CloseStdioProcess(void);
static std::string ExtractIdJson(const std::string& json);
static void StartHttpServerIfConfigured(const McpConfig& cfg);
static void StopHttpServer(void);

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
    cfg->enabled = MCPTOOLS_DEFAULT_ENABLED;
    StringCchCopyW(cfg->name, _countof(cfg->name), L"local-mcp");
    StringCchCopyW(cfg->transport, _countof(cfg->transport), L"stdio");
    StringCchCopyW(cfg->url, _countof(cfg->url), L"http://127.0.0.1:3000/mcp");
    StringCchCopyW(cfg->pipe_name, _countof(cfg->pipe_name), L"\\\\.\\pipe\\Z0BDbgMcpBridge");
    StringCchCopyW(cfg->pipe_protocol, _countof(cfg->pipe_protocol), L"line");
    StringCchCopyW(cfg->role, _countof(cfg->role), MCPTOOLS_DEFAULT_ROLE);
    cfg->auto_connect = FALSE;
    cfg->auto_reconnect = TRUE;
    cfg->mcp_initialize = TRUE;
    cfg->reconnect_interval_ms = 2000;
    cfg->reconnect_max_attempts = 3;
    StringCchCopyW(cfg->protocol_version, _countof(cfg->protocol_version), L"2024-11-05");
    StringCchCopyW(cfg->client_name, _countof(cfg->client_name), L"Z0BDbg MCP Tools");
    StringCchCopyW(cfg->client_version, _countof(cfg->client_version), PLUGIN_VERSION_TEXT);
    cfg->connect_on_debug_open = FALSE;
    cfg->reconnect_on_save = TRUE;
    cfg->send_debug_events = TRUE;
    cfg->receive_server_commands = TRUE;
    cfg->auto_reply_requests = TRUE;
    cfg->request_timeout_ms = 30000;
    StringCchCopyW(cfg->test_tool_name, _countof(cfg->test_tool_name), L"get_status");
    StringCchCopyW(cfg->http_method, _countof(cfg->http_method), L"POST");
    StringCchCopyW(cfg->http_user_agent, _countof(cfg->http_user_agent), L"Z0BDbg MCP Tools/1.0");
    cfg->http_verify_tls = TRUE;
    cfg->sse_retry_interval_ms = 2000;
    cfg->sse_heartbeat_timeout_ms = 30000;
    cfg->stdio_shell = FALSE;
    cfg->stdio_show_console = FALSE;
    cfg->stdio_inherit_env = TRUE;
    cfg->stdio_restart_on_exit = TRUE;
    StringCchCopyW(cfg->stdio_encoding, _countof(cfg->stdio_encoding), L"utf-8");
    StringCchCopyW(cfg->stdio_stderr_mode, _countof(cfg->stdio_stderr_mode), L"inherit");
    cfg->stdio_max_output = 1024 * 1024;
    cfg->pipe_handshake_timeout_ms = 30000;
    cfg->pipe_read_timeout_ms = 30000;
    cfg->pipe_write_timeout_ms = 30000;
    cfg->pipe_allow_unencrypted = TRUE;
    cfg->pipe_retain_queue = TRUE;
    cfg->allow_read = TRUE;
    cfg->allow_write = TRUE;
    cfg->allow_execute = TRUE;
    cfg->allow_breakpoint = TRUE;
    cfg->allow_patch = TRUE;
    cfg->allow_delete_breakpoint = TRUE;
    cfg->allow_registers = TRUE;
    cfg->allow_high_risk = TRUE;
    cfg->agent_readonly = cfg->agent_require_target = FALSE;
    cfg->agent_scope[0] = cfg->agent_tools[0] = cfg->agent_address_min[0] = cfg->agent_address_max[0] = 0;
    cfg->agent_max_read_bytes = 1024 * 1024; cfg->agent_max_argument_kb = 64;
    cfg->stdio_isolate = FALSE; cfg->stdio_memory_mb = 256; cfg->stdio_cpu_seconds = 300;
    cfg->stdio_strict = cfg->agent_strict = FALSE;
    cfg->stdio_files[0] = cfg->agent_files[0] = cfg->agent_network[0] = 0;
    cfg->confirm_high_risk = FALSE;
    cfg->event_exception = TRUE;
    cfg->event_thread = TRUE;
    cfg->event_module = TRUE;
    cfg->event_process = TRUE;
    cfg->event_output = TRUE;
    cfg->event_ignore_duplicates = TRUE;
    cfg->event_queue_max = (int)MCP_MAX_QUEUE;
    cfg->log_level = 1;
    cfg->log_to_file = FALSE;
    cfg->log_raw_json = FALSE;
    cfg->log_transport_data = FALSE;
    cfg->log_redact_secrets = TRUE;
    cfg->http_server_enable = MCPTOOLS_DEFAULT_HTTP_SERVER;
    StringCchCopyW(cfg->http_server_bind, _countof(cfg->http_server_bind), L"127.0.0.1");
    cfg->http_server_port = 8765;
    cfg->timeout_ms = 30000;
}

static void ApplyLocalServerEnvironment(McpConfig* cfg)
{
    wchar_t local_url[256] = {0};
    DWORD local_url_length = GetEnvironmentVariableW(L"Z0B_MCP_LOCAL_URL", local_url, _countof(local_url));
    if (!local_url_length || local_url_length >= _countof(local_url) ||
        wcsncmp(local_url, L"http://", 7) != 0) return;
    cfg->enabled = TRUE;
    cfg->auto_connect = TRUE;
    cfg->mcp_initialize = TRUE;
    cfg->allow_breakpoint = TRUE;
    cfg->allow_read = TRUE;
    cfg->allow_write = TRUE;
    cfg->allow_execute = TRUE;
    cfg->allow_patch = TRUE;
    cfg->allow_delete_breakpoint = TRUE;
    cfg->allow_registers = TRUE;
    cfg->allow_high_risk = TRUE;
    cfg->agent_readonly = FALSE;
    cfg->agent_strict = FALSE;
    cfg->agent_tools[0] = 0;
    g_auto_confirm_local_server = TRUE;
    if (cfg->timeout_ms > 3000) cfg->timeout_ms = 3000;
    if (cfg->request_timeout_ms > 3000) cfg->request_timeout_ms = 3000;
    StringCchCopyW(cfg->transport, _countof(cfg->transport), L"http");
    StringCchCopyW(cfg->http_method, _countof(cfg->http_method), L"POST");
    StringCchCopyW(cfg->url, _countof(cfg->url), local_url);
    wchar_t local_token[512] = {0};
    DWORD token_length = GetEnvironmentVariableW(L"Z0B_MCP_LOCAL_TOKEN", local_token, _countof(local_token));
    if (token_length < _countof(local_token))
        StringCchCopyW(cfg->auth_token, _countof(cfg->auth_token), local_token);
}

template<typename T>
static void ResolveHostExport(T* target, const char* name)
{
    HMODULE host = GetModuleHandleW(NULL);
    *target = host ? (T)GetProcAddress(host, name) : NULL;
}

static void ResolveHostExports(void)
{
    ResolveHostExport(&g_host_process_id, "processid");
    if (!g_host_process_id) ResolveHostExport(&g_host_process_id, "_processid");
    ResolveHostExport(&pFindnameA, "Findname");
    ResolveHostExport(&pGetstatus, "Getstatus");
    ResolveHostExport(&pMcpAttachPid, "Z0B_McpAttachPid");
    ResolveHostExport(&pMcpOpenProcess, "Z0B_McpOpenProcess");
    ResolveHostExport(&pMcpOpenProcessEx, "Z0B_McpOpenProcessEx");
    ResolveHostExport(&pMcpStopDebug, "Z0B_McpStopDebug");
    ResolveHostExport(&pMcpDebugState, "Z0B_McpDebugState");
    ResolveHostExport(&pMcpActiveProcessId, "Z0B_McpActiveProcessId");
    ResolveHostExport(&pMcpTargetBits, "Z0B_McpTargetBits");
    ResolveHostExport(&pMcpGetRegister, "Z0B_McpGetRegister");
    ResolveHostExport(&pMcpSetRegister, "Z0B_McpSetRegister");
    ResolveHostExport(&pMcpStaticQuery, "Z0B_McpStaticQuery");
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

static DWORD CurrentDebugProcessId(void)
{
    if (pMcpActiveProcessId) return (DWORD)pMcpActiveProcessId();
    return g_host_process_id && *g_host_process_id
        ? (DWORD)*g_host_process_id : g_observed_process_id;
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
    GetPrivateProfileStringW(L"server", L"pipe_name", cfg.pipe_name, cfg.pipe_name, _countof(cfg.pipe_name), path);
    GetPrivateProfileStringW(L"server", L"pipe_protocol", cfg.pipe_protocol, cfg.pipe_protocol, _countof(cfg.pipe_protocol), path);
    GetPrivateProfileStringW(L"server", L"shared_key", cfg.shared_key, cfg.shared_key, _countof(cfg.shared_key), path);
    GetPrivateProfileStringW(L"server", L"role", cfg.role, cfg.role, _countof(cfg.role), path);
    cfg.auto_connect = GetPrivateProfileIntW(L"server", L"auto_connect", cfg.auto_connect, path) ? TRUE : FALSE;
    cfg.auto_reconnect = GetPrivateProfileIntW(L"server", L"auto_reconnect", cfg.auto_reconnect, path) ? TRUE : FALSE;
    cfg.mcp_initialize = GetPrivateProfileIntW(L"server", L"mcp_initialize", cfg.mcp_initialize, path) ? TRUE : FALSE;
    cfg.reconnect_interval_ms = GetPrivateProfileIntW(L"server", L"reconnect_interval_ms", cfg.reconnect_interval_ms, path);
    cfg.reconnect_max_attempts = GetPrivateProfileIntW(L"server", L"reconnect_max_attempts", cfg.reconnect_max_attempts, path);
    GetPrivateProfileStringW(L"server", L"protocol_version", cfg.protocol_version, cfg.protocol_version, _countof(cfg.protocol_version), path);
    GetPrivateProfileStringW(L"server", L"client_name", cfg.client_name, cfg.client_name, _countof(cfg.client_name), path);
    GetPrivateProfileStringW(L"server", L"client_version", cfg.client_version, cfg.client_version, _countof(cfg.client_version), path);
    cfg.connect_on_debug_open = GetPrivateProfileIntW(L"server", L"connect_on_debug_open", cfg.connect_on_debug_open, path) ? TRUE : FALSE;
    cfg.reconnect_on_save = GetPrivateProfileIntW(L"server", L"reconnect_on_save", cfg.reconnect_on_save, path) ? TRUE : FALSE;
    cfg.send_debug_events = GetPrivateProfileIntW(L"server", L"send_debug_events", cfg.send_debug_events, path) ? TRUE : FALSE;
    cfg.receive_server_commands = GetPrivateProfileIntW(L"server", L"receive_server_commands", cfg.receive_server_commands, path) ? TRUE : FALSE;
    cfg.auto_reply_requests = GetPrivateProfileIntW(L"server", L"auto_reply_requests", cfg.auto_reply_requests, path) ? TRUE : FALSE;
    cfg.request_timeout_ms = GetPrivateProfileIntW(L"server", L"request_timeout_ms", cfg.request_timeout_ms, path);
    GetPrivateProfileStringW(L"server", L"test_tool_name", cfg.test_tool_name, cfg.test_tool_name, _countof(cfg.test_tool_name), path);
    GetPrivateProfileStringW(L"server", L"test_tool_args", cfg.test_tool_args, cfg.test_tool_args, _countof(cfg.test_tool_args), path);
    GetPrivateProfileStringW(L"server", L"http_headers", cfg.http_headers, cfg.http_headers, _countof(cfg.http_headers), path);
    GetPrivateProfileStringW(L"server", L"auth_token", cfg.auth_token, cfg.auth_token, _countof(cfg.auth_token), path);
    GetPrivateProfileStringW(L"http", L"method", cfg.http_method, cfg.http_method, _countof(cfg.http_method), path);
    GetPrivateProfileStringW(L"http", L"user_agent", cfg.http_user_agent, cfg.http_user_agent, _countof(cfg.http_user_agent), path);
    GetPrivateProfileStringW(L"http", L"proxy", cfg.http_proxy, cfg.http_proxy, _countof(cfg.http_proxy), path);
    cfg.http_verify_tls = GetPrivateProfileIntW(L"http", L"verify_tls", cfg.http_verify_tls, path) ? TRUE : FALSE;
    cfg.sse_retry_interval_ms = GetPrivateProfileIntW(L"sse", L"retry_interval_ms", cfg.sse_retry_interval_ms, path);
    cfg.sse_heartbeat_timeout_ms = GetPrivateProfileIntW(L"sse", L"heartbeat_timeout_ms", cfg.sse_heartbeat_timeout_ms, path);
    cfg.stdio_shell = GetPrivateProfileIntW(L"stdio", L"shell", cfg.stdio_shell, path) ? TRUE : FALSE;
    cfg.stdio_show_console = GetPrivateProfileIntW(L"stdio", L"show_console", cfg.stdio_show_console, path) ? TRUE : FALSE;
    cfg.stdio_inherit_env = GetPrivateProfileIntW(L"stdio", L"inherit_env", cfg.stdio_inherit_env, path) ? TRUE : FALSE;
    cfg.stdio_restart_on_exit = GetPrivateProfileIntW(L"stdio", L"restart_on_exit", cfg.stdio_restart_on_exit, path) ? TRUE : FALSE;
    GetPrivateProfileStringW(L"stdio", L"encoding", cfg.stdio_encoding, cfg.stdio_encoding, _countof(cfg.stdio_encoding), path);
    GetPrivateProfileStringW(L"stdio", L"stderr_mode", cfg.stdio_stderr_mode, cfg.stdio_stderr_mode, _countof(cfg.stdio_stderr_mode), path);
    cfg.stdio_max_output = GetPrivateProfileIntW(L"stdio", L"max_output", cfg.stdio_max_output, path);
    cfg.pipe_handshake_timeout_ms = GetPrivateProfileIntW(L"pipe", L"handshake_timeout_ms", cfg.pipe_handshake_timeout_ms, path);
    cfg.pipe_read_timeout_ms = GetPrivateProfileIntW(L"pipe", L"read_timeout_ms", cfg.pipe_read_timeout_ms, path);
    cfg.pipe_write_timeout_ms = GetPrivateProfileIntW(L"pipe", L"write_timeout_ms", cfg.pipe_write_timeout_ms, path);
    cfg.pipe_allow_unencrypted = GetPrivateProfileIntW(L"pipe", L"allow_unencrypted", cfg.pipe_allow_unencrypted, path) ? TRUE : FALSE;
    cfg.pipe_retain_queue = GetPrivateProfileIntW(L"pipe", L"retain_queue", cfg.pipe_retain_queue, path) ? TRUE : FALSE;
    cfg.allow_read = GetPrivateProfileIntW(L"permissions", L"allow_read", cfg.allow_read, path) ? TRUE : FALSE;
    cfg.agent_readonly = GetPrivateProfileIntW(L"agent_isolation", L"readonly", 0, path) != 0;
    cfg.agent_require_target = GetPrivateProfileIntW(L"agent_isolation", L"require_target", 0, path) != 0;
    GetPrivateProfileStringW(L"agent_isolation", L"scope", L"", cfg.agent_scope, 128, path);
    GetPrivateProfileStringW(L"agent_isolation", L"tools", L"", cfg.agent_tools, 1024, path);
    GetPrivateProfileStringW(L"agent_isolation", L"address_min", L"", cfg.agent_address_min, 32, path);
    GetPrivateProfileStringW(L"agent_isolation", L"address_max", L"", cfg.agent_address_max, 32, path);
    cfg.agent_max_read_bytes = GetPrivateProfileIntW(L"agent_isolation", L"max_read_bytes", 1024 * 1024, path);
    cfg.agent_max_argument_kb = GetPrivateProfileIntW(L"agent_isolation", L"max_argument_kb", 64, path);
    cfg.stdio_isolate = GetPrivateProfileIntW(L"stdio", L"isolate", 0, path) != 0;
    cfg.stdio_strict = GetPrivateProfileIntW(L"stdio", L"strict", 0, path) != 0;
    if (cfg.stdio_strict) cfg.stdio_isolate = TRUE;
    GetPrivateProfileStringW(L"stdio", L"files", L"", cfg.stdio_files, 2048, path);
    cfg.agent_strict = GetPrivateProfileIntW(L"agent_isolation", L"strict", 0, path) != 0;
    GetPrivateProfileStringW(L"agent_isolation", L"files", L"", cfg.agent_files, 2048, path);
    GetPrivateProfileStringW(L"agent_isolation", L"network", L"", cfg.agent_network, 2048, path);
    cfg.stdio_memory_mb = GetPrivateProfileIntW(L"stdio", L"memory_mb", 256, path);
    cfg.stdio_cpu_seconds = GetPrivateProfileIntW(L"stdio", L"cpu_seconds", 300, path);
    cfg.allow_write = GetPrivateProfileIntW(L"permissions", L"allow_write", cfg.allow_write, path) ? TRUE : FALSE;
    cfg.allow_execute = GetPrivateProfileIntW(L"permissions", L"allow_execute", cfg.allow_execute, path) ? TRUE : FALSE;
    cfg.allow_breakpoint = GetPrivateProfileIntW(L"permissions", L"allow_breakpoint", cfg.allow_breakpoint, path) ? TRUE : FALSE;
    cfg.allow_patch = GetPrivateProfileIntW(L"permissions", L"allow_patch", cfg.allow_patch, path) ? TRUE : FALSE;
    cfg.allow_delete_breakpoint = GetPrivateProfileIntW(L"permissions", L"allow_delete_breakpoint", cfg.allow_delete_breakpoint, path) ? TRUE : FALSE;
    cfg.allow_registers = GetPrivateProfileIntW(L"permissions", L"allow_registers", cfg.allow_registers, path) ? TRUE : FALSE;
    cfg.allow_high_risk = GetPrivateProfileIntW(L"permissions", L"allow_high_risk", cfg.allow_high_risk, path) ? TRUE : FALSE;
    cfg.confirm_high_risk = GetPrivateProfileIntW(L"permissions", L"confirm_high_risk", cfg.confirm_high_risk, path) ? TRUE : FALSE;
    cfg.event_exception = GetPrivateProfileIntW(L"events", L"exception", cfg.event_exception, path) ? TRUE : FALSE;
    cfg.event_thread = GetPrivateProfileIntW(L"events", L"thread", cfg.event_thread, path) ? TRUE : FALSE;
    cfg.event_module = GetPrivateProfileIntW(L"events", L"module", cfg.event_module, path) ? TRUE : FALSE;
    cfg.event_process = GetPrivateProfileIntW(L"events", L"process", cfg.event_process, path) ? TRUE : FALSE;
    cfg.event_output = GetPrivateProfileIntW(L"events", L"output", cfg.event_output, path) ? TRUE : FALSE;
    cfg.event_ignore_duplicates = GetPrivateProfileIntW(L"events", L"ignore_duplicates", cfg.event_ignore_duplicates, path) ? TRUE : FALSE;
    cfg.event_queue_max = GetPrivateProfileIntW(L"events", L"queue_max", cfg.event_queue_max, path);
    cfg.log_level = GetPrivateProfileIntW(L"diagnostics", L"log_level", cfg.log_level, path);
    cfg.log_to_file = GetPrivateProfileIntW(L"diagnostics", L"log_to_file", cfg.log_to_file, path) ? TRUE : FALSE;
    cfg.log_raw_json = GetPrivateProfileIntW(L"diagnostics", L"log_raw_json", cfg.log_raw_json, path) ? TRUE : FALSE;
    cfg.log_transport_data = GetPrivateProfileIntW(L"diagnostics", L"log_transport_data", cfg.log_transport_data, path) ? TRUE : FALSE;
    cfg.log_redact_secrets = GetPrivateProfileIntW(L"diagnostics", L"redact_secrets", cfg.log_redact_secrets, path) ? TRUE : FALSE;
    cfg.http_server_enable = GetPrivateProfileIntW(L"http_server", L"enabled", cfg.http_server_enable, path) ? TRUE : FALSE;
    GetPrivateProfileStringW(L"http_server", L"bind", cfg.http_server_bind, cfg.http_server_bind, _countof(cfg.http_server_bind), path);
    cfg.http_server_port = GetPrivateProfileIntW(L"http_server", L"port", cfg.http_server_port, path);
    cfg.timeout_ms = GetPrivateProfileIntW(L"server", L"timeout_ms", cfg.timeout_ms, path);
    if (cfg.timeout_ms <= 0)
        cfg.timeout_ms = 30000;
    if (cfg.request_timeout_ms < 100)
        cfg.request_timeout_ms = cfg.timeout_ms;
    if (cfg.reconnect_interval_ms < 100)
        cfg.reconnect_interval_ms = 2000;
    if (cfg.reconnect_max_attempts < 0)
        cfg.reconnect_max_attempts = 3;
    if (cfg.sse_retry_interval_ms < 100)
        cfg.sse_retry_interval_ms = 2000;
    if (cfg.sse_heartbeat_timeout_ms < 100)
        cfg.sse_heartbeat_timeout_ms = 30000;
    if (cfg.stdio_max_output < 4096)
        cfg.stdio_max_output = 1024 * 1024;
    if (cfg.pipe_handshake_timeout_ms < 100)
        cfg.pipe_handshake_timeout_ms = cfg.timeout_ms;
    if (cfg.pipe_read_timeout_ms < 100)
        cfg.pipe_read_timeout_ms = cfg.timeout_ms;
    if (cfg.pipe_write_timeout_ms < 100)
        cfg.pipe_write_timeout_ms = cfg.timeout_ms;
    if (cfg.event_queue_max < 16)
        cfg.event_queue_max = (int)MCP_MAX_QUEUE;
    if (cfg.event_queue_max > 4096)
        cfg.event_queue_max = 4096;
    if (cfg.log_level < 0)
        cfg.log_level = 0;
    if (cfg.log_level > 3)
        cfg.log_level = 3;
    if (cfg.http_server_port <= 0 || cfg.http_server_port > 65535)
        cfg.http_server_port = 8765;

    ApplyLocalServerEnvironment(&cfg);

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
    WritePrivateProfileStringW(L"server", L"pipe_name", cfg.pipe_name, path);
    WritePrivateProfileStringW(L"server", L"pipe_protocol", cfg.pipe_protocol, path);
    WritePrivateProfileStringW(L"server", L"shared_key", cfg.shared_key, path);
    WritePrivateProfileStringW(L"server", L"role", cfg.role, path);
    WriteIntIni(path, L"server", L"auto_connect", cfg.auto_connect ? 1 : 0);
    WriteIntIni(path, L"server", L"auto_reconnect", cfg.auto_reconnect ? 1 : 0);
    WriteIntIni(path, L"server", L"mcp_initialize", cfg.mcp_initialize ? 1 : 0);
    WriteIntIni(path, L"server", L"reconnect_interval_ms", cfg.reconnect_interval_ms);
    WriteIntIni(path, L"server", L"reconnect_max_attempts", cfg.reconnect_max_attempts);
    WritePrivateProfileStringW(L"server", L"protocol_version", cfg.protocol_version, path);
    WritePrivateProfileStringW(L"server", L"client_name", cfg.client_name, path);
    WritePrivateProfileStringW(L"server", L"client_version", cfg.client_version, path);
    WriteIntIni(path, L"server", L"connect_on_debug_open", cfg.connect_on_debug_open ? 1 : 0);
    WriteIntIni(path, L"server", L"reconnect_on_save", cfg.reconnect_on_save ? 1 : 0);
    WriteIntIni(path, L"server", L"send_debug_events", cfg.send_debug_events ? 1 : 0);
    WriteIntIni(path, L"server", L"receive_server_commands", cfg.receive_server_commands ? 1 : 0);
    WriteIntIni(path, L"server", L"auto_reply_requests", cfg.auto_reply_requests ? 1 : 0);
    WriteIntIni(path, L"server", L"request_timeout_ms", cfg.request_timeout_ms);
    WritePrivateProfileStringW(L"server", L"test_tool_name", cfg.test_tool_name, path);
    WritePrivateProfileStringW(L"server", L"test_tool_args", cfg.test_tool_args, path);
    WritePrivateProfileStringW(L"server", L"http_headers", cfg.http_headers, path);
    WritePrivateProfileStringW(L"server", L"auth_token", cfg.auth_token, path);
    WritePrivateProfileStringW(L"http", L"method", cfg.http_method, path);
    WritePrivateProfileStringW(L"http", L"user_agent", cfg.http_user_agent, path);
    WritePrivateProfileStringW(L"http", L"proxy", cfg.http_proxy, path);
    WriteIntIni(path, L"http", L"verify_tls", cfg.http_verify_tls ? 1 : 0);
    WriteIntIni(path, L"sse", L"retry_interval_ms", cfg.sse_retry_interval_ms);
    WriteIntIni(path, L"sse", L"heartbeat_timeout_ms", cfg.sse_heartbeat_timeout_ms);
    WriteIntIni(path, L"stdio", L"shell", cfg.stdio_shell ? 1 : 0);
    WriteIntIni(path, L"stdio", L"show_console", cfg.stdio_show_console ? 1 : 0);
    WriteIntIni(path, L"stdio", L"inherit_env", cfg.stdio_inherit_env ? 1 : 0);
    WriteIntIni(path, L"stdio", L"restart_on_exit", cfg.stdio_restart_on_exit ? 1 : 0);
    WritePrivateProfileStringW(L"stdio", L"encoding", cfg.stdio_encoding, path);
    WritePrivateProfileStringW(L"stdio", L"stderr_mode", cfg.stdio_stderr_mode, path);
    WriteIntIni(path, L"stdio", L"max_output", cfg.stdio_max_output);
    WriteIntIni(path, L"pipe", L"handshake_timeout_ms", cfg.pipe_handshake_timeout_ms);
    WriteIntIni(path, L"pipe", L"read_timeout_ms", cfg.pipe_read_timeout_ms);
    WriteIntIni(path, L"pipe", L"write_timeout_ms", cfg.pipe_write_timeout_ms);
    WriteIntIni(path, L"pipe", L"allow_unencrypted", cfg.pipe_allow_unencrypted ? 1 : 0);
    WriteIntIni(path, L"pipe", L"retain_queue", cfg.pipe_retain_queue ? 1 : 0);
    WriteIntIni(path, L"permissions", L"allow_read", cfg.allow_read ? 1 : 0);
    WriteIntIni(path, L"agent_isolation", L"readonly", cfg.agent_readonly ? 1 : 0);
    WriteIntIni(path, L"agent_isolation", L"require_target", cfg.agent_require_target ? 1 : 0);
    WritePrivateProfileStringW(L"agent_isolation", L"scope", cfg.agent_scope, path);
    WritePrivateProfileStringW(L"agent_isolation", L"tools", cfg.agent_tools, path);
    WritePrivateProfileStringW(L"agent_isolation", L"address_min", cfg.agent_address_min, path);
    WritePrivateProfileStringW(L"agent_isolation", L"address_max", cfg.agent_address_max, path);
    WriteIntIni(path, L"agent_isolation", L"max_read_bytes", cfg.agent_max_read_bytes);
    WriteIntIni(path, L"agent_isolation", L"max_argument_kb", cfg.agent_max_argument_kb);
    WriteIntIni(path, L"stdio", L"isolate", cfg.stdio_isolate ? 1 : 0);
    WriteIntIni(path, L"stdio", L"strict", cfg.stdio_strict ? 1 : 0);
    WritePrivateProfileStringW(L"stdio", L"files", cfg.stdio_files, path);
    WriteIntIni(path, L"agent_isolation", L"strict", cfg.agent_strict ? 1 : 0);
    WritePrivateProfileStringW(L"agent_isolation", L"files", cfg.agent_files, path);
    WritePrivateProfileStringW(L"agent_isolation", L"network", cfg.agent_network, path);
    WriteIntIni(path, L"stdio", L"memory_mb", cfg.stdio_memory_mb);
    WriteIntIni(path, L"stdio", L"cpu_seconds", cfg.stdio_cpu_seconds);
    WriteIntIni(path, L"permissions", L"allow_write", cfg.allow_write ? 1 : 0);
    WriteIntIni(path, L"permissions", L"allow_execute", cfg.allow_execute ? 1 : 0);
    WriteIntIni(path, L"permissions", L"allow_breakpoint", cfg.allow_breakpoint ? 1 : 0);
    WriteIntIni(path, L"permissions", L"allow_patch", cfg.allow_patch ? 1 : 0);
    WriteIntIni(path, L"permissions", L"allow_delete_breakpoint", cfg.allow_delete_breakpoint ? 1 : 0);
    WriteIntIni(path, L"permissions", L"allow_registers", cfg.allow_registers ? 1 : 0);
    WriteIntIni(path, L"permissions", L"allow_high_risk", cfg.allow_high_risk ? 1 : 0);
    WriteIntIni(path, L"permissions", L"confirm_high_risk", cfg.confirm_high_risk ? 1 : 0);
    WriteIntIni(path, L"events", L"exception", cfg.event_exception ? 1 : 0);
    WriteIntIni(path, L"events", L"thread", cfg.event_thread ? 1 : 0);
    WriteIntIni(path, L"events", L"module", cfg.event_module ? 1 : 0);
    WriteIntIni(path, L"events", L"process", cfg.event_process ? 1 : 0);
    WriteIntIni(path, L"events", L"output", cfg.event_output ? 1 : 0);
    WriteIntIni(path, L"events", L"ignore_duplicates", cfg.event_ignore_duplicates ? 1 : 0);
    WriteIntIni(path, L"events", L"queue_max", cfg.event_queue_max);
    WriteIntIni(path, L"diagnostics", L"log_level", cfg.log_level);
    WriteIntIni(path, L"diagnostics", L"log_to_file", cfg.log_to_file ? 1 : 0);
    WriteIntIni(path, L"diagnostics", L"log_raw_json", cfg.log_raw_json ? 1 : 0);
    WriteIntIni(path, L"diagnostics", L"log_transport_data", cfg.log_transport_data ? 1 : 0);
    WriteIntIni(path, L"diagnostics", L"redact_secrets", cfg.log_redact_secrets ? 1 : 0);
    WriteIntIni(path, L"http_server", L"enabled", cfg.http_server_enable ? 1 : 0);
    WritePrivateProfileStringW(L"http_server", L"bind", cfg.http_server_bind, path);
    WriteIntIni(path, L"http_server", L"port", cfg.http_server_port);
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

static void DiagnosticLog(int level, const wchar_t* text)
{
    McpConfig cfg = CopyConfig();
    if (!cfg.log_to_file || level > cfg.log_level || !text)
        return;
    wchar_t path[MAX_PATH];
    GetPluginDirectory(path, _countof(path));
    StringCchCatW(path, _countof(path), L"McpTools.log");
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    const wchar_t* level_text = L"INFO";
    if (level == 0)
        level_text = L"ERROR";
    else if (level == 1)
        level_text = L"WARN";
    else if (level >= 3)
        level_text = L"DEBUG";
    wchar_t line[1200];
    StringCchPrintfW(line, _countof(line),
        L"%04u-%02u-%02u %02u:%02u:%02u.%03u [%s] %s\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        st.wMilliseconds, level_text, text);
    std::string utf8 = WideToUtf8(line);
    DWORD written = 0;
    if (!utf8.empty())
        WriteFile(file, utf8.data(), (DWORD)utf8.size(), &written, NULL);
    CloseHandle(file);
}

static void DiagnosticLogUtf8(int level, const char* prefix, const std::string& text)
{
    std::string combined = prefix ? prefix : "";
    combined += text;
    std::wstring wide = Utf8ToWide(combined);
    DiagnosticLog(level, wide.c_str());
}

static void LogTransportJson(const McpConfig& cfg, const char* prefix, const std::string& json)
{
    if (!cfg.log_transport_data)
        return;
    if (cfg.log_redact_secrets) {
        char text[160];
        StringCchPrintfA(text, _countof(text), "%s%u bytes",
            prefix ? prefix : "", (unsigned int)json.size());
        DiagnosticLogUtf8(3, "", text);
    }
    else {
        DiagnosticLogUtf8(3, prefix, json);
    }
}

static void SetRuntimeStatus(BOOL connected, const wchar_t* error_text)
{
    EnterCriticalSection(&g_status_cs);
    g_connected = connected;
    if (connected) {
        g_last_connect_tick = GetTickCount();
        g_last_error[0] = L'\0';
    }
    else if (error_text) {
        StringCchCopyW(g_last_error, _countof(g_last_error), error_text);
    }
    LeaveCriticalSection(&g_status_cs);
    if (error_text)
        DiagnosticLog(connected ? 2 : 0, error_text);
}

static void GetRuntimeStatus(BOOL* connected, wchar_t* error_text, size_t error_cch,
    LONG* reconnect_attempts)
{
    EnterCriticalSection(&g_status_cs);
    if (connected)
        *connected = g_connected;
    if (error_text && error_cch)
        StringCchCopyW(error_text, error_cch, g_last_error);
    if (reconnect_attempts)
        *reconnect_attempts = g_reconnect_attempts;
    LeaveCriticalSection(&g_status_cs);
}

static void SetConnectionError(const wchar_t* error_text)
{
    SetRuntimeStatus(FALSE, error_text);
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

static void JsonAppendRawOrObject(std::string& out, const wchar_t* text)
{
    std::string utf8 = WideToUtf8(text);
    const char* p = utf8.c_str();
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        ++p;
    if (*p == '{')
        out += p;
    else
        out += "{}";
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
    McpConfig cfg = CopyConfig();
    if (cfg.log_raw_json)
        DiagnosticLogUtf8(3, "queue json: ", json);
    EnterCriticalSection(&g_queue_cs);
    size_t max_queue = cfg.event_queue_max > 0 ? (size_t)cfg.event_queue_max : MCP_MAX_QUEUE;
    if (g_queue.size() >= max_queue)
        g_queue.pop_front();
    g_queue.push_back(json);
    LeaveCriticalSection(&g_queue_cs);
    if (g_queue_event)
        SetEvent(g_queue_event);
}

static bool JsonHasKey(const std::string& json, const char* key)
{
    std::string pattern = "\"";
    pattern += key;
    pattern += "\"";
    return json.find(pattern) != std::string::npos;
}

static void NoteIncomingResponse(const std::string& json)
{
    std::string id = ExtractIdJson(json);
    if (id.empty() || (!JsonHasKey(json, "result") && !JsonHasKey(json, "error")))
        return;
    EnterCriticalSection(&g_response_cs);
    for (size_t i = 0; i < g_pending_responses.size(); ++i) {
        if (g_pending_responses[i].id == id) {
            g_pending_responses[i].response = json;
            SetEvent(g_pending_responses[i].event);
            break;
        }
    }
    LeaveCriticalSection(&g_response_cs);
}

static bool IsJsonRpcResponseMessage(const std::string& json)
{
    return !ExtractIdJson(json).empty() &&
        (JsonHasKey(json, "result") || JsonHasKey(json, "error"));
}

static HANDLE BeginJsonResponseWait(const std::string& id)
{
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!event)
        return NULL;
    PendingResponse pending;
    pending.id = id;
    pending.event = event;
    EnterCriticalSection(&g_response_cs);
    g_pending_responses.push_back(pending);
    LeaveCriticalSection(&g_response_cs);
    return event;
}

static bool FinishJsonResponseWait(HANDLE event, DWORD timeout_ms, std::string& response)
{
    if (!event)
        return false;
    bool ok = WaitForSingleObject(event, timeout_ms) == WAIT_OBJECT_0;
    EnterCriticalSection(&g_response_cs);
    for (std::vector<PendingResponse>::iterator it = g_pending_responses.begin();
         it != g_pending_responses.end(); ++it) {
        if (it->event == event) {
            if (ok)
                response = it->response;
            g_pending_responses.erase(it);
            break;
        }
    }
    LeaveCriticalSection(&g_response_cs);
    CloseHandle(event);
    return ok && !response.empty();
}

static std::string ExtractJsonMemberObject(const std::string& json, const char* key)
{
    std::string pattern = "\"";
    pattern += key;
    pattern += "\"";
    size_t p = json.find(pattern);
    if (p == std::string::npos)
        return std::string();
    p = json.find(':', p + pattern.size());
    if (p == std::string::npos)
        return std::string();
    ++p;
    while (p < json.size() && isspace((unsigned char)json[p]))
        ++p;
    if (p >= json.size() || json[p] != '{')
        return std::string();
    size_t start = p;
    int depth = 0;
    bool in_string = false;
    bool escape = false;
    for (; p < json.size(); ++p) {
        char ch = json[p];
        if (in_string) {
            if (escape)
                escape = false;
            else if (ch == '\\')
                escape = true;
            else if (ch == '"')
                in_string = false;
            continue;
        }
        if (ch == '"') {
            in_string = true;
        }
        else if (ch == '{') {
            ++depth;
        }
        else if (ch == '}') {
            --depth;
            if (depth == 0)
                return json.substr(start, p - start + 1);
        }
    }
    return std::string();
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

static bool HttpPostJsonWithResponse(const McpConfig& cfg, const std::string& json, std::string* response_body)
{
    if (cfg.agent_strict && !AccessNetworkAllowed(cfg.url, cfg.agent_network)) return false;
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

    DWORD access_type = cfg.http_proxy[0]
        ? WINHTTP_ACCESS_TYPE_NAMED_PROXY : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
    std::wstring proxy = cfg.http_proxy;
    HINTERNET session = WinHttpOpen(
        cfg.http_user_agent[0] ? cfg.http_user_agent : L"Z0BDbg MCP Tools/1.0",
        access_type,
        cfg.http_proxy[0] ? proxy.c_str() : WINHTTP_NO_PROXY_NAME,
        cfg.http_proxy[0] ? L"<local>" : WINHTTP_NO_PROXY_BYPASS, 0);
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
    const wchar_t* method = lstrcmpiW(cfg.http_method, L"GET") == 0 ? L"GET" :
        (lstrcmpiW(cfg.http_method, L"PUT") == 0 ? L"PUT" : L"POST");
    HINTERNET request = WinHttpOpenRequest(connect, method, path.c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }
    if (cfg.agent_strict) {
        DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
        if (!WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled))) {
            WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return false;
        }
    }
    if (!cfg.http_verify_tls && (flags & WINHTTP_FLAG_SECURE)) {
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS,
            &security_flags, sizeof(security_flags));
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (cfg.auth_token[0]) {
        headers += L"Authorization: Bearer ";
        headers += cfg.auth_token;
        headers += L"\r\n";
    }
    const wchar_t* custom = cfg.http_headers;
    while (custom && *custom) {
        const wchar_t* line = custom;
        while (*custom && *custom != L'\r' && *custom != L'\n')
            ++custom;
        if (custom > line) {
            headers.append(line, custom - line);
            headers += L"\r\n";
        }
        while (*custom == L'\r' || *custom == L'\n')
            ++custom;
    }
    BOOL ok = WinHttpSendRequest(request, headers.c_str(), (DWORD)-1L,
        (LPVOID)json.data(), (DWORD)json.size(), (DWORD)json.size(), 0);
    LogTransportJson(cfg, "http send: ", json);
    if (ok)
        ok = WinHttpReceiveResponse(request, NULL);
    if (ok && response_body) {
        response_body->clear();
        for (;;) {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available) || available == 0)
                break;
            std::string chunk;
            chunk.resize(available);
            DWORD read = 0;
            if (!WinHttpReadData(request, &chunk[0], available, &read) || read == 0)
                break;
            chunk.resize(read);
            response_body->append(chunk);
        }
        if (!response_body->empty())
            NoteIncomingResponse(*response_body);
        if (!response_body->empty())
            LogTransportJson(cfg, "http recv: ", *response_body);
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    if (ok)
        SetRuntimeStatus(TRUE, NULL);
    else
        SetConnectionError(McpText(L"HTTP 请求失败。", L"HTTP request failed."));
    return ok ? true : false;
}

static bool HttpPostJson(const McpConfig& cfg, const std::string& json)
{
    return HttpPostJsonWithResponse(cfg, json, NULL);
}

static std::string PipeJsonString(const std::string& json, const char* key)
{
    std::string token = "\"";
    token += key;
    token += "\"";
    size_t p = json.find(token);
    if (p == std::string::npos)
        return std::string();
    p = json.find(':', p + token.size());
    if (p == std::string::npos)
        return std::string();
    p = json.find('"', p + 1);
    if (p == std::string::npos)
        return std::string();
    ++p;
    std::string value;
    while (p < json.size()) {
        char ch = json[p++];
        if (ch == '"')
            break;
        if (ch == '\\' && p < json.size()) {
            char escaped = json[p++];
            value.push_back(escaped == 'n' ? '\n' : escaped == 'r' ? '\r' : escaped);
        } else {
            value.push_back(ch);
        }
    }
    return value;
}

static std::string PipeHex(const unsigned char* data, size_t size)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.resize(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = digits[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[data[i] & 0xF];
    }
    return out;
}

static bool PipeUnhex(const std::string& text, std::string& output)
{
    if ((text.size() & 1) != 0)
        return false;
    output.clear();
    output.resize(text.size() / 2);
    for (size_t i = 0; i < output.size(); ++i) {
        int high = HexDigit(text[i * 2]);
        int low = HexDigit(text[i * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        output[i] = (char)((high << 4) | low);
    }
    return true;
}

static bool PipeHmacSha256(const std::string& key, const std::string& input, std::string& output)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    DWORD object_size = 0;
    DWORD result_size = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status >= 0)
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&object_size, sizeof(object_size), &result_size, 0);
    if (status >= 0) {
        object = new unsigned char[object_size];
        status = BCryptCreateHash(algorithm, &hash, object, object_size,
            (PUCHAR)(key.empty() ? NULL : (void*)key.data()), (ULONG)key.size(), 0);
    }
    if (status >= 0)
        status = BCryptHashData(hash, (PUCHAR)(input.empty() ? NULL : (void*)input.data()),
            (ULONG)input.size(), 0);
    unsigned char digest[32] = {0};
    if (status >= 0)
        status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (hash)
        BCryptDestroyHash(hash);
    if (algorithm)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    delete[] object;
    if (status < 0)
        return false;
    output = PipeHex(digest, sizeof(digest));
    return true;
}

static std::string PipeXorCrypt(const std::string& key, const std::string& nonce, const std::string& input)
{
    std::string output(input.size(), '\0');
    size_t offset = 0;
    unsigned int counter = 0;
    while (offset < input.size()) {
        char counter_text[32];
        StringCchPrintfA(counter_text, _countof(counter_text), "%u", counter++);
        std::string block;
        if (!PipeHmacSha256(key, "stream|" + nonce + "|" + counter_text, block))
            return std::string();
        size_t count = input.size() - offset;
        if (count > block.size() / 2)
            count = block.size() / 2;
        for (size_t i = 0; i < count; ++i) {
            int high = HexDigit(block[i * 2]);
            int low = HexDigit(block[i * 2 + 1]);
            output[offset + i] = (char)((unsigned char)input[offset + i] ^
                (unsigned char)((high << 4) | low));
        }
        offset += count;
    }
    return output;
}

static std::string PipeRandomHex(size_t bytes)
{
    std::vector<unsigned char> data(bytes);
    if (BCryptGenRandom(NULL, data.data(), (ULONG)data.size(),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return std::string();
    return PipeHex(data.data(), data.size());
}

static bool PipeWriteLine(HANDLE pipe, const std::string& json)
{
    std::string line = json;
    line += "\n";
    DWORD written = 0;
    return WriteFile(pipe, line.data(), (DWORD)line.size(), &written, NULL) &&
        written == line.size() && FlushFileBuffers(pipe);
}

static bool PipeReadLine(HANDLE pipe, DWORD timeout_ms, std::string& line)
{
    line.clear();
    DWORD start = GetTickCount();
    for (;;) {
        char ch = 0;
        DWORD read = 0;
        if (ReadFile(pipe, &ch, 1, &read, NULL) && read == 1) {
            if (ch == '\n')
                return true;
            if (ch != '\r')
                line.push_back(ch);
            if (line.size() > 1024 * 1024)
                return false;
            continue;
        }
        if (GetTickCount() - start >= timeout_ms)
            return false;
        Sleep(10);
    }
}

static bool PipeHandshake(
    HANDLE pipe,
    const McpConfig& cfg,
    bool* encrypted_out,
    std::string* server_nonce_out,
    std::string* client_nonce_out)
{
    if (encrypted_out)
        *encrypted_out = false;
    if (server_nonce_out)
        server_nonce_out->clear();
    if (client_nonce_out)
        client_nonce_out->clear();
    if (lstrcmpiW(cfg.pipe_protocol, L"z0bdbg") != 0 &&
        lstrcmpiW(cfg.pipe_protocol, L"z0bdbg-strict") != 0)
        return true;

    std::string challenge;
    if (!PipeReadLine(pipe, (DWORD)cfg.pipe_handshake_timeout_ms, challenge))
        return false;
    std::string protocol = PipeJsonString(challenge, "protocol");
    std::string server_mode = PipeJsonString(challenge, "mode");
    std::string server_nonce = PipeJsonString(challenge, "nonce");
    if (protocol != "Z0BDbgMcpBridge-v1" || server_nonce.empty())
        return false;

    std::string client_mode = lstrcmpiW(cfg.pipe_protocol, L"z0bdbg-strict") == 0
        ? "strict" : (cfg.shared_key[0] ? "optional" : "plain");
    if (!cfg.pipe_allow_unencrypted && !cfg.shared_key[0])
        return false;
    std::string hello = "{\"hello\":true,\"protocol\":\"Z0BDbgMcpBridge-v1\",\"mode\":\"";
    hello += client_mode;
    hello += "\",\"nonce\":\"";
    std::string client_nonce = PipeRandomHex(16);
    hello += client_nonce;
    hello += "\"";
    bool encrypted = lstrcmpiW(cfg.pipe_protocol, L"z0bdbg-strict") == 0 ||
        server_mode == "strict" ||
        (server_mode == "optional" && client_mode == "optional");
    if (encrypted) {
        if (!cfg.shared_key[0])
            return false;
        std::string proof;
        if (!PipeHmacSha256(WideToUtf8(cfg.shared_key),
            "hello|Z0BDbgMcpBridge-v1|" + server_nonce + "|" + client_nonce + "|encrypted", proof))
            return false;
        hello += ",\"proof\":\"" + proof + "\"";
    }
    hello += "}";
    if (!PipeWriteLine(pipe, hello))
        return false;

    std::string ack;
    if (!PipeReadLine(pipe, (DWORD)cfg.pipe_handshake_timeout_ms, ack))
        return false;
    if (PipeJsonString(ack, "protocol") != "Z0BDbgMcpBridge-v1" ||
        PipeJsonString(ack, "mode") != (encrypted ? "encrypted" : "plain"))
        return false;
    if (encrypted_out)
        *encrypted_out = encrypted;
    if (server_nonce_out)
        *server_nonce_out = server_nonce;
    if (client_nonce_out)
        *client_nonce_out = client_nonce;
    return PipeJsonString(ack, "ok") == "true" || ack.find("\"ok\":true") != std::string::npos;
}

static bool EnsurePipeConnection(const McpConfig& cfg)
{
    if (g_pipe_handle)
        return true;
    if (!cfg.pipe_name[0])
        return false;
    DWORD timeout = (DWORD)(cfg.timeout_ms > 0 ? cfg.timeout_ms : 30000);
    if (!WaitNamedPipeW(cfg.pipe_name, timeout))
        return false;
    HANDLE pipe = CreateFileW(cfg.pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
        return false;
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(pipe, &mode, NULL, NULL);
    bool encrypted = false;
    std::string server_nonce;
    std::string client_nonce;
    if (!PipeHandshake(pipe, cfg, &encrypted, &server_nonce, &client_nonce)) {
        CloseHandle(pipe);
        SetConnectionError(McpText(L"pipe 握手失败。", L"pipe handshake failed."));
        return false;
    }
    g_pipe_encrypted = encrypted;
    g_pipe_server_nonce = server_nonce;
    g_pipe_client_nonce = client_nonce;
    g_pipe_handle = pipe;
    SetRuntimeStatus(TRUE, NULL);
    g_pipe_reader_thread = CreateThread(NULL, 0, PipeReaderThreadProc, NULL, 0, NULL);
    if (!g_pipe_reader_thread) {
        CloseHandle(g_pipe_handle);
        g_pipe_handle = NULL;
        g_pipe_encrypted = false;
        g_pipe_server_nonce.clear();
        g_pipe_client_nonce.clear();
        return false;
    }
    return true;
}

static void ClosePipeConnection(void)
{
    HANDLE reader = NULL;
    EnterCriticalSection(&g_pipe_cs);
    reader = g_pipe_reader_thread;
    g_pipe_reader_thread = NULL;
    if (g_pipe_handle) {
        FlushFileBuffers(g_pipe_handle);
        CloseHandle(g_pipe_handle);
        g_pipe_handle = NULL;
        g_pipe_encrypted = false;
        g_pipe_server_nonce.clear();
        g_pipe_client_nonce.clear();
        InterlockedExchange(&g_mcp_initialized, 0);
        SetRuntimeStatus(FALSE, NULL);
    }
    LeaveCriticalSection(&g_pipe_cs);
    if (reader) {
        WaitForSingleObject(reader, 1000);
        CloseHandle(reader);
    }
}

static bool SendPipeJson(const McpConfig& cfg, const std::string& json, bool expect_response)
{
    (void)expect_response;
    EnterCriticalSection(&g_pipe_cs);
    if (!EnsurePipeConnection(cfg)) {
        LeaveCriticalSection(&g_pipe_cs);
        return false;
    }
    std::string payload = json;
    if (lstrcmpiW(cfg.pipe_protocol, L"z0bdbg") == 0) {
        payload = json;
    }
    if (g_pipe_encrypted) {
        std::string nonce = PipeRandomHex(16);
        std::string cipher = PipeXorCrypt(WideToUtf8(cfg.shared_key), nonce, payload);
        std::string data = PipeHex((const unsigned char*)cipher.data(), cipher.size());
        std::string tag;
        if (nonce.empty() || cipher.size() != payload.size() ||
            !PipeHmacSha256(WideToUtf8(cfg.shared_key), "packet|" + nonce + "|" + data, tag)) {
            LeaveCriticalSection(&g_pipe_cs);
            return false;
        }
        payload = "{\"secure\":1,\"nonce\":\"" + nonce + "\",\"data\":\"" + data +
            "\",\"tag\":\"" + tag + "\"}";
    }
    if (!PipeWriteLine(g_pipe_handle, payload)) {
        CloseHandle(g_pipe_handle);
        g_pipe_handle = NULL;
        g_pipe_encrypted = false;
        g_pipe_server_nonce.clear();
        g_pipe_client_nonce.clear();
        LeaveCriticalSection(&g_pipe_cs);
        return false;
    }
    LogTransportJson(cfg, "pipe send: ", json);
    LeaveCriticalSection(&g_pipe_cs);
    return true;
}

static bool PipeDecodePayload(const std::string& wire, const McpConfig& cfg, std::string& json)
{
    json = wire;
    if (!g_pipe_encrypted)
        return true;

    std::string nonce = PipeJsonString(wire, "nonce");
    std::string data = PipeJsonString(wire, "data");
    std::string tag = PipeJsonString(wire, "tag");
    std::string cipher;
    std::string expected;
    if (nonce.empty() || data.empty() || tag.empty() ||
        !PipeUnhex(data, cipher) ||
        !PipeHmacSha256(WideToUtf8(cfg.shared_key), "packet|" + nonce + "|" + data, expected) ||
        expected != tag)
        return false;
    json = PipeXorCrypt(WideToUtf8(cfg.shared_key), nonce, cipher);
    return json.size() == cipher.size();
}

static bool PipeWritePayload(HANDLE pipe, const McpConfig& cfg, const std::string& json)
{
    std::string payload = json;
    if (g_pipe_encrypted) {
        std::string nonce = PipeRandomHex(16);
        std::string cipher = PipeXorCrypt(WideToUtf8(cfg.shared_key), nonce, payload);
        std::string data = PipeHex((const unsigned char*)cipher.data(), cipher.size());
        std::string tag;
        if (nonce.empty() || cipher.size() != payload.size() ||
            !PipeHmacSha256(WideToUtf8(cfg.shared_key), "packet|" + nonce + "|" + data, tag))
            return false;
        payload = "{\"secure\":1,\"nonce\":\"" + nonce + "\",\"data\":\"" + data +
            "\",\"tag\":\"" + tag + "\"}";
    }
    return PipeWriteLine(pipe, payload);
}

static DWORD WINAPI PipeReaderThreadProc(LPVOID)
{
    HANDLE pipe = g_pipe_handle;
    if (!pipe)
        return 0;

    for (;;) {
        std::string wire;
        if (!PipeReadLine(pipe, 0xFFFFFFFF, wire))
            break;

        McpConfig cfg = CopyConfig();
        std::string request;
        if (!PipeDecodePayload(wire, cfg, request))
            continue;
        LogTransportJson(cfg, "pipe recv: ", request);
        NoteIncomingResponse(request);
        if (IsJsonRpcResponseMessage(request))
            continue;

        std::string method;
        std::string tool;
        std::string name;
        JsonFindString(request, "method", method);
        JsonFindString(request, "tool", tool);
        JsonFindString(request, "name", name);

        // Responses and event notifications are not debugger commands.
        if (method == "z0dbg/event" ||
            (method.empty() && tool.empty() && name.empty()))
            continue;
        if (!cfg.receive_server_commands)
            continue;

        std::string response = ExecuteToolCommand(request);
        EnterCriticalSection(&g_pipe_cs);
        if (g_pipe_handle == pipe && cfg.auto_reply_requests)
            PipeWritePayload(pipe, cfg, response);
        LeaveCriticalSection(&g_pipe_cs);
    }
    return 0;
}

static bool SendStdioJson(const McpConfig& cfg, const std::string& json);

static bool BuildTestEvent(std::string& json)
{
    json = BuildBaseEventPrefix("test");
    json += "}}";
    return true;
}

static bool SendTestWithConfig(const McpConfig& cfg)
{
    std::string json;
    BuildTestEvent(json);
    if (lstrcmpiW(cfg.transport, L"stdio") == 0)
        return SendStdioJson(cfg, json);
    if (lstrcmpiW(cfg.transport, L"pipe") == 0)
        return SendPipeJson(cfg, json, true);
    return HttpPostJson(cfg, json);
}

static bool SendControlJson(const McpConfig& cfg, const std::string& json)
{
    if (!EnsureTransportReady(cfg))
        return false;
    if (lstrcmpiW(cfg.transport, L"stdio") == 0)
        return SendStdioJson(cfg, json);
    if (lstrcmpiW(cfg.transport, L"pipe") == 0)
        return SendPipeJson(cfg, json, false);
    return HttpPostJson(cfg, json);
}

static bool SendJsonRequestWithResponse(const McpConfig& cfg, const std::string& json,
    std::string* response, bool initialize_first)
{
    if (response)
        response->clear();
    if (!EnsureTransportReady(cfg))
        return false;
    if (initialize_first && !EnsureMcpInitialized(cfg))
        return false;
    std::string id = ExtractIdJson(json);
    if (id.empty())
        return false;
    if (lstrcmpiW(cfg.transport, L"http") == 0 ||
        lstrcmpiW(cfg.transport, L"sse") == 0) {
        return HttpPostJsonWithResponse(cfg, json, response);
    }
    HANDLE response_event = BeginJsonResponseWait(id);
    if (!response_event)
        return false;
    bool sent = false;
    if (lstrcmpiW(cfg.transport, L"stdio") == 0)
        sent = SendStdioJson(cfg, json);
    else if (lstrcmpiW(cfg.transport, L"pipe") == 0)
        sent = SendPipeJson(cfg, json, false);
    if (!sent) {
        FinishJsonResponseWait(response_event, 0, *response);
        return false;
    }
    return FinishJsonResponseWait(response_event, (DWORD)cfg.request_timeout_ms, *response);
}

static bool TestConnectionWithConfig(const McpConfig& cfg, std::string* response)
{
    return SendJsonRequestWithResponse(cfg,
        "{\"jsonrpc\":\"2.0\",\"id\":1001,\"method\":\"ping\",\"params\":{}}", response, true);
}

static bool TestInitializeWithConfig(const McpConfig& cfg, std::string* response)
{
    bool ok = SendJsonRequestWithResponse(cfg, BuildInitializeJson(cfg), response, false);
    if (ok)
        InterlockedExchange(&g_mcp_initialized, 1);
    if (ok)
        ok = SendControlJson(cfg, BuildInitializedJson());
    return ok;
}

static bool TestToolsWithConfig(const McpConfig& cfg, std::string* response)
{
    return SendJsonRequestWithResponse(cfg,
        "{\"jsonrpc\":\"2.0\",\"id\":1002,\"method\":\"tools/list\",\"params\":{}}", response, true);
}

static bool TestToolWithConfig(const McpConfig& cfg, std::string* response)
{
    std::string name = WideToUtf8(cfg.test_tool_name);
    if (name.empty())
        return false;
    std::string json = "{\"jsonrpc\":\"2.0\",\"id\":1003,\"method\":\"tools/call\",\"params\":{\"name\":";
    JsonAppendEscaped(json, name.c_str());
    json += ",\"arguments\":";
    std::string args = WideToUtf8(cfg.test_tool_args);
    const char* p = args.c_str();
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        ++p;
    if (*p == '{')
        json += p;
    else
        json += "{}";
    json += "}}";
    return SendJsonRequestWithResponse(cfg, json, response, true);
}

static void SetResponseStatus(HWND hwnd, const wchar_t* action, bool ok,
    const std::string& response)
{
    std::wstring wide_response = Utf8ToWide(response);
    wchar_t message[1400];
    StringCchPrintfW(message, _countof(message), ok
        ? (McpIsEnglish() ? L"%s ok.\r\n%s" : L"%s成功。\r\n%s")
        : (McpIsEnglish() ? L"%s failed or timed out.\r\n%s" : L"%s失败或超时。\r\n%s"),
        action,
        wide_response.empty() ? L"" : wide_response.c_str());
    SetDlgItemTextW(hwnd, IDC_STATUS, message);
}

static void SetServerInfoStatus(HWND hwnd, bool ok, const std::string& response)
{
    std::string result = ExtractJsonMemberObject(response, "result");
    std::string server_info = ExtractJsonMemberObject(result.empty() ? response : result, "serverInfo");
    std::wstring wide_response = Utf8ToWide(server_info.empty() ? response : server_info);
    wchar_t message[1400];
    StringCchPrintfW(message, _countof(message), ok
        ? (McpIsEnglish() ? L"Server info:\r\n%s" : L"Server 信息：\r\n%s")
        : (McpIsEnglish() ? L"Server info request failed or timed out.\r\n%s" : L"Server 信息请求失败或超时。\r\n%s"),
        wide_response.empty() ? L"" : wide_response.c_str());
    SetDlgItemTextW(hwnd, IDC_STATUS, message);
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
    if (cfg.stdio_inherit_env && !cfg.stdio_isolate) {
        LPWCH current = GetEnvironmentStringsW();
        if (current) {
            for (LPWCH p = current; *p; p += lstrlenW(p) + 1) {
                env_block.append(p);
                env_block.push_back(L'\0');
            }
            FreeEnvironmentStringsW(current);
        }
    }
    if (cfg.stdio_isolate) {
        const wchar_t* names[] = { L"SystemRoot", L"TEMP", L"TMP" };
        for (int i = 0; i < 3; ++i) {
            wchar_t value[32768]; DWORD size = GetEnvironmentVariableW(names[i], value, _countof(value));
            if (size && size < _countof(value)) { env_block += names[i]; env_block += L'='; env_block += value; env_block += L'\0'; }
        }
    }
    AppendEnvironmentBlock(env_block, cfg.env);
    env_block.push_back(L'\0');
    return env_block;
}

static bool EnsureStdioProcess(const McpConfig& cfg)
{
    if (g_stdio_stdin) {
        if (!cfg.stdio_restart_on_exit || !g_stdio_process)
            return true;
        DWORD exit_code = STILL_ACTIVE;
        if (GetExitCodeProcess(g_stdio_process, &exit_code) && exit_code == STILL_ACTIVE)
            return true;
        if (g_stdio_stdout) {
            CloseHandle(g_stdio_stdout);
            g_stdio_stdout = NULL;
        }
        if (g_stdio_stdin) {
            CloseHandle(g_stdio_stdin);
            g_stdio_stdin = NULL;
        }
        CloseHandle(g_stdio_process);
        g_stdio_process = NULL;
        if (g_stdio_job) { CloseHandle(g_stdio_job); g_stdio_job = NULL; }
        InterlockedExchange(&g_mcp_initialized, 0);
    }
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

    std::wstring command = L"\"";
    command += cfg.command;
    command += L"\"";
    if (cfg.arguments[0]) {
        command += L" ";
        command += cfg.arguments;
    }
    std::wstring cmdline;
    if (cfg.stdio_shell) {
        cmdline = L"cmd.exe /d /s /c \"";
        cmdline += command;
        cmdline += L"\"";
    }
    else {
        cmdline = command;
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
    si.wShowWindow = cfg.stdio_show_console ? SW_SHOW : SW_HIDE;
    HANDLE stderr_handle = NULL;
    if (lstrcmpiW(cfg.stdio_stderr_mode, L"discard") == 0) {
        stderr_handle = CreateFileW(L"NUL", GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);
        if (stderr_handle != INVALID_HANDLE_VALUE)
            si.hStdError = stderr_handle;
        else
            stderr_handle = NULL;
    }

    std::wstring env = BuildEnvironmentBlock(cfg);
    DWORD creation_flags = CREATE_UNICODE_ENVIRONMENT;
    if (!cfg.stdio_show_console)
        creation_flags |= CREATE_NO_WINDOW;
    BOOL ok = cfg.stdio_isolate ? CreateIsolatedAgentProcess(&cmdline[0], env.empty() ? NULL : (LPVOID)env.c_str(),
        cfg.workdir[0] ? cfg.workdir : NULL, creation_flags, si, cfg.stdio_memory_mb, cfg.stdio_cpu_seconds, &pi, &g_stdio_job,
        cfg.stdio_strict ? cfg.stdio_files : NULL) :
        CreateProcessW(NULL, &cmdline[0], NULL, NULL, TRUE, creation_flags,
            env.empty() ? NULL : (LPVOID)env.c_str(), cfg.workdir[0] ? cfg.workdir : NULL, &si, &pi);
    if (stderr_handle)
        CloseHandle(stderr_handle);
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
    if (g_stdio_job) { CloseHandle(g_stdio_job); g_stdio_job = NULL; }
    InterlockedExchange(&g_mcp_initialized, 0);
    SetRuntimeStatus(FALSE, NULL);
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
        SetConnectionError(McpText(L"stdio Server 启动失败。", L"stdio Server failed to start."));
        LeaveCriticalSection(&g_stdio_cs);
        return false;
    }
    std::string line = json;
    line += "\n";
    LogTransportJson(cfg, "stdio send: ", json);
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
        if (g_stdio_job) { CloseHandle(g_stdio_job); g_stdio_job = NULL; }
        SetConnectionError(McpText(L"stdio 写入失败。", L"stdio write failed."));
        LeaveCriticalSection(&g_stdio_cs);
        return false;
    }
    SetRuntimeStatus(TRUE, NULL);
    LeaveCriticalSection(&g_stdio_cs);
    return true;
}

static std::string BuildInitializeJson(const McpConfig& cfg)
{
    std::string json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":";
    JsonAppendWide(json, cfg.protocol_version[0] ? cfg.protocol_version : L"2024-11-05");
    json += ",\"capabilities\":{},\"clientInfo\":{\"name\":";
    JsonAppendWide(json, cfg.client_name);
    json += ",\"version\":";
    JsonAppendWide(json, cfg.client_version);
    json += "}}}";
    return json;
}

static std::string BuildInitializedJson(void)
{
    return "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}";
}

static bool EnsureTransportReady(const McpConfig& cfg)
{
    if (lstrcmpiW(cfg.transport, L"stdio") == 0)
        return EnsureStdioProcess(cfg);
    if (lstrcmpiW(cfg.transport, L"pipe") == 0)
        return EnsurePipeConnection(cfg);
    return true;
}

static DWORD WINAPI LocalDispatchThread(LPVOID parameter)
{
    McpConfig cfg = *(McpConfig*)parameter;
    delete (McpConfig*)parameter;
    unsigned request_number = 2000;
    DWORD last_registration = 0;
    while (InterlockedCompareExchange(&g_local_dispatch_stop, 0, 0) == 0) {
        // The local MCP Server may restart while the debugger remains open.
        // Re-register the catalog so the new server instance can discover it.
        DWORD now = GetTickCount();
        if (last_registration == 0 || now - last_registration >= 2000) {
            char registration_id[32]; sprintf_s(registration_id, sizeof(registration_id), "%u", request_number++);
            std::string registration = "{\"jsonrpc\":\"2.0\",\"id\":" + std::string(registration_id) +
                ",\"method\":\"z0dbg/register_tools\",\"params\":{\"tools\":" +
                ToolListJson() + "}}";
            if (SendJsonRequestWithResponse(cfg, registration, NULL, false))
                last_registration = now;
        }
        char id[32]; sprintf_s(id, sizeof(id), "%u", request_number++);
        std::string poll = "{\"jsonrpc\":\"2.0\",\"id\":" + std::string(id) +
            ",\"method\":\"z0dbg/poll\",\"params\":{}}";
        std::string response;
        if (SendJsonRequestWithResponse(cfg, poll, &response, false)) {
            if (InterlockedCompareExchange(&g_local_dispatch_stop, 0, 0) != 0)
                break;
            ModelJson root;
            const ModelJson* result = NULL;
            const ModelJson* pending = NULL;
            if (ModelJson::parse(response, &root) && (result = root.get("result")) &&
                (pending = result->get("pending")) && pending->raw == "true") {
                const ModelJson* request_id = result->get("request_id");
                const ModelJson* request = result->get("request");
                if (request_id && request && request_id->kind == ModelJson::STRING && request->kind == ModelJson::STRING) {
                    std::string tool_response = ExecuteToolCommand(request->value);
                    if (InterlockedCompareExchange(&g_local_dispatch_stop, 0, 0) != 0)
                        break;
                    std::string submit = "{\"jsonrpc\":\"2.0\",\"id\":" + std::string(id) +
                        ",\"method\":\"z0dbg/result\",\"params\":{\"request_id\":";
                    JsonAppendEscaped(submit, request_id->value.c_str()); submit += ",\"response\":";
                    JsonAppendEscaped(submit, tool_response.c_str()); submit += "}}";
                    SendJsonRequestWithResponse(cfg, submit, NULL, false);
                }
            }
        }
        Sleep(50);
    }
    return 0;
}

static bool EnsureMcpInitialized(const McpConfig& cfg)
{
    if (!cfg.mcp_initialize)
        return true;
    if (InterlockedCompareExchange(&g_mcp_initialized, 1, 1) == 1)
        return true;

    std::string initialize = BuildInitializeJson(cfg);
    std::string initialized = BuildInitializedJson();
    bool ok = false;
    if (lstrcmpiW(cfg.transport, L"stdio") == 0) {
        ok = SendStdioJson(cfg, initialize) && SendStdioJson(cfg, initialized);
    }
    else if (lstrcmpiW(cfg.transport, L"pipe") == 0) {
        ok = SendPipeJson(cfg, initialize, false) && SendPipeJson(cfg, initialized, false);
    }
    else {
        ok = HttpPostJson(cfg, initialize) && HttpPostJson(cfg, initialized);
    }
    if (ok) {
        InterlockedExchange(&g_mcp_initialized, 1);
        // Advertise the debugger tools to a local MCP Server so it can serve
        // the catalog directly to its model conversation.
        std::string registration = "{\"jsonrpc\":\"2.0\",\"id\":1004,\"method\":\"z0dbg/register_tools\",\"params\":{\"tools\":" +
            ToolListJson() + "}}";
        std::string registration_response;
        if (!SendJsonRequestWithResponse(cfg, registration, &registration_response, false)) {
            InterlockedExchange(&g_mcp_initialized, 0);
            return false;
        }
        if (!g_local_dispatch_thread) {
            McpConfig* worker_cfg = new McpConfig(cfg);
            InterlockedExchange(&g_local_dispatch_stop, 0);
            g_local_dispatch_thread = CreateThread(NULL, 0, LocalDispatchThread, worker_cfg, 0, NULL);
        }
        return true;
    }
    InterlockedExchange(&g_mcp_initialized, 0);
    return false;
}

static bool SendJsonToServer(const McpConfig& cfg, const std::string& json)
{
    if (!cfg.enabled)
        return false;
    int attempts = 1;
    if (cfg.auto_reconnect)
        attempts = cfg.reconnect_max_attempts > 0 ? cfg.reconnect_max_attempts : 1;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (g_stop_event && WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0)
            return false;
        if (attempt > 0) {
            InterlockedIncrement(&g_reconnect_attempts);
            if (g_stop_event && WaitForSingleObject(g_stop_event,
                (DWORD)cfg.reconnect_interval_ms) == WAIT_OBJECT_0)
                return false;
        }
        if (!EnsureTransportReady(cfg) || !EnsureMcpInitialized(cfg))
            continue;
        bool ok = false;
        if (lstrcmpiW(cfg.transport, L"stdio") == 0)
            ok = SendStdioJson(cfg, json);
        else if (lstrcmpiW(cfg.transport, L"pipe") == 0)
            ok = SendPipeJson(cfg, json, false);
        else
            ok = HttpPostJson(cfg, json);
        if (ok) {
            InterlockedExchange(&g_reconnect_attempts, 0);
            return true;
        }
    }
    SetConnectionError(McpText(L"连接失败，已达到重试次数。", L"Connection failed; retry limit reached."));
    return false;
}

static void AutoConnectConfiguredServer(const McpConfig& cfg)
{
    if (!cfg.enabled || !cfg.auto_connect)
        return;
    if (EnsureTransportReady(cfg) && EnsureMcpInitialized(cfg)) {
        InterlockedExchange(&g_reconnect_attempts, 0);
        SetRuntimeStatus(TRUE, NULL);
    }
    else {
        SetConnectionError(McpText(L"自动连接失败。", L"Automatic connection failed."));
    }
}

static DWORD WINAPI WorkerThreadProc(LPVOID)
{
    AutoConnectConfiguredServer(CopyConfig());
    HANDLE handles[2] = { g_stop_event, g_queue_event };
    for (;;) {
        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0)
            break;
        for (;;) {
            if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0)
                break;
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
            if (!SendJsonToServer(cfg, item) &&
                lstrcmpiW(cfg.transport, L"pipe") == 0 &&
                cfg.pipe_retain_queue) {
                EnterCriticalSection(&g_queue_cs);
                if (g_queue.size() < MCP_MAX_QUEUE)
                    g_queue.push_front(item);
                LeaveCriticalSection(&g_queue_cs);
                if (WaitForSingleObject(g_stop_event,
                    (DWORD)cfg.reconnect_interval_ms) == WAIT_OBJECT_0)
                    break;
            }
        }
    }
    CloseStdioProcess();
    ClosePipeConnection();
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
    StartHttpServerIfConfigured(CopyConfig());
}

static void StopWorker(void)
{
    InterlockedExchange(&g_runtime_ready, 0);
    InterlockedExchange(&g_local_dispatch_stop, 1);
    if (g_stop_event)
        SetEvent(g_stop_event);
    if (g_worker_thread) {
        WaitForSingleObject(g_worker_thread, INFINITE);
        CloseHandle(g_worker_thread);
        g_worker_thread = NULL;
    }
    if (g_local_dispatch_thread) {
        WaitForSingleObject(g_local_dispatch_thread, INFINITE);
        CloseHandle(g_local_dispatch_thread);
        g_local_dispatch_thread = NULL;
    }
    StopHttpServer();
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
        if ((ev->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
            ev->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_IN_PAGE_ERROR) && ev->u.Exception.ExceptionRecord.NumberParameters >= 2) {
            json += ",\"accessType\":" + DebugRuntimeFeed::number(ev->u.Exception.ExceptionRecord.ExceptionInformation[0]);
            json += ",\"faultAddress\":";
            JsonAppendHex64(json, ev->u.Exception.ExceptionRecord.ExceptionInformation[1]);
        }
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
    std::string captured = "{";
    AppendDebugEventData(captured, ev);
    // AppendDebugEventData starts fields with a comma.
    if (captured.size() > 1 && captured[1] == ',') captured.erase(1, 1);
    captured += "}";
    g_debug_feed.push(captured, ev->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT || ev->dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT,
        ev->dwDebugEventCode == EXCEPTION_DEBUG_EVENT, captured);
    McpConfig cfg = CopyConfig();
    if (!cfg.send_debug_events)
        return;
    switch (ev->dwDebugEventCode) {
    case EXCEPTION_DEBUG_EVENT:
        if (!cfg.event_exception)
            return;
        break;
    case CREATE_THREAD_DEBUG_EVENT:
    case EXIT_THREAD_DEBUG_EVENT:
        if (!cfg.event_thread)
            return;
        break;
    case CREATE_PROCESS_DEBUG_EVENT:
    case EXIT_PROCESS_DEBUG_EVENT:
        if (!cfg.event_process)
            return;
        break;
    case LOAD_DLL_DEBUG_EVENT:
    case UNLOAD_DLL_DEBUG_EVENT:
        if (!cfg.event_module)
            return;
        break;
    case OUTPUT_DEBUG_STRING_EVENT:
        if (!cfg.event_output)
            return;
        break;
    }
    if (cfg.event_ignore_duplicates) {
        char key[128];
        StringCchPrintfA(key, _countof(key), "%lu:%lu:%lu",
            ev->dwDebugEventCode, ev->dwProcessId, ev->dwThreadId);
        EnterCriticalSection(&g_queue_cs);
        bool duplicate = g_last_event_key == key;
        if (!duplicate)
            g_last_event_key = key;
        LeaveCriticalSection(&g_queue_cs);
        if (duplicate)
            return;
    }
    std::string json = BuildBaseEventPrefix("debug_event");
    AppendDebugEventData(json, ev);
    json += "}}";
    QueueJsonEvent(json);
}

static bool ShouldSendNotifyEvent(const McpConfig& cfg, int code)
{
    if (!cfg.send_debug_events)
        return false;
    switch (code) {
    case PN_NEWPROC:
    case PN_ENDPROC:
        return cfg.event_process != FALSE;
    case PN_NEWTHR:
    case PN_ENDTHR:
        return cfg.event_thread != FALSE;
    case PN_PREMOD:
    case PN_NEWMOD:
    case PN_ENDMOD:
        return cfg.event_module != FALSE;
    default:
        return true;
    }
}

static void QueueNotifyEvent(int code, void* data, ulong parm1, ulong parm2)
{
    McpConfig cfg = CopyConfig();
    if (!ShouldSendNotifyEvent(cfg, code))
        return;
    if (cfg.event_ignore_duplicates) {
        char key[160];
        StringCchPrintfA(key, _countof(key), "notify:%d:%llX:%llX",
            code, (unsigned long long)parm1, (unsigned long long)parm2);
        EnterCriticalSection(&g_queue_cs);
        bool duplicate = g_last_event_key == key;
        if (!duplicate)
            g_last_event_key = key;
        LeaveCriticalSection(&g_queue_cs);
        if (duplicate)
            return;
    }
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
    ModelJson root;
    if (!ModelJson::parse(json, &root)) return false;
    const ModelJson* field = root.get(key), *params = root.get("params");
    if (!field && params) field = params->get(key);
    const ModelJson* args = params ? params->get("arguments") : root.get("arguments");
    if (!field && args) field = args->get(key);
    if (!field || field->kind != ModelJson::STRING) return false;
    value = field->value; return true;
}

static bool JsonFindUInt64(const std::string& json, const char* key, unsigned __int64& value)
{
    ModelJson root;
    if (!ModelJson::parse(json, &root)) return false;
    const ModelJson* field = root.get(key), *params = root.get("params");
    if (!field && params) field = params->get(key);
    const ModelJson* args = params ? params->get("arguments") : root.get("arguments");
    if (!field && args) field = args->get(key);
    if (!field || (field->kind != ModelJson::STRING && field->kind != ModelJson::NUMBER)) return false;
    const std::string& text = field->kind == ModelJson::STRING ? field->value : field->raw;
    if (text.empty() || text[0] == '-' || text[0] == '+' || isspace((unsigned char)text[0])) return false;
    char* end = NULL; errno = 0;
    unsigned __int64 parsed = _strtoui64(text.c_str(), &end, field->kind == ModelJson::STRING ? 0 : 10);
    if (errno == ERANGE || !end || end == text.c_str() || *end) return false;
    value = parsed; return true;
}

static bool ListPageArguments(const std::string& json, unsigned __int64 default_limit,
    unsigned __int64& offset, unsigned __int64& limit)
{
    ModelJson args;
    if (!ModelJson::parse(json, &args) || args.kind != ModelJson::OBJECT) return false;
    offset = 0; limit = default_limit;
    const ModelJson* field = args.get("offset");
    if (field && (field->kind != ModelJson::NUMBER || !JsonFindUInt64(json, "offset", offset))) return false;
    field = args.get("limit");
    if (field && (field->kind != ModelJson::NUMBER || !JsonFindUInt64(json, "limit", limit))) return false;
    return offset <= 65535 && limit >= 1 && limit <= 64;
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

static bool StaticDebugTargetPath(wchar_t* path, size_t capacity)
{
    if (!path || !capacity) return false;
    DWORD pid = pMcpActiveProcessId ? CurrentDebugProcessId() : 0;
    if (!pid) return false;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W module = {}; module.dwSize = sizeof(module);
    bool found = Module32FirstW(snapshot, &module) != FALSE;
    if (found) {
        size_t name_length = wcslen(module.szModule);
        found = name_length >= 4 &&
            _wcsicmp(module.szModule + name_length - 4, L".exe") == 0 &&
            wcslen(module.szExePath) < capacity &&
            SUCCEEDED(StringCchCopyW(path, capacity, module.szExePath));
    }
    CloseHandle(snapshot);
    return found;
}

class IdaMappedSymbolCache {
    HANDLE file_, mapping_;
    const unsigned char* data_;
    const IdaMappedSymbolRecord* records_;
    size_t count_;
    unsigned __int64 image_base_;
    unsigned __int64 strings_offset_;
    unsigned __int64 file_size_;
public:
    IdaMappedSymbolCache() : file_(INVALID_HANDLE_VALUE), mapping_(NULL), data_(NULL),
        records_(NULL), count_(0), image_base_(0), strings_offset_(0), file_size_(0) {}
    ~IdaMappedSymbolCache() {
        if (data_) UnmapViewOfFile(data_);
        if (mapping_) CloseHandle(mapping_);
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    }
    bool open(const wchar_t* source, const StaticPeImage& image) {
        WIN32_FILE_ATTRIBUTE_DATA info = {};
        GUID guid = {};
        DWORD age = 0;
        if (!GetFileAttributesExW(source, GetFileExInfoStandard, &info) ||
            !image.pdb_identity(&guid, &age)) return false;
        unsigned __int64 source_size = ((unsigned __int64)info.nFileSizeHigh << 32) | info.nFileSizeLow;
        unsigned __int64 hash = 1469598103934665603ULL;
        for (const wchar_t* p = source; *p; ++p)
            hash = (hash ^ (unsigned short)towlower(*p)) * 1099511628211ULL;
        hash = (hash ^ source_size) * 1099511628211ULL;
        hash = (hash ^ (((unsigned __int64)info.ftLastWriteTime.dwHighDateTime << 32) |
            info.ftLastWriteTime.dwLowDateTime)) * 1099511628211ULL;
        wchar_t directory[MAX_PATH] = {};
        DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", directory, _countof(directory));
        if (!length || length >= _countof(directory)) {
            length = GetTempPathW(_countof(directory), directory);
            if (!length || length >= _countof(directory)) return false;
        }
        while (length && (directory[length - 1] == L'\\' || directory[length - 1] == L'/'))
            directory[--length] = 0;
        wchar_t path[MAX_PATH] = {};
        if (FAILED(StringCchPrintfW(path, _countof(path),
            L"%s\\Z0BDbg\\IdaCache\\%016llX.sym", directory, hash))) return false;
        file_ = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        LARGE_INTEGER size = {};
        if (file_ == INVALID_HANDLE_VALUE || !GetFileSizeEx(file_, &size) ||
            size.QuadPart < sizeof(IdaMappedSymbolHeader) ||
            (unsigned __int64)size.QuadPart > SIZE_MAX) return false;
        mapping_ = CreateFileMappingW(file_, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!mapping_) return false;
        data_ = (const unsigned char*)MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!data_) return false;
        const IdaMappedSymbolHeader* header = (const IdaMappedSymbolHeader*)data_;
        static const char magic[8] = {'Z','0','S','Y','M','0','0','1'};
        unsigned __int64 file_size = (unsigned __int64)size.QuadPart;
        if (memcmp(header->Magic, magic, sizeof(magic)) != 0 ||
            memcmp(&header->PdbGuid, &guid, sizeof(guid)) != 0 || header->PdbAge != age ||
            header->SourceSize != source_size ||
            CompareFileTime(&header->SourceTime, &info.ftLastWriteTime) != 0 ||
            header->Count > (file_size - sizeof(*header)) / sizeof(IdaMappedSymbolRecord) ||
            header->StringsOffset != sizeof(*header) +
                header->Count * sizeof(IdaMappedSymbolRecord)) return false;
        records_ = (const IdaMappedSymbolRecord*)(data_ + sizeof(*header));
        count_ = (size_t)header->Count;
        strings_offset_ = header->StringsOffset;
        image_base_ = image.image_base();
        file_size_ = file_size;
        return true;
    }
    const wchar_t* find(unsigned __int64 address) const {
        if (!records_ || address < image_base_) return NULL;
        unsigned __int64 rva = address - image_base_;
        const IdaMappedSymbolRecord* found = std::lower_bound(records_, records_ + count_, rva,
            [](const IdaMappedSymbolRecord& record, unsigned __int64 value) {
                return record.Rva < value;
            });
        if (found == records_ + count_ || found->Rva != rva || !found->NameLength ||
            found->NameOffset > file_size_ - strings_offset_) return NULL;
        unsigned __int64 bytes = ((unsigned __int64)found->NameLength + 1) * sizeof(wchar_t);
        if (bytes > file_size_ - strings_offset_ - found->NameOffset) return NULL;
        const wchar_t* name = (const wchar_t*)(data_ + strings_offset_ + found->NameOffset);
        return name[found->NameLength] == 0 ? name : NULL;
    }
};

static unsigned __int64 ResolveLoadedModuleExport(DWORD pid, const std::string& qualified,
    unsigned depth = 0)
{
    size_t separator = qualified.find('!');
    if (!pid || !separator || separator == qualified.size() - 1 || depth >= 4) return 0;
    std::wstring module_name = Utf8ToWide(qualified.substr(0, separator));
    if (module_name.empty()) return 0;
    if (module_name.find(L'.') == std::wstring::npos) module_name += L".dll";
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W module = {}; module.dwSize = sizeof(module);
    bool found = false;
    if (Module32FirstW(snapshot, &module)) do {
        if (_wcsicmp(module.szModule, module_name.c_str()) == 0) { found = true; break; }
    } while (Module32NextW(snapshot, &module));
    CloseHandle(snapshot);
    if (!found) return 0;

    StaticPeImage image;
    DWORD rva = 0;
    std::string forwarder;
    if (!image.open(module.szExePath) ||
        !image.find_export(qualified.substr(separator + 1), &rva, &forwarder)) return 0;
    if (!forwarder.empty()) {
        size_t dot = forwarder.rfind('.');
        return dot == std::string::npos ? 0 :
            ResolveLoadedModuleExport(pid, forwarder.substr(0, dot) + "!" + forwarder.substr(dot + 1), depth + 1);
    }
    return rva < module.modBaseSize ? (unsigned __int64)(ULONG_PTR)module.modBaseAddr + rva : 0;
}

static unsigned __int64 FindLoadedMainImport(DWORD pid, const std::string& name,
    unsigned __int64 range_start = 0, unsigned __int64 range_size = 0)
{
    if (!pid || name.empty()) return 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W module = {}; module.dwSize = sizeof(module);
    bool found = Module32FirstW(snapshot, &module) != FALSE;
    CloseHandle(snapshot);
    if (!found) return 0;
    StaticPeImage image;
    DWORD rva = 0;
    if (!image.open(module.szExePath) || !image.find_import(name, &rva) ||
        rva >= module.modBaseSize) return 0;
    unsigned __int64 slot = (unsigned __int64)(ULONG_PTR)module.modBaseAddr + rva;
    if (range_start && (slot < range_start ||
        (range_size && slot - range_start >= range_size))) return 0;
    return slot;
}

static bool ToolExportAvailable(const std::string& tool)
{
    if (tool.find("static_") == 0) {
        wchar_t target[MAX_PATH] = {0};
        return pMcpStaticQuery != NULL || StaticDebugTargetPath(target, _countof(target));
    }
    struct Export { const char* name; bool available; };
    Export exports[] = {
        { "get_status", pGetstatus != NULL }, { "get_cpu_thread_id", pGetcputhreadid != NULL },
        { "debug_open_process", pMcpOpenProcess != NULL || pMcpOpenProcessEx != NULL },
        { "debug_attach_pid", pMcpAttachPid != NULL }, { "debug_stop", pMcpStopDebug != NULL },
        { "register_get", pMcpGetRegister && pMcpTargetBits },
        { "register_list", pMcpGetRegister && pMcpTargetBits },
        { "register_set", pMcpSetRegister != NULL },
        { "stack_get_pointers", pMcpGetRegister && pMcpTargetBits },
        { "stack_read", pReadmemory != NULL },
        { "breakpoint_list", pGetnextbreakpoint != NULL },
        { "dump_memory_region", pReadmemory != NULL },
        { "run", pRun != NULL }, { "go", pGo && pGetcputhreadid }, { "pause", pSuspendprocess != NULL },
        { "step_into", pRun != NULL }, { "step_over", pRun != NULL }, { "trace_into", pRun != NULL }, { "trace_over", pRun != NULL },
        { "auto_step_into", pRun != NULL }, { "auto_step_over", pRun != NULL },
        { "read_memory", pReadmemory != NULL }, { "write_memory", pWritememory != NULL }, { "list_memory", pListmemory != NULL },
        { "find_memory", pFindmemory != NULL }, { "find_data_ptr", pFinddataptr != NULL },
        { "set_software_breakpoint", pSetbreakpoint != NULL }, { "set_software_breakpoint_ext", pSetbreakpointext != NULL },
        { "delete_software_breakpoint", pSetbreakpoint != NULL }, { "delete_breakpoint_range", pDeletebreakpoints != NULL },
        { "delete_all_breakpoints", pDeletebreakpoints != NULL }, { "set_memory_breakpoint", pSetmembreakpointSimple != NULL },
        { "delete_memory_breakpoint", pRemovemembreakpoint != NULL }, { "set_hardware_breakpoint", pSethardwarebreakpoint != NULL },
        { "delete_hardware_breakpoint", pDeletehardwarebreakbyaddr || pDeletehardwarebreakpoint },
        { "get_breakpoint_type", pGetbreakpointtype != NULL }, { "get_breakpoint_type_count", pGetbreakpointtypecount != NULL },
        { "get_next_breakpoint", pGetnextbreakpoint != NULL }, { "set_temp_breakpoint", pTempbreakpoint != NULL },
        { "plugin_temp_breakpoint", pPlugintempbreakpoint != NULL }, { "disassemble", pReadmemory && pDisasm },
        { "assemble", pAssemble && pWritememory }, { "set_cpu", pSetcpu && pGetcputhreadid }, { "set_disasm", pSetdisasm != NULL },
        { "evaluate", pExpressionA && pGetcputhreadid }, { "resolve_symbol", true }, { "find_name", pFindnameA != NULL }, { "insert_name", pInsertnameA != NULL },
        { "decode_address", pDecodeaddressA != NULL }, { "decode_name", pDecodenameA != NULL }, { "comment_address", pCommentaddressW != NULL },
        { "simple_address", pSimpleaddressW != NULL }, { "find_label", pFindlabelA != NULL }, { "find_module", pFindmodule != NULL },
        { "find_thread", pFindthread && pGetcputhreadid }, { "find_data", pFinddataA != NULL }, { "find_decode", pFinddecodeA != NULL },
        { "find_strings", pFindstringsA != NULL }, { "find_references", pFindreferencesA != NULL }, { "find_import_by_name", true },
        { "find_file_offset", pFindfileoffset != NULL }, { "follow_call", pFollowcall != NULL }, { "walk_reference", pWalkreference != NULL },
        { "walk_reference_ex", pWalkreferenceex != NULL }, { "is_prefix", pIsprefix != NULL }, { "get_last_error", pGetlasterrorW != NULL },
        { "get_cpu_disasm_dump", pGetcpudisasmdump != NULL }, { "get_cpu_disasm_table", pGetcpudisasmtable != NULL },
        { "plugin_read_ini_int", pPluginreadintfromini != NULL }, { "plugin_write_ini_int", pPluginwriteinttoini != NULL },
        { "plugin_read_ini_string", pPluginreadstringfromini != NULL }, { "plugin_write_ini_string", pPluginwritestringtoini != NULL },
        { "redraw_disasm", pRedrawcpudisasm != NULL }, { "redraw_registers", pRedrawcpureg != NULL }, { "redraw_list", pRedrawlist != NULL },
        { "suspend_all_threads", pSuspendallthreads != NULL }, { "resume_all_threads", pResumeallthreads != NULL },
        { "show_hardware_breakpoints", pHardbreakpoints != NULL }, { "show_threads", pCreatethreadwindow != NULL },
        { "show_trace", pCreatertracewindow != NULL }, { "show_windows", pCreatewinwindow != NULL }, { "show_patches", pCreatepatchwindow != NULL },
        { "show_watch", pCreatewatchwindow != NULL }, { "set_trace_condition", pSettraceconditionA != NULL }, { "set_trace_count", pSettracecount != NULL },
        { "set_trace_pause_on_commands", pSettracepauseoncommandsA != NULL }, { "set_dump_type", pSetdumptype != NULL },
        { "dump_backup", pDumpbackup != NULL }, { "plugin_module_changed", pPluginmodulechanged != NULL }
    };
    for (size_t i = 0; i < _countof(exports); ++i) if (tool == exports[i].name) return exports[i].available;
    return true;
}

static std::string ToolInputSchema(const std::string& tool)
{
    if (tool == "static_pe_info" || tool == "static_macho_info" || tool == "static_list_sections")
        return "{\"type\":\"object\",\"additionalProperties\":false}";
    if (tool == "static_list_imports" || tool == "static_list_exports")
        return "{\"type\":\"object\",\"properties\":{\"offset\":{\"type\":\"integer\",\"minimum\":0},\"limit\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":64}},\"additionalProperties\":false}";
    if (tool == "static_list_strings")
        return "{\"type\":\"object\",\"properties\":{\"file_offset\":{\"type\":\"integer\",\"minimum\":0},\"limit\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":64},\"min_length\":{\"type\":\"integer\",\"minimum\":4,\"maximum\":32}},\"additionalProperties\":false}";
    if (tool == "static_read_bytes")
        return "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"integer\",\"string\"]},\"size\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4096}},\"required\":[\"address\",\"size\"],\"additionalProperties\":false}";
    if (tool == "static_disassemble")
        return "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"integer\",\"string\"]},\"count\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":32}},\"required\":[\"address\"],\"additionalProperties\":false}";
    if (tool == "debug_find_process") return "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Exact executable name, with or without .exe\"}},\"required\":[\"name\"],\"additionalProperties\":false}";
    if (tool == "debug_open_process") return "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\",\"description\":\"Absolute path to a local executable\"},\"arguments\":{\"type\":\"string\",\"description\":\"Optional command-line arguments\"},\"auto_run\":{\"type\":\"boolean\",\"description\":\"Default false: pause at the entry point. True: continue through the initial breakpoint and run until another stop or exit.\"}},\"required\":[\"path\"],\"additionalProperties\":false}";
    if (tool == "debug_attach_pid") return "{\"type\":\"object\",\"properties\":{\"pid\":{\"type\":\"integer\",\"minimum\":1}},\"required\":[\"pid\"],\"additionalProperties\":false}";
    if (tool == "register_get") return "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"General-purpose register name\"}},\"required\":[\"name\"],\"additionalProperties\":false}";
    if (tool == "register_set") return "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"value\":{\"type\":[\"integer\",\"string\"],\"description\":\"Unsigned integer or 0x-prefixed hexadecimal value\"}},\"required\":[\"name\",\"value\"],\"additionalProperties\":false}";
    if (tool == "stack_read") return "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"integer\",\"string\"]},\"size\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":65536}},\"required\":[\"address\",\"size\"],\"additionalProperties\":false}";
    if (tool == "thread_get") return "{\"type\":\"object\",\"properties\":{\"thread_id\":{\"type\":\"integer\",\"minimum\":1}},\"required\":[\"thread_id\"],\"additionalProperties\":false}";
    if (tool == "module_get") return "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"integer\",\"string\"]}},\"required\":[\"address\"],\"additionalProperties\":false}";
    if (tool == "thread_list" || tool == "module_list" || tool == "breakpoint_list")
        return "{\"type\":\"object\",\"properties\":{\"offset\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":65535},\"limit\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":64}},\"additionalProperties\":false}";
    if (tool == "dump_memory_region") return "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":[\"integer\",\"string\"]},\"size\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":16777216},\"output_path\":{\"type\":\"string\"}},\"required\":[\"address\",\"size\",\"output_path\"],\"additionalProperties\":false}";
    if (tool == "get_event_capabilities" || tool == "debug_stop" || tool == "register_list" || tool == "stack_get_pointers" ||
        tool == "thread_list" || tool == "module_list")
        return "{\"type\":\"object\",\"additionalProperties\":false}";
    if (tool == "wait_debug_event") return "{\"type\":\"object\",\"properties\":{\"cursor\":{\"type\":\"integer\",\"minimum\":0},\"timeout_ms\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":1000}},\"required\":[\"cursor\"],\"additionalProperties\":false}";
    if (tool == "evaluate") return "{\"type\":\"object\",\"properties\":{\"expression\":{\"type\":\"string\",\"description\":\"Debugger expression, including registers and memory dereferences\"}},\"required\":[\"expression\"]}";
    if (tool == "resolve_symbol") return "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Export symbol, preferably module!function, for example KernelBase!CreateFileW\"}},\"required\":[\"name\"],\"additionalProperties\":false}";
    std::string address = "\"address\":{\"type\":[\"integer\",\"string\"],\"description\":\"Absolute address: decimal integer or 0x-prefixed hexadecimal string\"}";
    if (tool == "read_memory") return "{\"type\":\"object\",\"properties\":{" + address +
        ",\"size\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1048576}},\"required\":[\"address\",\"size\"]}";
    if (tool == "write_memory") return "{\"type\":\"object\",\"properties\":{" + address +
        ",\"hex\":{\"type\":\"string\",\"description\":\"Bytes as hexadecimal pairs, for example 90 90\"},\"expected_hex\":{\"type\":\"string\",\"description\":\"Optional exact current bytes; mismatch refuses the write\"}},\"required\":[\"address\",\"hex\"]}";
    if (tool == "assemble") return "{\"type\":\"object\",\"properties\":{" + address +
        ",\"assembly\":{\"type\":\"string\"}},\"required\":[\"address\",\"assembly\"]}";
    if (tool == "disassemble" || tool == "find_memory" || tool == "find_module" || tool == "follow_call" ||
        tool == "get_breakpoint_type" || tool == "get_breakpoint_type_count")
        return "{\"type\":\"object\",\"properties\":{" + address + "},\"required\":[\"address\"]}";
    if (tool == "set_software_breakpoint" || tool == "delete_software_breakpoint")
        return "{\"type\":\"object\",\"properties\":{" + address +
            "},\"required\":[\"address\"],\"additionalProperties\":false}";
    if (tool == "find_references")
        return "{\"type\":\"object\",\"properties\":{" + address +
            ",\"size\":{\"type\":\"integer\",\"minimum\":1},\"target\":{\"type\":[\"integer\",\"string\"]},\"target1\":{\"type\":[\"integer\",\"string\"]},\"text\":{\"type\":\"string\"}},\"required\":[\"address\",\"size\",\"target\"],\"additionalProperties\":false}";
    if (tool == "find_import_by_name")
        return "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Imported function name, for example ReadFile or WriteFile\"}," +
            address + ",\"size\":{\"type\":\"integer\",\"minimum\":1}},\"required\":[\"name\"],\"additionalProperties\":false}";
    if (tool == "go") return "{\"type\":\"object\",\"properties\":{" + address + "}}";
    return "{\"type\":\"object\"}";
}

static std::string ToolListJson(void)
{
    Z0B_StaticQuery static_view = {};
    static_view.version = Z0B_STATIC_QUERY_VERSION;
    static_view.operation = Z0B_STATIC_QUERY_ACTIVE;
    wchar_t target[MAX_PATH] = {0};
    bool static_available = (pMcpStaticQuery && pMcpStaticQuery(&static_view)) ||
        StaticDebugTargetPath(target, _countof(target));
    const char* tools[] = {
        "static_pe_info", "static_macho_info", "static_list_sections", "static_list_imports", "static_list_exports", "static_list_strings", "static_read_bytes", "static_disassemble",
        "get_status", "get_cpu_thread_id", "get_debug_context", "get_event_capabilities", "get_isolation_policy", "wait_debug_event", "run", "go", "pause", "step_into", "step_over", "trace_into", "trace_over",
        "debug_find_process", "debug_open_process", "debug_attach_pid", "debug_stop", "register_get", "register_list", "register_set", "stack_get_pointers", "stack_read",
        "thread_list", "thread_get", "module_list", "module_get", "breakpoint_list", "dump_memory_region",
        "auto_step_into", "auto_step_over",
        "read_memory", "write_memory", "list_memory", "find_memory", "find_data_ptr",
        "set_software_breakpoint", "set_software_breakpoint_ext", "delete_software_breakpoint", "delete_breakpoint_range", "delete_all_breakpoints",
        "set_memory_breakpoint", "delete_memory_breakpoint",
        "set_hardware_breakpoint", "delete_hardware_breakpoint",
        "get_breakpoint_type", "get_breakpoint_type_count", "get_next_breakpoint", "set_temp_breakpoint",
        "plugin_temp_breakpoint",
        "disassemble", "assemble", "set_cpu", "set_disasm",
        "evaluate", "resolve_symbol", "find_name", "insert_name", "decode_address", "decode_name", "comment_address", "simple_address", "find_label", "find_module", "find_thread", "find_data", "find_decode", "find_strings", "find_references", "find_import_by_name", "find_file_offset", "follow_call", "walk_reference", "walk_reference_ex", "is_prefix",
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
        if (!static_available && std::string(tools[i]).find("static_") == 0) continue;
        if (!ToolExportAvailable(tools[i])) continue;
        if (out.size() > 1)
            out += ",";
        out += "{\"name\":";
        JsonAppendEscaped(out, tools[i]);
        std::string description = "Z0BDbg debugger tool: ";
        description += tools[i];
        if (std::string(tools[i]) == "debug_find_process") description = "Find running processes by exact executable name before attaching; returns up to 16 PID candidates";
        if (std::string(tools[i]) == "debug_open_process") description = "Open a local executable in the debugger. By default it pauses at the entry point; set auto_run=true to continue after the initial breakpoint. Requires no active target. Read get_debug_context after opening; use run later if paused.";
        if (std::string(tools[i]) == "debug_attach_pid") description = "Attach the debugger to a running process by PID; closes the current debug session";
        if (std::string(tools[i]) == "debug_stop") description = "Stop the current debug session using the host close policy";
        if (std::string(tools[i]) == "set_software_breakpoint") description = "Set an executable software breakpoint at a numeric absolute address in the paused debug target. Resolve module!function with resolve_symbol first; pause a running target before setting the breakpoint";
        if (std::string(tools[i]) == "run") description = "Continue execution of the paused debug target until the next debug event or breakpoint";
        if (std::string(tools[i]) == "resolve_symbol") description = "Resolve a loaded target module's exported function entry as a runtime virtual address, including while running. Use module!function, for example ntdll!NtQuerySystemInformation. Pass the result to disassemble when paused, or to a breakpoint tool; never pass it directly to static_disassemble. A missing import does not imply a missing export";
        if (std::string(tools[i]) == "find_import_by_name") description = "Find an import table slot in the loaded main executable's file-backed imports, not a function entry. An absent import does not prove the API is unused; it may be resolved dynamically. Use resolve_symbol for executable breakpoints";
        if (std::string(tools[i]) == "breakpoint_list") description = "Page through configured breakpoints with offset and limit; works while the target is running. Running results are a best-effort observation and may change between calls";
        if (std::string(tools[i]) == "get_breakpoint_type" || std::string(tools[i]) == "get_breakpoint_type_count") description = "Read the configured breakpoint type at a numeric address, including while the target is running. Running results may change between calls";
        if (std::string(tools[i]) == "get_cpu_thread_id") description = "Read the selected CPU thread ID; available while running, but it is not a current register snapshot";
        if (std::string(tools[i]) == "register_get") description = "Read one general-purpose register from the current debugger thread";
        if (std::string(tools[i]) == "register_list") description = "Read general-purpose registers from the current debugger thread; requires a paused target. For a running target, wait for a debug event or pause it first";
        if (std::string(tools[i]) == "register_set") description = "Set a general-purpose register in the paused debugger thread";
        if (std::string(tools[i]) == "stack_get_pointers") description = "Read the current thread's stack and frame pointers";
        if (std::string(tools[i]) == "stack_read") description = "Read bytes at a stack address; maximum 64 KiB";
        if (std::string(tools[i]) == "thread_list") description = "Page through target threads with offset and limit; default 16, maximum 64. Uses a system snapshot and works while the target is running";
        if (std::string(tools[i]) == "thread_get") description = "Get a thread belonging to the debug target";
        if (std::string(tools[i]) == "module_list") description = "Page through target modules with offset and limit; default 8, maximum 64";
        if (std::string(tools[i]) == "module_get") description = "Get the module containing an address";
        if (std::string(tools[i]) == "dump_memory_region") description = "Write a raw memory region to a new local file; never overwrite an existing file";
        if (std::string(tools[i]) == "get_debug_context") description += " (runtime v1: session/process/thread/status/revision/modules/event cursor; status 18=paused, 19=running; use this context for target identity)";
        if (std::string(tools[i]) == "get_event_capabilities") description = "List debugger event kinds, payload fields, currently enabled server notifications, and how to read the event feed. Call before planning event-driven debugging";
        if (std::string(tools[i]) == "wait_debug_event") description = "Read debugger events after a cursor (0..1000 ms long poll). Includes exceptions/breakpoints, process/thread/module events, debug strings and state changes. On gap, refresh context";
        if (std::string(tools[i]) == "static_pe_info") description = "Read PE metadata from the active -ida static view or current debug target executable on disk, including while the target is running; includes machine, image base and entry point";
        if (std::string(tools[i]) == "static_macho_info") description = "Read Mach-O or Universal/Fat header and architecture slices from the active -ida static view; reports the preferred default slice; no debug target required";
        if (std::string(tools[i]) == "static_list_sections") description = "List PE sections in the active -ida view or current debug target executable on disk; addresses use the preferred image base";
        if (std::string(tools[i]) == "static_list_imports") description = "Page through PE imports and IAT addresses in the active -ida view or current debug target executable on disk";
        if (std::string(tools[i]) == "static_list_exports") description = "Page through named PE exports in the active -ida view or current debug target executable on disk";
        if (std::string(tools[i]) == "static_list_strings") description = "Page through printable ASCII and UTF-16LE strings in the active -ida view or current debug target executable on disk";
        if (std::string(tools[i]) == "static_read_bytes") description = "Read file-backed bytes by preferred virtual address from the active -ida view or current debug target executable on disk, maximum 4096 bytes";
        if (std::string(tools[i]) == "static_disassemble") description = "Decode up to 32 file-backed instructions in the active -ida view or current debug target executable on disk. Address must belong to that PE at its preferred image base, not a resolve_symbol runtime address from another module; use disassemble for loaded module code when paused";
        out += ",\"description\":";
        JsonAppendEscaped(out, description.c_str());
        out += ",\"inputSchema\":";
        out += ToolInputSchema(tools[i]);
        out += ",\"annotations\":{\"readOnlyHint\":";
        out += McpReadOnlyTool(tools[i]) ? "true" : "false";
        out += ",\"destructiveHint\":";
        out += McpKnownDangerousTool(tools[i]) ? "true}}" : "false}}";
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

static bool IsReadTool(const std::string& tool)
{
    return McpReadOnlyTool(tool);
}

static std::string EventCapabilitiesJson(const McpConfig& cfg)
{
    struct EventKind { const char* name; const char* fields; };
    static const EventKind kinds[] = {
        { "state_changed", "state_changed,status" },
        { "process_exit", "notify" },
        { "exception", "debugEventCode,debugEventName,processId,threadId,exceptionCode,exceptionAddress,firstChance,accessType,faultAddress" },
        { "create_process", "debugEventCode,debugEventName,processId,threadId,imageBase,startAddress,threadLocalBase" },
        { "exit_process", "debugEventCode,debugEventName,processId,threadId,exitCode" },
        { "create_thread", "debugEventCode,debugEventName,processId,threadId,threadStartAddress,threadLocalBase" },
        { "exit_thread", "debugEventCode,debugEventName,processId,threadId,exitCode" },
        { "load_dll", "debugEventCode,debugEventName,processId,threadId,dllBase,imageNameAddress,unicodeImageName" },
        { "unload_dll", "debugEventCode,debugEventName,processId,threadId,dllBase" },
        { "output_debug_string", "debugEventCode,debugEventName,processId,threadId,stringAddress,stringLength,unicodeString" },
        { "rip", "debugEventCode,debugEventName,processId,threadId,error,type" }
    };
    std::string out = "{\"version\":1,\"feed\":{\"tool\":\"wait_debug_event\",\"cursor_from\":\"get_debug_context.sequence\",\"max_timeout_ms\":1000,\"capacity\":256,\"gap_action\":\"refresh get_debug_context\",\"kinds\":[";
    for (size_t i = 0; i < _countof(kinds); ++i) {
        if (i) out += ',';
        out += "{\"name\":";
        JsonAppendEscaped(out, kinds[i].name);
        out += ",\"fields\":[";
        std::string fields = kinds[i].fields;
        for (size_t start = 0; start < fields.size();) {
            size_t end = fields.find(',', start);
            if (end == std::string::npos) end = fields.size();
            if (start) out += ',';
            JsonAppendEscaped(out, fields.substr(start, end - start).c_str());
            start = end + 1;
        }
        out += "]}";
    }
    out += "],\"exception_notes\":\"Software breakpoints use exceptionCode 0x80000003; single-step uses 0x80000004. Refresh context before acting.\"},\"server_notifications\":{\"method\":\"z0dbg/event\",\"enabled\":";
    out += cfg.send_debug_events ? "true" : "false";
    out += ",\"delivery\":\"Wakes waiting MCP tasks; event details reach the model through wait_debug_event, not an unsolicited model request.\",\"categories\":{";
    struct Category { const char* name; BOOL enabled; };
    Category categories[] = {
        { "exception", cfg.event_exception }, { "thread", cfg.event_thread },
        { "process", cfg.event_process }, { "module", cfg.event_module },
        { "output_debug_string", cfg.event_output },
        { "rip", TRUE }, { "other_plugin_notify", TRUE }
    };
    for (size_t i = 0; i < _countof(categories); ++i) {
        if (i) out += ',';
        JsonAppendEscaped(out, categories[i].name);
        out += ':';
        out += cfg.send_debug_events && categories[i].enabled ? "true" : "false";
    }
    out += "}}}";
    return out;
}

static bool IsBreakpointTool(const std::string& tool)
{
    return tool.find("breakpoint") != std::string::npos ||
        tool == "set_temp_breakpoint" || tool == "plugin_temp_breakpoint";
}

static bool IsExecuteTool(const std::string& tool)
{
    return tool == "debug_open_process" || tool == "debug_attach_pid" || tool == "debug_stop" ||
        tool == "run" || tool == "go" || tool == "pause" ||
        tool == "step_into" || tool == "step_over" || tool == "trace_into" ||
        tool == "trace_over" || tool == "auto_step_into" ||
        tool == "auto_step_over" || tool == "suspend_all_threads" ||
        tool == "resume_all_threads" || tool == "show_memory" ||
        tool == "show_breakpoints" || tool == "show_hardware_breakpoints" ||
        tool == "show_threads" || tool == "show_trace" ||
        tool == "show_windows" || tool == "show_patches" ||
        tool == "show_watch" || tool == "redraw_disasm" ||
        tool == "redraw_registers" || tool == "redraw_list" ||
        tool == "redraw_all";
}

static bool IsWriteTool(const std::string& tool)
{
    return tool == "register_set" || tool == "dump_memory_region" ||
        tool == "write_memory" || tool == "insert_name" ||
        tool == "comment_address" || tool == "set_cpu" ||
        tool == "set_disasm" || tool == "set_trace_condition" ||
        tool == "set_trace_count" || tool == "set_trace_pause_on_commands" ||
        tool == "set_dump_type" || tool == "dump_backup" ||
        tool == "plugin_module_changed" || tool == "plugin_write_ini_int" ||
        tool == "plugin_write_ini_string";
}

static bool IsPatchTool(const std::string& tool)
{
    return tool == "assemble" || tool == "write_memory" ||
        tool == "set_dump_type" || tool == "dump_backup";
}

static bool IsDeleteBreakpointTool(const std::string& tool)
{
    return tool == "delete_software_breakpoint" ||
        tool == "delete_breakpoint_range" ||
        tool == "delete_all_breakpoints" ||
        tool == "delete_memory_breakpoint" ||
        tool == "delete_hardware_breakpoint";
}

static bool IsRegisterTool(const std::string& tool)
{
    return tool == "register_set" || tool == "set_cpu" || tool == "set_disasm";
}

static bool IsHighRiskTool(const std::string& tool)
{
    return tool == "debug_open_process" || tool == "debug_attach_pid" || tool == "debug_stop" ||
        tool == "register_set" || tool == "dump_memory_region" ||
        tool == "run" || tool == "go" || tool == "pause" ||
        tool == "step_into" || tool == "step_over" ||
        tool == "trace_into" || tool == "trace_over" ||
        tool == "auto_step_into" || tool == "auto_step_over" ||
        tool == "write_memory" || tool == "assemble" ||
        tool == "delete_all_breakpoints" || tool == "set_trace_condition" ||
        tool == "set_trace_pause_on_commands" || tool == "dump_backup";
}

static bool ConfirmHighRiskTool(const McpConfig& cfg, const std::string& tool, bool internal_direct = false)
{
    if (!IsHighRiskTool(tool))
        return true;
    if (!cfg.allow_high_risk)
        return false;
    if (internal_direct || g_auto_confirm_local_server)
        return true;
    bool always_confirm = tool == "debug_open_process" || tool == "debug_attach_pid" || tool == "debug_stop" ||
        tool == "run" || tool == "go" ||
        tool == "register_set" || tool == "dump_memory_region" || tool == "dump_backup";
    if (!cfg.confirm_high_risk && !always_confirm)
        return true;
    std::wstring wide = Utf8ToWide(tool);
    wchar_t text[512];
    StringCchPrintfW(text, _countof(text),
        McpText(L"MCP Server 请求执行高风险调试器操作：%s\r\n是否允许？",
                L"MCP Server requested a high-risk debugger operation: %s\r\nAllow it?"),
        wide.c_str());
    return MessageBoxW(GetActiveWindow(), text, PLUGIN_NAME,
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

static bool IsToolAllowed(const McpConfig& cfg, const std::string& tool, bool internal_direct = false)
{
    if (IsHighRiskTool(tool) && !ConfirmHighRiskTool(cfg, tool, internal_direct))
        return false;
    if (IsReadTool(tool))
        return cfg.allow_read ? true : false;
    if (IsDeleteBreakpointTool(tool) && !cfg.allow_delete_breakpoint)
        return false;
    if (IsRegisterTool(tool) && !cfg.allow_registers)
        return false;
    if (IsPatchTool(tool) && !cfg.allow_patch)
        return false;
    if (IsBreakpointTool(tool) && !cfg.allow_breakpoint)
        return false;
    if (IsExecuteTool(tool) && !cfg.allow_execute)
        return false;
    if (IsWriteTool(tool) && !cfg.allow_write)
        return false;
    return cfg.allow_execute || cfg.allow_write;
}

static bool NativeAgentScopeAllowed(const McpConfig& cfg, const std::string& tool, const ModelJson& rpc,
    const std::string& arguments)
{
    if (cfg.agent_strict) {
        ModelJson args;
        if (tool == "plugin_write_ini_int" || tool == "plugin_write_ini_string" || !ModelJson::parse(arguments, &args) || !AccessArgumentsAllowed(args, cfg.agent_files, cfg.agent_network) ||
            (!McpReadOnlyTool(tool) && !McpKnownModifyTool(tool) && !McpKnownDangerousTool(tool))) return false;
    }
    const ModelJson* params = rpc.get("params"), *meta = params ? params->get("_meta") : NULL;
    if (cfg.agent_scope[0]) {
        const ModelJson* scope = meta ? meta->get("z0dbg/scope") : NULL;
        if (!scope || scope->kind != ModelJson::STRING || scope->value != WideToUtf8(cfg.agent_scope)) return false;
    }
    if (cfg.agent_readonly && !McpReadOnlyTool(tool)) return false;
    if (cfg.agent_tools[0]) {
        std::string list = WideToUtf8(cfg.agent_tools); bool found = false;
        for (size_t start = 0; start < list.size();) {
            size_t end = list.find(',', start); if (end == std::string::npos) end = list.size();
            std::string name = list.substr(start, end - start);
            size_t first = name.find_first_not_of(" \t"), last = name.find_last_not_of(" \t");
            if (first != std::string::npos && name.substr(first, last - first + 1) == tool) found = true;
            start = end + 1;
        }
        if (!found) return false;
    }
    if (cfg.agent_max_argument_kb < 1 || cfg.agent_max_argument_kb > 256 || arguments.size() > (size_t)cfg.agent_max_argument_kb * 1024) return false;
    if (cfg.agent_require_target && tool.find("static_") != 0 && tool != "get_debug_context" && tool != "get_event_capabilities" && tool != "get_isolation_policy" &&
        tool != "debug_find_process" && tool != "debug_open_process" && tool != "debug_attach_pid") {
        const ModelJson* target = meta ? meta->get("z0dbg/target") : NULL; ModelJson context;
        if (!target || target->kind != ModelJson::STRING || !ModelJson::parse(g_debug_feed.context(), &context) ||
            target->value != context.get("session")->value + ":" + context.get("process_id")->raw) return false;
    }
    bool ranged = cfg.agent_address_min[0] || cfg.agent_address_max[0];
    if (tool == "read_memory" || tool == "stack_read" || tool == "dump_memory_region" || tool == "disassemble") {
        unsigned __int64 address = 0, size = 32;
        if (!JsonFindUInt64(arguments, "address", address)) JsonFindUInt64(arguments, "addr", address);
        if ((tool == "read_memory" || tool == "stack_read" || tool == "dump_memory_region") && !JsonFindUInt64(arguments, "size", size)) return false;
        if (!size || cfg.agent_max_read_bytes < 1 || cfg.agent_max_read_bytes > 1024 * 1024 || size > (unsigned int)cfg.agent_max_read_bytes) return false;
        if (ranged) {
            unsigned __int64 first = 0, last = 0;
            std::string bounds = "{\"first\":"; JsonAppendWide(bounds, cfg.agent_address_min);
            bounds += ",\"last\":"; JsonAppendWide(bounds, cfg.agent_address_max); bounds += '}';
            if (!JsonFindUInt64(bounds, "first", first) || !JsonFindUInt64(bounds, "last", last) || first > last ||
                address < first || address > last || size - 1 > last - address) return false;
        }
    }
    else if (ranged && tool != "get_debug_context" && tool != "get_event_capabilities" && tool != "get_isolation_policy" && tool != "get_status" && tool != "get_cpu_thread_id" && tool != "wait_debug_event" &&
        tool != "debug_find_process" && tool != "debug_open_process" && tool != "debug_attach_pid") return false;
    return true;
}

static std::string ExecuteToolCommand(const std::string& json, bool internal_direct)
{
    std::string id = ExtractIdJson(json);
    std::string method;
    JsonFindString(json, "method", method);

    if (method == "initialize") {
        McpConfig cfg = CopyConfig();
        std::string result = "{\"protocolVersion\":";
        JsonAppendWide(result, cfg.protocol_version[0] ? cfg.protocol_version : L"2024-11-05");
        result += ",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"Z0BDbg MCP Tools\",\"version\":";
        JsonAppendWide(result, PLUGIN_VERSION_TEXT);
        result += "}}";
        return JsonRpcResult(id, result);
    }
    if (method == "ping")
        return JsonRpcResult(id, "{}");
    if (method == "notifications/initialized")
        return std::string();
    if (method == "z0dbg.tools")
        return JsonRpcResult(id, ToolListJson());
    if (method == "tools/list") {
        std::string result = "{\"tools\":";
        result += ToolListJson();
        result += "}";
        return JsonRpcResult(id, result);
    }

    std::string tool;
    if (!JsonFindString(json, "tool", tool))
        JsonFindString(json, "name", tool);
    ModelJson rpc;
    if (!ModelJson::parse(json, &rpc)) return McpRpcErrorResponse(id, MCP_RPC_INVALID_JSON);
    const ModelJson* call_params = rpc.get("params");
    const ModelJson* call_arguments = call_params ? call_params->get("arguments") : NULL;
    if (method == "tools/call") {
        const ModelJson* call_name = call_params ? call_params->get("name") : NULL;
        if (!call_name || call_name->kind != ModelJson::STRING || (call_arguments && call_arguments->kind != ModelJson::OBJECT))
            return McpRpcErrorResponse(id, MCP_RPC_TOOLS_CALL_REQUIRES_PARAMS_NAME_AND_OBJECT_ARGUMENTS);
        tool = call_name->value;
    }
    if (tool.empty() && method.find("z0dbg.") == 0)
        tool = method.substr(6);
    if (tool.empty())
        return McpRpcErrorResponse(id, MCP_RPC_MISSING_TOOL_NAME);
    McpConfig permission_config = CopyConfig();
    if (!NativeAgentScopeAllowed(permission_config, tool, rpc, method == "tools/call" ? (call_arguments ? call_arguments->raw : "{}") : json))
        return McpRpcErrorResponse(id, MCP_RPC_SERVER_AGENT_ISOLATION_REFUSED_SCOPE_TOOL_TARGET_RANGE_BUD);
    if (!IsToolAllowed(permission_config, tool, internal_direct))
        return McpRpcErrorResponse(id, MCP_RPC_TOOL_IS_DISABLED_BY_MCP_TOOLS_PERMISSIONS);

    if (tool.find("static_") == 0) {
        Z0B_StaticQuery query = {};
        query.version = Z0B_STATIC_QUERY_VERSION;
        query.operation = Z0B_STATIC_QUERY_ACTIVE;
        bool active_view = pMcpStaticQuery && pMcpStaticQuery(&query);
        if (!active_view && !StaticDebugTargetPath(query.path, _countof(query.path)))
            return McpRpcErrorResponse(id, MCP_RPC_STATIC_SOURCE_UNAVAILABLE);
        if (permission_config.agent_strict &&
            !AccessFileAllowed(query.path, permission_config.agent_files))
            return McpRpcErrorResponse(id, MCP_RPC_STATIC_FILE_IS_OUTSIDE_THE_AGENT_FILE_SCOPE);
        if (tool == "static_macho_info") {
            MachOImage macho;
            if (!macho.open(query.path)) return McpRpcErrorResponse(id, MCP_RPC_ACTIVE_STATIC_FILE_IS_NOT_A_VALID_MACH_O_IMAGE);
            std::string result = "{\"ok\":true,\"format\":\"mach-o\",\"fat\":";
            result += macho.fat() ? "true" : "false";
            result += ",\"file_size\":" + std::to_string((unsigned long long)macho.file_size());
            result += ",\"preferred_slice\":" + std::to_string((unsigned long long)macho.preferred_slice());
            result += ",\"slices\":[";
            for (size_t i = 0; i < macho.slices().size(); ++i) {
                const MachOImage::Slice& slice = macho.slices()[i];
                if (i) result += ',';
                result += "{\"index\":" + std::to_string((unsigned long long)i);
                result += ",\"cpu\":"; ModelJson::quote(&result, WideToUtf8(MachOImage::cpu_name(slice.cpu_type)));
                result += ",\"cpu_type\":" + std::to_string((unsigned long long)slice.cpu_type);
                result += ",\"cpu_subtype\":" + std::to_string((unsigned long long)slice.cpu_subtype);
                result += ",\"bits\":" + std::string(slice.is64 ? "64" : "32");
                result += ",\"file_type\":" + std::to_string((unsigned long long)slice.file_type);
                result += ",\"offset\":" + std::to_string((unsigned long long)slice.offset);
                result += ",\"size\":" + std::to_string((unsigned long long)slice.size);
                result += ",\"load_commands\":" + std::to_string((unsigned long long)slice.command_count);
                result += ",\"load_command_bytes\":" + std::to_string((unsigned long long)slice.command_bytes);
                result += ",\"segment_count\":" + std::to_string((unsigned long long)slice.segments.size());
                size_t sections = 0;
                for (size_t s = 0; s < slice.segments.size(); ++s)
                    sections += slice.segments[s].sections.size();
                result += ",\"section_count\":" + std::to_string((unsigned long long)sections);
                result += ",\"little_endian\":" + std::string(slice.little_endian ? "true" : "false") + '}';
            }
            return JsonRpcResult(id, result + "]}");
        }
        StaticPeImage image;
        if (!image.open(query.path)) return McpRpcErrorResponse(id, MCP_RPC_COULD_NOT_READ_A_VALID_PE_FILE_FROM_THE_STATIC_VIEW);
        std::string args = method == "tools/call" ?
            (call_arguments ? call_arguments->raw : "{}") : json;
        if (tool == "static_pe_info") return JsonRpcResult(id, image.info(query.path));
        if (tool == "static_list_sections") return JsonRpcResult(id, image.sections());
        if (tool == "static_list_imports" || tool == "static_list_exports") {
            unsigned __int64 offset = 0, limit = 32;
            JsonFindUInt64(args, "offset", offset);
            JsonFindUInt64(args, "limit", limit);
            if (offset > 1000000 || !limit || limit > 64) return McpRpcErrorResponse(id, MCP_RPC_INVALID_OFFSET_OR_LIMIT);
            return JsonRpcResult(id, tool == "static_list_imports" ?
                image.imports((size_t)offset, (size_t)limit) : image.exports((size_t)offset, (size_t)limit));
        }
        if (tool == "static_list_strings") {
            unsigned __int64 offset = 0, limit = 32, minimum = 4;
            JsonFindUInt64(args, "file_offset", offset);
            JsonFindUInt64(args, "limit", limit);
            JsonFindUInt64(args, "min_length", minimum);
            if (offset > 0x20000000ULL || !limit || limit > 64 || minimum < 4 || minimum > 32)
                return McpRpcErrorResponse(id, MCP_RPC_INVALID_STRING_SCAN_PARAMETERS);
            return JsonRpcResult(id, image.strings((size_t)offset, (size_t)limit, (size_t)minimum));
        }
        unsigned __int64 address = 0;
        if (!JsonFindUInt64(args, "address", address) || !address)
            return McpRpcErrorResponse(id, MCP_RPC_ABSOLUTE_STATIC_ADDRESS_IS_REQUIRED);
        if (tool == "static_read_bytes") {
            unsigned __int64 size = 0;
            if (!JsonFindUInt64(args, "size", size) || !size || size > 4096 ||
                size > (unsigned)permission_config.agent_max_read_bytes)
                return McpRpcErrorResponse(id, MCP_RPC_INVALID_STATIC_BYTE_COUNT);
            return JsonRpcResult(id, image.bytes(address, (size_t)size));
        }
        if (tool == "static_disassemble") {
            unsigned __int64 count = 8;
            JsonFindUInt64(args, "count", count);
            if (!count || count > 32) return McpRpcErrorResponse(id, MCP_RPC_INVALID_INSTRUCTION_COUNT);
            IdaMappedSymbolCache cached_symbols;
            bool have_cached_symbols = !active_view && cached_symbols.open(query.path, image);
            const unsigned __int64 requested_address = address;
            std::string result = "{\"ok\":true,\"path\":";
            JsonAppendWide(result, query.path);
            result += ",\"instructions\":[";
            size_t decoded = 0;
            bool zero_padding = false;
            for (; decoded < count; ++decoded) {
                unsigned char probe[4] = {0};
                if (image.read(address, probe, sizeof(probe)) == sizeof(probe) &&
                    !probe[0] && !probe[1] && !probe[2] && !probe[3]) {
                    zero_padding = true;
                    break;
                }
                Z0B_StaticQuery line = {};
                const wchar_t* symbol = NULL;
                const wchar_t* target_symbol = NULL;
                unsigned __int64 target_address = 0;
                line.version = Z0B_STATIC_QUERY_VERSION;
                line.operation = Z0B_STATIC_QUERY_DISASSEMBLE;
                line.address = address;
                if (active_view) {
                    if (!pMcpStaticQuery(&line) || !line.instruction_size ||
                        wcscmp(line.path, query.path) != 0) break;
                } else {
                    unsigned char bytes[32] = {0};
                    size_t available = image.read(address, bytes, sizeof(bytes));
                    if (!available || !pDisasm) break;
                    HostDisasm decoded_line = {};
                    ulong length = pDisasm(bytes, (ulong)available, (ulong)address,
                        NULL, &decoded_line, 0, 0);
                    if (!length || length > available) break;
                    line.instruction_size = (DWORD)length;
                    MultiByteToWideChar(CP_ACP, 0, decoded_line.result, -1, line.text, _countof(line.text));
                    if (have_cached_symbols) {
                        symbol = cached_symbols.find(address);
                        target_address = decoded_line.jmpaddr;
                        if (target_address) target_symbol = cached_symbols.find(target_address);
                        if (target_symbol && wcslen(line.text) + wcslen(target_symbol) + 3 < _countof(line.text)) {
                            StringCchCatW(line.text, _countof(line.text), L" ; ");
                            StringCchCatW(line.text, _countof(line.text), target_symbol);
                        }
                    }
                    static const wchar_t digits[] = L"0123456789ABCDEF";
                    for (size_t byte = 0; byte < length && byte * 2 + 1 < _countof(line.bytes); ++byte) {
                        line.bytes[byte * 2] = digits[bytes[byte] >> 4];
                        line.bytes[byte * 2 + 1] = digits[bytes[byte] & 15];
                    }
                }
                if (decoded) result += ',';
                result += "{\"address\":"; JsonAppendHex64(result, address);
                result += ",\"size\":" + std::to_string((unsigned long long)line.instruction_size);
                result += ",\"hex\":"; JsonAppendWide(result, line.bytes);
                result += ",\"text\":"; JsonAppendWide(result, line.text);
                if (symbol) { result += ",\"symbol\":"; JsonAppendWide(result, symbol); }
                if (target_symbol) {
                    result += ",\"target_address\":"; JsonAppendHex64(result, target_address);
                    result += ",\"target_symbol\":"; JsonAppendWide(result, target_symbol);
                }
                result += '}';
                address += line.instruction_size;
            }
            if (!decoded && !zero_padding) {
                unsigned char file_byte = 0;
                if (!image.read(requested_address, &file_byte, 1)) {
                    char address_text[32], base_text[32];
                    sprintf_s(address_text, sizeof(address_text), "0x%llX", requested_address);
                    sprintf_s(base_text, sizeof(base_text), "0x%llX", image.image_base());
                    return McpRpcErrorResponse(id, MCP_RPC_STATIC_ADDRESS_HAS_NO_DECODABLE_INSTRUCTION_IN_THE_ACTIVE,
                        std::string("Address ") + address_text + " is not backed by the active static PE " +
                        WideToUtf8(query.path) + " (preferred image base " + base_text +
                        "). A resolve_symbol address is a runtime VA; pause the target and use disassemble for loaded module code.");
                }
                return McpRpcErrorResponse(id, MCP_RPC_STATIC_ADDRESS_HAS_NO_DECODABLE_INSTRUCTION_IN_THE_ACTIVE);
            }
            result += "],\"next_address\":"; JsonAppendHex64(result, address);
            result += ",\"truncated\":";
            result += decoded == count ? "false" : "true";
            if (zero_padding) result += ",\"stop_reason\":\"zero_padding\"";
            result += '}';
            return JsonRpcResult(id, result);
        }
        return McpRpcErrorResponse(id, MCP_RPC_UNKNOWN_STATIC_TOOL);
    }

    if (tool == "get_isolation_policy") {
        std::string policy = "{\"version\":1,\"enforcement\":\"mcp-dispatch-v1\",\"strict\":" + std::string(permission_config.agent_strict ? "true" : "false");
        policy += ",\"readonly\":" + std::string(permission_config.agent_readonly ? "true" : "false");
        policy += ",\"require_target\":" + std::string(permission_config.agent_require_target ? "true" : "false");
        policy += ",\"scope\":"; JsonAppendWide(policy, permission_config.agent_scope);
        policy += ",\"files\":"; JsonAppendWide(policy, permission_config.agent_files);
        policy += ",\"network\":"; JsonAppendWide(policy, permission_config.agent_network);
        return JsonRpcResult(id, policy + '}');
    }
    if (tool == "get_event_capabilities")
        return JsonRpcResult(id, EventCapabilitiesJson(permission_config));
    if (tool == "get_debug_context") {
        if (pMcpActiveProcessId)
            g_debug_feed.update(CurrentDebugProcessId(),
                pGetcputhreadid ? (DWORD)pGetcputhreadid() : 0,
                pMcpDebugState ? pMcpDebugState() : pGetstatus ? pGetstatus() : -1);
        ModelJson context; std::string result = g_debug_feed.context();
        ModelJson::parse(result, &context);
        DWORD pid = (DWORD)strtoul(context.get("process_id")->raw.c_str(), NULL, 10);
        HANDLE snapshot = pid ? CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) : INVALID_HANDLE_VALUE;
        MODULEENTRY32W module; ZeroMemory(&module, sizeof(module)); module.dwSize = sizeof(module);
        bool known = snapshot != INVALID_HANDLE_VALUE && Module32FirstW(snapshot, &module) != FALSE;
        result.resize(result.size() - 1); result += std::string(",\"modules_known\":") + (known ? "true" : "false") + ",\"modules\":[";
        int count = 0;
        if (known) do {
            if (count++) result += ',';
            result += "{\"base\":"; JsonAppendHex64(result, (unsigned __int64)(ULONG_PTR)module.modBaseAddr);
            result += ",\"size\":" + DebugRuntimeFeed::number(module.modBaseSize) + ",\"name\":"; JsonAppendWide(result, module.szModule);
            result += ",\"path\":"; JsonAppendWide(result, module.szExePath); result += '}';
        } while (count < 128 && Module32NextW(snapshot, &module));
        if (snapshot != INVALID_HANDLE_VALUE) CloseHandle(snapshot);
        result += "]}"; return JsonRpcResult(id, result);
    }
    if (tool == "wait_debug_event") {
        ModelJson root;
        if (!ModelJson::parse(json, &root)) return McpRpcErrorResponse(id, MCP_RPC_INVALID_ARGUMENTS);
        const ModelJson* params = root.get("params");
        const ModelJson* args = params ? params->get("arguments") : NULL;
        const ModelJson* cursor = args ? args->get("cursor") : NULL;
        const ModelJson* timeout = args ? args->get("timeout_ms") : NULL;
        if (!cursor || cursor->kind != ModelJson::NUMBER || cursor->raw.find_first_not_of("0123456789") != std::string::npos || cursor->raw.size() > 18 ||
            (timeout && (timeout->kind != ModelJson::NUMBER || timeout->raw.find_first_not_of("0123456789") != std::string::npos || timeout->raw.size() > 4 || atoi(timeout->raw.c_str()) > 1000)))
            return McpRpcErrorResponse(id, MCP_RPC_CURSOR_MUST_BE_A_NONNEGATIVE_INTEGER_TIMEOUT_MS_IS_0_1000);
        return JsonRpcResult(id, g_debug_feed.wait(_strtoui64(cursor->raw.c_str(), NULL, 10), timeout ? atoi(timeout->raw.c_str()) : 1000));
    }
    ModelJson runtime_request;
    if (ModelJson::parse(json, &runtime_request)) {
        const ModelJson* params = runtime_request.get("params");
        const ModelJson* meta = params ? params->get("_meta") : NULL;
        if (meta && (meta->get("z0dbg/target") || meta->get("z0dbg/revision"))) {
            const ModelJson* expected = meta->get("z0dbg/target"), *revision = meta->get("z0dbg/revision");
            ModelJson context;
            if (!ModelJson::parse(g_debug_feed.context(), &context)) return McpRpcErrorResponse(id, MCP_RPC_DEBUG_CONTEXT_UNAVAILABLE);
            std::string identity = context.get("session")->value + ":" + context.get("process_id")->raw;
            if (!expected || expected->kind != ModelJson::STRING || expected->value != identity ||
                (revision && (revision->kind != ModelJson::STRING || revision->value != context.get("revision")->value)))
                return McpRpcErrorResponse(id, MCP_RPC_DEBUG_TARGET_CONTEXT_CHANGED_BEFORE_DISPATCH_REFRESH_OBSER);
        }
    }

    unsigned __int64 address = 0, size = 0, index = 0, type_value = 0, count = 0;
    std::string access, hex, text, name, expression, condition, cmdset, key, value, defvalue;
    std::string argument_json = method == "tools/call" ? (call_arguments ? call_arguments->raw : "{}") : json;
    JsonFindUInt64(argument_json, "address", address);
    JsonFindUInt64(argument_json, "addr", address);
    JsonFindUInt64(argument_json, "size", size);
    JsonFindUInt64(argument_json, "index", index);
    JsonFindUInt64(argument_json, "type", type_value);
    JsonFindUInt64(argument_json, "count", count);
    JsonFindString(argument_json, "access", access);
    JsonFindString(argument_json, "hex", hex);
    JsonFindString(argument_json, "data", hex);
    JsonFindString(argument_json, "text", text);
    JsonFindString(argument_json, "assembly", text);
    JsonFindString(argument_json, "name", name);
    JsonFindString(argument_json, "expression", expression);
    JsonFindString(argument_json, "condition", condition);
    JsonFindString(argument_json, "cmdset", cmdset);
    JsonFindString(argument_json, "key", key);
    JsonFindString(argument_json, "value", value);
    JsonFindString(argument_json, "default", defvalue);

    int rc = 0;
    if (tool == "get_status") {
        if (!pGetstatus)
            return McpRpcErrorResponse(id, MCP_RPC_GETSTATUS_IS_NOT_AVAILABLE);
        rc = pGetstatus();
    }
    else if (tool == "get_cpu_thread_id") {
        if (!pGetcputhreadid)
            return McpRpcErrorResponse(id, MCP_RPC_GETCPUTHREADID_IS_NOT_AVAILABLE);
        std::string result = "{\"ok\":true,\"threadId\":";
        JsonAppendHex64(result, (unsigned __int64)pGetcputhreadid());
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "debug_find_process") {
        const ModelJson* requested = call_arguments ? call_arguments->get("name") : NULL;
        if (!requested || requested->kind != ModelJson::STRING || requested->value.empty() || requested->value.size() > 260)
            return McpRpcErrorResponse(id, MCP_RPC_NAME_MUST_BE_A_BOUNDED_EXECUTABLE_NAME);
        std::wstring wanted = Utf8ToWide(requested->value);
        if (wanted.empty() || wanted.find(L'\0') != std::wstring::npos ||
            wanted.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos)
            return McpRpcErrorResponse(id, MCP_RPC_NAME_MUST_BE_AN_EXECUTABLE_BASENAME);
        if (wanted.size() < 4 || _wcsicmp(wanted.c_str() + wanted.size() - 4, L".exe")) wanted += L".exe";
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return McpRpcErrorResponse(id, MCP_RPC_COULD_NOT_ENUMERATE_PROCESSES);
        PROCESSENTRY32W entry = {}; entry.dwSize = sizeof(entry);
        std::string result = "{\"processes\":[";
        unsigned int count = 0;
        bool more = false;
        if (Process32FirstW(snapshot, &entry)) do {
            if (_wcsicmp(entry.szExeFile, wanted.c_str())) continue;
            if (count == 16) { more = true; break; }
            if (count++) result += ',';
            result += "{\"pid\":" + DebugRuntimeFeed::number(entry.th32ProcessID) + ",\"name\":";
            JsonAppendWide(result, entry.szExeFile); result += '}';
        } while (Process32NextW(snapshot, &entry));
        CloseHandle(snapshot);
        result += "],\"truncated\":" + std::string(more ? "true" : "false") + '}';
        return JsonRpcResult(id, result);
    }
    else if (tool == "debug_open_process") {
        const ModelJson* args = call_arguments;
        const ModelJson* path = args ? args->get("path") : NULL;
        const ModelJson* arguments = args ? args->get("arguments") : NULL;
        const ModelJson* auto_run = args ? args->get("auto_run") : NULL;
        if ((!pMcpOpenProcess && !pMcpOpenProcessEx) || !path || path->kind != ModelJson::STRING || path->value.empty() ||
            path->value.size() > 2048 || (arguments && (arguments->kind != ModelJson::STRING || arguments->value.size() > 4096)) ||
            (auto_run && auto_run->kind != ModelJson::BOOLEAN))
            return McpRpcErrorResponse(id, MCP_RPC_PATH_AND_OPTIONAL_ARGUMENTS_MUST_BE_BOUNDED_STRINGS);
        if (auto_run && auto_run->value == "true" && !pMcpOpenProcessEx)
            return McpRpcErrorResponse(id, MCP_RPC_OPERATION_REFUSED,
                "This debugger host does not support debug_open_process auto_run. Update the debugger or open paused and call run after reading get_debug_context.");
        std::wstring wide_path = Utf8ToWide(path->value);
        std::wstring wide_arguments = arguments ? Utf8ToWide(arguments->value) : L"";
        if (wide_path.empty() || wide_path.find(L'\0') != std::wstring::npos ||
            wide_arguments.find(L'\0') != std::wstring::npos)
            return McpRpcErrorResponse(id, MCP_RPC_INVALID_EXECUTABLE_PATH_OR_ARGUMENTS);
        bool run_after_open = auto_run && auto_run->value == "true";
        int opened = pMcpOpenProcessEx ? pMcpOpenProcessEx(wide_path.c_str(), wide_arguments.c_str(), run_after_open ? 1 : 0) :
            pMcpOpenProcess(wide_path.c_str(), wide_arguments.c_str());
        return JsonRpcResult(id, opened ?
            (run_after_open ? "{\"ok\":true,\"auto_run_requested\":true}" : "{\"ok\":true,\"auto_run_requested\":false}") :
            "{\"ok\":false}");
    }
    else if (tool == "debug_attach_pid") {
        unsigned __int64 pid = 0;
        if (!pMcpAttachPid || !JsonFindUInt64(argument_json, "pid", pid) || !pid || pid > 0xFFFFFFFFULL)
            return McpRpcErrorResponse(id, MCP_RPC_VALID_PID_AND_HOST_ATTACH_BRIDGE_REQUIRED);
        return JsonRpcResult(id, pMcpAttachPid((unsigned long)pid) ? "{\"ok\":true}" : "{\"ok\":false}");
    }
    else if (tool == "debug_stop") {
        if (!pMcpStopDebug) return McpRpcErrorResponse(id, MCP_RPC_HOST_STOP_BRIDGE_IS_UNAVAILABLE);
        return JsonRpcResult(id, pMcpStopDebug() ? "{\"ok\":true}" : "{\"ok\":false}");
    }
    else if (tool == "register_set") {
        unsigned __int64 value = 0;
        if (!pMcpSetRegister || name.empty() || !JsonFindUInt64(argument_json, "value", value))
            return McpRpcErrorResponse(id, MCP_RPC_REGISTER_NAME_AND_UNSIGNED_VALUE_REQUIRED);
        return JsonRpcResult(id, pMcpSetRegister(name.c_str(), value) ? "{\"ok\":true}" : "{\"ok\":false}");
    }
    else if (tool == "register_get" || tool == "register_list" || tool == "stack_get_pointers") {
        if (!pMcpGetRegister || !pMcpTargetBits || !pMcpTargetBits())
            return McpRpcErrorResponse(id, MCP_RPC_REGISTER_CONTEXT_IS_UNAVAILABLE);
#ifdef _WIN64
        const char* names64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags" };
#else
        if (pMcpTargetBits() != 32) return McpRpcErrorResponse(id, MCP_RPC_UNSUPPORTED_TARGET_ARCHITECTURE);
#endif
        const char* names32[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags" };
        bool is64 = pMcpTargetBits() == 64;
#ifdef _WIN64
        const char** names = is64 ? names64 : names32;
        size_t name_count = is64 ? _countof(names64) : _countof(names32);
#else
        const char** names = names32;
        size_t name_count = _countof(names32);
#endif
        const char* stack_names64[] = { "rsp", "rbp" };
        const char* stack_names32[] = { "esp", "ebp" };
        const char** stack_names = is64 ? stack_names64 : stack_names32;
        std::string result = "{\"ok\":true,\"registers\":{";
        size_t selected = tool == "register_get" ? 1 : tool == "stack_get_pointers" ? 2 : name_count;
        bool found = false;
        for (size_t i = 0; i < selected; ++i) {
            const char* reg = tool == "register_get" ? name.c_str() : tool == "stack_get_pointers" ? stack_names[i] : names[i];
            bool allowed = false;
            for (size_t k = 0; k < name_count; ++k) if (_stricmp(reg, names[k]) == 0) allowed = true;
            if (!allowed) return McpRpcErrorResponse(id, MCP_RPC_UNSUPPORTED_REGISTER_NAME);
            unsigned __int64 number = 0;
            if (!pMcpGetRegister(reg, &number)) {
                if (tool == "register_get" || tool == "stack_get_pointers")
                    return McpRpcErrorResponse(id, MCP_RPC_REGISTER_VALUE_IS_UNAVAILABLE);
                continue;
            }
            if (found) result += ',';
            JsonAppendEscaped(result, reg);
            result += ':';
            JsonAppendHex64(result, number);
            found = true;
        }
        result += "}}";
        if (!found) return McpRpcErrorResponse(id, MCP_RPC_REGISTER_VALUES_ARE_UNAVAILABLE);
        return JsonRpcResult(id, result);
    }
    else if (tool == "stack_read") {
        if (!address || !size || size > 65536 || !pReadmemory ||
            address > (unsigned __int64)(ULONG_PTR)~(ULONG_PTR)0 ||
            size - 1 > (unsigned __int64)(ULONG_PTR)~(ULONG_PTR)0 - address)
            return McpRpcErrorResponse(id, MCP_RPC_STACK_READ_REQUIRES_ADDRESS_AND_SIZE_65536);
        std::vector<uchar> bytes((size_t)size);
        ulong read = pReadmemory(&bytes[0], (ulong)address, (ulong)size, MM_SILENT);
        if (read > size) return McpRpcErrorResponse(id, MCP_RPC_HOST_RETURNED_AN_INVALID_READ_LENGTH);
        std::string result = "{\"ok\":true,\"read\":" + DebugRuntimeFeed::number(read) + ",\"hex\":";
        std::string hex = BytesToHex(&bytes[0], read);
        JsonAppendEscaped(result, hex.c_str());
        return JsonRpcResult(id, result + '}');
    }
    else if (tool == "thread_list" || tool == "thread_get") {
        unsigned __int64 offset = 0, limit = 16;
        if (tool == "thread_list" && !ListPageArguments(argument_json, 16, offset, limit))
            return McpRpcErrorResponse(id, MCP_RPC_OFFSET_MUST_BE_0_65535_AND_LIMIT_1_64);
        DWORD pid = g_host_process_id && *g_host_process_id ? (DWORD)*g_host_process_id : g_observed_process_id;
        if (!pid) return McpRpcErrorResponse(id, MCP_RPC_NO_DEBUG_TARGET);
        unsigned __int64 requested = 0;
        if (tool == "thread_get" && (!JsonFindUInt64(argument_json, "thread_id", requested) || !requested || requested > 0xFFFFFFFFULL))
            return McpRpcErrorResponse(id, MCP_RPC_VALID_THREAD_ID_REQUIRED);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return McpRpcErrorResponse(id, MCP_RPC_THREAD_SNAPSHOT_FAILED);
        THREADENTRY32 entry; ZeroMemory(&entry, sizeof(entry)); entry.dwSize = sizeof(entry);
        std::string result = "{\"ok\":true,\"threads\":[";
        unsigned __int64 count = 0, seen = 0;
        bool more = false;
        if (Thread32First(snapshot, &entry)) do {
            if (entry.th32OwnerProcessID != pid || (requested && entry.th32ThreadID != requested)) continue;
            if (!requested && seen++ < offset) continue;
            if (!requested && count >= limit) { more = true; break; }
            if (count++) result += ',';
            result += "{\"thread_id\":" + DebugRuntimeFeed::number(entry.th32ThreadID);
            result += ",\"base_priority\":" + DebugRuntimeFeed::state_number(entry.tpBasePri);
            result += ",\"current\":";
            result += pGetcputhreadid && pGetcputhreadid() == entry.th32ThreadID ? "true}" : "false}";
            if (requested) break;
        } while (Thread32Next(snapshot, &entry));
        CloseHandle(snapshot);
        result += "],\"next_offset\":";
        result += more ? DebugRuntimeFeed::number(offset + count) : "null";
        result += '}';
        if (requested && !count) return McpRpcErrorResponse(id, MCP_RPC_THREAD_NOT_FOUND_IN_TARGET);
        return JsonRpcResult(id, result);
    }
    else if (tool == "module_list" || tool == "module_get") {
        unsigned __int64 offset = 0, limit = 8;
        if (tool == "module_list" && !ListPageArguments(argument_json, 8, offset, limit))
            return McpRpcErrorResponse(id, MCP_RPC_OFFSET_MUST_BE_0_65535_AND_LIMIT_1_64);
        DWORD pid = g_host_process_id && *g_host_process_id ? (DWORD)*g_host_process_id : g_observed_process_id;
        if (!pid) return McpRpcErrorResponse(id, MCP_RPC_NO_DEBUG_TARGET);
        if (tool == "module_get" && (!address || address > (unsigned __int64)(ULONG_PTR)~(ULONG_PTR)0))
            return McpRpcErrorResponse(id, MCP_RPC_VALID_ADDRESS_REQUIRED);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE) return McpRpcErrorResponse(id, MCP_RPC_MODULE_SNAPSHOT_FAILED);
        MODULEENTRY32W entry; ZeroMemory(&entry, sizeof(entry)); entry.dwSize = sizeof(entry);
        std::string result = "{\"ok\":true,\"modules\":[";
        unsigned __int64 count = 0, seen = 0;
        bool more = false;
        if (Module32FirstW(snapshot, &entry)) do {
            unsigned __int64 base = (unsigned __int64)(ULONG_PTR)entry.modBaseAddr;
            if (tool == "module_get" && (address < base || address - base >= entry.modBaseSize)) continue;
            if (tool == "module_list" && seen++ < offset) continue;
            if (tool == "module_list" && count >= limit) { more = true; break; }
            std::string item = "{\"base\":"; JsonAppendHex64(item, base);
            item += ",\"size\":" + DebugRuntimeFeed::number(entry.modBaseSize) + ",\"name\":";
            JsonAppendWide(item, entry.szModule);
            item += ",\"path\":"; JsonAppendWide(item, entry.szExePath);
            item += '}';
            if (tool == "module_list" && count && result.size() + item.size() > 7000) { more = true; break; }
            if (count++) result += ',';
            result += item;
            if (tool == "module_get") break;
        } while (Module32NextW(snapshot, &entry));
        CloseHandle(snapshot);
        result += "],\"next_offset\":";
        result += more ? DebugRuntimeFeed::number(offset + count) : "null";
        result += '}';
        if (tool == "module_get" && !count) return McpRpcErrorResponse(id, MCP_RPC_MODULE_NOT_FOUND);
        return JsonRpcResult(id, result);
    }
    else if (tool == "breakpoint_list") {
        if (!pGetnextbreakpoint) return McpRpcErrorResponse(id, MCP_RPC_BREAKPOINT_ENUMERATION_UNAVAILABLE);
        unsigned __int64 offset = 0, limit = 16;
        if (!ListPageArguments(argument_json, 16, offset, limit))
            return McpRpcErrorResponse(id, MCP_RPC_OFFSET_MUST_BE_0_65535_AND_LIMIT_1_64);
        std::string result = "{\"ok\":true,\"breakpoints\":[";
        ulong previous = 0;
        unsigned __int64 count = 0, seen = 0;
        bool more = false;
        for (; seen <= offset + limit; ) {
            ulong type = 0; int command = 0;
            ulong next = pGetnextbreakpoint(previous, &type, &command);
            if (!next || next <= previous) break;
            previous = next;
            if (seen++ < offset) continue;
            if (count >= limit) { more = true; break; }
            if (count) result += ',';
            result += "{\"address\":"; JsonAppendHex64(result, next);
            result += ",\"type\":" + DebugRuntimeFeed::number(type) + '}';
            ++count;
        }
        result += "],\"next_offset\":";
        result += more ? DebugRuntimeFeed::number(offset + count) : "null";
        result += '}';
        return JsonRpcResult(id, result);
    }
    else if (tool == "dump_memory_region") {
        std::string output_path;
        if (!pReadmemory || !address || !size || size > 16 * 1024 * 1024 ||
            address > (unsigned __int64)(ULONG_PTR)~(ULONG_PTR)0 ||
            size - 1 > (unsigned __int64)(ULONG_PTR)~(ULONG_PTR)0 - address ||
            !JsonFindString(argument_json, "output_path", output_path) || output_path.empty())
            return McpRpcErrorResponse(id, MCP_RPC_ADDRESS_SIZE_16_MB_AND_OUTPUT_PATH_REQUIRED);
        std::wstring path = Utf8ToWide(output_path);
        if (path.size() < 4 || path[1] != L':' || path[2] != L'\\')
            return McpRpcErrorResponse(id, MCP_RPC_OUTPUT_PATH_MUST_BE_AN_ABSOLUTE_LOCAL_PATH);
        std::vector<uchar> bytes((size_t)size);
        ulong read = pReadmemory(&bytes[0], (ulong)address, (ulong)size, MM_SILENT);
        if (read != size) return McpRpcErrorResponse(id, MCP_RPC_COULD_NOT_READ_THE_ENTIRE_MEMORY_REGION);
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) return McpRpcErrorResponse(id, MCP_RPC_COULD_NOT_CREATE_OUTPUT_FILE_EXISTING_FILES_ARE_NOT_OVERWR);
        DWORD written = 0;
        BOOL saved = WriteFile(file, &bytes[0], (DWORD)size, &written, NULL);
        CloseHandle(file);
        if (!saved || written != size) {
            DeleteFileW(path.c_str());
            return McpRpcErrorResponse(id, MCP_RPC_MEMORY_DUMP_WRITE_WAS_INCOMPLETE);
        }
        std::string result = "{\"ok\":true,\"bytes\":" + DebugRuntimeFeed::number(written) + ",\"path\":";
        JsonAppendEscaped(result, output_path.c_str());
        return JsonRpcResult(id, result + '}');
    }
    else if (tool == "run")
    {
        if (!pRun)
            return McpRpcErrorResponse(id, MCP_RPC_RUN_IS_NOT_AVAILABLE);
        rc = pRun(STAT_RUNNING, 0);
    }
    else if (tool == "go")
    {
        if (!pGo)
            return McpRpcErrorResponse(id, MCP_RPC_GO_IS_NOT_AVAILABLE);
        if (!pGetcputhreadid)
            return McpRpcErrorResponse(id, MCP_RPC_GETCPUTHREADID_IS_NOT_AVAILABLE);
        rc = pGo(pGetcputhreadid(), (ulong)address, 0, 0, 0);
    }
    else if (tool == "pause")
    {
        if (!pSuspendprocess)
            return McpRpcErrorResponse(id, MCP_RPC_SUSPENDPROCESS_IS_NOT_AVAILABLE);
        rc = pSuspendprocess(0);
    }
    else if (tool == "step_into")
    {
        if (!pRun)
            return McpRpcErrorResponse(id, MCP_RPC_RUN_IS_NOT_AVAILABLE);
        rc = pRun(STAT_STEPIN, 0);
    }
    else if (tool == "step_over")
    {
        if (!pRun)
            return McpRpcErrorResponse(id, MCP_RPC_RUN_IS_NOT_AVAILABLE);
        rc = pRun(STAT_STEPOVER, 0);
    }
    else if (tool == "trace_into")
    {
        if (!pRun)
            return McpRpcErrorResponse(id, MCP_RPC_RUN_IS_NOT_AVAILABLE);
        rc = pRun(STAT_TRACEIN, 0);
    }
    else if (tool == "trace_over")
    {
        if (!pRun)
            return McpRpcErrorResponse(id, MCP_RPC_RUN_IS_NOT_AVAILABLE);
        rc = pRun(STAT_TRACEOVER, 0);
    }
    else if (tool == "auto_step_into")
    {
        if (!pRun)
            return McpRpcErrorResponse(id, MCP_RPC_RUN_IS_NOT_AVAILABLE);
        rc = pRun(STAT_ANIMIN, 0);
    }
    else if (tool == "auto_step_over")
    {
        if (!pRun)
            return McpRpcErrorResponse(id, MCP_RPC_RUN_IS_NOT_AVAILABLE);
        rc = pRun(STAT_ANIMOVER, 0);
    }
    else if (tool == "close_process")
        return McpRpcErrorResponse(id, MCP_RPC_CLOSE_PROCESS_IS_NOT_EXPORTED_BY_CURRENT_DEBUGGER_SDK);
    else if (tool == "list_memory")
    {
        if (!pListmemory)
            return McpRpcErrorResponse(id, MCP_RPC_LISTMEMORY_IS_NOT_AVAILABLE);
        rc = pListmemory();
    }
    else if (tool == "find_memory") {
        if (!pFindmemory)
            return McpRpcErrorResponse(id, MCP_RPC_FINDMEMORY_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_FINDDATAPTR_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_READ_MEMORY_REQUIRES_ADDRESS_AND_SIZE_1MB);
        std::vector<uchar> buf((size_t)size);
        if (!pReadmemory)
            return McpRpcErrorResponse(id, MCP_RPC_READMEMORY_IS_NOT_AVAILABLE);
        ulong read = pReadmemory(buf.data(), (ulong)address, (ulong)size, MM_SILENT);
        if (read > size) return McpRpcErrorResponse(id, MCP_RPC_HOST_RETURNED_AN_INVALID_READ_LENGTH);
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
            return McpRpcErrorResponse(id, MCP_RPC_WRITE_MEMORY_REQUIRES_ADDRESS_AND_HEX_DATA);
        size_t digits = 0;
        for (size_t i = 0; i < hex.size(); ++i) {
            if (HexDigit(hex[i]) >= 0) ++digits;
            else if (hex[i] != ' ' && hex[i] != '\t' && hex[i] != '\r' && hex[i] != '\n')
                return McpRpcErrorResponse(id, MCP_RPC_WRITE_MEMORY_HEX_CONTAINS_INVALID_DIGITS);
        }
        if (!digits || digits % 2) return McpRpcErrorResponse(id, MCP_RPC_WRITE_MEMORY_REQUIRES_COMPLETE_HEXADECIMAL_BYTE_PAIRS);
        std::vector<uchar> buf = HexToBytes(hex);
        if (!pWritememory)
            return McpRpcErrorResponse(id, MCP_RPC_WRITEMEMORY_IS_NOT_AVAILABLE);
        ModelJson args; ModelJson::parse(argument_json, &args);
        const ModelJson* expected = args.get("expected_hex");
        if (expected) {
            if (expected->kind != ModelJson::STRING || expected->value.empty() || expected->value.size() != buf.size() * 2 || buf.size() > 4096)
                return McpRpcErrorResponse(id, MCP_RPC_EXPECTED_HEX_MUST_CONTAIN_EXACT_HEXADECIMAL_PAIRS_FOR_4096);
            for (size_t i = 0; i < expected->value.size(); ++i) if (HexDigit(expected->value[i]) < 0)
                return McpRpcErrorResponse(id, MCP_RPC_EXPECTED_HEX_CONTAINS_INVALID_HEXADECIMAL_DIGITS);
            std::vector<uchar> before(buf.size()), wanted = HexToBytes(expected->value);
            if (!pReadmemory || pReadmemory(before.data(), (ulong)address, (ulong)before.size(), MM_SILENT) != before.size() || before != wanted)
                return McpRpcErrorResponse(id, MCP_RPC_MEMORY_CHANGED_SINCE_SNAPSHOT_CONDITIONAL_WRITE_REFUSED);
        }
        ulong written = buf.empty() ? 0 : pWritememory(buf.data(), (ulong)address, (ulong)buf.size(), MM_SILENT);
        char num[32];
        std::string result = written == buf.size() && !buf.empty() ? "{\"ok\":true,\"written\":" : "{\"ok\":false,\"written\":";
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)written);
        result += num;
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "set_software_breakpoint") {
        if (!pSetbreakpoint)
            return McpRpcErrorResponse(id, MCP_RPC_SETBREAKPOINT_IS_NOT_AVAILABLE);
        rc = pSetbreakpoint((ulong)address, BP_MANUAL | BP_BREAK, 0);
    }
    else if (tool == "set_software_breakpoint_ext") {
        if (!pSetbreakpointext)
            return McpRpcErrorResponse(id, MCP_RPC_SETBREAKPOINTEXT_IS_NOT_AVAILABLE);
        rc = pSetbreakpointext((ulong)address, BP_MANUAL | BP_BREAK, 0, (ulong)count);
    }
    else if (tool == "delete_software_breakpoint") {
        if (!pDeletebreakpoints)
            return McpRpcErrorResponse(id, MCP_RPC_DELETEBREAKPOINTS_IS_NOT_AVAILABLE);
        pDeletebreakpoints((ulong)address, (ulong)address + 1, 1);
        rc = 0;
    }
    else if (tool == "delete_breakpoint_range") {
        if (!size)
            return McpRpcErrorResponse(id, MCP_RPC_DELETE_BREAKPOINT_RANGE_REQUIRES_ADDRESS_AND_SIZE);
        if (!pDeletebreakpoints)
            return McpRpcErrorResponse(id, MCP_RPC_DELETEBREAKPOINTS_IS_NOT_AVAILABLE);
        pDeletebreakpoints((ulong)address, (ulong)(address + size), 1);
        rc = 0;
    }
    else if (tool == "delete_all_breakpoints") {
        if (!pDeletebreakpoints)
            return McpRpcErrorResponse(id, MCP_RPC_DELETEBREAKPOINTS_IS_NOT_AVAILABLE);
        pDeletebreakpoints(0, ~(ulong)0, 1);
        rc = 0;
    }
    else if (tool == "set_memory_breakpoint") {
        if (!size)
            size = 1;
        if (!pSetmembreakpointSimple)
            return McpRpcErrorResponse(id, MCP_RPC_SETMEMBREAKPOINT_IS_NOT_AVAILABLE);
        rc = pSetmembreakpointSimple((int)BreakAccessFromText(access, BP_READ | BP_WRITE), (ulong)address, (ulong)size);
    }
    else if (tool == "delete_memory_breakpoint") {
        if (!pRemovemembreakpoint)
            return McpRpcErrorResponse(id, MCP_RPC_REMOVEMEMBREAKPOINT_IS_NOT_AVAILABLE);
        rc = pRemovemembreakpoint((ulong)address);
    }
    else if (tool == "set_hardware_breakpoint") {
        if (!size)
            size = 1;
        if (!pSethardwarebreakpoint)
            return McpRpcErrorResponse(id, MCP_RPC_SETHARDWAREBREAKPOINT_IS_NOT_AVAILABLE);
        rc = pSethardwarebreakpoint((ulong)address, (int)size, (int)(BreakAccessFromText(access, BP_EXEC) | BP_MANUAL | BP_BREAK));
    }
    else if (tool == "delete_hardware_breakpoint") {
        if (address)
        {
            if (!pDeletehardwarebreakbyaddr)
                return McpRpcErrorResponse(id, MCP_RPC_DELETEHARDWAREBREAKBYADDR_IS_NOT_AVAILABLE);
            rc = pDeletehardwarebreakbyaddr((ulong)address);
        }
        else
        {
            if (!pDeletehardwarebreakpoint)
                return McpRpcErrorResponse(id, MCP_RPC_DELETEHARDWAREBREAKPOINT_IS_NOT_AVAILABLE);
            rc = pDeletehardwarebreakpoint((int)index);
        }
    }
    else if (tool == "get_breakpoint_type") {
        if (!pGetbreakpointtype)
            return McpRpcErrorResponse(id, MCP_RPC_GETBREAKPOINTTYPE_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_GETBREAKPOINTTYPECOUNT_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_GETNEXTBREAKPOINT_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_TEMPBREAKPOINT_IS_NOT_AVAILABLE);
        pTempbreakpoint((ulong)address, (int)type_value);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "plugin_temp_breakpoint") {
        if (!pPlugintempbreakpoint)
            return McpRpcErrorResponse(id, MCP_RPC_PLUGINTEMPBREAKPOINT_IS_NOT_AVAILABLE);
        rc = pPlugintempbreakpoint((ulong)address, (int)type_value, (int)BreakAccessFromText(access, BP_EXEC), (int)size, 1);
    }
    else if (tool == "disassemble") {
        uchar cmd[32] = { 0 };
        if (!pReadmemory || !pDisasm)
            return McpRpcErrorResponse(id, MCP_RPC_DISASM_IS_NOT_AVAILABLE);
        ulong read = pReadmemory(cmd, (ulong)address, sizeof(cmd), MM_SILENT);
        if (!read)
            return McpRpcErrorResponse(id, MCP_RPC_FAILED_TO_READ_INSTRUCTION_BYTES);
        HostDisasm da;
        ZeroMemory(&da, sizeof(da));
        ulong len = pDisasm(cmd, read, (ulong)address, NULL, &da, 0, 0);
        std::string result = "{\"ok\":true,\"size\":";
        char num[32];
        StringCchPrintfA(num, _countof(num), "%llu", (unsigned long long)len);
        result += num;
        result += ",\"text\":";
        JsonAppendEscaped(result, da.result);
        result += ",\"dump\":";
        JsonAppendEscaped(result, da.dump);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "assemble") {
        if (text.empty())
            return McpRpcErrorResponse(id, MCP_RPC_ASSEMBLE_REQUIRES_TEXT_ASSEMBLY);
        uchar buf[32] = { 0 };
        wchar_t err[TEXTLEN] = { 0 };
        std::wstring wtext = Utf8ToWide(text);
        if (!pAssemble)
            return McpRpcErrorResponse(id, MCP_RPC_ASSEMBLE_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_SETCPU_IS_NOT_AVAILABLE);
        pSetcpu(pGetcputhreadid(), (ulong)address, 0, 0, 0, CPU_ASMHIST | CPU_ASMCENTER | CPU_ASMFOCUS | CPU_REDRAW);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "set_disasm") {
        if (!pSetdisasm)
            return McpRpcErrorResponse(id, MCP_RPC_SETDISASM_IS_NOT_AVAILABLE);
        pSetdisasm((ulong)address, (ulong)size, (int)type_value);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "evaluate") {
        if (!pExpressionA)
            return McpRpcErrorResponse(id, MCP_RPC_EXPRESSION_IS_NOT_AVAILABLE);
        if (expression.empty())
            expression = text;
        if (expression.empty())
            return McpRpcErrorResponse(id, MCP_RPC_EVALUATE_REQUIRES_EXPRESSION);
        Z0B_RESULT res;
        ZeroMemory(&res, sizeof(res));
        if (!pGetcputhreadid)
            return McpRpcErrorResponse(id, MCP_RPC_GETCPUTHREADID_IS_NOT_AVAILABLE);
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
    else if (tool == "resolve_symbol") {
        if (name.empty() || name.size() >= TEXTLEN)
            return McpRpcErrorResponse(id, MCP_RPC_RESOLVE_SYMBOL_REQUIRES_A_SYMBOL_NAME);
        unsigned __int64 symbol_address = 0;
        bool paused = pMcpDebugState ? pMcpDebugState() == STAT_PAUSED :
            pGetstatus && pGetstatus() == STAT_PAUSED;
        if (paused && pExpressionA && pGetcputhreadid) {
            Z0B_RESULT resolved;
            ZeroMemory(&resolved, sizeof(resolved));
            if (pExpressionA(&resolved, (char*)name.c_str(), 0, 0, NULL, 0, 0, pGetcputhreadid())) {
                char* end = NULL;
                unsigned __int64 value = _strtoui64(resolved.value, &end, 16);
                if (value && end && *end == 0) symbol_address = value;
            }
        }
        bool from_export = false;
        if (!symbol_address) {
            symbol_address = ResolveLoadedModuleExport(CurrentDebugProcessId(), name);
            from_export = symbol_address != 0;
        }
        std::string result = "{\"ok\":";
        result += symbol_address ? "true" : "false";
        result += ",\"address\":";
        JsonAppendHex64(result, symbol_address);
        result += ",\"source\":\"";
        result += symbol_address ? (from_export ? "module_export" : "debugger_symbol") : "unresolved";
        result += "\"";
        result += ",\"address_space\":\"runtime_va\"";
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_name") {
        if (!pFindnameA)
            return McpRpcErrorResponse(id, MCP_RPC_FINDNAME_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_INSERTNAME_IS_NOT_AVAILABLE);
        if (name.empty())
            name = text;
        rc = pInsertnameA((ulong)address, (int)type_value, (char*)name.c_str());
    }
    else if (tool == "decode_address") {
        if (!pDecodeaddressA)
            return McpRpcErrorResponse(id, MCP_RPC_DECODEADDRESS_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_DECODENAME_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_COMMENTADDRESS_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_SIMPLEADDRESS_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_FINDLABEL_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_FINDMODULE_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_FINDTHREAD_IS_NOT_AVAILABLE);
        if (!pGetcputhreadid)
            return McpRpcErrorResponse(id, MCP_RPC_GETCPUTHREADID_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_FINDDATA_IS_NOT_AVAILABLE);
        std::vector<uchar> buf = HexToBytes(hex);
        if (buf.empty())
            return McpRpcErrorResponse(id, MCP_RPC_FIND_DATA_REQUIRES_HEX_DATA);
        ulong found = pFinddataA((ulong)address, (int)type_value, buf.data(), (ulong)buf.size());
        std::string result = "{\"ok\":true,\"address\":";
        JsonAppendHex64(result, found);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_decode") {
        if (!pFinddecodeA)
            return McpRpcErrorResponse(id, MCP_RPC_FINDDECODE_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_FINDSTRINGS_IS_NOT_AVAILABLE);
        if (!size)
            return McpRpcErrorResponse(id, MCP_RPC_FIND_STRINGS_REQUIRES_BASE_ADDRESS_AND_SIZE);
        rc = pFindstringsA((ulong)address, (ulong)size, 0, (char*)(text.empty() ? "MCP strings" : text.c_str()));
    }
    else if (tool == "find_references") {
        if (!pFindreferencesA)
            return McpRpcErrorResponse(id, MCP_RPC_FINDREFERENCES_IS_NOT_AVAILABLE);
        unsigned __int64 target0 = 0, target1 = 0;
        JsonFindUInt64(argument_json, "target", target0);
        JsonFindUInt64(argument_json, "target1", target1);
        if (!size || !target0)
            return McpRpcErrorResponse(id, MCP_RPC_FIND_REFERENCES_REQUIRES_BASE_ADDRESS_SIZE_AND_TARGET);
        rc = pFindreferencesA((ulong)address, (ulong)size, (ulong)target0, (ulong)target1, 0, 0, (char*)(text.empty() ? "MCP references" : text.c_str()));
    }
    else if (tool == "find_import_by_name") {
        if (name.empty())
            name = text;
        unsigned __int64 found = FindLoadedMainImport(CurrentDebugProcessId(), name, address, size);
        std::string result = "{\"ok\":";
        result += found ? "true" : "false";
        result += ",\"address\":";
        JsonAppendHex64(result, found);
        result += ",\"source\":\"";
        result += found ? "main_executable_import" : "unresolved";
        result += "\"";
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "find_file_offset") {
        if (!pFindmodule || !pFindfileoffset)
            return McpRpcErrorResponse(id, MCP_RPC_FINDMODULE_FINDFILEOFFSET_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_FOLLOWCALL_IS_NOT_AVAILABLE);
        ulong target = pFollowcall((ulong)address);
        std::string result = "{\"ok\":true,\"address\":";
        JsonAppendHex64(result, target);
        result += "}";
        return JsonRpcResult(id, result);
    }
    else if (tool == "walk_reference") {
        if (!pWalkreference)
            return McpRpcErrorResponse(id, MCP_RPC_WALKREFERENCE_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_WALKREFERENCEEX_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_ISPREFIX_IS_NOT_AVAILABLE);
        rc = pIsprefix((int)type_value);
    }
    else if (tool == "get_last_error") {
        if (!pGetlasterrorW)
            return McpRpcErrorResponse(id, MCP_RPC_GETLASTERROR_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_GETCPUDISASMDUMP_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_GETCPUDISASMTABLE_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_PLUGINREADINTFROMINI_IS_NOT_AVAILABLE);
        if (key.empty())
            return McpRpcErrorResponse(id, MCP_RPC_PLUGIN_READ_INI_INT_REQUIRES_KEY);
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
            return McpRpcErrorResponse(id, MCP_RPC_PLUGINWRITEINTTOINI_IS_NOT_AVAILABLE);
        if (key.empty())
            return McpRpcErrorResponse(id, MCP_RPC_PLUGIN_WRITE_INI_INT_REQUIRES_KEY);
        rc = pPluginwriteinttoini(g_instance, (char*)key.c_str(), (int)type_value);
    }
    else if (tool == "plugin_read_ini_string") {
        if (!pPluginreadstringfromini)
            return McpRpcErrorResponse(id, MCP_RPC_PLUGINREADSTRINGFROMINI_IS_NOT_AVAILABLE);
        if (key.empty())
            return McpRpcErrorResponse(id, MCP_RPC_PLUGIN_READ_INI_STRING_REQUIRES_KEY);
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
            return McpRpcErrorResponse(id, MCP_RPC_PLUGINWRITESTRINGTOINI_IS_NOT_AVAILABLE);
        if (key.empty())
            return McpRpcErrorResponse(id, MCP_RPC_PLUGIN_WRITE_INI_STRING_REQUIRES_KEY);
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
            return McpRpcErrorResponse(id, MCP_RPC_LISTMEMORY_IS_NOT_AVAILABLE);
        rc = pListmemory();
    }
    else if (tool == "show_breakpoints") {
        if (!pHardbreakpoints)
            return McpRpcErrorResponse(id, MCP_RPC_HARDBREAKPOINTS_IS_NOT_AVAILABLE);
        rc = pHardbreakpoints(0);
    }
    else if (tool == "show_hardware_breakpoints") {
        if (!pHardbreakpoints)
            return McpRpcErrorResponse(id, MCP_RPC_HARDBREAKPOINTS_IS_NOT_AVAILABLE);
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
            return McpRpcErrorResponse(id, MCP_RPC_SETTRACECONDITION_IS_NOT_AVAILABLE);
        pSettraceconditionA((char*)condition.c_str(), 0, 0, 0, 0, 0);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "set_trace_count") {
        if (!pSettracecount)
            return McpRpcErrorResponse(id, MCP_RPC_SETTRACECOUNT_IS_NOT_AVAILABLE);
        pSettracecount((ulong)count);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "set_trace_pause_on_commands") {
        if (!pSettracepauseoncommandsA)
            return McpRpcErrorResponse(id, MCP_RPC_SETTRACEPAUSEONCOMMANDS_IS_NOT_AVAILABLE);
        pSettracepauseoncommandsA((char*)cmdset.c_str());
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "set_dump_type") {
        if (!pSetdumptype)
            return McpRpcErrorResponse(id, MCP_RPC_SETDUMPTYPE_IS_NOT_AVAILABLE);
        pSetdumptype(NULL, (ulong)type_value);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "dump_backup") {
        if (!pDumpbackup)
            return McpRpcErrorResponse(id, MCP_RPC_DUMPBACKUP_IS_NOT_AVAILABLE);
        pDumpbackup(NULL, (int)type_value);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else if (tool == "plugin_module_changed") {
        if (!pPluginmodulechanged)
            return McpRpcErrorResponse(id, MCP_RPC_PLUGINMODULECHANGED_IS_NOT_AVAILABLE);
        pPluginmodulechanged((ulong)address);
        return JsonRpcResult(id, "{\"ok\":true}");
    }
    else {
        return McpRpcErrorResponse(id, MCP_RPC_UNKNOWN_TOOL);
    }

    char num[32];
    StringCchPrintfA(num, _countof(num), "%d", rc);
    std::string result = "{\"ok\":true,\"return\":";
    result += num;
    result += "}";
    return JsonRpcResult(id, result);
}

static bool HttpServerSendAll(SOCKET s, const char* data, int size)
{
    int sent = 0;
    while (sent < size) {
        int n = send(s, data + sent, size - sent, 0);
        if (n <= 0)
            return false;
        sent += n;
    }
    return true;
}

static void HttpServerSendResponse(SOCKET s, int status, const char* status_text,
    const std::string& body)
{
    char header[512];
    StringCchPrintfA(header, _countof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n",
        status, status_text, (unsigned int)body.size());
    HttpServerSendAll(s, header, (int)strlen(header));
    if (!body.empty())
        HttpServerSendAll(s, body.data(), (int)body.size());
}

static std::string HttpServerHeaderValue(const std::string& headers, const char* name)
{
    std::string lower = headers;
    for (size_t i = 0; i < lower.size(); ++i)
        lower[i] = (char)tolower((unsigned char)lower[i]);
    std::string key = name;
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = (char)tolower((unsigned char)key[i]);
    key += ":";
    size_t p = lower.find(key);
    if (p == std::string::npos)
        return std::string();
    p += key.size();
    while (p < headers.size() && (headers[p] == ' ' || headers[p] == '\t'))
        ++p;
    size_t e = headers.find("\r\n", p);
    if (e == std::string::npos)
        e = headers.size();
    return headers.substr(p, e - p);
}

static bool HttpServerAuthorized(const McpConfig& cfg, const std::string& headers)
{
    if (!cfg.auth_token[0])
        return true;
    std::string auth = HttpServerHeaderValue(headers, "Authorization");
    std::string expected = "Bearer ";
    expected += WideToUtf8(cfg.auth_token);
    return auth == expected;
}

static void HttpServerHandleClient(SOCKET client)
{
    std::string request;
    char buf[2048];
    size_t header_end = std::string::npos;
    int content_length = 0;
    for (;;) {
        int n = recv(client, buf, sizeof(buf), 0);
        if (n <= 0)
            return;
        request.append(buf, buf + n);
        header_end = request.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            std::string headers = request.substr(0, header_end + 4);
            std::string len = HttpServerHeaderValue(headers, "Content-Length");
            content_length = atoi(len.c_str());
            break;
        }
        if (request.size() > 64 * 1024)
            return;
    }
    size_t body_start = header_end + 4;
    while (content_length > 0 && request.size() < body_start + (size_t)content_length) {
        int n = recv(client, buf, sizeof(buf), 0);
        if (n <= 0)
            return;
        request.append(buf, buf + n);
    }

    std::string headers = request.substr(0, header_end + 4);
    McpConfig cfg = CopyConfig();
    if (request.find("POST ") != 0) {
        HttpServerSendResponse(client, 405, "Method Not Allowed",
            McpRpcErrorResponse("null", MCP_RPC_POST_REQUIRED));
        return;
    }
    if (!HttpServerAuthorized(cfg, headers)) {
        HttpServerSendResponse(client, 401, "Unauthorized",
            McpRpcErrorResponse("null", MCP_RPC_UNAUTHORIZED));
        return;
    }
    std::string body;
    if (content_length > 0 && request.size() >= body_start + (size_t)content_length)
        body = request.substr(body_start, (size_t)content_length);
    LogTransportJson(cfg, "http server recv: ", body);
    std::string response = ExecuteToolCommand(body);
    if (response.empty())
        response = "{}";
    LogTransportJson(cfg, "http server send: ", response);
    HttpServerSendResponse(client, 200, "OK", response);
}

static DWORD WINAPI HttpServerThreadProc(LPVOID)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 0;

    McpConfig cfg = CopyConfig();
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        WSACleanup();
        return 0;
    }
    BOOL reuse = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)cfg.http_server_port);
    std::string bind_addr = WideToUtf8(cfg.http_server_bind);
    if (bind_addr.empty() || bind_addr == "0.0.0.0")
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        addr.sin_addr.s_addr = inet_addr(bind_addr.c_str());
    if (addr.sin_addr.s_addr == INADDR_NONE)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(listener, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(listener, 8) == SOCKET_ERROR) {
        closesocket(listener);
        WSACleanup();
        SetConnectionError(McpText(L"HTTP MCP Server 监听失败。", L"HTTP MCP Server listen failed."));
        return 0;
    }
    g_http_server_socket = listener;
    SetRuntimeStatus(TRUE, NULL);
    DiagnosticLog(2, McpText(L"HTTP MCP Server 已启动。", L"HTTP MCP Server started."));

    while (InterlockedCompareExchange(&g_http_server_stop, 0, 0) == 0) {
        SOCKET client = accept(listener, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (InterlockedCompareExchange(&g_http_server_stop, 0, 0) != 0)
                break;
            Sleep(10);
            continue;
        }
        HttpServerHandleClient(client);
        closesocket(client);
    }
    closesocket(listener);
    if (g_http_server_socket == listener)
        g_http_server_socket = INVALID_SOCKET;
    WSACleanup();
    return 0;
}

static void StartHttpServerIfConfigured(const McpConfig& cfg)
{
    if (!cfg.http_server_enable && lstrcmpiW(cfg.role, L"server") != 0)
        return;
    if (g_http_server_thread)
        return;
    InterlockedExchange(&g_http_server_stop, 0);
    g_http_server_thread = CreateThread(NULL, 0, HttpServerThreadProc, NULL, 0, NULL);
}

static void StopHttpServer(void)
{
    InterlockedExchange(&g_http_server_stop, 1);
    if (g_http_server_socket != INVALID_SOCKET) {
        closesocket(g_http_server_socket);
        g_http_server_socket = INVALID_SOCKET;
    }
    if (g_http_server_thread) {
        WaitForSingleObject(g_http_server_thread, 2000);
        CloseHandle(g_http_server_thread);
        g_http_server_thread = NULL;
    }
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
        McpConfig output_cfg = CopyConfig();
        size_t max_output = output_cfg.stdio_max_output > 4096
            ? (size_t)output_cfg.stdio_max_output : (size_t)(1024 * 1024);
        if (pending.size() > max_output) {
            pending.erase(0, pending.size() - max_output);
            SetConnectionError(McpText(L"stdio 输出超过缓存上限，已丢弃旧数据。",
                                        L"stdio output exceeded the buffer limit; old data was discarded."));
        }
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
            LogTransportJson(CopyConfig(), "stdio recv: ", line);
            NoteIncomingResponse(line);
            if (IsJsonRpcResponseMessage(line))
                continue;
            std::string method;
            std::string tool;
            std::string name;
            JsonFindString(line, "method", method);
            JsonFindString(line, "tool", tool);
            JsonFindString(line, "name", name);
            if (method == "z0dbg/event" ||
                (method.empty() && tool.empty() && name.empty()))
                continue;
            McpConfig command_cfg = CopyConfig();
            if (!command_cfg.receive_server_commands)
                continue;
            std::string response = ExecuteToolCommand(line);
            if (command_cfg.auto_reply_requests)
                SendStdioJson(command_cfg, response);
        }
    }
    return 0;
}

static HWND AddLabel(HWND parent, int x, int y, int w, int h, const wchar_t* text)
{
    return CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
        x, y, w, h, parent, NULL, g_instance, NULL);
}

static HWND AddLabelWithId(HWND parent, int id, int x, int y, int w, int h, const wchar_t* text)
{
    return CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, g_instance, NULL);
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

static void ExpandSettingsDialog(HWND hwnd, HWND owner)
{
    RECT window, client;
    GetWindowRect(hwnd, &window);
    GetClientRect(hwnd, &client);
    MONITORINFO monitor = { sizeof(monitor) };
    GetMonitorInfoW(MonitorFromWindow(owner ? owner : hwnd, MONITOR_DEFAULTTONEAREST), &monitor);
    const RECT& work = monitor.rcWork;
    const int old_width = window.right - window.left;
    const int old_client_width = client.right - client.left;
    HDC dc = GetDC(hwnd);
    int dpi = dc ? GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc) ReleaseDC(hwnd, dc);
    int scale = (std::max)(125, MulDiv(dpi, 100, 96));
    int width = (std::min)(MulDiv(old_width, scale, 100), (int)(work.right - work.left - 32));
    width = (std::max)(width, old_width);
    int client_width = old_client_width + width - old_width;
    for (HWND child = GetWindow(hwnd, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        RECT bounds;
        GetWindowRect(child, &bounds);
        MapWindowPoints(HWND_DESKTOP, hwnd, (LPPOINT)&bounds, 2);
        SetWindowPos(child, NULL, MulDiv(bounds.left, client_width, old_client_width), bounds.top,
            MulDiv(bounds.right - bounds.left, client_width, old_client_width),
            bounds.bottom - bounds.top, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    int height = window.bottom - window.top;
    int x = work.left + (work.right - work.left - width) / 2;
    int y = work.top + (work.bottom - work.top - height) / 2;
    SetWindowPos(hwnd, NULL, (std::max)((int)work.left, x), (std::max)((int)work.top, y), width, height,
        SWP_NOZORDER | SWP_NOACTIVATE);
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

static void SetTransportUiState(HWND hwnd);
static void FillDialogFromConfig(HWND hwnd, const McpConfig& cfg);
static void ShowAdvancedDialog(HWND owner);

static void FillDialog(HWND hwnd)
{
    McpConfig cfg = CopyConfig();
    FillDialogFromConfig(hwnd, cfg);
}

static void FillDialogFromConfig(HWND hwnd, const McpConfig& cfg)
{
    CheckDlgButton(hwnd, IDC_ENABLE, cfg.enabled ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(hwnd, IDC_NAME, cfg.name);
    SetDlgItemTextW(hwnd, IDC_URL, cfg.url);
    SetDlgItemTextW(hwnd, IDC_COMMAND, cfg.command);
    SetDlgItemTextW(hwnd, IDC_ARGUMENTS, cfg.arguments);
    SetDlgItemTextW(hwnd, IDC_WORKDIR, cfg.workdir);
    SetDlgItemTextW(hwnd, IDC_ENV, cfg.env);
    SetDlgItemTextW(hwnd, IDC_PIPE_NAME, cfg.pipe_name);
    SetDlgItemTextW(hwnd, IDC_SHARED_KEY, cfg.shared_key);
    CheckDlgButton(hwnd, IDC_AUTO_CONNECT, cfg.auto_connect ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_AUTO_RECONNECT, cfg.auto_reconnect ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_MCP_INITIALIZE, cfg.mcp_initialize ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(hwnd, IDC_CLIENT_NAME, cfg.client_name);
    SetDlgItemTextW(hwnd, IDC_CLIENT_VERSION, cfg.client_version);
    SetDlgItemTextW(hwnd, IDC_PROTOCOL_VERSION, cfg.protocol_version);
    wchar_t number[32];
    StringCchPrintfW(number, _countof(number), L"%d", cfg.request_timeout_ms);
    SetDlgItemTextW(hwnd, IDC_REQUEST_TIMEOUT, number);
    SetDlgItemTextW(hwnd, IDC_TEST_TOOL_NAME, cfg.test_tool_name);
    SetDlgItemTextW(hwnd, IDC_TEST_TOOL_ARGS, cfg.test_tool_args);
    CheckDlgButton(hwnd, IDC_CONNECT_DEBUG_OPEN, cfg.connect_on_debug_open ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_RECONNECT_ON_SAVE, cfg.reconnect_on_save ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_SEND_DEBUG_EVENTS, cfg.send_debug_events ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_RECEIVE_COMMANDS, cfg.receive_server_commands ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_AUTO_REPLY, cfg.auto_reply_requests ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(hwnd, IDC_HTTP_HEADERS, cfg.http_headers);
    SetDlgItemTextW(hwnd, IDC_AUTH_TOKEN, cfg.auth_token);
    CheckDlgButton(hwnd, IDC_ALLOW_READ, cfg.allow_read ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_ALLOW_WRITE, cfg.allow_write ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_ALLOW_EXECUTE, cfg.allow_execute ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_ALLOW_BREAKPOINT, cfg.allow_breakpoint ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_ALLOW_PATCH, cfg.allow_patch ? BST_CHECKED : BST_UNCHECKED);

    HWND combo = GetDlgItem(hwnd, IDC_TRANSPORT);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"stdio");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"http");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"sse");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"pipe");
    int sel = 0;
    if (lstrcmpiW(cfg.transport, L"http") == 0)
        sel = 1;
    else if (lstrcmpiW(cfg.transport, L"sse") == 0)
        sel = 2;
    else if (lstrcmpiW(cfg.transport, L"pipe") == 0)
        sel = 3;
    SendMessageW(combo, CB_SETCURSEL, sel, 0);

    HWND role = GetDlgItem(hwnd, IDC_ROLE);
    SendMessageW(role, CB_RESETCONTENT, 0, 0);
    SendMessageW(role, CB_ADDSTRING, 0, (LPARAM)L"client");
    SendMessageW(role, CB_ADDSTRING, 0, (LPARAM)L"server");
    SendMessageW(role, CB_ADDSTRING, 0, (LPARAM)L"bridge");
    int role_sel = 0;
    if (lstrcmpiW(cfg.role, L"server") == 0)
        role_sel = 1;
    else if (lstrcmpiW(cfg.role, L"bridge") == 0)
        role_sel = 2;
    SendMessageW(role, CB_SETCURSEL, role_sel, 0);

    HWND pipe_protocol = GetDlgItem(hwnd, IDC_PIPE_PROTOCOL);
    SendMessageW(pipe_protocol, CB_SETDROPPEDWIDTH, 300, 0);
    SendMessageW(pipe_protocol, CB_RESETCONTENT, 0, 0);
    SendMessageW(pipe_protocol, CB_ADDSTRING, 0, (LPARAM)L"line");
    SendMessageW(pipe_protocol, CB_ADDSTRING, 0, (LPARAM)L"z0bdbg");
    SendMessageW(pipe_protocol, CB_ADDSTRING, 0, (LPARAM)L"z0bdbg-strict");
    int pipe_sel = 0;
    if (lstrcmpiW(cfg.pipe_protocol, L"z0bdbg") == 0)
        pipe_sel = 1;
    else if (lstrcmpiW(cfg.pipe_protocol, L"z0bdbg-strict") == 0)
        pipe_sel = 2;
    SendMessageW(pipe_protocol, CB_SETCURSEL, pipe_sel, 0);

    wchar_t timeout[32];
    StringCchPrintfW(timeout, _countof(timeout), L"%d", cfg.timeout_ms);
    SetDlgItemTextW(hwnd, IDC_TIMEOUT, timeout);
    StringCchPrintfW(timeout, _countof(timeout), L"%d", cfg.reconnect_interval_ms);
    SetDlgItemTextW(hwnd, IDC_RECONNECT_INTERVAL, timeout);
    StringCchPrintfW(timeout, _countof(timeout), L"%d", cfg.reconnect_max_attempts);
    SetDlgItemTextW(hwnd, IDC_RECONNECT_MAX, timeout);
    SetTransportUiState(hwnd);
}

static bool ReadDialogConfig(HWND hwnd, McpConfig* out)
{
    if (!out)
        return false;
    McpConfig cfg = CopyConfig();
    wchar_t timeout[32];
    cfg.enabled = IsDlgButtonChecked(hwnd, IDC_ENABLE) == BST_CHECKED;
    GetDlgItemTextW(hwnd, IDC_NAME, cfg.name, _countof(cfg.name));
    GetDlgItemTextW(hwnd, IDC_URL, cfg.url, _countof(cfg.url));
    GetDlgItemTextW(hwnd, IDC_COMMAND, cfg.command, _countof(cfg.command));
    GetDlgItemTextW(hwnd, IDC_ARGUMENTS, cfg.arguments, _countof(cfg.arguments));
    GetDlgItemTextW(hwnd, IDC_WORKDIR, cfg.workdir, _countof(cfg.workdir));
    GetDlgItemTextW(hwnd, IDC_ENV, cfg.env, _countof(cfg.env));
    GetDlgItemTextW(hwnd, IDC_PIPE_NAME, cfg.pipe_name, _countof(cfg.pipe_name));
    GetDlgItemTextW(hwnd, IDC_SHARED_KEY, cfg.shared_key, _countof(cfg.shared_key));
    cfg.auto_connect = IsDlgButtonChecked(hwnd, IDC_AUTO_CONNECT) == BST_CHECKED;
    cfg.auto_reconnect = IsDlgButtonChecked(hwnd, IDC_AUTO_RECONNECT) == BST_CHECKED;
    cfg.mcp_initialize = IsDlgButtonChecked(hwnd, IDC_MCP_INITIALIZE) == BST_CHECKED;
    GetDlgItemTextW(hwnd, IDC_CLIENT_NAME, cfg.client_name, _countof(cfg.client_name));
    GetDlgItemTextW(hwnd, IDC_CLIENT_VERSION, cfg.client_version, _countof(cfg.client_version));
    GetDlgItemTextW(hwnd, IDC_PROTOCOL_VERSION, cfg.protocol_version, _countof(cfg.protocol_version));
    GetDlgItemTextW(hwnd, IDC_REQUEST_TIMEOUT, timeout, _countof(timeout));
    cfg.request_timeout_ms = _wtoi(timeout);
    GetDlgItemTextW(hwnd, IDC_TEST_TOOL_NAME, cfg.test_tool_name, _countof(cfg.test_tool_name));
    GetDlgItemTextW(hwnd, IDC_TEST_TOOL_ARGS, cfg.test_tool_args, _countof(cfg.test_tool_args));
    cfg.connect_on_debug_open = IsDlgButtonChecked(hwnd, IDC_CONNECT_DEBUG_OPEN) == BST_CHECKED;
    cfg.reconnect_on_save = IsDlgButtonChecked(hwnd, IDC_RECONNECT_ON_SAVE) == BST_CHECKED;
    cfg.send_debug_events = IsDlgButtonChecked(hwnd, IDC_SEND_DEBUG_EVENTS) == BST_CHECKED;
    cfg.receive_server_commands = IsDlgButtonChecked(hwnd, IDC_RECEIVE_COMMANDS) == BST_CHECKED;
    cfg.auto_reply_requests = IsDlgButtonChecked(hwnd, IDC_AUTO_REPLY) == BST_CHECKED;
    GetDlgItemTextW(hwnd, IDC_HTTP_HEADERS, cfg.http_headers, _countof(cfg.http_headers));
    GetDlgItemTextW(hwnd, IDC_AUTH_TOKEN, cfg.auth_token, _countof(cfg.auth_token));
    cfg.allow_read = IsDlgButtonChecked(hwnd, IDC_ALLOW_READ) == BST_CHECKED;
    cfg.allow_write = IsDlgButtonChecked(hwnd, IDC_ALLOW_WRITE) == BST_CHECKED;
    cfg.allow_execute = IsDlgButtonChecked(hwnd, IDC_ALLOW_EXECUTE) == BST_CHECKED;
    cfg.allow_breakpoint = IsDlgButtonChecked(hwnd, IDC_ALLOW_BREAKPOINT) == BST_CHECKED;
    cfg.allow_patch = IsDlgButtonChecked(hwnd, IDC_ALLOW_PATCH) == BST_CHECKED;

    HWND combo = GetDlgItem(hwnd, IDC_TRANSPORT);
    int sel = (int)SendMessageW(combo, CB_GETCURSEL, 0, 0);
    if (sel == 1)
        StringCchCopyW(cfg.transport, _countof(cfg.transport), L"http");
    else if (sel == 2)
        StringCchCopyW(cfg.transport, _countof(cfg.transport), L"sse");
    else if (sel == 3)
        StringCchCopyW(cfg.transport, _countof(cfg.transport), L"pipe");
    else
        StringCchCopyW(cfg.transport, _countof(cfg.transport), L"stdio");

    HWND role = GetDlgItem(hwnd, IDC_ROLE);
    int role_sel = (int)SendMessageW(role, CB_GETCURSEL, 0, 0);
    if (role_sel == 1)
        StringCchCopyW(cfg.role, _countof(cfg.role), L"server");
    else if (role_sel == 2)
        StringCchCopyW(cfg.role, _countof(cfg.role), L"bridge");
    else
        StringCchCopyW(cfg.role, _countof(cfg.role), L"client");

    HWND pipe_protocol = GetDlgItem(hwnd, IDC_PIPE_PROTOCOL);
    int pipe_sel = (int)SendMessageW(pipe_protocol, CB_GETCURSEL, 0, 0);
    if (pipe_sel == 1)
        StringCchCopyW(cfg.pipe_protocol, _countof(cfg.pipe_protocol), L"z0bdbg");
    else if (pipe_sel == 2)
        StringCchCopyW(cfg.pipe_protocol, _countof(cfg.pipe_protocol), L"z0bdbg-strict");
    else
        StringCchCopyW(cfg.pipe_protocol, _countof(cfg.pipe_protocol), L"line");

    GetDlgItemTextW(hwnd, IDC_TIMEOUT, timeout, _countof(timeout));
    cfg.timeout_ms = _wtoi(timeout);
    if (cfg.timeout_ms <= 0)
        cfg.timeout_ms = 30000;
    GetDlgItemTextW(hwnd, IDC_RECONNECT_INTERVAL, timeout, _countof(timeout));
    cfg.reconnect_interval_ms = _wtoi(timeout);
    GetDlgItemTextW(hwnd, IDC_RECONNECT_MAX, timeout, _countof(timeout));
    cfg.reconnect_max_attempts = _wtoi(timeout);

    if (!cfg.name[0]) {
        MessageBoxW(hwnd, McpText(L"名称不能为空。", L"Name cannot be empty."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_NAME));
        return false;
    }
    if (cfg.timeout_ms < 100 || cfg.timeout_ms > 600000) {
        MessageBoxW(hwnd, McpText(L"超时必须在 100 到 600000 毫秒之间。",
                                  L"Timeout must be between 100 and 600000 milliseconds."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_TIMEOUT));
        return false;
    }
    if (!cfg.protocol_version[0])
        StringCchCopyW(cfg.protocol_version, _countof(cfg.protocol_version), L"2024-11-05");
    if (cfg.request_timeout_ms < 100 || cfg.request_timeout_ms > 600000) {
        MessageBoxW(hwnd, McpText(L"请求超时必须在 100 到 600000 毫秒之间。",
                                  L"Request timeout must be between 100 and 600000 milliseconds."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_REQUEST_TIMEOUT));
        return false;
    }
    if (cfg.reconnect_interval_ms < 100 || cfg.reconnect_interval_ms > 600000) {
        MessageBoxW(hwnd, McpText(L"重连间隔必须在 100 到 600000 毫秒之间。",
                                  L"Reconnect interval must be between 100 and 600000 milliseconds."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_RECONNECT_INTERVAL));
        return false;
    }
    if (cfg.reconnect_max_attempts < 0 || cfg.reconnect_max_attempts > 100) {
        MessageBoxW(hwnd, McpText(L"最大重试次数必须在 0 到 100 之间。",
                                  L"Maximum reconnect attempts must be between 0 and 100."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_RECONNECT_MAX));
        return false;
    }
    if (lstrcmpiW(cfg.transport, L"stdio") == 0 && !cfg.command[0]) {
        MessageBoxW(hwnd, McpText(L"stdio 模式必须填写命令路径或命令名。",
                                  L"stdio mode requires a command path or command name."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_COMMAND));
        return false;
    }
    if (lstrcmpiW(cfg.transport, L"stdio") != 0 && !cfg.url[0]) {
        if (lstrcmpiW(cfg.transport, L"pipe") == 0 && !cfg.pipe_name[0]) {
            MessageBoxW(hwnd, McpText(L"pipe 模式必须填写管道名。",
                                      L"pipe mode requires a named pipe."),
                PLUGIN_NAME, MB_OK | MB_ICONWARNING);
            SetFocus(GetDlgItem(hwnd, IDC_PIPE_NAME));
            return false;
        }
        if (lstrcmpiW(cfg.transport, L"pipe") == 0)
            goto valid_transport;
        MessageBoxW(hwnd, McpText(L"http/sse 模式必须填写 URL。",
                                  L"http/sse mode requires a URL."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(hwnd, IDC_URL));
        return false;
    }

valid_transport:
    *out = cfg;
    return true;
}

static bool ReadDialog(HWND hwnd)
{
    McpConfig cfg;
    if (!ReadDialogConfig(hwnd, &cfg))
        return false;
    EnterCriticalSection(&g_config_cs);
    g_config = cfg;
    LeaveCriticalSection(&g_config_cs);
    return true;
}

static void SetTransportUiState(HWND hwnd)
{
    HWND combo = GetDlgItem(hwnd, IDC_TRANSPORT);
    int sel = (int)SendMessageW(combo, CB_GETCURSEL, 0, 0);
    const bool isStdio = sel == 0;
    const bool isHttp = sel == 1;
    const bool isSse = sel == 2;
    const bool isPipe = sel == 3;
    EnableWindow(GetDlgItem(hwnd, IDC_URL), isHttp || isSse);
    EnableWindow(GetDlgItem(hwnd, IDC_COMMAND), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_ARGUMENTS), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_WORKDIR), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_ENV), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_BROWSE_CMD), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_BROWSE_DIR), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_PIPE_NAME), isPipe);
    EnableWindow(GetDlgItem(hwnd, IDC_PIPE_PROTOCOL), isPipe);
    EnableWindow(GetDlgItem(hwnd, IDC_SHARED_KEY), isPipe);
    EnableWindow(GetDlgItem(hwnd, IDC_HTTP_HEADERS), isHttp || isSse);
    EnableWindow(GetDlgItem(hwnd, IDC_AUTH_TOKEN), isHttp || isSse);

    EnableWindow(GetDlgItem(hwnd, IDC_URL_LABEL), isHttp || isSse);
    EnableWindow(GetDlgItem(hwnd, IDC_COMMAND_LABEL), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_ARGUMENTS_LABEL), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_WORKDIR_LABEL), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_ENV_LABEL), isStdio);
    EnableWindow(GetDlgItem(hwnd, IDC_PIPE_NAME_LABEL), isPipe);
    EnableWindow(GetDlgItem(hwnd, IDC_PIPE_PROTOCOL_LABEL), isPipe);
    EnableWindow(GetDlgItem(hwnd, IDC_SHARED_KEY_LABEL), isPipe);

    SetDlgItemTextW(hwnd, IDC_URL_LABEL,
        isHttp || isSse
            ? McpText(L"URL", L"URL")
            : McpText(L"URL（HTTP/SSE）", L"URL (HTTP/SSE)"));
    SetDlgItemTextW(hwnd, IDC_COMMAND_LABEL,
        isStdio
            ? McpText(L"启动命令", L"Start command")
            : McpText(L"启动命令（stdio）", L"Start command (stdio)"));
    SetDlgItemTextW(hwnd, IDC_ARGUMENTS_LABEL,
        isStdio
            ? McpText(L"启动参数", L"Arguments")
            : McpText(L"启动参数（stdio）", L"Arguments (stdio)"));
    SetDlgItemTextW(hwnd, IDC_WORKDIR_LABEL,
        isStdio
            ? McpText(L"工作目录", L"Working dir")
            : McpText(L"工作目录（stdio）", L"Working dir (stdio)"));
    SetDlgItemTextW(hwnd, IDC_ENV_LABEL,
        isStdio
            ? McpText(L"环境变量", L"Environment")
            : McpText(L"环境变量（stdio）", L"Environment (stdio)"));

    const wchar_t* status = L"";
    if (isStdio) {
        status = McpText(
            L"通道：stdio。插件按需启动本地 MCP Server，通过标准输入输出收发 JSON；使用启动命令、参数、工作目录和环境变量。",
            L"Channel: stdio. Starts the local MCP Server on demand and exchanges JSON over stdin/stdout; command, arguments, working directory and environment are used.");
    }
    else if (isPipe) {
        status = McpText(
            L"通道：pipe。连接已有 Windows 命名管道；line 为普通按行 JSON，z0bdbg 兼容 WinDbgLite 握手，z0bdbg-strict 强制共享密钥加密。",
            L"Channel: pipe. Connects to an existing Windows named pipe; line uses plain JSON lines, z0bdbg supports the WinDbgLite handshake, and z0bdbg-strict requires shared-key encryption.");
    }
    else if (isHttp) {
        status = McpText(
            L"通道：http。插件向 URL 发送 HTTP POST JSON 事件。",
            L"Channel: http. Sends JSON events to the URL with HTTP POST.");
    }
    else {
        status = McpText(
            L"通道：sse。当前实现按 HTTP POST JSON 方式向 URL 发送事件。",
            L"Channel: sse. The current implementation sends events to the URL as HTTP POST JSON.");
    }
    BOOL connected = FALSE;
    LONG reconnect_attempts = 0;
    wchar_t last_error[512];
    GetRuntimeStatus(&connected, last_error, _countof(last_error), &reconnect_attempts);
    wchar_t runtime_status[1024];
    StringCchCopyW(runtime_status, _countof(runtime_status), status);
    StringCchCatW(runtime_status, _countof(runtime_status), L"\r\n");
    StringCchCatW(runtime_status, _countof(runtime_status),
        connected
            ? McpText(L"连接状态：已连接", L"Connection: connected")
            : McpText(L"连接状态：未连接", L"Connection: disconnected"));
    if (reconnect_attempts > 0) {
        wchar_t retry_text[128];
        StringCchPrintfW(retry_text, _countof(retry_text),
            McpIsEnglish() ? L" | retries: %ld" : L" | 重试：%ld",
            reconnect_attempts);
        StringCchCatW(runtime_status, _countof(runtime_status), retry_text);
    }
    if (last_error[0]) {
        StringCchCatW(runtime_status, _countof(runtime_status),
            McpText(L"\r\n最近错误：", L"\r\nLast error:"));
        StringCchCatW(runtime_status, _countof(runtime_status), last_error);
    }
    SetDlgItemTextW(hwnd, IDC_STATUS, runtime_status);
}

static void FillAdvancedDialog(HWND hwnd, const McpConfig& cfg)
{
    HWND combo = GetDlgItem(hwnd, IDC_HTTP_METHOD);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"POST");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"GET");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"PUT");
    int method_sel = lstrcmpiW(cfg.http_method, L"GET") == 0 ? 1 :
        (lstrcmpiW(cfg.http_method, L"PUT") == 0 ? 2 : 0);
    SendMessageW(combo, CB_SETCURSEL, method_sel, 0);
    SetDlgItemTextW(hwnd, IDC_HTTP_USER_AGENT, cfg.http_user_agent);
    SetDlgItemTextW(hwnd, IDC_HTTP_PROXY, cfg.http_proxy);
    CheckDlgButton(hwnd, IDC_HTTP_VERIFY_TLS, cfg.http_verify_tls ? BST_CHECKED : BST_UNCHECKED);

    wchar_t number[32];
    StringCchPrintfW(number, _countof(number), L"%d", cfg.sse_retry_interval_ms);
    SetDlgItemTextW(hwnd, IDC_SSE_RETRY, number);
    StringCchPrintfW(number, _countof(number), L"%d", cfg.sse_heartbeat_timeout_ms);
    SetDlgItemTextW(hwnd, IDC_SSE_HEARTBEAT, number);

    CheckDlgButton(hwnd, IDC_STDIO_SHELL, cfg.stdio_shell ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_STDIO_CONSOLE, cfg.stdio_show_console ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_STDIO_INHERIT_ENV, cfg.stdio_inherit_env ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_STDIO_RESTART, cfg.stdio_restart_on_exit ? BST_CHECKED : BST_UNCHECKED);
    combo = GetDlgItem(hwnd, IDC_STDIO_ENCODING);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"utf-8");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"ansi");
    SendMessageW(combo, CB_SETCURSEL, lstrcmpiW(cfg.stdio_encoding, L"ansi") == 0 ? 1 : 0, 0);
    combo = GetDlgItem(hwnd, IDC_STDIO_STDERR);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"inherit");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"discard");
    SendMessageW(combo, CB_SETCURSEL, lstrcmpiW(cfg.stdio_stderr_mode, L"discard") == 0 ? 1 : 0, 0);
    StringCchPrintfW(number, _countof(number), L"%d", cfg.stdio_max_output);
    SetDlgItemTextW(hwnd, IDC_STDIO_MAX_OUTPUT, number);

    StringCchPrintfW(number, _countof(number), L"%d", cfg.pipe_handshake_timeout_ms);
    SetDlgItemTextW(hwnd, IDC_PIPE_HANDSHAKE, number);
    StringCchPrintfW(number, _countof(number), L"%d", cfg.pipe_read_timeout_ms);
    SetDlgItemTextW(hwnd, IDC_PIPE_READ_TIMEOUT, number);
    StringCchPrintfW(number, _countof(number), L"%d", cfg.pipe_write_timeout_ms);
    SetDlgItemTextW(hwnd, IDC_PIPE_WRITE_TIMEOUT, number);
    CheckDlgButton(hwnd, IDC_PIPE_ALLOW_PLAIN, cfg.pipe_allow_unencrypted ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_PIPE_RETAIN_QUEUE, cfg.pipe_retain_queue ? BST_CHECKED : BST_UNCHECKED);

    CheckDlgButton(hwnd, IDC_ALLOW_DELETE_BP, cfg.allow_delete_breakpoint ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_ALLOW_REGISTERS, cfg.allow_registers ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_ALLOW_HIGH_RISK, cfg.allow_high_risk ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_CONFIRM_RISK, cfg.confirm_high_risk ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_EVENT_EXCEPTION, cfg.event_exception ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_EVENT_THREAD, cfg.event_thread ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_EVENT_MODULE, cfg.event_module ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_EVENT_PROCESS, cfg.event_process ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_EVENT_OUTPUT, cfg.event_output ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_EVENT_IGNORE_DUP, cfg.event_ignore_duplicates ? BST_CHECKED : BST_UNCHECKED);
    StringCchPrintfW(number, _countof(number), L"%d", cfg.event_queue_max);
    SetDlgItemTextW(hwnd, IDC_EVENT_QUEUE_MAX, number);
    combo = GetDlgItem(hwnd, IDC_LOG_LEVEL);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"error");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"warning");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"info");
    SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)L"debug");
    SendMessageW(combo, CB_SETCURSEL, cfg.log_level >= 0 && cfg.log_level <= 3 ? cfg.log_level : 1, 0);
    CheckDlgButton(hwnd, IDC_LOG_FILE, cfg.log_to_file ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_LOG_RAW_JSON, cfg.log_raw_json ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_LOG_TRANSPORT, cfg.log_transport_data ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_LOG_REDACT, cfg.log_redact_secrets ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_HTTP_SERVER_ENABLE, cfg.http_server_enable ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(hwnd, IDC_HTTP_SERVER_BIND, cfg.http_server_bind);
    StringCchPrintfW(number, _countof(number), L"%d", cfg.http_server_port);
    SetDlgItemTextW(hwnd, IDC_HTTP_SERVER_PORT, number);
}

static bool ReadAdvancedDialog(HWND hwnd, McpConfig* out)
{
    if (!out)
        return false;
    McpConfig cfg = CopyConfig();
    HWND combo = GetDlgItem(hwnd, IDC_HTTP_METHOD);
    int method_sel = (int)SendMessageW(combo, CB_GETCURSEL, 0, 0);
    StringCchCopyW(cfg.http_method, _countof(cfg.http_method),
        method_sel == 1 ? L"GET" : (method_sel == 2 ? L"PUT" : L"POST"));
    GetDlgItemTextW(hwnd, IDC_HTTP_USER_AGENT, cfg.http_user_agent, _countof(cfg.http_user_agent));
    GetDlgItemTextW(hwnd, IDC_HTTP_PROXY, cfg.http_proxy, _countof(cfg.http_proxy));
    cfg.http_verify_tls = IsDlgButtonChecked(hwnd, IDC_HTTP_VERIFY_TLS) == BST_CHECKED;
    wchar_t number[32];
    GetDlgItemTextW(hwnd, IDC_SSE_RETRY, number, _countof(number));
    cfg.sse_retry_interval_ms = _wtoi(number);
    GetDlgItemTextW(hwnd, IDC_SSE_HEARTBEAT, number, _countof(number));
    cfg.sse_heartbeat_timeout_ms = _wtoi(number);
    cfg.stdio_shell = IsDlgButtonChecked(hwnd, IDC_STDIO_SHELL) == BST_CHECKED;
    cfg.stdio_show_console = IsDlgButtonChecked(hwnd, IDC_STDIO_CONSOLE) == BST_CHECKED;
    cfg.stdio_inherit_env = IsDlgButtonChecked(hwnd, IDC_STDIO_INHERIT_ENV) == BST_CHECKED;
    cfg.stdio_restart_on_exit = IsDlgButtonChecked(hwnd, IDC_STDIO_RESTART) == BST_CHECKED;
    combo = GetDlgItem(hwnd, IDC_STDIO_ENCODING);
    StringCchCopyW(cfg.stdio_encoding, _countof(cfg.stdio_encoding),
        SendMessageW(combo, CB_GETCURSEL, 0, 0) == 1 ? L"ansi" : L"utf-8");
    combo = GetDlgItem(hwnd, IDC_STDIO_STDERR);
    StringCchCopyW(cfg.stdio_stderr_mode, _countof(cfg.stdio_stderr_mode),
        SendMessageW(combo, CB_GETCURSEL, 0, 0) == 1 ? L"discard" : L"inherit");
    GetDlgItemTextW(hwnd, IDC_STDIO_MAX_OUTPUT, number, _countof(number));
    cfg.stdio_max_output = _wtoi(number);
    GetDlgItemTextW(hwnd, IDC_PIPE_HANDSHAKE, number, _countof(number));
    cfg.pipe_handshake_timeout_ms = _wtoi(number);
    GetDlgItemTextW(hwnd, IDC_PIPE_READ_TIMEOUT, number, _countof(number));
    cfg.pipe_read_timeout_ms = _wtoi(number);
    GetDlgItemTextW(hwnd, IDC_PIPE_WRITE_TIMEOUT, number, _countof(number));
    cfg.pipe_write_timeout_ms = _wtoi(number);
    cfg.pipe_allow_unencrypted = IsDlgButtonChecked(hwnd, IDC_PIPE_ALLOW_PLAIN) == BST_CHECKED;
    cfg.pipe_retain_queue = IsDlgButtonChecked(hwnd, IDC_PIPE_RETAIN_QUEUE) == BST_CHECKED;
    cfg.allow_delete_breakpoint = IsDlgButtonChecked(hwnd, IDC_ALLOW_DELETE_BP) == BST_CHECKED;
    cfg.allow_registers = IsDlgButtonChecked(hwnd, IDC_ALLOW_REGISTERS) == BST_CHECKED;
    cfg.allow_high_risk = IsDlgButtonChecked(hwnd, IDC_ALLOW_HIGH_RISK) == BST_CHECKED;
    cfg.confirm_high_risk = IsDlgButtonChecked(hwnd, IDC_CONFIRM_RISK) == BST_CHECKED;
    cfg.event_exception = IsDlgButtonChecked(hwnd, IDC_EVENT_EXCEPTION) == BST_CHECKED;
    cfg.event_thread = IsDlgButtonChecked(hwnd, IDC_EVENT_THREAD) == BST_CHECKED;
    cfg.event_module = IsDlgButtonChecked(hwnd, IDC_EVENT_MODULE) == BST_CHECKED;
    cfg.event_process = IsDlgButtonChecked(hwnd, IDC_EVENT_PROCESS) == BST_CHECKED;
    cfg.event_output = IsDlgButtonChecked(hwnd, IDC_EVENT_OUTPUT) == BST_CHECKED;
    cfg.event_ignore_duplicates = IsDlgButtonChecked(hwnd, IDC_EVENT_IGNORE_DUP) == BST_CHECKED;
    GetDlgItemTextW(hwnd, IDC_EVENT_QUEUE_MAX, number, _countof(number));
    cfg.event_queue_max = _wtoi(number);
    combo = GetDlgItem(hwnd, IDC_LOG_LEVEL);
    cfg.log_level = (int)SendMessageW(combo, CB_GETCURSEL, 0, 0);
    if (cfg.log_level < 0)
        cfg.log_level = 1;
    cfg.log_to_file = IsDlgButtonChecked(hwnd, IDC_LOG_FILE) == BST_CHECKED;
    cfg.log_raw_json = IsDlgButtonChecked(hwnd, IDC_LOG_RAW_JSON) == BST_CHECKED;
    cfg.log_transport_data = IsDlgButtonChecked(hwnd, IDC_LOG_TRANSPORT) == BST_CHECKED;
    cfg.log_redact_secrets = IsDlgButtonChecked(hwnd, IDC_LOG_REDACT) == BST_CHECKED;
    cfg.http_server_enable = IsDlgButtonChecked(hwnd, IDC_HTTP_SERVER_ENABLE) == BST_CHECKED;
    GetDlgItemTextW(hwnd, IDC_HTTP_SERVER_BIND, cfg.http_server_bind, _countof(cfg.http_server_bind));
    GetDlgItemTextW(hwnd, IDC_HTTP_SERVER_PORT, number, _countof(number));
    cfg.http_server_port = _wtoi(number);

    if (cfg.sse_retry_interval_ms < 100 || cfg.sse_heartbeat_timeout_ms < 100 ||
        cfg.pipe_handshake_timeout_ms < 100 || cfg.pipe_read_timeout_ms < 100 ||
        cfg.pipe_write_timeout_ms < 100 || cfg.stdio_max_output < 4096) {
        MessageBoxW(hwnd,
            McpText(L"高级超时必须不小于 100 毫秒，stdio 输出缓存必须不小于 4096 字节。",
                    L"Advanced timeouts must be at least 100 ms and the stdio output buffer at least 4096 bytes."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        return false;
    }
    if (cfg.event_queue_max < 16 || cfg.event_queue_max > 4096) {
        MessageBoxW(hwnd,
            McpText(L"事件队列最大长度必须在 16 到 4096 之间。",
                    L"Event queue limit must be between 16 and 4096."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        return false;
    }
    if (!cfg.http_server_bind[0])
        StringCchCopyW(cfg.http_server_bind, _countof(cfg.http_server_bind), L"127.0.0.1");
    if (cfg.http_server_port <= 0 || cfg.http_server_port > 65535) {
        MessageBoxW(hwnd,
            McpText(L"HTTP Server 端口必须在 1 到 65535 之间。",
                    L"HTTP Server port must be between 1 and 65535."),
            PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        return false;
    }
    *out = cfg;
    return true;
}

static LRESULT CALLBACK AdvancedSettingsWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_CREATE: {
        NONCLIENTMETRICSW ncm;
        ZeroMemory(&ncm, sizeof(ncm));
        ncm.cbSize = sizeof(ncm);
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        HFONT font = CreateFontIndirectW(&ncm.lfMessageFont);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)font);

        AddLabel(hwnd, 14, 14, 150, 22, McpText(L"HTTP / SSE", L"HTTP / SSE"));
        AddLabel(hwnd, 14, 48, 110, 22, McpText(L"HTTP 方法", L"HTTP method"));
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            130, 46, 100, 100, hwnd, (HMENU)(INT_PTR)IDC_HTTP_METHOD, g_instance, NULL);
        AddLabel(hwnd, 250, 48, 100, 22, McpText(L"User-Agent", L"User-Agent"));
        AddEdit(hwnd, IDC_HTTP_USER_AGENT, 355, 46, 355, 24, 0);
        AddLabel(hwnd, 14, 82, 110, 22, McpText(L"代理", L"Proxy"));
        AddEdit(hwnd, IDC_HTTP_PROXY, 130, 80, 580, 24, 0);
        AddButton(hwnd, IDC_HTTP_VERIFY_TLS, 14, 114, 230, 22,
            McpText(L"验证 HTTPS 证书", L"Verify HTTPS certificate"), BS_AUTOCHECKBOX);
        AddLabel(hwnd, 260, 116, 160, 22, McpText(L"SSE 重连间隔(ms)", L"SSE retry(ms)"));
        AddEdit(hwnd, IDC_SSE_RETRY, 425, 114, 100, 24, ES_NUMBER);
        AddLabel(hwnd, 535, 116, 120, 22, McpText(L"心跳超时(ms)", L"Heartbeat(ms)"));
        AddEdit(hwnd, IDC_SSE_HEARTBEAT, 655, 114, 55, 24, ES_NUMBER);

        AddLabel(hwnd, 14, 160, 150, 22, McpText(L"stdio", L"stdio"));
        AddButton(hwnd, IDC_STDIO_SHELL, 14, 194, 150, 22,
            McpText(L"通过 Shell 启动", L"Launch through shell"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_STDIO_CONSOLE, 175, 194, 150, 22,
            McpText(L"显示控制台", L"Show console"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_STDIO_INHERIT_ENV, 336, 194, 150, 22,
            McpText(L"继承环境变量", L"Inherit environment"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_STDIO_RESTART, 497, 194, 150, 22,
            McpText(L"退出后自动重启", L"Restart on exit"), BS_AUTOCHECKBOX);
        AddLabel(hwnd, 14, 228, 110, 22, McpText(L"编码", L"Encoding"));
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            130, 226, 100, 100, hwnd, (HMENU)(INT_PTR)IDC_STDIO_ENCODING, g_instance, NULL);
        AddLabel(hwnd, 250, 228, 110, 22, McpText(L"stderr", L"stderr"));
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            365, 226, 100, 100, hwnd, (HMENU)(INT_PTR)IDC_STDIO_STDERR, g_instance, NULL);
        AddLabel(hwnd, 485, 228, 130, 22, McpText(L"最大输出缓存", L"Max output buffer"));
        AddEdit(hwnd, IDC_STDIO_MAX_OUTPUT, 620, 226, 90, 24, ES_NUMBER);

        AddLabel(hwnd, 14, 272, 150, 22, McpText(L"Windows pipe", L"Windows pipe"));
        AddLabel(hwnd, 14, 306, 145, 22, McpText(L"握手超时(ms)", L"Handshake(ms)"));
        AddEdit(hwnd, IDC_PIPE_HANDSHAKE, 165, 304, 100, 24, ES_NUMBER);
        AddLabel(hwnd, 285, 306, 120, 22, McpText(L"读取超时(ms)", L"Read timeout(ms)"));
        AddEdit(hwnd, IDC_PIPE_READ_TIMEOUT, 410, 304, 100, 24, ES_NUMBER);
        AddLabel(hwnd, 530, 306, 120, 22, McpText(L"写入超时(ms)", L"Write timeout(ms)"));
        AddEdit(hwnd, IDC_PIPE_WRITE_TIMEOUT, 655, 304, 55, 24, ES_NUMBER);
        AddButton(hwnd, IDC_PIPE_ALLOW_PLAIN, 14, 340, 220, 22,
            McpText(L"允许未加密连接", L"Allow unencrypted"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_PIPE_RETAIN_QUEUE, 245, 340, 220, 22,
            McpText(L"断线保留发送队列", L"Retain queue on disconnect"), BS_AUTOCHECKBOX);

        AddLabel(hwnd, 14, 374, 150, 22, McpText(L"内置 HTTP Server", L"Built-in HTTP Server"));
        AddButton(hwnd, IDC_HTTP_SERVER_ENABLE, 14, 408, 150, 22,
            McpText(L"启用 HTTP 监听", L"Enable HTTP listener"), BS_AUTOCHECKBOX);
        AddLabel(hwnd, 175, 410, 80, 22, McpText(L"绑定地址", L"Bind"));
        AddEdit(hwnd, IDC_HTTP_SERVER_BIND, 260, 408, 150, 24, 0);
        AddLabel(hwnd, 425, 410, 50, 22, McpText(L"端口", L"Port"));
        AddEdit(hwnd, IDC_HTTP_SERVER_PORT, 480, 408, 80, 24, ES_NUMBER);

        AddLabel(hwnd, 735, 14, 150, 22, McpText(L"调试器权限", L"Debugger permissions"));
        AddButton(hwnd, IDC_ALLOW_DELETE_BP, 735, 48, 190, 22,
            McpText(L"允许删除断点", L"Allow deleting breakpoints"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_ALLOW_REGISTERS, 735, 80, 190, 22,
            McpText(L"允许修改寄存器/CPU", L"Allow register/CPU edits"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_ALLOW_HIGH_RISK, 735, 112, 190, 22,
            McpText(L"允许高风险操作", L"Allow high-risk operations"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_CONFIRM_RISK, 735, 144, 190, 22,
            McpText(L"高风险操作前确认", L"Confirm high-risk operations"), BS_AUTOCHECKBOX);

        AddLabel(hwnd, 735, 186, 150, 22, McpText(L"事件过滤", L"Event filters"));
        AddButton(hwnd, IDC_EVENT_EXCEPTION, 735, 220, 120, 22,
            McpText(L"异常事件", L"Exceptions"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_EVENT_THREAD, 865, 220, 120, 22,
            McpText(L"线程事件", L"Threads"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_EVENT_MODULE, 735, 252, 120, 22,
            McpText(L"模块事件", L"Modules"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_EVENT_PROCESS, 865, 252, 120, 22,
            McpText(L"进程事件", L"Processes"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_EVENT_OUTPUT, 735, 284, 120, 22,
            McpText(L"调试输出", L"Debug output"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_EVENT_IGNORE_DUP, 865, 284, 120, 22,
            McpText(L"忽略重复事件", L"Ignore duplicates"), BS_AUTOCHECKBOX);
        AddLabel(hwnd, 735, 318, 130, 22, McpText(L"事件队列最大长度", L"Event queue limit"));
        AddEdit(hwnd, IDC_EVENT_QUEUE_MAX, 875, 316, 90, 24, ES_NUMBER);

        AddLabel(hwnd, 735, 360, 150, 22, McpText(L"日志和诊断", L"Logs and diagnostics"));
        AddLabel(hwnd, 735, 394, 90, 22, McpText(L"日志级别", L"Log level"));
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            830, 392, 120, 120, hwnd, (HMENU)(INT_PTR)IDC_LOG_LEVEL, g_instance, NULL);
        AddButton(hwnd, IDC_LOG_FILE, 735, 426, 120, 22,
            McpText(L"写入日志文件", L"Write log file"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_LOG_RAW_JSON, 865, 426, 120, 22,
            McpText(L"保存原始 JSON", L"Save raw JSON"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_LOG_TRANSPORT, 735, 458, 120, 22,
            McpText(L"记录收发数据", L"Log transport data"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_LOG_REDACT, 865, 458, 120, 22,
            McpText(L"隐藏密钥/Token", L"Redact secrets"), BS_AUTOCHECKBOX);

        AddLabel(hwnd, 14, 452, 690, 60,
            McpText(L"说明：当前 SSE 仍使用 HTTP POST 发送；pipe 服务端监听、长度前缀和真正的 SSE 长连接将在后续协议实现中启用。",
                    L"Note: SSE currently uses HTTP POST; pipe server listening, length framing and true SSE streaming will be enabled with the protocol implementation."));
        AddButton(hwnd, IDC_ADVANCED_SAVE, 805, 540, 95, 28,
            McpText(L"应用", L"Apply"), BS_DEFPUSHBUTTON);
        AddButton(hwnd, IDC_ADVANCED_CANCEL, 910, 540, 95, 28,
            McpText(L"取消", L"Cancel"), BS_PUSHBUTTON);
        SetChildFont(hwnd, font);
        FillAdvancedDialog(hwnd, CopyConfig());
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wparam) == IDC_ADVANCED_SAVE) {
            McpConfig cfg;
            if (ReadAdvancedDialog(hwnd, &cfg)) {
                EnterCriticalSection(&g_config_cs);
                g_config = cfg;
                LeaveCriticalSection(&g_config_cs);
                SaveConfig();
                if (cfg.reconnect_on_save) {
                    CloseStdioProcess();
                    ClosePipeConnection();
                    StopHttpServer();
                    StartHttpServerIfConfigured(CopyConfig());
                }
                DestroyWindow(hwnd);
            }
            return 0;
        }
        if (LOWORD(wparam) == IDC_ADVANCED_CANCEL) {
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

static void ShowAdvancedDialog(HWND owner)
{
    const wchar_t* cls = L"Z0B_McpTools_Advanced";
    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = AdvancedSettingsWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = cls;
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, cls,
        McpText(L"MCP Tools 高级设置", L"MCP Tools Advanced Settings"),
        WS_CAPTION | WS_SYSMENU | WS_POPUP,
        CW_USEDEFAULT, CW_USEDEFAULT, 1040, 620,
        owner, NULL, g_instance, NULL);
    if (!hwnd)
        return;
    ExpandSettingsDialog(hwnd, owner);
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
        AddEdit(hwnd, IDC_NAME, 115, 46, 350, 24, 0);
        AddLabel(hwnd, 14, 82, 90, 22, McpText(L"传输类型", L"Transport"));
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            115, 80, 180, 140, hwnd, (HMENU)(INT_PTR)IDC_TRANSPORT, g_instance, NULL);
        AddLabelWithId(hwnd, IDC_URL_LABEL, 14, 116, 90, 22, L"URL");
        AddEdit(hwnd, IDC_URL, 115, 114, 350, 24, 0);
        AddLabelWithId(hwnd, IDC_COMMAND_LABEL, 14, 150, 90, 22, McpText(L"启动命令", L"Start command"));
        AddEdit(hwnd, IDC_COMMAND, 115, 148, 260, 24, 0);
        AddButton(hwnd, IDC_BROWSE_CMD, 385, 147, 80, 26, McpText(L"浏览...", L"Browse..."), BS_PUSHBUTTON);
        AddLabelWithId(hwnd, IDC_ARGUMENTS_LABEL, 14, 184, 90, 22, McpText(L"启动参数", L"Arguments"));
        AddEdit(hwnd, IDC_ARGUMENTS, 115, 182, 350, 24, 0);
        AddLabelWithId(hwnd, IDC_WORKDIR_LABEL, 14, 218, 90, 22, McpText(L"工作目录", L"Working dir"));
        AddEdit(hwnd, IDC_WORKDIR, 115, 216, 260, 24, 0);
        AddButton(hwnd, IDC_BROWSE_DIR, 385, 215, 80, 26, McpText(L"浏览...", L"Browse..."), BS_PUSHBUTTON);
        AddLabelWithId(hwnd, IDC_ENV_LABEL, 14, 252, 90, 22, McpText(L"环境变量", L"Environment"));
        AddEdit(hwnd, IDC_ENV, 115, 250, 350, 58, ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL);
        AddLabelWithId(hwnd, IDC_PIPE_NAME_LABEL, 14, 322, 90, 22, McpText(L"管道名", L"Pipe name"));
        AddEdit(hwnd, IDC_PIPE_NAME, 115, 320, 350, 24, 0);
        AddLabelWithId(hwnd, IDC_PIPE_PROTOCOL_LABEL, 14, 356, 90, 22, McpText(L"管道协议", L"Pipe protocol"));
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            115, 354, 135, 140, hwnd, (HMENU)(INT_PTR)IDC_PIPE_PROTOCOL, g_instance, NULL);
        AddLabelWithId(hwnd, IDC_SHARED_KEY_LABEL, 265, 356, 80, 22, McpText(L"共享密钥", L"Shared key"));
        AddEdit(hwnd, IDC_SHARED_KEY, 345, 354, 120, 24, ES_PASSWORD);
        AddLabel(hwnd, 14, 390, 90, 22, McpText(L"超时(ms)", L"Timeout(ms)"));
        AddEdit(hwnd, IDC_TIMEOUT, 115, 388, 90, 24, ES_NUMBER);
        AddLabel(hwnd, 220, 388, 245, 34,
            McpText(L"环境变量每行一个 NAME=VALUE；超时范围：100-600000。",
                    L"One NAME=VALUE per environment line; timeout range: 100-600000."));
        AddButton(hwnd, IDC_AUTO_CONNECT, 14, 424, 150, 22,
            McpText(L"启动时自动连接", L"Connect on startup"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_AUTO_RECONNECT, 175, 424, 150, 22,
            McpText(L"断线自动重连", L"Reconnect on failure"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_MCP_INITIALIZE, 336, 424, 150, 22,
            McpText(L"发送 MCP 初始化", L"Send MCP initialize"), BS_AUTOCHECKBOX);
        AddLabelWithId(hwnd, IDC_ROLE_LABEL, 14, 458, 90, 22,
            McpText(L"连接角色", L"Connection role"));
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            115, 456, 110, 100, hwnd, (HMENU)(INT_PTR)IDC_ROLE, g_instance, NULL);
        AddLabelWithId(hwnd, IDC_RECONNECT_INTERVAL_LABEL, 240, 458, 105, 22,
            McpText(L"重连间隔(ms)", L"Retry interval(ms)"));
        AddEdit(hwnd, IDC_RECONNECT_INTERVAL, 350, 456, 70, 24, ES_NUMBER);
        AddLabelWithId(hwnd, IDC_RECONNECT_MAX_LABEL, 14, 492, 90, 22,
            McpText(L"最大重试", L"Max retries"));
        AddEdit(hwnd, IDC_RECONNECT_MAX, 115, 490, 90, 24, ES_NUMBER);

        AddLabelWithId(hwnd, IDC_CLIENT_NAME_LABEL, 500, 14, 90, 22,
            McpText(L"客户端名称", L"Client name"));
        AddEdit(hwnd, IDC_CLIENT_NAME, 600, 12, 200, 24, 0);
        AddLabelWithId(hwnd, IDC_CLIENT_VERSION_LABEL, 815, 14, 50, 22,
            McpText(L"版本", L"Version"));
        AddEdit(hwnd, IDC_CLIENT_VERSION, 865, 12, 85, 24, 0);
        AddLabel(hwnd, 500, 48, 90, 22, McpText(L"协议版本", L"Protocol"));
        AddEdit(hwnd, IDC_PROTOCOL_VERSION, 600, 46, 130, 24, 0);
        AddLabel(hwnd, 745, 48, 105, 22, McpText(L"请求超时(ms)", L"Request timeout"));
        AddEdit(hwnd, IDC_REQUEST_TIMEOUT, 855, 46, 95, 24, ES_NUMBER);
        AddButton(hwnd, IDC_CONNECT_DEBUG_OPEN, 500, 82, 150, 22,
            McpText(L"目标打开后连接", L"Connect on debug open"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_RECONNECT_ON_SAVE, 660, 82, 150, 22,
            McpText(L"保存后立即重连", L"Reconnect after save"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_SEND_DEBUG_EVENTS, 820, 82, 130, 22,
            McpText(L"发送调试事件", L"Send debug events"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_RECEIVE_COMMANDS, 500, 114, 150, 22,
            McpText(L"接收 Server 指令", L"Receive commands"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_AUTO_REPLY, 660, 114, 150, 22,
            McpText(L"自动回复请求", L"Auto reply"), BS_AUTOCHECKBOX);
        AddLabel(hwnd, 500, 148, 90, 22, McpText(L"测试工具", L"Test tool"));
        AddEdit(hwnd, IDC_TEST_TOOL_NAME, 600, 146, 160, 24, 0);
        AddLabel(hwnd, 775, 148, 80, 22, McpText(L"参数JSON", L"Args JSON"));
        AddEdit(hwnd, IDC_TEST_TOOL_ARGS, 855, 146, 95, 24, 0);
        AddLabelWithId(hwnd, IDC_HTTP_HEADERS_LABEL, 500, 182, 90, 22,
            McpText(L"HTTP 请求头", L"HTTP headers"));
        AddEdit(hwnd, IDC_HTTP_HEADERS, 600, 180, 350, 58,
            ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL);
        AddLabelWithId(hwnd, IDC_AUTH_TOKEN_LABEL, 500, 252, 90, 22,
            McpText(L"认证 Token", L"Auth token"));
        AddEdit(hwnd, IDC_AUTH_TOKEN, 600, 250, 350, 24, ES_PASSWORD);
        AddLabelWithId(hwnd, IDC_PERMISSION_LABEL, 500, 286, 90, 22,
            McpText(L"调试器权限", L"Debugger permissions"));
        AddButton(hwnd, IDC_ALLOW_READ, 600, 284, 70, 22,
            McpText(L"读取", L"Read"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_ALLOW_WRITE, 675, 284, 70, 22,
            McpText(L"写入", L"Write"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_ALLOW_EXECUTE, 750, 284, 80, 22,
            McpText(L"运行控制", L"Execute"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_ALLOW_BREAKPOINT, 835, 284, 60, 22,
            McpText(L"断点", L"Breakpoints"), BS_AUTOCHECKBOX);
        AddButton(hwnd, IDC_ALLOW_PATCH, 900, 284, 60, 22,
            McpText(L"补丁", L"Patching"), BS_AUTOCHECKBOX);
        AddLabel(hwnd, 500, 320, 90, 22, McpText(L"状态", L"Status"));
        CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE,
            600, 320, 350, 116, hwnd, (HMENU)(INT_PTR)IDC_STATUS, g_instance, NULL);
        AddButton(hwnd, IDC_TEST, 500, 454, 88, 28,
            McpText(L"测试事件", L"Test event"), BS_PUSHBUTTON);
        AddButton(hwnd, IDC_TEST_CONNECT, 596, 454, 88, 28,
            McpText(L"测试连接", L"Test connection"), BS_PUSHBUTTON);
        AddButton(hwnd, IDC_TEST_INITIALIZE, 692, 454, 88, 28,
            McpText(L"测试初始化", L"Test initialize"), BS_PUSHBUTTON);
        AddButton(hwnd, IDC_TEST_TOOLS, 788, 454, 88, 28,
            McpText(L"获取工具列表", L"List tools"), BS_PUSHBUTTON);
        AddButton(hwnd, IDC_TEST_TOOL, 884, 454, 66, 28,
            McpText(L"调用工具", L"Call tool"), BS_PUSHBUTTON);
        AddButton(hwnd, IDC_DEFAULTS, 500, 494, 88, 28,
            McpText(L"恢复默认值", L"Defaults"), BS_PUSHBUTTON);
        AddButton(hwnd, IDC_ADVANCED, 596, 494, 88, 28,
            McpText(L"高级设置", L"Advanced"), BS_PUSHBUTTON);
        AddButton(hwnd, IDC_SERVER_INFO, 692, 494, 88, 28,
            McpText(L"Server 信息", L"Server info"), BS_PUSHBUTTON);
        AddButton(hwnd, IDC_SAVE, 788, 494, 78, 28,
            McpText(L"保存", L"Save"), BS_DEFPUSHBUTTON);
        AddButton(hwnd, IDC_CANCEL, 872, 494, 78, 28,
            McpText(L"取消", L"Cancel"), BS_PUSHBUTTON);

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
        case IDC_TRANSPORT:
            if (HIWORD(wparam) == CBN_SELCHANGE)
                SetTransportUiState(hwnd);
            return 0;
        case IDC_TEST: {
            McpConfig cfg;
            if (!ReadDialogConfig(hwnd, &cfg))
                return 0;
            if (SendTestWithConfig(cfg)) {
                const wchar_t* transport = lstrcmpiW(cfg.transport, L"stdio") == 0
                    ? L"stdio" : (lstrcmpiW(cfg.transport, L"pipe") == 0
                    ? L"pipe" : cfg.transport);
                wchar_t message[256];
                StringCchPrintfW(message, _countof(message),
                    McpIsEnglish() ? L"Test event sent through %s." : L"测试事件已通过 %s 通道发送。",
                    transport);
                SetDlgItemTextW(hwnd, IDC_STATUS,
                    message);
            }
            else {
                SetDlgItemTextW(hwnd, IDC_STATUS,
                    McpText(L"测试发送失败，请检查命令、工作目录、URL 和超时设置。",
                            L"Test failed. Check the command, working directory, URL, and timeout."));
                MessageBoxW(hwnd,
                    McpText(L"测试事件发送失败。", L"Test event could not be sent."),
                    PLUGIN_NAME, MB_OK | MB_ICONWARNING);
            }
            return 0;
        }
        case IDC_TEST_CONNECT:
        case IDC_TEST_INITIALIZE:
        case IDC_TEST_TOOLS:
        case IDC_TEST_TOOL:
        case IDC_SERVER_INFO: {
            McpConfig cfg;
            if (!ReadDialogConfig(hwnd, &cfg))
                return 0;
            bool ok = false;
            std::string response;
            const wchar_t* action = L"";
            if (LOWORD(wparam) == IDC_TEST_CONNECT) {
                ok = TestConnectionWithConfig(cfg, &response);
                action = McpText(L"连接测试", L"Connection test");
            }
            else if (LOWORD(wparam) == IDC_TEST_INITIALIZE) {
                ok = TestInitializeWithConfig(cfg, &response);
                action = McpText(L"初始化测试", L"Initialize test");
            }
            else if (LOWORD(wparam) == IDC_TEST_TOOL) {
                ok = TestToolWithConfig(cfg, &response);
                action = McpText(L"工具调用", L"Tool call");
            }
            else if (LOWORD(wparam) == IDC_SERVER_INFO) {
                ok = TestInitializeWithConfig(cfg, &response);
                SetServerInfoStatus(hwnd, ok, response);
                if (!ok)
                    MessageBoxW(hwnd, McpText(L"Server 信息请求失败或超时。",
                                               L"Server info request failed or timed out."),
                        PLUGIN_NAME, MB_OK | MB_ICONWARNING);
                return 0;
            }
            else {
                ok = TestToolsWithConfig(cfg, &response);
                action = McpText(L"工具列表请求", L"Tools list request");
            }
            SetResponseStatus(hwnd, action, ok, response);
            if (!ok)
                MessageBoxW(hwnd, McpText(L"请求失败或超时。", L"Request failed or timed out."),
                    PLUGIN_NAME, MB_OK | MB_ICONWARNING);
            return 0;
        }
        case IDC_DEFAULTS: {
            McpConfig defaults;
            SetDefaultConfig(&defaults);
            FillDialogFromConfig(hwnd, defaults);
            return 0;
        }
        case IDC_ADVANCED: {
            McpConfig cfg;
            if (!ReadDialogConfig(hwnd, &cfg))
                return 0;
            EnterCriticalSection(&g_config_cs);
            g_config = cfg;
            LeaveCriticalSection(&g_config_cs);
            ShowAdvancedDialog(hwnd);
            return 0;
        }
        case IDC_SAVE:
            if (!ReadDialog(hwnd))
                return 0;
            {
                McpConfig saved_cfg = CopyConfig();
                SaveConfig();
                if (saved_cfg.reconnect_on_save) {
                    CloseStdioProcess();
                    ClosePipeConnection();
                    StopHttpServer();
                    StartHttpServerIfConfigured(saved_cfg);
                }
            }
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
        CW_USEDEFAULT, CW_USEDEFAULT, 980, 600,
        owner, NULL, g_instance, NULL);
    if (!hwnd)
        return;

    ExpandSettingsDialog(hwnd, owner);

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
        ClosePipeConnection();
        StopHttpServer();
        StartHttpServerIfConfigured(CopyConfig());
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
            McpText(L"MCP Tools 插件\r\n\r\n用于保存和管理 MCP Server 配置，转发调试事件，并提供 MCP 调试控制、目标会话和事件等待接口。\r\n地址参数支持 64 位，x64 构建使用当前调试器的 x64 反汇编/汇编能力。",
                    L"MCP Tools plugin\r\n\r\nSaves and manages MCP Server configuration, forwards debug events, and exposes debugger controls, target sessions and event waiting.\r\nAddress parameters support 64-bit values. x64 builds use the debugger's x64 disassembly/assembly path."),
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

typedef void (__cdecl *AgentDirectResult)(const char*, size_t, void*);

extern "C" __declspec(dllexport) BOOL __cdecl Z0B_AgentDirectRequest(
    const char* request, AgentDirectResult deliver, void* context)
{
    if (!request || !deliver || !InterlockedCompareExchange(&g_runtime_ready, 0, 0))
        return FALSE;
    std::string response = ExecuteToolCommand(request, true);
    deliver(response.data(), response.size(), context);
    return TRUE;
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
    InitializeCriticalSection(&g_pipe_cs);
    InitializeCriticalSection(&g_status_cs);
    InitializeCriticalSection(&g_response_cs);
    ResolveHostExports();
    g_observed_process_id = g_host_process_id && *g_host_process_id ? (DWORD)*g_host_process_id : 0;
    g_debug_feed.update(CurrentDebugProcessId(), pGetcputhreadid ? (DWORD)pGetcputhreadid() : 0,
        pMcpDebugState ? pMcpDebugState() : pGetstatus ? pGetstatus() : -1);
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
    if (debugevent) g_observed_process_id = debugevent->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT ? 0 : debugevent->dwProcessId;
    DWORD pid = CurrentDebugProcessId();
    g_debug_feed.update(pid, pGetcputhreadid ? (DWORD)pGetcputhreadid() : 0,
        pMcpDebugState ? pMcpDebugState() : pGetstatus ? pGetstatus() : -1,
        debugevent && debugevent->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT);
    if (debugevent && debugevent->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        McpConfig cfg = CopyConfig();
        if (cfg.connect_on_debug_open)
            AutoConnectConfiguredServer(cfg);
    }
    QueueDebuggerEvent(debugevent);
}

extern "C" __declspec(dllexport) void __cdecl ODBG2_Pluginnotify(int code, void* data, ulong parm1, ulong parm2)
{
    if (code == PN_NEWPROC || code == PN_ENDPROC) {
        DWORD pid = code == PN_ENDPROC ? 0 : CurrentDebugProcessId();
        g_debug_feed.update(pid, pGetcputhreadid ? (DWORD)pGetcputhreadid() : 0,
            pMcpDebugState ? pMcpDebugState() : pGetstatus ? pGetstatus() : -1, true);
    }
    if (code == PN_ENDPROC) g_debug_feed.push("{\"notify\":\"process_exit\"}", false, false);
    QueueNotifyEvent(code, data, parm1, parm2);
}

extern "C" __declspec(dllexport) void __cdecl ODBG2_Plugindestroy(void)
{
    QueueSimpleEvent("plugin_destroy");
    StopWorker();
    DeleteCriticalSection(&g_stdio_cs);
    DeleteCriticalSection(&g_pipe_cs);
    DeleteCriticalSection(&g_status_cs);
    EnterCriticalSection(&g_response_cs);
    for (size_t i = 0; i < g_pending_responses.size(); ++i)
        SetEvent(g_pending_responses[i].event);
    g_pending_responses.clear();
    LeaveCriticalSection(&g_response_cs);
    DeleteCriticalSection(&g_response_cs);
    DeleteCriticalSection(&g_queue_cs);
    DeleteCriticalSection(&g_config_cs);
}
