#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <strsafe.h>
#include <ctype.h>
#include <map>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

#define APP_NAME L"MCP Server"
#define IDI_MCP_SERVER 1

#define IDC_NAME        1001
#define IDC_VERSION     1002
#define IDC_PROTOCOL    1003
#define IDC_BIND        1004
#define IDC_PORT        1005
#define IDC_TOKEN       1006
#define IDC_AUTOSTART   1007
#define IDC_STATUS      1008
#define IDC_SAVE        1009
#define IDC_START       1010
#define IDC_STOP        1011
#define IDC_REMOTE_URL       1012
#define IDC_REMOTE_TRANSPORT 1013
#define IDC_REMOTE_TOKEN     1014
#define IDC_REMOTE_HEADERS   1015
#define IDC_REMOTE_AUTOCONNECT 1016
#define IDC_REMOTE_RECONNECT 1017
#define IDC_REMOTE_RETRY     1018
#define IDC_REMOTE_MAX       1019
#define IDC_REMOTE_TIMEOUT   1020
#define IDC_REMOTE_STATUS    1021
#define IDC_REMOTE_TEST      1022
#define IDC_REMOTE_INIT      1023
#define IDC_REMOTE_TOOLS     1024
#define IDC_REMOTE_CLEAR     1025
#define IDC_REMOTE_VERIFY_TLS 1026

struct ServerConfig {
    wchar_t name[64];
    wchar_t version[32];
    wchar_t protocol_version[32];
    wchar_t bind[64];
    wchar_t auth_token[128];
    int port;
    BOOL auto_start;
    wchar_t remote_url[512];
    wchar_t remote_transport[32];
    wchar_t remote_token[128];
    wchar_t remote_headers[1024];
    BOOL remote_auto_connect;
    BOOL remote_auto_reconnect;
    int remote_retry_interval_ms;
    int remote_max_retries;
    int remote_timeout_ms;
    BOOL remote_verify_tls;
};

static HINSTANCE g_instance = NULL;
static HWND g_hwnd = NULL;
static HFONT g_font = NULL;
static CRITICAL_SECTION g_config_cs;
static ServerConfig g_config;
static HANDLE g_server_thread = NULL;
static SOCKET g_server_socket = INVALID_SOCKET;
static volatile LONG g_server_stop = 0;
static volatile LONG g_server_running = 0;
static CRITICAL_SECTION g_remote_cs;
static std::string g_remote_tools_result;
static volatile LONG g_remote_connected = 0;
static HANDLE g_remote_thread = NULL;
static volatile LONG g_remote_stop = 0;
static CRITICAL_SECTION g_sse_cs;
static HINTERNET g_sse_request = NULL;
static HANDLE g_sse_thread = NULL;
static std::wstring g_sse_endpoint;
static std::map<std::string, std::string> g_sse_responses;
static HANDLE g_sse_response_event = NULL;
static volatile LONG g_sse_ready = 0;

static void SetDefaultConfig(ServerConfig* cfg)
{
    ZeroMemory(cfg, sizeof(*cfg));
    StringCchCopyW(cfg->name, _countof(cfg->name), L"Z0BDbg MCP Server");
    StringCchCopyW(cfg->version, _countof(cfg->version), L"1.0");
    StringCchCopyW(cfg->protocol_version, _countof(cfg->protocol_version), L"2024-11-05");
    StringCchCopyW(cfg->bind, _countof(cfg->bind), L"127.0.0.1");
    cfg->port = 8765;
    cfg->auto_start = TRUE;
    StringCchCopyW(cfg->remote_url, _countof(cfg->remote_url), L"http://127.0.0.1:3000/mcp");
    StringCchCopyW(cfg->remote_transport, _countof(cfg->remote_transport), L"http");
    cfg->remote_auto_connect = FALSE;
    cfg->remote_auto_reconnect = TRUE;
    cfg->remote_retry_interval_ms = 3000;
    cfg->remote_max_retries = 0;
    cfg->remote_timeout_ms = 30000;
    cfg->remote_verify_tls = TRUE;
}

static void GetConfigPath(wchar_t* path, size_t cch)
{
    path[0] = L'\0';
    GetModuleFileNameW(NULL, path, (DWORD)cch);
    wchar_t* slash = wcsrchr(path, L'\\');
    if (slash)
        slash[1] = L'\0';
    StringCchCatW(path, cch, L"McpServer.ini");
}

static ServerConfig CopyConfig(void)
{
    ServerConfig cfg;
    EnterCriticalSection(&g_config_cs);
    cfg = g_config;
    LeaveCriticalSection(&g_config_cs);
    return cfg;
}

static void LoadConfig(void)
{
    wchar_t path[MAX_PATH];
    ServerConfig cfg;
    SetDefaultConfig(&cfg);
    GetConfigPath(path, _countof(path));
    GetPrivateProfileStringW(L"server", L"name", cfg.name, cfg.name, _countof(cfg.name), path);
    GetPrivateProfileStringW(L"server", L"version", cfg.version, cfg.version, _countof(cfg.version), path);
    GetPrivateProfileStringW(L"server", L"protocol_version", cfg.protocol_version, cfg.protocol_version, _countof(cfg.protocol_version), path);
    GetPrivateProfileStringW(L"http", L"bind", cfg.bind, cfg.bind, _countof(cfg.bind), path);
    GetPrivateProfileStringW(L"http", L"auth_token", cfg.auth_token, cfg.auth_token, _countof(cfg.auth_token), path);
    cfg.port = GetPrivateProfileIntW(L"http", L"port", cfg.port, path);
    cfg.auto_start = GetPrivateProfileIntW(L"http", L"auto_start", cfg.auto_start, path) ? TRUE : FALSE;
    GetPrivateProfileStringW(L"remote", L"url", cfg.remote_url, cfg.remote_url, _countof(cfg.remote_url), path);
    GetPrivateProfileStringW(L"remote", L"transport", cfg.remote_transport, cfg.remote_transport, _countof(cfg.remote_transport), path);
    GetPrivateProfileStringW(L"remote", L"token", cfg.remote_token, cfg.remote_token, _countof(cfg.remote_token), path);
    GetPrivateProfileStringW(L"remote", L"headers", cfg.remote_headers, cfg.remote_headers, _countof(cfg.remote_headers), path);
    cfg.remote_auto_connect = GetPrivateProfileIntW(L"remote", L"auto_connect", cfg.remote_auto_connect, path) ? TRUE : FALSE;
    cfg.remote_auto_reconnect = GetPrivateProfileIntW(L"remote", L"auto_reconnect", cfg.remote_auto_reconnect, path) ? TRUE : FALSE;
    cfg.remote_retry_interval_ms = GetPrivateProfileIntW(L"remote", L"retry_interval_ms", cfg.remote_retry_interval_ms, path);
    cfg.remote_max_retries = GetPrivateProfileIntW(L"remote", L"max_retries", cfg.remote_max_retries, path);
    cfg.remote_timeout_ms = GetPrivateProfileIntW(L"remote", L"timeout_ms", cfg.remote_timeout_ms, path);
    cfg.remote_verify_tls = GetPrivateProfileIntW(L"remote", L"verify_tls", cfg.remote_verify_tls, path) ? TRUE : FALSE;
    if (cfg.port <= 0 || cfg.port > 65535)
        cfg.port = 8765;
    if (cfg.remote_retry_interval_ms < 100)
        cfg.remote_retry_interval_ms = 3000;
    if (cfg.remote_timeout_ms < 100)
        cfg.remote_timeout_ms = 30000;
    if (cfg.remote_max_retries < 0)
        cfg.remote_max_retries = 0;
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

static void SaveConfig(void)
{
    wchar_t path[MAX_PATH];
    ServerConfig cfg = CopyConfig();
    GetConfigPath(path, _countof(path));
    WritePrivateProfileStringW(L"server", L"name", cfg.name, path);
    WritePrivateProfileStringW(L"server", L"version", cfg.version, path);
    WritePrivateProfileStringW(L"server", L"protocol_version", cfg.protocol_version, path);
    WritePrivateProfileStringW(L"http", L"bind", cfg.bind, path);
    WritePrivateProfileStringW(L"http", L"auth_token", cfg.auth_token, path);
    WriteIntIni(path, L"http", L"port", cfg.port);
    WriteIntIni(path, L"http", L"auto_start", cfg.auto_start ? 1 : 0);
    WritePrivateProfileStringW(L"remote", L"url", cfg.remote_url, path);
    WritePrivateProfileStringW(L"remote", L"transport", cfg.remote_transport, path);
    WritePrivateProfileStringW(L"remote", L"token", cfg.remote_token, path);
    WritePrivateProfileStringW(L"remote", L"headers", cfg.remote_headers, path);
    WriteIntIni(path, L"remote", L"auto_connect", cfg.remote_auto_connect ? 1 : 0);
    WriteIntIni(path, L"remote", L"auto_reconnect", cfg.remote_auto_reconnect ? 1 : 0);
    WriteIntIni(path, L"remote", L"retry_interval_ms", cfg.remote_retry_interval_ms);
    WriteIntIni(path, L"remote", L"max_retries", cfg.remote_max_retries);
    WriteIntIni(path, L"remote", L"timeout_ms", cfg.remote_timeout_ms);
    WriteIntIni(path, L"remote", L"verify_tls", cfg.remote_verify_tls ? 1 : 0);
}

static std::string WideToUtf8(const wchar_t* text)
{
    if (!text || !text[0])
        return std::string();
    int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (size <= 1)
        return std::string();
    std::string out;
    out.resize(size - 1);
    WideCharToMultiByte(CP_UTF8, 0, text, -1, &out[0], size, NULL, NULL);
    return out;
}

static void JsonAppendString(std::string& out, const wchar_t* text)
{
    std::string utf8 = WideToUtf8(text);
    out += "\"";
    for (size_t i = 0; i < utf8.size(); ++i) {
        unsigned char c = (unsigned char)utf8[i];
        if (c == '"' || c == '\\') {
            out += "\\";
            out += (char)c;
        }
        else if (c == '\n')
            out += "\\n";
        else if (c == '\r')
            out += "\\r";
        else if (c == '\t')
            out += "\\t";
        else
            out += (char)c;
    }
    out += "\"";
}

static std::string ExtractJsonId(const std::string& json)
{
    size_t p = json.find("\"id\"");
    if (p == std::string::npos)
        return "null";
    p = json.find(':', p);
    if (p == std::string::npos)
        return "null";
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t' || json[p] == '\r' || json[p] == '\n'))
        ++p;
    if (p >= json.size())
        return "null";
    if (json[p] == '"') {
        size_t e = p + 1;
        bool escaped = false;
        while (e < json.size()) {
            if (!escaped && json[e] == '"')
                return json.substr(p, e - p + 1);
            escaped = (!escaped && json[e] == '\\');
            if (json[e] != '\\')
                escaped = false;
            ++e;
        }
        return "null";
    }
    size_t e = p;
    while (e < json.size() && json[e] != ',' && json[e] != '}' && json[e] != '\r' && json[e] != '\n')
        ++e;
    return json.substr(p, e - p);
}

static bool JsonFindString(const std::string& json, const char* key, std::string& value)
{
    std::string needle = "\"";
    needle += key;
    needle += "\"";
    size_t p = json.find(needle);
    if (p == std::string::npos)
        return false;
    p = json.find(':', p + needle.size());
    if (p == std::string::npos)
        return false;
    p = json.find('"', p);
    if (p == std::string::npos)
        return false;
    ++p;
    size_t e = p;
    bool escaped = false;
    while (e < json.size()) {
        if (!escaped && json[e] == '"') {
            value = json.substr(p, e - p);
            return true;
        }
        escaped = (!escaped && json[e] == '\\');
        if (json[e] != '\\')
            escaped = false;
        ++e;
    }
    return false;
}

static bool ExtractJsonObjectMember(const std::string& json, const char* key, std::string& value)
{
    std::string needle = "\"";
    needle += key;
    needle += "\"";
    size_t p = json.find(needle);
    if (p == std::string::npos)
        return false;
    p = json.find(':', p + needle.size());
    if (p == std::string::npos)
        return false;
    p = json.find('{', p);
    if (p == std::string::npos)
        return false;
    int depth = 0;
    bool quoted = false;
    bool escaped = false;
    for (size_t i = p; i < json.size(); ++i) {
        char c = json[i];
        if (quoted) {
            if (!escaped && c == '"')
                quoted = false;
            escaped = (!escaped && c == '\\');
            if (c != '\\')
                escaped = false;
            continue;
        }
        if (c == '"') {
            quoted = true;
            continue;
        }
        if (c == '{')
            ++depth;
        else if (c == '}' && --depth == 0) {
            value = json.substr(p, i - p + 1);
            return true;
        }
    }
    return false;
}

static std::string NormalizeRemoteResponse(const std::string& body)
{
    size_t data = body.find("data:");
    if (data != std::string::npos) {
        data += 5;
        while (data < body.size() && (body[data] == ' ' || body[data] == '\t'))
            ++data;
        size_t end = body.find("\n\n", data);
        if (end == std::string::npos)
            end = body.find("\r\n\r\n", data);
        if (end == std::string::npos)
            end = body.size();
        std::string event = body.substr(data, end - data);
        size_t first = event.find('{');
        size_t last = event.rfind('}');
        if (first != std::string::npos && last != std::string::npos && last >= first)
            return event.substr(first, last - first + 1);
    }
    return body;
}

static bool RemoteHttpRequest(const ServerConfig& cfg, const std::string& json,
    std::string* response, DWORD* status_code)
{
    if (response)
        response->clear();
    if (status_code)
        *status_code = 0;
    if (!cfg.remote_url[0])
        return false;

    URL_COMPONENTSW uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256];
    wchar_t extra[1024];
    uc.lpszHostName = host;
    uc.dwHostNameLength = _countof(host);
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = _countof(extra);
    if (!WinHttpCrackUrl(cfg.remote_url, 0, 0, &uc))
        return false;

    HINTERNET session = WinHttpOpen(L"Z0BDbg-McpServer/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return false;
    int timeout = cfg.remote_timeout_ms > 100 ? cfg.remote_timeout_ms : 30000;
    WinHttpSetTimeouts(session, timeout, timeout, timeout, timeout);

    std::wstring host_name(uc.lpszHostName, uc.dwHostNameLength);
    HINTERNET connect = WinHttpConnect(session, host_name.c_str(), uc.nPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return false;
    }
    std::wstring path = uc.lpszExtraInfo && uc.dwExtraInfoLength
        ? std::wstring(uc.lpszExtraInfo, uc.dwExtraInfoLength) : L"/";
    DWORD flags = uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    std::wstring headers = L"Content-Type: application/json\r\n"
        L"Accept: application/json, text/event-stream\r\n";
    if (cfg.remote_token[0]) {
        headers += L"Authorization: Bearer ";
        headers += cfg.remote_token;
        headers += L"\r\n";
    }
    if (cfg.remote_headers[0]) {
        headers += cfg.remote_headers;
        if (headers.size() < 2 || headers.substr(headers.size() - 2) != L"\r\n")
            headers += L"\r\n";
    }
    if (!cfg.remote_verify_tls) {
        DWORD secure_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &secure_flags, sizeof(secure_flags));
    }

    std::string body = json;
    BOOL ok = WinHttpSendRequest(request, headers.c_str(), (DWORD)-1L,
        body.empty() ? NULL : &body[0], (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok)
        ok = WinHttpReceiveResponse(request, NULL);

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (ok)
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &status_size, NULL);
    if (status_code)
        *status_code = status;

    std::string received;
    while (ok) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available) || available == 0)
            break;
        std::string chunk;
        chunk.resize(available);
        DWORD read = 0;
        if (!WinHttpReadData(request, &chunk[0], available, &read))
            break;
        if (read == 0)
            break;
        received.append(chunk.data(), read);
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    if (!ok || status < 200 || status >= 300)
        return false;
    if (response)
        *response = NormalizeRemoteResponse(received);
    return !received.empty();
}

static void SetRemoteStatus(const wchar_t* text);

static std::wstring RemoteHeaderString(const ServerConfig& cfg)
{
    std::wstring headers = L"Accept: text/event-stream\r\n";
    if (cfg.remote_token[0]) {
        headers += L"Authorization: Bearer ";
        headers += cfg.remote_token;
        headers += L"\r\n";
    }
    if (cfg.remote_headers[0]) {
        headers += cfg.remote_headers;
        if (headers.size() < 2 || headers.substr(headers.size() - 2) != L"\r\n")
            headers += L"\r\n";
    }
    return headers;
}

static bool BuildRemoteUrl(const wchar_t* base, const std::wstring& endpoint,
    std::wstring* result)
{
    if (endpoint.compare(0, 7, L"http://") == 0 ||
        endpoint.compare(0, 8, L"https://") == 0) {
        *result = endpoint;
        return true;
    }
    URL_COMPONENTSW uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256];
    wchar_t extra[1024];
    uc.lpszHostName = host;
    uc.dwHostNameLength = _countof(host);
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = _countof(extra);
    if (!WinHttpCrackUrl(base, 0, 0, &uc))
        return false;
    std::wstring origin = uc.nScheme == INTERNET_SCHEME_HTTPS ? L"https://" : L"http://";
    origin.append(uc.lpszHostName, uc.dwHostNameLength);
    wchar_t port[32];
    if ((uc.nScheme == INTERNET_SCHEME_HTTPS && uc.nPort != INTERNET_DEFAULT_HTTPS_PORT) ||
        (uc.nScheme == INTERNET_SCHEME_HTTP && uc.nPort != INTERNET_DEFAULT_HTTP_PORT)) {
        StringCchPrintfW(port, _countof(port), L":%u", uc.nPort);
        origin += port;
    }
    if (endpoint.empty()) {
        if (uc.lpszExtraInfo && uc.dwExtraInfoLength)
            origin.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
        else
            origin += L"/";
    }
    else if (endpoint[0] == L'/')
        origin += endpoint;
    else {
        origin += L"/";
        origin += endpoint;
    }
    *result = origin;
    return true;
}

static bool WaitSseResponse(const std::string& id, const ServerConfig& cfg,
    std::string* response)
{
    DWORD timeout = cfg.remote_timeout_ms > 100 ? (DWORD)cfg.remote_timeout_ms : 30000;
    DWORD start = GetTickCount();
    for (;;) {
        EnterCriticalSection(&g_sse_cs);
        std::map<std::string, std::string>::iterator it = g_sse_responses.find(id);
        if (it != g_sse_responses.end()) {
            if (response)
                *response = it->second;
            g_sse_responses.erase(it);
            LeaveCriticalSection(&g_sse_cs);
            return true;
        }
        LeaveCriticalSection(&g_sse_cs);
        DWORD elapsed = GetTickCount() - start;
        if (elapsed >= timeout)
            return false;
        WaitForSingleObject(g_sse_response_event, timeout - elapsed);
    }
}

static bool SsePostMessage(const ServerConfig& cfg, const std::string& json,
    std::string* response)
{
    std::wstring endpoint;
    EnterCriticalSection(&g_sse_cs);
    endpoint = g_sse_endpoint;
    LeaveCriticalSection(&g_sse_cs);
    if (endpoint.empty())
        return false;
    std::wstring url;
    if (!BuildRemoteUrl(cfg.remote_url, endpoint, &url))
        return false;

    URL_COMPONENTSW uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256];
    wchar_t extra[2048];
    uc.lpszHostName = host;
    uc.dwHostNameLength = _countof(host);
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = _countof(extra);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc))
        return false;
    std::wstring host_name(uc.lpszHostName, uc.dwHostNameLength);
    HINTERNET session = WinHttpOpen(L"Z0BDbg-McpServer/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return false;
    WinHttpSetTimeouts(session, cfg.remote_timeout_ms, cfg.remote_timeout_ms,
        cfg.remote_timeout_ms, cfg.remote_timeout_ms);
    HINTERNET connect = WinHttpConnect(session, host_name.c_str(), uc.nPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return false;
    }
    DWORD flags = uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST",
        (uc.lpszExtraInfo && uc.dwExtraInfoLength) ? extra : L"/",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }
    if (!cfg.remote_verify_tls) {
        DWORD secure_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &secure_flags, sizeof(secure_flags));
    }
    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (cfg.remote_token[0]) {
        headers += L"Authorization: Bearer ";
        headers += cfg.remote_token;
        headers += L"\r\n";
    }
    if (cfg.remote_headers[0])
    {
        headers += cfg.remote_headers;
        if (headers.size() < 2 || headers.substr(headers.size() - 2) != L"\r\n")
            headers += L"\r\n";
    }
    BOOL ok = WinHttpSendRequest(request, headers.c_str(), (DWORD)-1L,
        (LPVOID)json.data(), (DWORD)json.size(), (DWORD)json.size(), 0);
    if (ok)
        ok = WinHttpReceiveResponse(request, NULL);
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (ok)
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &status_size, NULL);
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    if (!ok || status < 200 || status >= 300)
        return false;
    std::string id = ExtractJsonId(json);
    if (id == "null")
        return true;
    return WaitSseResponse(id, cfg, response);
}

static void SseProcessEvent(const std::string& event)
{
    std::string event_name;
    std::string data;
    size_t begin = 0;
    while (begin < event.size()) {
        size_t end = event.find('\n', begin);
        if (end == std::string::npos)
            end = event.size();
        size_t line_end = end;
        if (line_end > begin && event[line_end - 1] == '\r')
            --line_end;
        std::string line = event.substr(begin, line_end - begin);
        if (line.compare(0, 6, "event:") == 0) {
            size_t p = 6;
            while (p < line.size() && (line[p] == ' ' || line[p] == '\t'))
                ++p;
            event_name = line.substr(p);
        }
        else if (line.compare(0, 5, "data:") == 0) {
            size_t p = 5;
            if (p < line.size() && line[p] == ' ')
                ++p;
            if (!data.empty())
                data += "\n";
            data += line.substr(p);
        }
        begin = end < event.size() ? end + 1 : event.size();
    }
    if (event_name == "endpoint" || (event_name.empty() && data.size() > 0 &&
        data.find('{') == std::string::npos)) {
        std::wstring wide;
        int len = MultiByteToWideChar(CP_UTF8, 0, data.data(), (int)data.size(),
            NULL, 0);
        if (len > 0) {
            wide.resize(len);
            MultiByteToWideChar(CP_UTF8, 0, data.data(), (int)data.size(),
                &wide[0], len);
            EnterCriticalSection(&g_sse_cs);
            g_sse_endpoint = wide;
            InterlockedExchange(&g_sse_ready, 1);
            LeaveCriticalSection(&g_sse_cs);
            SetRemoteStatus(L"Remote SSE: endpoint ready");
        }
        return;
    }
    if (data.empty())
        return;
    std::string id = ExtractJsonId(data);
    if (id == "null")
        return;
    EnterCriticalSection(&g_sse_cs);
    g_sse_responses[id] = data;
    LeaveCriticalSection(&g_sse_cs);
    SetEvent(g_sse_response_event);
}

static bool FindSseEvent(const std::string& pending, size_t* position,
    size_t* length)
{
    size_t lf = pending.find("\n\n");
    size_t crlf = pending.find("\r\n\r\n");
    if (lf == std::string::npos && crlf == std::string::npos)
        return false;
    if (crlf != std::string::npos && (lf == std::string::npos || crlf < lf)) {
        *position = crlf;
        *length = 4;
    }
    else {
        *position = lf;
        *length = 2;
    }
    return true;
}

static DWORD WINAPI SseReaderThreadProc(LPVOID)
{
    ServerConfig cfg = CopyConfig();
    URL_COMPONENTSW uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256];
    wchar_t extra[1024];
    uc.lpszHostName = host;
    uc.dwHostNameLength = _countof(host);
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = _countof(extra);
    if (!WinHttpCrackUrl(cfg.remote_url, 0, 0, &uc))
        return 0;
    std::wstring host_name(uc.lpszHostName, uc.dwHostNameLength);
    HINTERNET session = WinHttpOpen(L"Z0BDbg-McpServer/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return 0;
    WinHttpSetTimeouts(session, cfg.remote_timeout_ms, cfg.remote_timeout_ms, cfg.remote_timeout_ms, 0);
    HINTERNET connect = WinHttpConnect(session, host_name.c_str(), uc.nPort, 0);
    DWORD flags = uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = connect ? WinHttpOpenRequest(connect, L"GET",
        (uc.lpszExtraInfo && uc.dwExtraInfoLength) ? extra : L"/",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags) : NULL;
    if (!request) {
        if (connect) WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return 0;
    }
    if (!cfg.remote_verify_tls) {
        DWORD secure_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &secure_flags, sizeof(secure_flags));
    }
    std::wstring headers = RemoteHeaderString(cfg);
    BOOL ok = WinHttpSendRequest(request, headers.c_str(), (DWORD)-1L, NULL, 0, 0, 0);
    if (ok)
        ok = WinHttpReceiveResponse(request, NULL);
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (ok)
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &status_size, NULL);
    if (!ok || status < 200 || status >= 300) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return 0;
    }
    EnterCriticalSection(&g_sse_cs);
    g_sse_request = request;
    LeaveCriticalSection(&g_sse_cs);
    char buffer[2048];
    std::string pending;
    while (InterlockedCompareExchange(&g_remote_stop, 0, 0) == 0) {
        DWORD read = 0;
        if (!WinHttpReadData(request, buffer, sizeof(buffer), &read) || read == 0)
            break;
        pending.append(buffer, read);
        size_t pos = 0;
        size_t separator = 0;
        while (FindSseEvent(pending, &pos, &separator)) {
            SseProcessEvent(pending.substr(0, pos));
            pending.erase(0, pos + separator);
        }
    }
    bool close_request = false;
    EnterCriticalSection(&g_sse_cs);
    if (g_sse_request == request) {
        g_sse_request = NULL;
        close_request = true;
    }
    LeaveCriticalSection(&g_sse_cs);
    if (close_request)
        WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    InterlockedExchange(&g_sse_ready, 0);
    InterlockedExchange(&g_remote_connected, 0);
    SetRemoteStatus(L"Remote SSE: disconnected");
    return 0;
}

static bool StartSseTransport(const ServerConfig& cfg)
{
    if (InterlockedCompareExchange(&g_sse_ready, 0, 0) != 0)
        return true;
    if (g_sse_thread) {
        if (WaitForSingleObject(g_sse_thread, 0) == WAIT_OBJECT_0) {
            CloseHandle(g_sse_thread);
            g_sse_thread = NULL;
        }
        else {
            return false;
        }
    }
    EnterCriticalSection(&g_sse_cs);
    g_sse_endpoint.clear();
    g_sse_responses.clear();
    LeaveCriticalSection(&g_sse_cs);
    InterlockedExchange(&g_remote_stop, 0);
    g_sse_thread = CreateThread(NULL, 0, SseReaderThreadProc, NULL, 0, NULL);
    if (!g_sse_thread)
        return false;
    DWORD start = GetTickCount();
    while (InterlockedCompareExchange(&g_sse_ready, 0, 0) == 0 &&
        GetTickCount() - start < (DWORD)cfg.remote_timeout_ms)
        Sleep(20);
    return InterlockedCompareExchange(&g_sse_ready, 0, 0) != 0;
}

static bool IsSseTransport(const ServerConfig& cfg)
{
    return lstrcmpiW(cfg.remote_transport, L"sse") == 0;
}

static std::string WrapRemoteResponse(const std::string& remote_response,
    const std::string& local_id)
{
    std::string result;
    if (ExtractJsonObjectMember(remote_response, "result", result)) {
        std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
        out += local_id;
        out += ",\"result\":";
        out += result;
        out += "}";
        return out;
    }
    std::string error;
    if (ExtractJsonObjectMember(remote_response, "error", error)) {
        std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
        out += local_id;
        out += ",\"error\":";
        out += error;
        out += "}";
        return out;
    }
    return remote_response;
}

static void SetRemoteStatus(const wchar_t* text)
{
    if (g_hwnd)
        SetDlgItemTextW(g_hwnd, IDC_REMOTE_STATUS, text);
}

static bool RemoteInitialize(const ServerConfig& cfg)
{
    std::string response;
    DWORD status = 0;
    const std::string initialize =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":"
        "{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"Z0BDbg MCP Server\",\"version\":\"1.0\"}}}";
    bool ok = IsSseTransport(cfg)
        ? (StartSseTransport(cfg) && SsePostMessage(cfg, initialize, &response))
        : RemoteHttpRequest(cfg, initialize, &response, &status);
    if (!ok) {
        InterlockedExchange(&g_remote_connected, 0);
        SetRemoteStatus(L"Remote: connection failed");
        return false;
    }
    const std::string initialized =
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}";
    if (IsSseTransport(cfg))
        SsePostMessage(cfg, initialized, NULL);
    else
        RemoteHttpRequest(cfg, initialized, NULL, NULL);
    InterlockedExchange(&g_remote_connected, 1);
    SetRemoteStatus(L"Remote: initialized");
    return true;
}

static bool EnsureRemoteInitialized(const ServerConfig& cfg)
{
    if (InterlockedCompareExchange(&g_remote_connected, 0, 0) != 0)
        return true;
    return RemoteInitialize(cfg);
}

static bool RemoteToolsList(const ServerConfig& cfg, std::string* response)
{
    if (!EnsureRemoteInitialized(cfg))
        return false;
    std::string remote;
    const std::string request =
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}";
    bool ok = IsSseTransport(cfg)
        ? SsePostMessage(cfg, request, &remote)
        : RemoteHttpRequest(cfg, request, &remote, NULL);
    if (!ok)
        return false;
    std::string result;
    if (!ExtractJsonObjectMember(remote, "result", result))
        return false;
    EnterCriticalSection(&g_remote_cs);
    g_remote_tools_result = result;
    LeaveCriticalSection(&g_remote_cs);
    SetRemoteStatus(L"Remote: tools cached");
    if (response)
        *response = result;
    return true;
}

static std::string CachedRemoteTools(void)
{
    std::string result;
    EnterCriticalSection(&g_remote_cs);
    result = g_remote_tools_result;
    LeaveCriticalSection(&g_remote_cs);
    return result;
}

static bool RemoteToolCall(const ServerConfig& cfg, const std::string& json,
    const std::string& local_id, std::string* response)
{
    if (!EnsureRemoteInitialized(cfg))
        return false;
    std::string remote;
    bool ok = IsSseTransport(cfg)
        ? SsePostMessage(cfg, json, &remote)
        : RemoteHttpRequest(cfg, json, &remote, NULL);
    if (!ok)
        return false;
    if (response)
        *response = WrapRemoteResponse(remote, local_id);
    SetRemoteStatus(L"Remote: tool call completed");
    return true;
}

static DWORD WINAPI RemoteReconnectThreadProc(LPVOID)
{
    int attempts = 0;
    while (InterlockedCompareExchange(&g_remote_stop, 0, 0) == 0) {
        ServerConfig cfg = CopyConfig();
        if (!cfg.remote_auto_reconnect || !cfg.remote_url[0])
            break;
        if (EnsureRemoteInitialized(cfg)) {
            attempts = 0;
            RemoteToolsList(cfg, NULL);
        }
        else {
            ++attempts;
            if (cfg.remote_max_retries > 0 && attempts >= cfg.remote_max_retries)
                break;
        }
        Sleep((DWORD)(cfg.remote_retry_interval_ms > 100 ? cfg.remote_retry_interval_ms : 3000));
    }
    return 0;
}

static void StartRemoteReconnect(void)
{
    if (g_remote_thread)
        return;
    InterlockedExchange(&g_remote_stop, 0);
    g_remote_thread = CreateThread(NULL, 0, RemoteReconnectThreadProc, NULL, 0, NULL);
}

static void StopRemoteReconnect(void)
{
    InterlockedExchange(&g_remote_stop, 1);
    HINTERNET sse_request = NULL;
    EnterCriticalSection(&g_sse_cs);
    sse_request = g_sse_request;
    g_sse_request = NULL;
    LeaveCriticalSection(&g_sse_cs);
    if (sse_request)
        WinHttpCloseHandle(sse_request);
    if (g_remote_thread) {
        WaitForSingleObject(g_remote_thread, 3000);
        CloseHandle(g_remote_thread);
        g_remote_thread = NULL;
    }
    if (g_sse_thread) {
        WaitForSingleObject(g_sse_thread, 3000);
        CloseHandle(g_sse_thread);
        g_sse_thread = NULL;
    }
    EnterCriticalSection(&g_sse_cs);
    g_sse_endpoint.clear();
    g_sse_responses.clear();
    LeaveCriticalSection(&g_sse_cs);
    InterlockedExchange(&g_sse_ready, 0);
    InterlockedExchange(&g_remote_connected, 0);
}

static bool ReadRemoteControls(HWND hwnd, ServerConfig* out)
{
    if (!out)
        return false;
    ServerConfig cfg = CopyConfig();
    wchar_t number[32];
    GetDlgItemTextW(hwnd, IDC_REMOTE_URL, cfg.remote_url, _countof(cfg.remote_url));
    GetDlgItemTextW(hwnd, IDC_REMOTE_TOKEN, cfg.remote_token, _countof(cfg.remote_token));
    GetDlgItemTextW(hwnd, IDC_REMOTE_HEADERS, cfg.remote_headers, _countof(cfg.remote_headers));
    GetDlgItemTextW(hwnd, IDC_REMOTE_RETRY, number, _countof(number));
    cfg.remote_retry_interval_ms = _wtoi(number);
    GetDlgItemTextW(hwnd, IDC_REMOTE_MAX, number, _countof(number));
    cfg.remote_max_retries = _wtoi(number);
    GetDlgItemTextW(hwnd, IDC_REMOTE_TIMEOUT, number, _countof(number));
    cfg.remote_timeout_ms = _wtoi(number);
    cfg.remote_auto_connect = IsDlgButtonChecked(hwnd, IDC_REMOTE_AUTOCONNECT) == BST_CHECKED;
    cfg.remote_auto_reconnect = IsDlgButtonChecked(hwnd, IDC_REMOTE_RECONNECT) == BST_CHECKED;
    cfg.remote_verify_tls = IsDlgButtonChecked(hwnd, IDC_REMOTE_VERIFY_TLS) == BST_CHECKED;
    HWND transport = GetDlgItem(hwnd, IDC_REMOTE_TRANSPORT);
    int sel = (int)SendMessageW(transport, CB_GETCURSEL, 0, 0);
    StringCchCopyW(cfg.remote_transport, _countof(cfg.remote_transport),
        sel == 1 ? L"sse" : L"streamable-http");
    if (cfg.remote_url[0] &&
        (wcsncmp(cfg.remote_url, L"http://", 7) != 0 &&
         wcsncmp(cfg.remote_url, L"https://", 8) != 0)) {
        MessageBoxW(hwnd, L"Remote URL must start with http:// or https://.",
            APP_NAME, MB_OK | MB_ICONWARNING);
        return false;
    }
    if (cfg.remote_retry_interval_ms < 100)
        cfg.remote_retry_interval_ms = 3000;
    if (cfg.remote_timeout_ms < 100)
        cfg.remote_timeout_ms = 30000;
    if (cfg.remote_max_retries < 0)
        cfg.remote_max_retries = 0;
    *out = cfg;
    return true;
}

static std::string ExecuteMcpRequest(const std::string& json)
{
    ServerConfig cfg = CopyConfig();
    std::string id = ExtractJsonId(json);
    std::string method;
    JsonFindString(json, "method", method);

    if (method == "initialize") {
        std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
        out += id;
        out += ",\"result\":{\"protocolVersion\":";
        JsonAppendString(out, cfg.protocol_version);
        out += ",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":";
        JsonAppendString(out, cfg.name);
        out += ",\"version\":";
        JsonAppendString(out, cfg.version);
        out += "}}}";
        return out;
    }
    if (method == "ping") {
        std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
        out += id;
        out += ",\"result\":{}}";
        return out;
    }
    if (method == "tools/list" || method == "z0dbg.tools") {
        ServerConfig remote_cfg = CopyConfig();
        if (remote_cfg.remote_url[0]) {
            std::string remote_result;
            if (RemoteToolsList(remote_cfg, &remote_result)) {
                std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
                out += id;
                out += ",\"result\":";
                out += remote_result;
                out += "}";
                return out;
            }
            std::string cached = CachedRemoteTools();
            if (!cached.empty()) {
                std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
                out += id;
                out += ",\"result\":";
                out += cached;
                out += "}";
                return out;
            }
        }
        std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
        out += id;
        out += ",\"result\":{\"tools\":[]}}";
        return out;
    }
    if (method == "tools/call") {
        ServerConfig remote_cfg = CopyConfig();
        std::string remote_response;
        if (remote_cfg.remote_url[0] &&
            RemoteToolCall(remote_cfg, json, id, &remote_response))
            return remote_response;
        return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
            ",\"error\":{\"code\":-32002,\"message\":\"remote MCP server unavailable\"}}";
    }
    if (method == "notifications/initialized")
        return "{}";

    std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
    out += id;
    out += ",\"error\":{\"code\":-32601,\"message\":\"method not found\"}}";
    return out;
}

static bool SendAll(SOCKET s, const char* data, int size)
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

static void SendHttpResponse(SOCKET s, int status, const char* status_text, const std::string& body)
{
    char header[512];
    StringCchPrintfA(header, _countof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: content-type, authorization\r\n"
        "\r\n",
        status, status_text, (unsigned int)body.size());
    SendAll(s, header, (int)strlen(header));
    if (!body.empty())
        SendAll(s, body.data(), (int)body.size());
}

static std::string HeaderValue(const std::string& headers, const char* name)
{
    std::string lower = headers;
    std::string key = name;
    for (size_t i = 0; i < lower.size(); ++i)
        lower[i] = (char)tolower((unsigned char)lower[i]);
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

static bool Authorized(const ServerConfig& cfg, const std::string& headers)
{
    if (!cfg.auth_token[0])
        return true;
    std::string expected = "Bearer ";
    expected += WideToUtf8(cfg.auth_token);
    return HeaderValue(headers, "Authorization") == expected;
}

static void HandleClient(SOCKET client)
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
            content_length = atoi(HeaderValue(headers, "Content-Length").c_str());
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
    if (request.find("OPTIONS ") == 0) {
        SendHttpResponse(client, 200, "OK", "{}");
        return;
    }
    if (request.find("POST ") != 0) {
        SendHttpResponse(client, 405, "Method Not Allowed",
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"POST required\"}}");
        return;
    }
    ServerConfig cfg = CopyConfig();
    if (!Authorized(cfg, headers)) {
        SendHttpResponse(client, 401, "Unauthorized",
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32001,\"message\":\"unauthorized\"}}");
        return;
    }

    std::string body;
    if (content_length > 0 && request.size() >= body_start + (size_t)content_length)
        body = request.substr(body_start, (size_t)content_length);
    SendHttpResponse(client, 200, "OK", ExecuteMcpRequest(body));
}

static void SetStatusText(const wchar_t* text)
{
    if (g_hwnd)
        SetDlgItemTextW(g_hwnd, IDC_STATUS, text);
}

static DWORD WINAPI ServerThreadProc(LPVOID)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        SetStatusText(L"Status: WSAStartup failed");
        return 0;
    }

    ServerConfig cfg = CopyConfig();
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        WSACleanup();
        SetStatusText(L"Status: socket failed");
        return 0;
    }
    BOOL reuse = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)cfg.port);
    std::string bind_addr = WideToUtf8(cfg.bind);
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
        SetStatusText(L"Status: listen failed");
        return 0;
    }

    g_server_socket = listener;
    InterlockedExchange(&g_server_running, 1);
    SetStatusText(L"Status: running");
    while (InterlockedCompareExchange(&g_server_stop, 0, 0) == 0) {
        SOCKET client = accept(listener, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (InterlockedCompareExchange(&g_server_stop, 0, 0) != 0)
                break;
            Sleep(10);
            continue;
        }
        HandleClient(client);
        closesocket(client);
    }

    closesocket(listener);
    g_server_socket = INVALID_SOCKET;
    InterlockedExchange(&g_server_running, 0);
    WSACleanup();
    SetStatusText(L"Status: stopped");
    return 0;
}

static bool StartServer(void)
{
    if (g_server_thread)
        return true;
    InterlockedExchange(&g_server_stop, 0);
    g_server_thread = CreateThread(NULL, 0, ServerThreadProc, NULL, 0, NULL);
    return g_server_thread != NULL;
}

static void StopServer(void)
{
    InterlockedExchange(&g_server_stop, 1);
    if (g_server_socket != INVALID_SOCKET) {
        closesocket(g_server_socket);
        g_server_socket = INVALID_SOCKET;
    }
    if (g_server_thread) {
        WaitForSingleObject(g_server_thread, 3000);
        CloseHandle(g_server_thread);
        g_server_thread = NULL;
    }
    InterlockedExchange(&g_server_running, 0);
    SetStatusText(L"Status: stopped");
}

static HWND AddControl(HWND parent, const wchar_t* cls, const wchar_t* text, int id,
    int x, int y, int w, int h, DWORD style, DWORD exstyle)
{
    HWND child = CreateWindowExW(exstyle, cls, text, WS_CHILD | WS_VISIBLE | style,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, g_instance, NULL);
    if (g_font)
        SendMessageW(child, WM_SETFONT, (WPARAM)g_font, TRUE);
    return child;
}

static void AddLabel(HWND parent, int x, int y, int w, int h, const wchar_t* text)
{
    if (h < 28)
        h = 28;
    AddControl(parent, L"STATIC", text, -1, x, y, w, h,
        SS_LEFT | SS_CENTERIMAGE | SS_NOPREFIX, 0);
}

static void FillWindow(HWND hwnd)
{
    ServerConfig cfg = CopyConfig();
    wchar_t text[32];
    SetDlgItemTextW(hwnd, IDC_NAME, cfg.name);
    SetDlgItemTextW(hwnd, IDC_VERSION, cfg.version);
    SetDlgItemTextW(hwnd, IDC_PROTOCOL, cfg.protocol_version);
    SetDlgItemTextW(hwnd, IDC_BIND, cfg.bind);
    StringCchPrintfW(text, _countof(text), L"%d", cfg.port);
    SetDlgItemTextW(hwnd, IDC_PORT, text);
    SetDlgItemTextW(hwnd, IDC_TOKEN, cfg.auth_token);
    CheckDlgButton(hwnd, IDC_AUTOSTART, cfg.auto_start ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(hwnd, IDC_REMOTE_URL, cfg.remote_url);
    SetDlgItemTextW(hwnd, IDC_REMOTE_TOKEN, cfg.remote_token);
    SetDlgItemTextW(hwnd, IDC_REMOTE_HEADERS, cfg.remote_headers);
    StringCchPrintfW(text, _countof(text), L"%d", cfg.remote_retry_interval_ms);
    SetDlgItemTextW(hwnd, IDC_REMOTE_RETRY, text);
    StringCchPrintfW(text, _countof(text), L"%d", cfg.remote_max_retries);
    SetDlgItemTextW(hwnd, IDC_REMOTE_MAX, text);
    StringCchPrintfW(text, _countof(text), L"%d", cfg.remote_timeout_ms);
    SetDlgItemTextW(hwnd, IDC_REMOTE_TIMEOUT, text);
    CheckDlgButton(hwnd, IDC_REMOTE_AUTOCONNECT, cfg.remote_auto_connect ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_REMOTE_RECONNECT, cfg.remote_auto_reconnect ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_REMOTE_VERIFY_TLS, cfg.remote_verify_tls ? BST_CHECKED : BST_UNCHECKED);
    HWND remote_transport = GetDlgItem(hwnd, IDC_REMOTE_TRANSPORT);
    SendMessageW(remote_transport, CB_SETCURSEL,
        lstrcmpiW(cfg.remote_transport, L"sse") == 0 ? 1 : 0, 0);
}

static bool ReadWindow(HWND hwnd)
{
    ServerConfig cfg = CopyConfig();
    wchar_t text[32];
    GetDlgItemTextW(hwnd, IDC_NAME, cfg.name, _countof(cfg.name));
    GetDlgItemTextW(hwnd, IDC_VERSION, cfg.version, _countof(cfg.version));
    GetDlgItemTextW(hwnd, IDC_PROTOCOL, cfg.protocol_version, _countof(cfg.protocol_version));
    GetDlgItemTextW(hwnd, IDC_BIND, cfg.bind, _countof(cfg.bind));
    GetDlgItemTextW(hwnd, IDC_TOKEN, cfg.auth_token, _countof(cfg.auth_token));
    GetDlgItemTextW(hwnd, IDC_PORT, text, _countof(text));
    cfg.port = _wtoi(text);
    cfg.auto_start = IsDlgButtonChecked(hwnd, IDC_AUTOSTART) == BST_CHECKED;
    if (!cfg.name[0] || !cfg.version[0] || !cfg.protocol_version[0] || !cfg.bind[0]) {
        MessageBoxW(hwnd, L"Name, version, protocol version and bind address are required.", APP_NAME, MB_OK | MB_ICONWARNING);
        return false;
    }
    if (cfg.port <= 0 || cfg.port > 65535) {
        MessageBoxW(hwnd, L"Port must be between 1 and 65535.", APP_NAME, MB_OK | MB_ICONWARNING);
        return false;
    }
    EnterCriticalSection(&g_config_cs);
    g_config = cfg;
    LeaveCriticalSection(&g_config_cs);
    ServerConfig with_remote;
    if (!ReadRemoteControls(hwnd, &with_remote))
        return false;
    EnterCriticalSection(&g_config_cs);
    g_config = with_remote;
    LeaveCriticalSection(&g_config_cs);
    return true;
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_CREATE: {
        NONCLIENTMETRICSW ncm;
        ZeroMemory(&ncm, sizeof(ncm));
        ncm.cbSize = sizeof(ncm);
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        g_font = CreateFontIndirectW(&ncm.lfMessageFont);

        AddLabel(hwnd, 24, 24, 130, 22, L"Server name");
        AddControl(hwnd, L"EDIT", L"", IDC_NAME, 170, 21, 430, 28, WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 24, 70, 130, 22, L"Version");
        AddControl(hwnd, L"EDIT", L"", IDC_VERSION, 170, 67, 140, 28, WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 340, 70, 105, 22, L"Protocol");
        AddControl(hwnd, L"EDIT", L"", IDC_PROTOCOL, 460, 67, 140, 28, WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 24, 116, 130, 22, L"Bind address");
        AddControl(hwnd, L"EDIT", L"", IDC_BIND, 170, 113, 250, 28, WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 450, 116, 50, 22, L"Port");
        AddControl(hwnd, L"EDIT", L"", IDC_PORT, 510, 113, 90, 28, WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 24, 162, 130, 22, L"Bearer token");
        AddControl(hwnd, L"EDIT", L"", IDC_TOKEN, 170, 159, 430, 28, WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddControl(hwnd, L"BUTTON", L"Auto start listener", IDC_AUTOSTART, 160, 204, 190, 26,
            WS_TABSTOP | BS_AUTOCHECKBOX, 0);
        AddControl(hwnd, L"STATIC", L"Status: stopped", IDC_STATUS, 24, 254, 576, 30,
            SS_LEFT | SS_CENTERIMAGE | SS_NOPREFIX, 0);
        AddControl(hwnd, L"BUTTON", L"Save", IDC_SAVE, 160, 310, 110, 32, WS_TABSTOP | BS_DEFPUSHBUTTON, 0);
        AddControl(hwnd, L"BUTTON", L"Start", IDC_START, 290, 310, 110, 32, WS_TABSTOP | BS_PUSHBUTTON, 0);
        AddControl(hwnd, L"BUTTON", L"Stop", IDC_STOP, 420, 310, 110, 32, WS_TABSTOP | BS_PUSHBUTTON, 0);

        AddLabel(hwnd, 660, 24, 220, 22, L"Remote MCP Server");
        AddLabel(hwnd, 660, 58, 115, 22, L"URL");
        AddControl(hwnd, L"EDIT", L"", IDC_REMOTE_URL, 790, 55, 420, 28,
            WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 660, 104, 115, 22, L"Transport");
        HWND remote_transport = AddControl(hwnd, L"COMBOBOX", L"", IDC_REMOTE_TRANSPORT,
            790, 101, 180, 30, WS_TABSTOP | CBS_DROPDOWNLIST, 0);
        SendMessageW(remote_transport, CB_ADDSTRING, 0, (LPARAM)L"Streamable HTTP");
        SendMessageW(remote_transport, CB_ADDSTRING, 0, (LPARAM)L"SSE (legacy)");
        AddLabel(hwnd, 990, 104, 60, 22, L"Token");
        AddControl(hwnd, L"EDIT", L"", IDC_REMOTE_TOKEN, 1060, 101, 150, 28,
            WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 660, 158, 115, 22, L"Headers");
        AddControl(hwnd, L"EDIT", L"", IDC_REMOTE_HEADERS, 790, 155, 420, 70,
            WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, WS_EX_CLIENTEDGE);
        AddControl(hwnd, L"BUTTON", L"Auto connect", IDC_REMOTE_AUTOCONNECT, 760, 240, 150, 26,
            WS_TABSTOP | BS_AUTOCHECKBOX, 0);
        AddControl(hwnd, L"BUTTON", L"Auto reconnect", IDC_REMOTE_RECONNECT, 925, 240, 160, 26,
            WS_TABSTOP | BS_AUTOCHECKBOX, 0);
        AddControl(hwnd, L"BUTTON", L"Verify HTTPS certificate", IDC_REMOTE_VERIFY_TLS, 760, 275, 220, 26,
            WS_TABSTOP | BS_AUTOCHECKBOX, 0);
        AddLabel(hwnd, 660, 320, 135, 22, L"Retry interval");
        AddControl(hwnd, L"EDIT", L"", IDC_REMOTE_RETRY, 805, 317, 95, 28,
            WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 915, 320, 85, 22, L"Max retries");
        AddControl(hwnd, L"EDIT", L"", IDC_REMOTE_MAX, 1010, 317, 95, 28,
            WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddLabel(hwnd, 660, 366, 135, 22, L"Timeout(ms)");
        AddControl(hwnd, L"EDIT", L"", IDC_REMOTE_TIMEOUT, 805, 363, 95, 28,
            WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE);
        AddControl(hwnd, L"STATIC", L"Remote: disconnected", IDC_REMOTE_STATUS, 660, 415, 550, 30,
            SS_LEFT | SS_CENTERIMAGE | SS_NOPREFIX, 0);
        AddControl(hwnd, L"BUTTON", L"Test connection", IDC_REMOTE_TEST, 660, 465, 130, 32,
            WS_TABSTOP | BS_PUSHBUTTON, 0);
        AddControl(hwnd, L"BUTTON", L"Initialize", IDC_REMOTE_INIT, 805, 465, 110, 32,
            WS_TABSTOP | BS_PUSHBUTTON, 0);
        AddControl(hwnd, L"BUTTON", L"Tools list", IDC_REMOTE_TOOLS, 930, 465, 110, 32,
            WS_TABSTOP | BS_PUSHBUTTON, 0);
        AddControl(hwnd, L"BUTTON", L"Clear cache", IDC_REMOTE_CLEAR, 1055, 465, 110, 32,
            WS_TABSTOP | BS_PUSHBUTTON, 0);
        FillWindow(hwnd);
        if (CopyConfig().auto_start)
            StartServer();
        if (CopyConfig().remote_auto_connect)
            StartRemoteReconnect();
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_SAVE:
            if (ReadWindow(hwnd)) {
                SaveConfig();
                MessageBoxW(hwnd, L"Settings saved.", APP_NAME, MB_OK | MB_ICONINFORMATION);
            }
            return 0;
        case IDC_START:
            if (ReadWindow(hwnd)) {
                SaveConfig();
                if (InterlockedCompareExchange(&g_server_running, 0, 0) != 0)
                    StopServer();
                StartServer();
            }
            return 0;
        case IDC_STOP:
            StopServer();
            return 0;
        case IDC_REMOTE_TEST:
        case IDC_REMOTE_INIT:
        case IDC_REMOTE_TOOLS:
            {
                ServerConfig cfg;
                if (!ReadWindow(hwnd))
                    return 0;
                cfg = CopyConfig();
                bool ok = false;
                std::string response;
                if (LOWORD(wparam) == IDC_REMOTE_TOOLS)
                    ok = RemoteToolsList(cfg, &response);
                else
                    ok = RemoteInitialize(cfg);
                if (ok) {
                    SaveConfig();
                    MessageBoxW(hwnd,
                        LOWORD(wparam) == IDC_REMOTE_TOOLS
                            ? L"Remote tools list loaded and cached."
                            : L"Remote MCP connection initialized.",
                        APP_NAME, MB_OK | MB_ICONINFORMATION);
                }
                else {
                    MessageBoxW(hwnd, L"Remote MCP request failed.",
                        APP_NAME, MB_OK | MB_ICONWARNING);
                }
            }
            return 0;
        case IDC_REMOTE_CLEAR:
            EnterCriticalSection(&g_remote_cs);
            g_remote_tools_result.clear();
            LeaveCriticalSection(&g_remote_cs);
            InterlockedExchange(&g_remote_connected, 0);
            SetRemoteStatus(L"Remote: cache cleared");
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        StopServer();
        StopRemoteReconnect();
        if (g_sse_response_event) {
            CloseHandle(g_sse_response_event);
            g_sse_response_event = NULL;
        }
        DeleteCriticalSection(&g_sse_cs);
        DeleteCriticalSection(&g_remote_cs);
        DeleteCriticalSection(&g_config_cs);
        if (g_font) {
            DeleteObject(g_font);
            g_font = NULL;
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int show)
{
    g_instance = instance;
    InitializeCriticalSection(&g_config_cs);
    InitializeCriticalSection(&g_remote_cs);
    InitializeCriticalSection(&g_sse_cs);
    g_sse_response_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_sse_response_event)
        return 1;
    SetDefaultConfig(&g_config);
    LoadConfig();

    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_MCP_SERVER));
    if (!wc.hIcon)
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"Z0B_McpServerApp";
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, APP_NAME,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 1260, 560,
        NULL, NULL, instance, NULL);
    if (!hwnd)
        return 1;
    g_hwnd = hwnd;

    RECT rc;
    GetWindowRect(hwnd, &rc);
    SetWindowPos(hwnd, NULL,
        (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER);
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    DeleteCriticalSection(&g_config_cs);
    DeleteCriticalSection(&g_remote_cs);
    return (int)msg.wParam;
}
