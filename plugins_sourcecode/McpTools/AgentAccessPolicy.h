#pragma once
#include <windows.h>
#include <winhttp.h>
#include "ModelJson.h"
#include <string>
#include <vector>
#include <cwctype>

static std::wstring AccessLower(std::wstring text) { for (size_t i = 0; i < text.size(); ++i) text[i] = (wchar_t)towlower(text[i]); return text; }
static std::vector<std::wstring> AccessList(const std::wstring& list)
{
    std::vector<std::wstring> out;
    for (size_t start = 0; start < list.size();) {
        size_t end = list.find(L'|', start); if (end == std::wstring::npos) end = list.size();
        std::wstring part = list.substr(start, end - start); size_t first = part.find_first_not_of(L" \t"), last = part.find_last_not_of(L" \t");
        if (first != std::wstring::npos) out.push_back(part.substr(first, last - first + 1)); start = end + 1;
    }
    return out;
}
static bool AccessCanonicalPath(const std::wstring& path, std::wstring* output)
{
    if (path.size() < 3 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') ||
        path.find_first_of(L"*?\r\n\"|") != std::wstring::npos || path.find(L':', 2) != std::wstring::npos) return false;
    wchar_t full[32768]; DWORD length = GetFullPathNameW(path.c_str(), _countof(full), full, NULL);
    if (!length || length >= _countof(full)) return false;
    std::wstring normal = AccessLower(full);
    for (size_t i = 0; i < normal.size(); ++i) if (normal[i] == L'/') normal[i] = L'\\';
    while (normal.size() > 3 && normal[normal.size() - 1] == L'\\') normal.resize(normal.size() - 1);
    for (size_t i = 3; i <= normal.size(); ++i) if (i == normal.size() || normal[i] == L'\\') {
        if (i > 3 && (normal[i - 1] == L'.' || normal[i - 1] == L' ')) return false;
        size_t start = normal.find_last_of(L'\\', i ? i - 1 : 0); start = start == std::wstring::npos ? 0 : start + 1;
        std::wstring segment = normal.substr(start, i - start); segment = segment.substr(0, segment.find(L'.'));
        if (segment == L"con" || segment == L"prn" || segment == L"aux" || segment == L"nul" ||
            (segment.size() == 4 && (segment.substr(0, 3) == L"com" || segment.substr(0, 3) == L"lpt") && segment[3] >= L'1' && segment[3] <= L'9')) return false;
        DWORD attributes = GetFileAttributesW(normal.substr(0, i).c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
        if (i < normal.size() && attributes == INVALID_FILE_ATTRIBUTES) return false;
    }
    *output = normal; return true;
}
static bool AccessFileAllowed(const std::wstring& path, const std::wstring& roots)
{
    std::wstring canonical; if (!AccessCanonicalPath(path, &canonical)) return false;
    std::vector<std::wstring> allowed = AccessList(roots);
    for (size_t i = 0; i < allowed.size(); ++i) {
        std::wstring root;
        if (!AccessCanonicalPath(allowed[i], &root) || GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        if (canonical == root || (canonical.size() > root.size() && canonical.compare(0, root.size(), root) == 0 && (root.size() == 3 || canonical[root.size()] == L'\\'))) return true;
    }
    return false;
}
static std::wstring AccessOrigin(const std::wstring& url)
{
    URL_COMPONENTSW parts = {}; parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = parts.dwUserNameLength = parts.dwPasswordLength = (DWORD)-1;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts) || parts.dwUserNameLength || parts.dwPasswordLength ||
        (parts.nScheme != INTERNET_SCHEME_HTTP && parts.nScheme != INTERNET_SCHEME_HTTPS)) return L"";
    std::wstring origin = parts.nScheme == INTERNET_SCHEME_HTTPS ? L"https://" : L"http://";
    origin += AccessLower(std::wstring(parts.lpszHostName, parts.dwHostNameLength));
    wchar_t port[16]; swprintf_s(port, 16, L":%u", parts.nPort); return origin + port;
}
static bool AccessNetworkAllowed(const std::wstring& url, const std::wstring& origins)
{
    std::wstring origin = AccessOrigin(url); if (origin.empty()) return false;
    std::vector<std::wstring> list = AccessList(origins);
    for (size_t i = 0; i < list.size(); ++i) if (AccessOrigin(list[i]) == origin) return true;
    return false;
}
static std::wstring AccessIntersect(const std::wstring& session, const std::wstring& policy, bool files)
{
    std::vector<std::wstring> a = AccessList(session), b = AccessList(policy); std::wstring result;
    for (size_t i = 0; i < a.size(); ++i) for (size_t j = 0; j < b.size(); ++j) {
        std::wstring match;
        if (files) {
            if (AccessFileAllowed(a[i], b[j])) match = a[i]; else if (AccessFileAllowed(b[j], a[i])) match = b[j];
        }
        else if (AccessNetworkAllowed(a[i], b[j])) match = a[i];
        if (!match.empty()) { if (!result.empty()) result += L'|'; result += match; }
    }
    return result.size() < 2048 ? result : L"";
}
static std::wstring AccessWide(const std::string& text)
{
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), (int)text.size(), NULL, 0);
    if (count <= 0) return L""; std::wstring wide(count, 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), (int)text.size(), &wide[0], count); return wide;
}
static bool AccessArgumentsAllowed(const ModelJson& value, const std::wstring& files, const std::wstring& network, int depth = 0, const std::string& key = "")
{
    if (depth > 16) return false;
    if (value.kind == ModelJson::OBJECT) {
        for (size_t i = 0; i < value.items.size(); ++i) if (!AccessArgumentsAllowed(value.items[i], files, network, depth + 1, value.keys[i])) return false;
    }
    else if (value.kind == ModelJson::ARRAY) {
        for (size_t i = 0; i < value.items.size(); ++i) if (!AccessArgumentsAllowed(value.items[i], files, network, depth + 1, key)) return false;
    }
    else if (value.kind == ModelJson::STRING) {
        std::wstring text = AccessWide(value.value), lower = AccessLower(text), field = AccessLower(AccessWide(key));
        bool path = field == L"path" || field == L"file" || field == L"filename" || field == L"file_name" || field == L"filepath" || field == L"folder" || field == L"workdir" || field == L"directory" || field == L"cwd" ||
            field.find(L"_path") != std::wstring::npos || field.find(L"_file") != std::wstring::npos ||
            (text.size() > 1 && text[1] == L':') || lower.compare(0, 2, L"\\\\") == 0;
        bool url = field == L"url" || field == L"endpoint" || field == L"uri" || lower.find(L"://") != std::wstring::npos;
        if ((path && !AccessFileAllowed(text, files)) || (url && !AccessNetworkAllowed(text, network))) return false;
    }
    return true;
}
