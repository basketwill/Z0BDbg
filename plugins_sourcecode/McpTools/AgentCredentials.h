#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#pragma comment(lib, "crypt32.lib")

static bool AgentProtectRecord(const std::string& clear, std::string* stored) {
    if (clear.empty() || clear.size() > 64 * 1024 * 1024) return false;
    DATA_BLOB input = { (DWORD)clear.size(), (BYTE*)clear.data() }, output = {};
    if (!CryptProtectData(&input, L"Z0 MCP local record v1", NULL, NULL, NULL,
        CRYPTPROTECT_UI_FORBIDDEN, &output)) return false;
    stored->assign("Z0DPAPI1", 8);
    stored->append((const char*)output.pbData, output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return true;
}

static bool AgentUnprotectRecord(const std::string& stored, size_t limit, std::string* clear) {
    if (stored.compare(0, 8, "Z0DPAPI1") != 0) {
        if (stored.size() > limit) return false;
        *clear = stored;
        return true;
    }
    if (stored.size() <= 8 || stored.size() > limit + 4096) return false;
    DATA_BLOB input = { (DWORD)(stored.size() - 8), (BYTE*)stored.data() + 8 }, output = {};
    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL,
        CRYPTPROTECT_UI_FORBIDDEN, &output)) return false;
    bool valid = output.cbData > 0 && output.cbData <= limit;
    if (valid) clear->assign((const char*)output.pbData, output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return valid;
}

static bool AgentProtectSecret(const std::wstring& clear, std::wstring* stored) {
    stored->clear(); if (clear.empty()) return true;
    if (clear.size() > 8192) return false;
    DATA_BLOB input = { (DWORD)(clear.size() * sizeof(wchar_t)), (BYTE*)clear.data() }, output = {};
    if (!CryptProtectData(&input, L"Z0 MCP credential v1", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &output)) return false;
    const wchar_t* hex = L"0123456789ABCDEF"; *stored = L"dpapi:v1:";
    for (DWORD i = 0; i < output.cbData; ++i) { *stored += hex[output.pbData[i] >> 4]; *stored += hex[output.pbData[i] & 15]; }
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData); return true;
}
static int AgentSecretHex(wchar_t c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}
static bool AgentUnprotectSecret(const std::wstring& stored, std::wstring* clear) {
    clear->clear();
    if (stored.compare(0, 6, L"dpapi:") != 0) { *clear = stored; return true; }
    if (stored.compare(0, 9, L"dpapi:v1:") != 0 || stored.size() <= 9 || stored.size() > 65536 || (stored.size() - 9) % 2) return false;
    std::vector<BYTE> bytes((stored.size() - 9) / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        int a = AgentSecretHex(stored[9 + i * 2]), b = AgentSecretHex(stored[10 + i * 2]);
        if (a < 0 || b < 0) return false; bytes[i] = (BYTE)((a << 4) | b);
    }
    DATA_BLOB input = { (DWORD)bytes.size(), &bytes[0] }, output = {};
    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &output)) return false;
    bool valid = output.cbData <= 16384 && output.cbData % sizeof(wchar_t) == 0;
    if (valid) clear->assign((wchar_t*)output.pbData, output.cbData / sizeof(wchar_t));
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    if (!valid || clear->find(L'\0') != std::wstring::npos) {
        if (!clear->empty()) SecureZeroMemory(&(*clear)[0], clear->size() * sizeof(wchar_t));
        clear->clear(); return false;
    }
    return true;
}
static bool AgentSecretSetting(const std::wstring& section, const std::wstring& key) {
    return key == L"api_key" || key == L"auth_token" || (section == L"remote" && (key == L"token" || key == L"headers"));
}
static bool AgentWriteSecret(const wchar_t* path, const wchar_t* section, const wchar_t* key, const wchar_t* clear) {
    std::wstring stored; if (!AgentProtectSecret(clear, &stored)) return false;
    return WritePrivateProfileStringW(section, key, stored.c_str(), path) != FALSE;
}
static bool AgentReadSecret(const wchar_t* path, const wchar_t* section, const wchar_t* key, wchar_t* target, size_t capacity) {
    std::vector<wchar_t> buffer(65536); std::wstring clear;
    DWORD size = GetPrivateProfileStringW(section, key, L"", &buffer[0], (DWORD)buffer.size(), path);
    target[0] = 0;
    bool ok = size + 1 < buffer.size() && AgentUnprotectSecret(&buffer[0], &clear) && clear.size() < capacity;
    if (ok) memcpy(target, clear.c_str(), (clear.size() + 1) * sizeof(wchar_t));
    SecureZeroMemory(&buffer[0], buffer.size() * sizeof(wchar_t));
    if (!clear.empty()) SecureZeroMemory(&clear[0], clear.size() * sizeof(wchar_t));
    return ok;
}

static std::string AgentRedactText(std::string text, const std::vector<std::string>& secrets) {
    for (size_t i = 0; i < secrets.size(); ++i) {
        if (secrets[i].size() < 4) continue;
        size_t pos = 0;
        while ((pos = text.find(secrets[i], pos)) != std::string::npos) { text.replace(pos, secrets[i].size(), "[redacted]"); pos += 10; }
    }
    std::string lower = text;
    for (size_t i = 0; i < lower.size(); ++i) if (lower[i] >= 'A' && lower[i] <= 'Z') lower[i] += 'a' - 'A';
    const char* markers[] = { "bearer ", "api_key=", "apikey=", "access_token=", "password=", "secret=", "token=" };
    for (int m = 0; m < 7; ++m) {
        size_t pos = 0;
        while ((pos = lower.find(markers[m], pos)) != std::string::npos) {
            size_t begin = pos + strlen(markers[m]), end = text.find_first_of(" \t\r\n\"'&<>\\", begin);
            if (end == std::string::npos) end = text.size();
            if (end > begin) { text.replace(begin, end - begin, "[redacted]"); lower.replace(begin, end - begin, "[redacted]"); }
            pos = begin + 10;
        }
    }
    return text;
}
