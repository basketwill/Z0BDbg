#pragma once
#include <windows.h>
#include <vector>
#include <aclapi.h>
#include <bcrypt.h>
#include "AgentAccessPolicy.h"
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

struct AgentSecurityCapabilities { PSID sid; PSID_AND_ATTRIBUTES capabilities; DWORD count, reserved; };
typedef HRESULT (WINAPI *AgentCreateContainer)(PCWSTR, PCWSTR, PCWSTR, PSID_AND_ATTRIBUTES, DWORD, PSID*);
typedef HRESULT (WINAPI *AgentDeriveContainer)(PCWSTR, PSID*);

static bool AgentContainerGrant(const std::wstring& path, PSID sid)
{
    PACL old_acl = NULL, acl = NULL; PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD result = GetNamedSecurityInfoW((LPWSTR)path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &old_acl, NULL, &descriptor);
    if (result != ERROR_SUCCESS) return false;
    EXPLICIT_ACCESSW access = {}; access.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
    access.grfAccessMode = GRANT_ACCESS; access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID; access.Trustee.TrusteeType = TRUSTEE_IS_USER; access.Trustee.ptstrName = (LPWSTR)sid;
    result = SetEntriesInAclW(1, &access, old_acl, &acl);
    if (result == ERROR_SUCCESS) result = SetNamedSecurityInfoW((LPWSTR)path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL);
    if (acl) LocalFree(acl); if (descriptor) LocalFree(descriptor); return result == ERROR_SUCCESS;
}

static PSID AgentContainerSid(const wchar_t* command, const std::wstring& roots)
{
    std::vector<std::wstring> allowed = AccessList(roots); if (allowed.empty()) return NULL;
    for (size_t i = 0; i < allowed.size(); ++i) {
        std::wstring canonical; DWORD attributes = GetFileAttributesW(allowed[i].c_str());
        if (!AccessCanonicalPath(allowed[i], &canonical) || attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) return NULL;
        allowed[i] = canonical;
    }
    HMODULE library = LoadLibraryW(L"userenv.dll"); if (!library) return NULL;
    AgentCreateContainer create = (AgentCreateContainer)GetProcAddress(library, "CreateAppContainerProfile");
    AgentDeriveContainer derive = (AgentDeriveContainer)GetProcAddress(library, "DeriveAppContainerSidFromAppContainerName");
    PSID sid = NULL; BCRYPT_ALG_HANDLE algorithm = NULL; BCRYPT_HASH_HANDLE hash = NULL;
    DWORD bytes = 0, size = 0; BYTE digest[32]; std::wstring identity(command); identity += L"\n" + roots;
    bool ok = create && derive && BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&bytes, sizeof(bytes), &size, 0) >= 0;
    std::vector<BYTE> object(bytes);
    if (ok) ok = bytes && BCryptCreateHash(algorithm, &hash, &object[0], bytes, NULL, 0, 0) >= 0 &&
        BCryptHashData(hash, (PUCHAR)identity.data(), (ULONG)(identity.size() * sizeof(wchar_t)), 0) >= 0 && BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0;
    if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (ok) {
        std::wstring name = L"Z0Mcp"; wchar_t hex[3];
        for (int i = 0; i < 32; ++i) { swprintf_s(hex, 3, L"%02x", digest[i]); name += hex; }
        HRESULT result = create(name.c_str(), name.c_str(), L"Z0 MCP strict helper", NULL, 0, &sid);
        if (FAILED(result) && result == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) result = derive(name.c_str(), &sid);
        ok = SUCCEEDED(result) && sid;
        for (size_t i = 0; i < allowed.size() && ok; ++i) ok = AgentContainerGrant(allowed[i], sid);
    }
    FreeLibrary(library);
    if (!ok && sid) { FreeSid(sid); sid = NULL; } return sid;
}

static HANDLE CreateAgentProcessJob(int memory_mb, int cpu_seconds)
{
    if (memory_mb < 16 || memory_mb > 1024 || cpu_seconds < 10 || cpu_seconds > 3600) return NULL;
    HANDLE job = CreateJobObjectW(NULL, NULL); if (!job) return NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_JOB_TIME;
    limits.BasicLimitInformation.ActiveProcessLimit = 4;
    limits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = (__int64)cpu_seconds * 10000000;
    limits.ProcessMemoryLimit = (SIZE_T)memory_mb * 1024 * 1024;
    limits.JobMemoryLimit = (SIZE_T)memory_mb * 1024 * 1024;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { DWORD error = GetLastError(); CloseHandle(job); SetLastError(error); return NULL; }
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui = {};
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
        JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
    if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui))) { DWORD error = GetLastError(); CloseHandle(job); SetLastError(error); return NULL; }
    return job;
}

static bool CreateIsolatedAgentProcess(wchar_t* command, void* environment, const wchar_t* directory,
    DWORD flags, const STARTUPINFOW& startup, int memory_mb, int cpu_seconds, PROCESS_INFORMATION* process, HANDLE* job_out,
    const wchar_t* strict_roots = NULL)
{
    *job_out = NULL; ZeroMemory(process, sizeof(*process));
    HANDLE job = CreateAgentProcessJob(memory_mb, cpu_seconds), token = NULL, restricted = NULL;
    if (!job) return false;
    BYTE admin_buffer[SECURITY_MAX_SID_SIZE]; DWORD sid_size = sizeof(admin_buffer);
    SID_AND_ATTRIBUTES admin = {}; admin.Sid = admin_buffer;
    bool ok = CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin.Sid, &sid_size) != FALSE &&
        OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &token) != FALSE &&
        CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 1, &admin, 0, NULL, 0, NULL, &restricted) != FALSE;
    HANDLE inherited[3] = { NULL, NULL, NULL };
    HANDLE original[] = { startup.hStdInput, startup.hStdOutput, startup.hStdError };
    for (int i = 0; i < 3 && ok; ++i) {
        if (!original[i] || original[i] == INVALID_HANDLE_VALUE) original[i] = startup.hStdOutput;
        ok = DuplicateHandle(GetCurrentProcess(), original[i], GetCurrentProcess(), &inherited[i], 0, TRUE, DUPLICATE_SAME_ACCESS) != FALSE;
    }
    PSID container = strict_roots ? AgentContainerSid(command, strict_roots) : NULL;
    if (strict_roots && !container) ok = false;
    SIZE_T bytes = 0; DWORD attribute_count = strict_roots ? 2 : 1;
    InitializeProcThreadAttributeList(NULL, attribute_count, 0, &bytes);
    std::vector<BYTE> storage(bytes); STARTUPINFOEXW extended = {};
    extended.StartupInfo = startup; extended.StartupInfo.cb = sizeof(extended);
    extended.StartupInfo.hStdInput = inherited[0]; extended.StartupInfo.hStdOutput = inherited[1]; extended.StartupInfo.hStdError = inherited[2];
    extended.lpAttributeList = bytes ? (LPPROC_THREAD_ATTRIBUTE_LIST)&storage[0] : NULL;
    bool attributes = ok && extended.lpAttributeList && InitializeProcThreadAttributeList(extended.lpAttributeList, attribute_count, 0, &bytes) != FALSE;
    ok = attributes && UpdateProcThreadAttribute(extended.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited, sizeof(inherited), NULL, NULL) != FALSE;
    AgentSecurityCapabilities capabilities = {}; capabilities.sid = container;
    if (ok && strict_roots) ok = UpdateProcThreadAttribute(extended.lpAttributeList, 0, 0x00020009,
        &capabilities, sizeof(capabilities), NULL, NULL) != FALSE;
    if (ok) ok = CreateProcessAsUserW(restricted, NULL, command, NULL, NULL, TRUE,
        flags | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, environment, directory, &extended.StartupInfo, process) != FALSE;
    if (ok) {
        ok = AssignProcessToJobObject(job, process->hProcess) != FALSE && ResumeThread(process->hThread) != (DWORD)-1;
        if (!ok) { TerminateProcess(process->hProcess, 1); WaitForSingleObject(process->hProcess, 5000); CloseHandle(process->hThread); CloseHandle(process->hProcess); ZeroMemory(process, sizeof(*process)); }
    }
    if (attributes) DeleteProcThreadAttributeList(extended.lpAttributeList);
    for (int i = 0; i < 3; ++i) if (inherited[i]) CloseHandle(inherited[i]);
    if (restricted) CloseHandle(restricted); if (token) CloseHandle(token);
    if (container) FreeSid(container);
    if (!ok) { CloseHandle(job); return false; }
    *job_out = job; return true;
}
