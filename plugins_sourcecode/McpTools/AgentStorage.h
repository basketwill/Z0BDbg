#pragma once
#include "AgentAccessPolicy.h"

struct AgentStorageFile { std::wstring path; unsigned __int64 bytes, modified; };
static bool AgentStorageScan(const std::wstring& root, std::vector<AgentStorageFile>* files, unsigned __int64* bytes, int depth = 0) {
    DWORD attributes = GetFileAttributesW(root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT || depth > 8) return false;
    WIN32_FIND_DATAW found; HANDLE scan = FindFirstFileW((root + L"\\*").c_str(), &found);
    if (scan == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    bool ok = true;
    do {
        if (wcscmp(found.cFileName, L".") == 0 || wcscmp(found.cFileName, L"..") == 0 || found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        std::wstring path = root + L"\\" + found.cFileName;
        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { if (!AgentStorageScan(path, files, bytes, depth + 1)) { ok = false; break; } }
        else {
            AgentStorageFile file; file.path = path; file.bytes = ((unsigned __int64)found.nFileSizeHigh << 32) | found.nFileSizeLow;
            file.modified = ((unsigned __int64)found.ftLastWriteTime.dwHighDateTime << 32) | found.ftLastWriteTime.dwLowDateTime;
            files->push_back(file); *bytes += file.bytes;
            if (files->size() > 50000) { ok = false; break; }
        }
    } while (FindNextFileW(scan, &found));
    DWORD error = GetLastError(); FindClose(scan);
    return ok && (error == ERROR_NO_MORE_FILES || error == ERROR_SUCCESS);
}
class AgentStorageReservation {
    HANDLE mutex; bool owned;
public:
    AgentStorageReservation() : mutex(NULL), owned(false) {}
    ~AgentStorageReservation() { if (owned) ReleaseMutex(mutex); if (mutex) CloseHandle(mutex); }
    bool acquire(const std::wstring& root, const std::wstring& path, unsigned __int64 size, unsigned quota_mb, bool append = false) {
        if (root.empty()) return false;
        std::wstring full_root, full_path;
        if (!AccessCanonicalPath(root, &full_root) || !AccessCanonicalPath(path, &full_path)) return false;
        bool within = full_path == full_root || (full_path.size() > full_root.size() && full_path.compare(0, full_root.size(), full_root) == 0 && full_path[full_root.size()] == L'\\');
        if (!within) return true;
        if (!AccessFileAllowed(path, root.c_str())) return false;
        if (size <= 256 && (full_path.substr(full_path.find_last_of(L'\\') + 1) == L"stop" ||
            (full_path.size() >= 6 && full_path.substr(full_path.size() - 6) == L".pause") ||
            (full_path.size() >= 7 && full_path.substr(full_path.size() - 7) == L".cancel"))) return true;
        std::wstring name = L"Local\\Z0McpStorage-";
        unsigned long hash = 2166136261UL; for (size_t i = 0; i < full_root.size(); ++i) { hash ^= full_root[i]; hash *= 16777619UL; }
        wchar_t suffix[16]; swprintf_s(suffix, 16, L"%08lx", hash); name += suffix;
        mutex = CreateMutexW(NULL, FALSE, name.c_str());
        DWORD wait = mutex ? WaitForSingleObject(mutex, 3000) : WAIT_FAILED;
        owned = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED; if (!owned) return false;
        std::vector<AgentStorageFile> files; unsigned __int64 used = 0, old = 0;
        if (!AgentStorageScan(root, &files, &used)) return false;
        for (size_t i = 0; i < files.size(); ++i) if (lstrcmpiW(files[i].path.c_str(), path.c_str()) == 0) old = files[i].bytes;
        unsigned __int64 limit = (unsigned __int64)quota_mb * 1024 * 1024;
        return append ? used + size <= limit : used - old + size <= limit;
    }
};
