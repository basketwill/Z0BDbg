#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include "ModelJson.h"
#include "AgentProcessIsolation.h"

typedef bool (*AgentPythonToolCall)(const std::string&, const std::string&,
    std::string*, std::string*, void*);
typedef void (*AgentPythonOutput)(const std::string&, void*);
typedef bool (*AgentPythonCancelled)(void*);

struct AgentPythonRunResult {
    bool ok;
    unsigned calls;
    std::string output, error;
    AgentPythonRunResult() : ok(false), calls(0) {}
};

static std::wstring AgentPythonExecutable()
{
    wchar_t configured[32768];
    DWORD length = GetEnvironmentVariableW(L"Z0B_PYTHON_EXE", configured, _countof(configured));
    if (length && length < _countof(configured) &&
        GetFileAttributesW(configured) != INVALID_FILE_ATTRIBUTES) return configured;
    length = GetEnvironmentVariableW(L"PATH", configured, _countof(configured));
    if (!length || length >= _countof(configured)) return L"";
    std::wstring paths(configured, length);
    for (size_t start = 0; start < paths.size();) {
        size_t end = paths.find(L';', start);
        if (end == std::wstring::npos) end = paths.size();
        std::wstring folder = paths.substr(start, end - start);
        if (folder.size() > 1 && folder[0] == L'"' && folder[folder.size() - 1] == L'"')
            folder = folder.substr(1, folder.size() - 2);
        if (!folder.empty() && folder.find(L"\\WindowsApps") == std::wstring::npos) {
            const wchar_t* names[] = { L"python3.exe", L"python.exe" };
            for (size_t i = 0; i < _countof(names); ++i) {
                std::wstring candidate = folder + L"\\" + names[i];
                DWORD attributes = GetFileAttributesW(candidate.c_str());
                if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY))
                    return candidate;
            }
        }
        start = end + 1;
    }
    return L"";
}

static std::wstring AgentPythonRunnerPath()
{
    wchar_t path[MAX_PATH];
#ifdef Z0B_AGENT_PLUGIN
    HMODULE module = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)&AgentPythonRunnerPath, &module)) return L"";
    DWORD length = GetModuleFileNameW(module, path, _countof(path));
#else
    DWORD length = GetModuleFileNameW(NULL, path, _countof(path));
#endif
    if (!length || length >= _countof(path)) return L"";
    std::wstring file(path, length);
    size_t slash = file.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L"";
    file.resize(slash + 1);
    file += L"DebugPythonRunner.py";
    return GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES ? L"" : file;
}

static bool AgentPythonWriteLine(HANDLE pipe, const std::string& line)
{
    std::string payload = line + '\n';
    for (size_t offset = 0; offset < payload.size();) {
        DWORD written = 0;
        if (!WriteFile(pipe, payload.data() + offset, (DWORD)(payload.size() - offset),
            &written, NULL) || !written) return false;
        offset += written;
    }
    return true;
}

static bool AgentPythonStartProcess(const std::wstring& python, std::wstring* command,
    HANDLE input, HANDLE output, PROCESS_INFORMATION* process, HANDLE* process_job)
{
    *process_job = CreateAgentProcessJob(256, 120);
    if (!*process_job) return false;
    HANDLE inherited[] = { input, output };
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    std::vector<BYTE> storage(bytes);
    STARTUPINFOEXW startup = {};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = output;
    startup.StartupInfo.hStdError = output;
    startup.lpAttributeList = bytes ? (LPPROC_THREAD_ATTRIBUTE_LIST)&storage[0] : NULL;
    bool initialized = startup.lpAttributeList &&
        InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes) != FALSE;
    bool ok = initialized && UpdateProcThreadAttribute(startup.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), NULL, NULL) != FALSE &&
        CreateProcessW(python.c_str(), &(*command)[0], NULL, NULL, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            NULL, NULL, &startup.StartupInfo, process) != FALSE;
    if (ok) {
        ok = AssignProcessToJobObject(*process_job, process->hProcess) != FALSE &&
            ResumeThread(process->hThread) != (DWORD)-1;
        if (!ok) {
            TerminateProcess(process->hProcess, 1);
            WaitForSingleObject(process->hProcess, 5000);
            CloseHandle(process->hThread);
            CloseHandle(process->hProcess);
            ZeroMemory(process, sizeof(*process));
        }
    }
    if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
    if (!ok) { CloseHandle(*process_job); *process_job = NULL; }
    return ok;
}

static bool RunAgentDebugPython(const std::string& code,
    const std::vector<std::string>& tools, unsigned max_calls, DWORD timeout_ms,
    AgentPythonToolCall call, AgentPythonOutput output, AgentPythonCancelled cancelled,
    void* context, AgentPythonRunResult* result)
{
    *result = AgentPythonRunResult();
    std::wstring python = AgentPythonExecutable(), runner = AgentPythonRunnerPath();
    if (python.empty() || runner.empty()) {
        result->error = "Python 3 or DebugPythonRunner.py is unavailable.";
        return false;
    }
    SECURITY_ATTRIBUTES security = { sizeof(security), NULL, TRUE };
    HANDLE input_read = NULL, input_write = NULL, output_read = NULL, output_write = NULL;
    HANDLE process_job = NULL;
    PROCESS_INFORMATION process = {};
    bool started = CreatePipe(&input_read, &input_write, &security, 0) &&
        CreatePipe(&output_read, &output_write, &security, 0);
    if (started) {
        std::wstring command = L"\"" + python + L"\" -I -u \"" + runner + L"\"";
        started = AgentPythonStartProcess(python, &command, input_read, output_write,
            &process, &process_job);
    }
    DWORD start_error = started ? ERROR_SUCCESS : GetLastError();
    if (input_read) CloseHandle(input_read);
    if (output_write) CloseHandle(output_write);
    if (!started) {
        if (input_write) CloseHandle(input_write);
        if (output_read) CloseHandle(output_read);
        char detail[128];
        sprintf_s(detail, sizeof(detail), "Could not start the bounded Python worker (Win32 %lu).", start_error);
        result->error = detail;
        return false;
    }
    std::string request = "{\"code\":";
    ModelJson::quote(&request, code);
    request += ",\"tools\":[";
    for (size_t i = 0; i < tools.size(); ++i) {
        if (i) request += ',';
        ModelJson::quote(&request, tools[i]);
    }
    request += "]}";
    bool running = AgentPythonWriteLine(input_write, request);
    if (!running) result->error = "Could not send the Python script to the worker.";
    std::string pending;
    DWORD started_at = GetTickCount();
    while (running && !result->ok && result->error.empty()) {
        if ((cancelled && cancelled(context)) || GetTickCount() - started_at >= timeout_ms) {
            result->error = cancelled && cancelled(context) ? "Python script cancelled." : "Python script timed out.";
            break;
        }
        DWORD available = 0;
        if (!PeekNamedPipe(output_read, NULL, 0, NULL, &available, NULL)) {
            DWORD exit_code = 0;
            GetExitCodeProcess(process.hProcess, &exit_code);
            char detail[128];
            sprintf_s(detail, sizeof(detail), "Python worker closed before reporting completion (exit 0x%08lx).", exit_code);
            result->error = detail;
            break;
        }
        if (!available) { Sleep(10); continue; }
        char bytes[4096]; DWORD read = 0;
        if (!ReadFile(output_read, bytes, (std::min)(available, (DWORD)sizeof(bytes)), &read, NULL) || !read) {
            result->error = "Could not read the Python worker response.";
            break;
        }
        pending.append(bytes, read);
        if (pending.size() > 65536) { result->error = "Python worker response is too large."; break; }
        size_t newline;
        while ((newline = pending.find('\n')) != std::string::npos && result->error.empty()) {
            std::string line = pending.substr(0, newline);
            pending.erase(0, newline + 1);
            ModelJson message;
            if (!ModelJson::parse(line, &message) || message.kind != ModelJson::OBJECT) {
                result->error = "Python worker returned invalid JSON: " + line.substr(0, 300); break;
            }
            const ModelJson* kind = message.get("kind");
            if (!kind || kind->kind != ModelJson::STRING) {
                result->error = "Python worker response has no kind."; break;
            }
            if (kind->value == "done") { result->ok = true; break; }
            if (kind->value == "error") {
                const ModelJson* error = message.get("message");
                result->error = error && error->kind == ModelJson::STRING ? error->value : "Python script failed.";
                break;
            }
            if (kind->value == "print") {
                const ModelJson* text = message.get("text");
                if (!text || text->kind != ModelJson::STRING ||
                    result->output.size() + text->value.size() + 1 > 4096) {
                    result->error = "Python script output exceeded 4 KiB."; break;
                }
                result->output += text->value + '\n';
                if (output) output(text->value, context);
                continue;
            }
            if (kind->value != "call") { result->error = "Unknown Python worker message."; break; }
            const ModelJson* name = message.get("name"), *arguments = message.get("arguments");
            if (!name || name->kind != ModelJson::STRING || !arguments ||
                arguments->kind != ModelJson::OBJECT ||
                (std::find)(tools.begin(), tools.end(), name->value) == tools.end() ||
                ++result->calls > max_calls) {
                result->error = "Python tool call is invalid or exceeded its call limit."; break;
            }
            std::string data, error;
            bool ok = call(name->value, arguments->raw, &data, &error, context);
            std::string reply = "{\"kind\":\"reply\",\"ok\":";
            reply += ok ? "true,\"data\":" + data : "false,\"error\":";
            if (!ok) ModelJson::quote(&reply, error);
            reply += '}';
            if (!AgentPythonWriteLine(input_write, reply)) {
                result->error = "Could not reply to the Python worker."; break;
            }
        }
    }
    CloseHandle(input_write);
    CloseHandle(output_read);
    CloseHandle(process_job);
    WaitForSingleObject(process.hProcess, 1000);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return result->ok;
}
