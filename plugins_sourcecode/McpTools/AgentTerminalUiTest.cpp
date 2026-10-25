#include "McpServerApp.cpp"
#include <stdio.h>
#include <assert.h>
#include <crtdbg.h>

static std::wstring Row(HANDLE output, int y)
{
    CONSOLE_SCREEN_BUFFER_INFO info; assert(GetConsoleScreenBufferInfo(output, &info));
    std::wstring text(info.dwSize.X, L' '); COORD position = { 0, (SHORT)y }; DWORD read = 0;
    assert(ReadConsoleOutputCharacterW(output, &text[0], (DWORD)text.size(), position, &read));
    return text;
}
static void CheckFooter(HANDLE output, const wchar_t* input)
{
    CONSOLE_SCREEN_BUFFER_INFO info; assert(GetConsoleScreenBufferInfo(output, &info));
    assert(Row(output, info.srWindow.Bottom - 1).find(input) == 0);
    assert(Row(output, info.srWindow.Bottom).find(L"  model-test | high") == 0);
}
static void CheckTextColor(HANDLE output, const wchar_t* text, WORD expected)
{
    CONSOLE_SCREEN_BUFFER_INFO info; assert(GetConsoleScreenBufferInfo(output, &info));
    for (int y = 0; y <= info.srWindow.Bottom; ++y) {
        size_t x = Row(output, y).find(text); if (x == std::wstring::npos) continue;
        for (size_t i = 0; text[i]; ++i) {
            if (text[i] == L' ' || text[i] == L'\t') continue;
            WORD color = 0; DWORD read = 0; COORD position = { (SHORT)(x + i), (SHORT)y };
            assert(ReadConsoleOutputAttribute(output, &color, 1, position, &read));
            if ((color & 0xff) != expected) {
                fwprintf(stderr, L"Color mismatch for %s at %u: got 0x%02x, expected 0x%02x\n",
                    text, (unsigned)i, color & 0xff, expected);
                fwprintf(stderr, L"Row: %s\n", Row(output, y).c_str());
                assert(false);
            }
        }
        return;
    }
    assert(!"Expected colored text is missing");
}
int main(int argc, char**)
{
    ModelJson direct_result, text_result, error_result;
    assert(ModelJson::parse("{\"jsonrpc\":\"2.0\",\"result\":{\"ok\":true,\"hex\":\"90\"}}", &direct_result));
    assert(InternalToolContent(direct_result) == "{\"ok\":true,\"hex\":\"90\"}");
    assert(ModelJson::parse("{\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"first\"},{\"type\":\"text\",\"text\":\"second\"}],\"structuredContent\":{\"ignored\":true}}}", &text_result));
    assert(InternalToolContent(text_result) == "first\nsecond");
    assert(ModelJson::parse("{\"error\":{\"code\":-32004,\"message\":\"Denied\"}}", &error_result));
    assert(InternalToolContent(error_result).find("Denied") != std::string::npos);
    ModelJson model_request, model_response;
    assert(ModelJson::parse("{\"messages\":[{\"role\":\"system\",\"content\":\"rules\"},{\"role\":\"user\",\"content\":\"question\"}]}", &model_request));
    assert(InternalModelRequestContent(model_request) == "question");
    assert(ModelJson::parse("{\"choices\":[{\"message\":{\"content\":\"working\",\"tool_calls\":[{}]}}]}", &model_response));
    bool model_calls = false;
    assert(InternalModelResponseContent(model_response, &model_calls) == "working" && model_calls);
    ChatJob failure_job;
    SetDefaultConfig(&failure_job.cfg);
    std::wstring failure_title = InternalToolFailureTitle(&failure_job, "read_memory",
        "{\"error\":{\"code\":-32008,\"message\":\"Hook exited with code 1\\nRetry later\"}}");
    assert(failure_title == L"\x2022 Tool failed: read_memory\n  \x2514 Hook exited with code 1 Retry later");
    assert(InternalToolFailureTitle(&failure_job, "read_memory",
        "{\"result\":{\"ok\":false,\"message\":\"Access denied\"}}") ==
        L"\x2022 Tool failed: read_memory\n  \x2514 Access denied");
    _set_error_mode(_OUT_TO_STDERR); _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 1) {
        wchar_t executable[MAX_PATH]; assert(GetModuleFileNameW(NULL, executable, MAX_PATH));
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --child";
        STARTUPINFOW startup = {}; startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES; startup.wShowWindow = SW_HIDE;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE); startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE); startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION process = {};
        assert(CreateProcessW(executable, &command[0], NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &startup, &process));
        DWORD result = 1;
        if (WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0) assert(GetExitCodeProcess(process.hProcess, &result));
        else { TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 2000); }
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        return (int)result;
    }
    bool allocated = !GetConsoleWindow(); if (allocated) assert(AllocConsole());
    assert(AgentTerminalTitle(123).find(L"Z0bdbg Agent Terminal [123]") != std::wstring::npos);
    HANDLE input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE output = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
    assert(input != INVALID_HANDLE_VALUE && output != INVALID_HANDLE_VALUE);
    DWORD mode; assert(GetConsoleMode(input, &mode));
    {
        AgentTerminalUi ui; assert(ui.begin(input, output));
        g_terminal_ui = &ui;
        ui.prompt(L"draft text", 5, L"  model-test | high");
        ui.question(L"  inspect   CreateFileW\nread files  ");
        for (int i = 0; i < 150; ++i) { wchar_t line[64]; swprintf_s(line, 64, L"history-%03d\n", i); ui.append(line, FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
        CheckFooter(output, L"> draft text");
        CONSOLE_SCREEN_BUFFER_INFO footer_info; assert(GetConsoleScreenBufferInfo(output, &footer_info));
        std::wstring footer = Row(output, footer_info.srWindow.Bottom);
        assert(footer.find(L"inspect CreateFileW read files") != std::wstring::npos);
        assert(footer.find(L"/h ") != std::wstring::npos);
        assert(footer.find(L"inspect CreateFileW") - footer.find(L"/h ") <= 16);
        CheckTextColor(output, L"/h", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CONSOLE_SCREEN_BUFFER_INFO working_info; assert(GetConsoleScreenBufferInfo(output, &working_info));
        int working_row = working_info.srWindow.Bottom - 3;
        volatile LONG cancelled = 0;
        ui.working(true, &cancelled);
        assert(Row(output, working_row).find(L"  Working.") == 0);
        assert(Row(output, working_row + 1).find(L"  \x2514\x2500 Preparing request") == 0);
        ui.activity(L"Waiting for model (round 1)");
        assert(Row(output, working_row + 1).find(L"Waiting for model (round 1)") != std::wstring::npos);
        ChatJob model_event = {};
        model_event.console_output = output;
        AgentModelEvent(&model_event, "Model waiting for approval");
        assert(Row(output, working_row + 1).find(L"Model waiting for approval") != std::wstring::npos);
        ui.setStatus(L"  Approval required | type yes to execute");
        assert(Row(output, working_info.srWindow.Bottom).find(L"Approval required") != std::wstring::npos);
        ui.setStatus(L"  model-test | high");
        ui.progress(L"Model", L"Round 3", 2, 4);
        assert(Row(output, working_row).find(L"Step 2/4") != std::wstring::npos);
        assert(Row(output, working_row + 1).find(L"Model: Round 3") != std::wstring::npos);
        ui.progress(L"Tool", L"read_memory", 2, 4);
        assert(Row(output, working_row + 1).find(L"Tool: read_memory") != std::wstring::npos);
        ui.progressHits(6, 30);
        ui.progress(L"Event wait", L"Checking file path", 2, 4);
        assert(Row(output, working_row).find(L"Hits 6/30") != std::wstring::npos);
        assert(Row(output, working_row + 1).find(L"Event wait: Checking file path") != std::wstring::npos);
        ChatJob verifying = {};
        verifying.task_enabled = true;
        verifying.task.steps.resize(2);
        verifying.task.steps[0].status = "done";
        verifying.task.steps[1].status = "verifying";
        verifying.task.steps[1].title = "file path";
        AgentWorkingProgress(&verifying, L"Tool", L"read_memory");
        assert(Row(output, working_row + 1).find(L"Tool: read_memory | Verifying file path") != std::wstring::npos);
        SMALL_RECT narrow_working = { 0, 0, 49, 11 };
        assert(SetConsoleWindowInfo(output, TRUE, &narrow_working));
        ui.render();
        assert(Row(output, working_row).find(L"Step 2/2") != std::wstring::npos);
        assert(Row(output, working_row).find(L"Hits 6/30") != std::wstring::npos);
        CheckFooter(output, L"> draft text");
        SMALL_RECT normal_working = { 0, 0, 79, 11 };
        assert(SetConsoleWindowInfo(output, TRUE, &normal_working));
        ui.render();
        assert(Row(output, working_row).find(L"0s | Esc to interrupt") != std::wstring::npos);
        DWORD animation_started = GetTickCount();
        while (Row(output, working_row).find(L"  Working..") != 0 &&
            GetTickCount() - animation_started < 2000) Sleep(10);
        assert(Row(output, working_row).find(L"  Working..") == 0);
        animation_started = GetTickCount();
        while (Row(output, working_row).find(L"  Working...") != 0 &&
            GetTickCount() - animation_started < 2000) Sleep(10);
        assert(Row(output, working_row).find(L"  Working...") == 0);
        animation_started = GetTickCount();
        while (Row(output, working_row).find(L"  Working. ") != 0 &&
            GetTickCount() - animation_started < 2000) Sleep(10);
        assert(Row(output, working_row).find(L"  Working. ") == 0);
        ui.working(true, &cancelled);
        DWORD seconds_started = GetTickCount();
        while (Row(output, working_row).find(L"1s | Esc to interrupt") == std::wstring::npos &&
            GetTickCount() - seconds_started < 2000) Sleep(10);
        assert(Row(output, working_row).find(L"1s | Esc to interrupt") != std::wstring::npos);
        INPUT_RECORD escape = {}; escape.EventType = KEY_EVENT;
        escape.Event.KeyEvent.bKeyDown = TRUE;
        escape.Event.KeyEvent.wVirtualKeyCode = VK_ESCAPE;
        DWORD escape_written = 0;
        assert(WriteConsoleInputW(input, &escape, 1, &escape_written) && escape_written == 1);
        DWORD cancel_started = GetTickCount();
        while (!InterlockedCompareExchange(&cancelled, 0, 0) &&
            GetTickCount() - cancel_started < 2000) Sleep(10);
        assert(cancelled == 1);
        while (Row(output, working_row).find(L"Interrupting") == std::wstring::npos &&
            GetTickCount() - cancel_started < 2000) Sleep(10);
        assert(Row(output, working_row).find(L"Interrupting") != std::wstring::npos);
        InterlockedExchange(&cancelled, 0);
        INPUT_RECORD ctrl_c = {}; ctrl_c.EventType = KEY_EVENT;
        ctrl_c.Event.KeyEvent.bKeyDown = TRUE; ctrl_c.Event.KeyEvent.wVirtualKeyCode = 'C';
        ctrl_c.Event.KeyEvent.dwControlKeyState = LEFT_CTRL_PRESSED;
        DWORD ctrl_written = 0;
        assert(WriteConsoleInputW(input, &ctrl_c, 1, &ctrl_written) && ctrl_written == 1);
        DWORD ctrl_c_started = GetTickCount();
        while (!InterlockedCompareExchange(&cancelled, 0, 0) && GetTickCount() - ctrl_c_started < 2000) Sleep(10);
        assert(cancelled == 1);
        CheckFooter(output, L"> draft text");
        ChatJob progress = {};
        progress.console_output = output;
        ConsoleWriteColor(output, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
            L"  live_tool ");
        ConsoleWriteAgentDetail(&progress, L"", "{\"path\":\"C:\\\\data\\\\file.txt\"}", 4096);
        ConsoleWriteToolReceipt(&progress, "live_tool", true, 123);
        ConsoleWriteAgentDetail(&progress, L"  result  ", "{\"ok\":true,\"count\":2}", 4096);
        ConsoleWriteToolReceipt(&progress, "failed_tool", false, 456);
        CheckTextColor(output, L"Ran", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"Failed", FOREGROUND_RED | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"live_tool", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"\"path\"", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"\"ok\"", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        assert(Row(output, working_row).find(L"  Working") == 0);
        ui.working(false);
        assert(Row(output, working_row).find(L"  Working") != 0);
        std::wstring latest = Row(output, 0);
        INPUT_RECORD mouse = {}; mouse.EventType = MOUSE_EVENT;
        mouse.Event.MouseEvent.dwEventFlags = MOUSE_WHEELED;
        mouse.Event.MouseEvent.dwButtonState = (DWORD)(WORD)WHEEL_DELTA << 16;
        DWORD written; assert(WriteConsoleInputW(input, &mouse, 1, &written) && written == 1);
        DWORD started = GetTickCount();
        while (Row(output, 0) == latest && GetTickCount() - started < 2000) Sleep(10);
        std::wstring scrolled = Row(output, 0); assert(scrolled != latest);
        CheckFooter(output, L"> draft text");
        ui.append(L"new model output\n", FOREGROUND_GREEN);
        assert(Row(output, 0) == scrolled); CheckFooter(output, L"> draft text");
        WORD color = 0; DWORD read; COORD origin = { 0, 0 };
        assert(ReadConsoleOutputAttribute(output, &color, 1, origin, &read) && color == (FOREGROUND_BLUE | FOREGROUND_INTENSITY));
        SMALL_RECT resized = { 0, 0, 49, 11 }; assert(SetConsoleWindowInfo(output, TRUE, &resized));
        ui.prompt(L"draft text", 5, L"  model-test | high"); CheckFooter(output, L"> draft text");
        ui.question(L"Inspect a very long debugger question at CreateFileW entry");
        assert(GetConsoleScreenBufferInfo(output, &footer_info));
        footer = Row(output, footer_info.srWindow.Bottom);
        assert(footer.find(L"  model-test | high") == 0 && footer.find(L"...") != std::wstring::npos);
        ui.question(L"\u5728 CreateFileW \u65ad\u70b9\u89c2\u5bdf\u6587\u4ef6\u8bfb\u53d6\u5e76\u5206\u6790\u5b8c\u6574\u8c03\u7528\u8def\u5f84\uff0c\u518d\u68c0\u67e5\u6bcf\u6b21\u547d\u4e2d\u7684\u53c2\u6570\u548c\u8fd4\u56de\u503c");
        footer = Row(output, footer_info.srWindow.Bottom);
        assert(footer.find(L"  model-test | high") == 0 && footer.find(L"CreateFileW") != std::wstring::npos &&
            footer.find(L"...") != std::wstring::npos);
        ui.question(L"");
        assert(Row(output, footer_info.srWindow.Bottom).find(L"CreateFileW") == std::wstring::npos);
        ui.follow();
        ConsoleWriteHelp(output, L"  /help normal ");
        ConsoleWriteColor(output, FOREGROUND_RED | FOREGROUND_INTENSITY, L"RED ");
        ConsoleWriteColor(output, FOREGROUND_GREEN | FOREGROUND_INTENSITY, L"GREEN\n");
        CheckTextColor(output, L"/help", FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"normal", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        CheckTextColor(output, L"RED", FOREGROUND_RED | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"GREEN", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"model-test", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        CONSOLE_SCREEN_BUFFER_INFO selection_info; assert(GetConsoleScreenBufferInfo(output, &selection_info));
        int selection_y = -1, selection_x = -1;
        for (int y = 0; y < selection_info.srWindow.Bottom - 1; ++y) {
            size_t found = Row(output, y).find(L"/help");
            if (found != std::wstring::npos) { selection_y = y; selection_x = (int)found; break; }
        }
        assert(selection_y >= 0);
        INPUT_RECORD drag[3] = {};
        for (int i = 0; i < 3; ++i) {
            drag[i].EventType = MOUSE_EVENT;
            drag[i].Event.MouseEvent.dwMousePosition.X = (SHORT)(selection_x + (i ? 4 : 0));
            drag[i].Event.MouseEvent.dwMousePosition.Y = (SHORT)selection_y;
            drag[i].Event.MouseEvent.dwButtonState = i == 2 ? 0 : FROM_LEFT_1ST_BUTTON_PRESSED;
            drag[i].Event.MouseEvent.dwEventFlags = i == 1 ? MOUSE_MOVED : 0;
        }
        assert(WriteConsoleInputW(input, drag, 3, &written) && written == 3);
        std::wstring copied;
        started = GetTickCount();
        while (GetTickCount() - started < 2000) {
            if (OpenClipboard(NULL)) {
                HANDLE clipboard = GetClipboardData(CF_UNICODETEXT);
                const wchar_t* value = clipboard ? (const wchar_t*)GlobalLock(clipboard) : NULL;
                if (value) { copied = value; GlobalUnlock(clipboard); }
                CloseClipboard();
            }
            if (copied == L"/help") break;
            Sleep(10);
        }
        assert(copied == L"/help");
        COORD selection_cell = { (SHORT)selection_x, (SHORT)selection_y };
        WORD selection_color = 0;
        started = GetTickCount();
        while (GetTickCount() - started < 2000) {
            assert(ReadConsoleOutputAttribute(output, &selection_color, 1, selection_cell, &read));
            if ((selection_color & 0xff) == 0x90) break;
            Sleep(10);
        }
        assert((selection_color & 0xff) == 0x90);
        assert(OpenClipboard(NULL));
        assert(EmptyClipboard());
        HGLOBAL marker = GlobalAlloc(GMEM_MOVEABLE, 16 * sizeof(wchar_t));
        assert(marker);
        wchar_t* marker_text = (wchar_t*)GlobalLock(marker);
        assert(marker_text);
        wcscpy_s(marker_text, 16, L"before-click");
        GlobalUnlock(marker);
        assert(SetClipboardData(CF_UNICODETEXT, marker) == marker);
        CloseClipboard();
        INPUT_RECORD right = {}; right.EventType = MOUSE_EVENT;
        right.Event.MouseEvent.dwMousePosition.X = (SHORT)selection_x;
        right.Event.MouseEvent.dwMousePosition.Y = (SHORT)selection_y;
        right.Event.MouseEvent.dwButtonState = RIGHTMOST_BUTTON_PRESSED;
        assert(WriteConsoleInputW(input, &right, 1, &written) && written == 1);
        copied.clear(); started = GetTickCount();
        while (GetTickCount() - started < 2000) {
            if (OpenClipboard(NULL)) {
                HANDLE clipboard = GetClipboardData(CF_UNICODETEXT);
                const wchar_t* value = clipboard ? (const wchar_t*)GlobalLock(clipboard) : NULL;
                if (value) { copied = value; GlobalUnlock(clipboard); }
                CloseClipboard();
            }
            if (copied == L"/help") break;
            Sleep(10);
        }
        assert(copied == L"/help");
        started = GetTickCount();
        while (GetTickCount() - started < 2000) {
            assert(ReadConsoleOutputAttribute(output, &selection_color, 1, selection_cell, &read));
            if ((selection_color & 0xff) == (FOREGROUND_BLUE | FOREGROUND_INTENSITY)) break;
            Sleep(10);
        }
        assert((selection_color & 0xff) == (FOREGROUND_BLUE | FOREGROUND_INTENSITY));
        right.Event.MouseEvent.dwButtonState = 0;
        assert(WriteConsoleInputW(input, &right, 1, &written) && written == 1);
        // With no active selection, right-clicking transcript/output area also
        // pastes into the active prompt, matching the input-row behavior.
        right.Event.MouseEvent.dwMousePosition.Y = (SHORT)selection_y;
        right.Event.MouseEvent.dwButtonState = RIGHTMOST_BUTTON_PRESSED;
        assert(WriteConsoleInputW(input, &right, 1, &written) && written == 1);
        INPUT_RECORD transcript_paste_key; assert(ui.next(&transcript_paste_key));
        assert(transcript_paste_key.EventType == KEY_EVENT &&
            transcript_paste_key.Event.KeyEvent.wVirtualKeyCode == 'V' &&
            (transcript_paste_key.Event.KeyEvent.dwControlKeyState & LEFT_CTRL_PRESSED));
        right.Event.MouseEvent.dwButtonState = 0;
        assert(WriteConsoleInputW(input, &right, 1, &written) && written == 1);
        CONSOLE_SCREEN_BUFFER_INFO paste_info; assert(GetConsoleScreenBufferInfo(output, &paste_info));
        right.Event.MouseEvent.dwMousePosition.Y = paste_info.srWindow.Bottom - 1;
        right.Event.MouseEvent.dwButtonState = RIGHTMOST_BUTTON_PRESSED;
        assert(WriteConsoleInputW(input, &right, 1, &written) && written == 1);
        INPUT_RECORD paste_key; assert(ui.next(&paste_key));
        assert(paste_key.EventType == KEY_EVENT && paste_key.Event.KeyEvent.wVirtualKeyCode == 'V' &&
            (paste_key.Event.KeyEvent.dwControlKeyState & LEFT_CTRL_PRESSED));
        ui.follow();
        ui.prompt(L"draft text", 5, L"  model-test | high");
        CheckTextColor(output, L"/help", FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        ConsoleWriteContent(output, L"{\"path\":\"file\",\"count\":98765,\"ok\":true}\n");
        CheckTextColor(output, L"\"path\"", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"\"file\"", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"98765", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::vector<std::string> saved;
        saved.push_back(ChatMessage("assistant", "{\"history_key\":\"history_value\"}"));
        ShowTerminalHistory(output, saved);
        CheckTextColor(output, L"\"history_key\"", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"\"history_value\"", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        ConsoleWriteContent(output, L"inline { \"inline_key\": 98766 }\n");
        CheckTextColor(output, L"\"inline_key\"", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"98766", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        ConsoleWriteContent(output, L"## \u5206\u6790\u7ed3\u8bba\n**\u5173\u952e\u7ed3\u8bba**\n`WriteFile` 0x7FF76D8C634E\n");
        CheckTextColor(output, L"\u5206\u6790\u7ed3\u8bba", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"\u5173\u952e\u7ed3\u8bba", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"WriteFile", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"0x7FF76D8C634E", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        ConsoleWriteContent(output, L"```asm\nMOV RAX, 0x14001F9E6\nCALL KERNEL32!CreateFileW\n```\n");
        CheckTextColor(output, L"MOV", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"RAX", FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"CALL", FOREGROUND_RED | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"KERNEL32!CreateFileW", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        ConsoleWriteContent(output, L"{\"assembly\":\"JMP 14001F9E6\"}\n");
        CheckTextColor(output, L"JMP", FOREGROUND_RED | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"14001F9E6", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        ConsoleWriteContent(output, L"0000000140011005 E9DCE90000 JMP 14001F9E6\n");
        CheckTextColor(output, L"E9DCE90000", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        ConsoleWriteContent(output, L"CALL KERNEL32!CreateFileW\n");
        CheckTextColor(output, L"KERNEL32!CreateFileW", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        saved.clear();
        saved.push_back(ChatMessage("assistant", "## History heading\n**History conclusion** `HistoryCall`\n"));
        ShowTerminalHistory(output, saved);
        CheckTextColor(output, L"History heading", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"History conclusion", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        CheckTextColor(output, L"HistoryCall", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        ConsoleTextStyleState streamed;
        ConsoleWriteStyled(output, L"**\u6d41", &streamed);
        ConsoleWriteStyled(output, L"\u5f0f\u7ed3\u8bba**\n", &streamed, true);
        CheckTextColor(output, L"\u6d41\u5f0f\u7ed3\u8bba", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        ui.prompt(L"hidden-api-key", 14, L"  model-test | high", true);
        assert(Row(output, 10).find(L"hidden-api-key") == std::wstring::npos); CheckFooter(output, L"> ");
        std::vector<std::wstring> panel;
        panel.push_back(L"  task-panel [running]"); panel.push_back(L"  1 running slot 0 child-analysis"); ui.panel(panel);
        CONSOLE_SCREEN_BUFFER_INFO panel_info; assert(GetConsoleScreenBufferInfo(output, &panel_info));
        assert(Row(output, panel_info.srWindow.Bottom - 3).find(L"task-panel") != std::wstring::npos && Row(output, panel_info.srWindow.Bottom - 2).find(L"child-analysis") != std::wstring::npos);
        AgentTask visible_task;
        visible_task.title = "task-panel"; visible_task.state = "running";
        visible_task.steps.resize(2); visible_task.steps[0].status = "done"; visible_task.steps[0].title = "first";
        visible_task.steps[1].status = "running"; visible_task.steps[1].title = "child-analysis";
        UpdateAgentTaskPanel(visible_task);
        assert(Row(output, panel_info.srWindow.Bottom - 4).find(L"steps 2  current 2") != std::wstring::npos);
        CheckFooter(output, L"> "); ui.append(L"More output with a pinned subtask panel\n", FOREGROUND_GREEN);
        assert(Row(output, panel_info.srWindow.Bottom - 2).find(L"child-analysis") != std::wstring::npos); CheckFooter(output, L"> ");
        panel.clear(); ui.panel(panel);
        INPUT_RECORD key = {}; key.EventType = KEY_EVENT; key.Event.KeyEvent.bKeyDown = TRUE;
        key.Event.KeyEvent.wRepeatCount = 1; key.Event.KeyEvent.wVirtualKeyCode = 'A'; key.Event.KeyEvent.uChar.UnicodeChar = L'a';
        assert(WriteConsoleInputW(input, &key, 1, &written));
        INPUT_RECORD received; assert(ui.next(&received) && received.Event.KeyEvent.uChar.UnicodeChar == L'a');
        TerminalInputHistory input_history;
        input_history.add(L"first prompt");
        input_history.add(L"second prompt");
        std::wstring edited = L"unfinished draft"; size_t edit_cursor = edited.size();
        assert(input_history.navigate(true, &edited, &edit_cursor) && edited == L"second prompt");
        assert(input_history.navigate(true, &edited, &edit_cursor) && edited == L"first prompt");
        assert(input_history.navigate(false, &edited, &edit_cursor) && edited == L"second prompt");
        assert(input_history.navigate(false, &edited, &edit_cursor) && edited == L"unfinished draft");
        assert(!input_history.navigate(false, &edited, &edit_cursor));
        INPUT_RECORD input_keys[8] = {};
        const wchar_t* draft = L"draft";
        for (int i = 0; i < 5; ++i) {
            input_keys[i].EventType = KEY_EVENT;
            input_keys[i].Event.KeyEvent.bKeyDown = TRUE;
            input_keys[i].Event.KeyEvent.wRepeatCount = 1;
            input_keys[i].Event.KeyEvent.uChar.UnicodeChar = draft[i];
        }
        for (int i = 5; i < 8; ++i) {
            input_keys[i].EventType = KEY_EVENT;
            input_keys[i].Event.KeyEvent.bKeyDown = TRUE;
            input_keys[i].Event.KeyEvent.wRepeatCount = 1;
            input_keys[i].Event.KeyEvent.wVirtualKeyCode = i == 5 ? VK_UP : i == 6 ? VK_DOWN : VK_RETURN;
        }
        assert(WriteConsoleInputW(input, input_keys, 8, &written) && written == 8);
        std::wstring submitted;
        assert(ConsoleReadPrompt(input, output, L"  model-test | high", &submitted, false, &input_history));
        assert(submitted == L"draft");
        INPUT_RECORD recall[2] = {};
        for (int i = 0; i < 2; ++i) {
            recall[i].EventType = KEY_EVENT;
            recall[i].Event.KeyEvent.bKeyDown = TRUE;
            recall[i].Event.KeyEvent.wRepeatCount = 1;
            recall[i].Event.KeyEvent.wVirtualKeyCode = i ? VK_RETURN : VK_UP;
        }
        assert(WriteConsoleInputW(input, recall, 2, &written) && written == 2);
        assert(ConsoleReadPrompt(input, output, L"  model-test | high", &submitted, false, &input_history));
        assert(submitted == L"second prompt");
        wchar_t temp_path[MAX_PATH]; assert(GetTempPathW(MAX_PATH, temp_path));
        std::wstring store = std::wstring(temp_path) + L"agent-input-history-test";
        assert(SaveTerminalInputHistory(store, input_history));
        TerminalInputHistory restored;
        LoadTerminalInputHistory(store, &restored);
        assert(restored.entries.size() == 2 && restored.entries.back() == L"second prompt");
        DeleteFileW((store + L".input.json").c_str());
        ui.panel(std::vector<std::wstring>());
        ui.follow();
        for (int i = 0; i < 30; ++i) {
            wchar_t line[64]; swprintf_s(line, 64, L"drag-row-%02d\n", i);
            ui.append(line, FOREGROUND_GREEN);
        }
        CONSOLE_SCREEN_BUFFER_INFO drag_info; assert(GetConsoleScreenBufferInfo(output, &drag_info));
        int drag_body = drag_info.srWindow.Bottom - 1;
        std::wstring drag_top = Row(output, 0);
        std::wstring drag_anchor = Row(output, drag_body - 2);
        INPUT_RECORD scroll_drag[2] = {};
        for (int i = 0; i < 2; ++i) {
            scroll_drag[i].EventType = MOUSE_EVENT;
            scroll_drag[i].Event.MouseEvent.dwMousePosition.X = (SHORT)(i ? 0 : 11);
            scroll_drag[i].Event.MouseEvent.dwMousePosition.Y = (SHORT)(i ? 0 : drag_body - 2);
            scroll_drag[i].Event.MouseEvent.dwButtonState = FROM_LEFT_1ST_BUTTON_PRESSED;
            scroll_drag[i].Event.MouseEvent.dwEventFlags = i ? MOUSE_MOVED : 0;
        }
        assert(WriteConsoleInputW(input, scroll_drag, 2, &written) && written == 2);
        started = GetTickCount();
        while (Row(output, 0) == drag_top && GetTickCount() - started < 2000) Sleep(10);
        assert(Row(output, 0) != drag_top);
        Sleep(350);
        INPUT_RECORD release = scroll_drag[1]; release.Event.MouseEvent.dwButtonState = 0;
        assert(WriteConsoleInputW(input, &release, 1, &written) && written == 1);
        copied.clear(); started = GetTickCount();
        while (GetTickCount() - started < 2000) {
            if (OpenClipboard(NULL)) {
                HANDLE clipboard = GetClipboardData(CF_UNICODETEXT);
                const wchar_t* value = clipboard ? (const wchar_t*)GlobalLock(clipboard) : NULL;
                if (value) { copied = value; GlobalUnlock(clipboard); }
                CloseClipboard();
            }
            if (copied.find(L"drag-row-") != std::wstring::npos && copied.find(drag_anchor.substr(0, 11)) != std::wstring::npos) break;
            Sleep(10);
        }
        assert(copied.find(L"drag-row-") != std::wstring::npos);
        assert(copied.find(drag_anchor.substr(0, 11)) != std::wstring::npos);
        assert((int)std::count(copied.begin(), copied.end(), L'\n') >= drag_body);
        g_terminal_ui = NULL;
    }
    DWORD restored; assert(GetConsoleMode(input, &restored) && restored == mode);
    CloseHandle(output); CloseHandle(input); if (allocated) FreeConsole();
    puts("PASS: one-line working animation, mouse scrolling, cross-viewport drag selection, right-click copy and paste from any area, pinned draft/model footer, stable scroll during output, retained colors, resize, hidden secrets, key delivery and mode restoration");
    return 0;
}
