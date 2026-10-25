#pragma once
#include <windows.h>
#include <strsafe.h>
#include <deque>
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>
#include <string.h>

struct AgentTerminalGlyph {
    wchar_t first, second;
    WORD color;
    int width;
};

class AgentTerminalUi {
    HANDLE input_, output_, stop_, ready_, thread_;
    DWORD input_mode_, output_mode_;
    bool active_, vt_, hidden_, working_;
    DWORD working_started_;
    int working_phase_;
    volatile LONG* cancel_flag_;
    CRITICAL_SECTION lock_;
    std::deque<AgentTerminalGlyph> transcript_;
    std::deque<INPUT_RECORD> keys_;
    std::wstring prompt_, status_, question_, activity_;
    std::wstring work_phase_;
    int work_step_, work_steps_, work_hits_, work_hit_target_;
    std::vector<std::wstring> panel_;
    size_t cursor_;
    int scroll_, wheel_, row_count_, columns_;
    int body_rows_, frame_width_, input_row_, drag_x_, drag_y_;
    DWORD drag_tick_;
    bool selecting_, selected_, right_down_, drag_scrolling_;
    struct SelectionPoint { int x, row; };
    SelectionPoint selection_start_, selection_end_;
    std::vector<std::vector<CHAR_INFO> > transcript_rows_;
    static void copyText(const std::wstring& text) {
        if (!OpenClipboard(NULL)) return;
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
        if (!memory) { CloseClipboard(); return; }
        wchar_t* destination = (wchar_t*)GlobalLock(memory);
        if (!destination) { GlobalFree(memory); CloseClipboard(); return; }
        memcpy(destination, text.c_str(), (text.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(memory);
        if (EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, memory)) memory = NULL;
        if (memory) GlobalFree(memory);
        CloseClipboard();
    }
    void copyTranscript() {
        std::wstring text;
        for (size_t i = 0; i < transcript_.size(); ++i) {
            const AgentTerminalGlyph& glyph = transcript_[i];
            if (glyph.first == L'\n') text += L"\r\n";
            else { text += glyph.first; if (glyph.second) text += glyph.second; }
        }
        copyText(text);
    }
    static bool before(SelectionPoint a, SelectionPoint b) {
        return a.row < b.row || (a.row == b.row && a.x < b.x);
    }
    SelectionPoint pointAt(int x, int y) const {
        SelectionPoint point = { (std::max)(0, (std::min)(x, frame_width_ - 1)),
            (std::max)(0, row_count_ - body_rows_ - scroll_) +
            (std::max)(0, (std::min)(y, body_rows_ - 1)) };
        return point;
    }
    void scrollSelection() {
        if (!selecting_ || !drag_scrolling_ || body_rows_ < 1) return;
        int direction = drag_y_ <= 0 ? 1 : drag_y_ >= body_rows_ - 1 ? -1 : 0;
        int maximum = (std::max)(0, row_count_ - body_rows_);
        int next = (std::max)(0, (std::min)(scroll_ + direction, maximum));
        if (next == scroll_) return;
        scroll_ = next;
        selection_end_ = pointAt(drag_x_, drag_y_);
        selected_ = before(selection_end_, selection_start_) || before(selection_start_, selection_end_);
        render();
    }
    bool selectedCell(int x, int y) const {
        if (!selected_ || y < 0 || y >= body_rows_) return false;
        SelectionPoint start = selection_start_, end = selection_end_;
        if (before(end, start)) std::swap(start, end);
        SelectionPoint cell = pointAt(x, y);
        return !before(cell, start) && !before(end, cell);
    }
    void copySelection() {
        if (!selected_ || transcript_rows_.empty()) return;
        SelectionPoint start = selection_start_, end = selection_end_;
        if (before(end, start)) std::swap(start, end);
        std::wstring text;
        for (int y = start.row; y <= end.row && y < (int)transcript_rows_.size(); ++y) {
            int first = y == start.row ? start.x : 0;
            int last = y == end.row ? end.x : frame_width_ - 1;
            std::wstring line;
            for (int x = first; x <= last; ++x) {
                if (x < (int)transcript_rows_[y].size()) {
                    const CHAR_INFO& cell = transcript_rows_[y][x];
                    if (!(cell.Attributes & COMMON_LVB_TRAILING_BYTE)) line += cell.Char.UnicodeChar;
                } else line += L' ';
            }
            while (!line.empty() && line[line.size() - 1] == L' ') line.resize(line.size() - 1);
            if (y != start.row) text += L"\r\n";
            text += line;
        }
        copyText(text);
    }
    void queuePaste() {
        INPUT_RECORD paste = {};
        paste.EventType = KEY_EVENT;
        paste.Event.KeyEvent.bKeyDown = TRUE;
        paste.Event.KeyEvent.wRepeatCount = 1;
        paste.Event.KeyEvent.wVirtualKeyCode = 'V';
        paste.Event.KeyEvent.dwControlKeyState = LEFT_CTRL_PRESSED;
        if (keys_.size() < 1024) {
            keys_.push_back(paste);
            SetEvent(ready_);
        }
    }
    void mouse(const MOUSE_EVENT_RECORD& event) {
        if (event.dwEventFlags == MOUSE_WHEELED) {
            wheel_ += (SHORT)HIWORD(event.dwButtonState);
            int lines = wheel_ / WHEEL_DELTA * 3;
            wheel_ %= WHEEL_DELTA;
            scroll_ = (std::max)(0, scroll_ + lines);
            if (!selecting_) selected_ = false;
            render();
            if (selecting_) {
                selection_end_ = pointAt(drag_x_, drag_y_);
                selected_ = before(selection_end_, selection_start_) || before(selection_start_, selection_end_);
                render();
            }
            return;
        }
        bool right_down = (event.dwButtonState & RIGHTMOST_BUTTON_PRESSED) != 0;
        if (right_down && !right_down_) {
            if (selected_ && event.dwMousePosition.Y != input_row_) {
                copySelection();
                selecting_ = selected_ = false;
                render();
            } else queuePaste();
        }
        right_down_ = right_down;
        if (right_down) return;
        COORD position = event.dwMousePosition;
        bool left_down = (event.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED) != 0;
        if (!selecting_ && (position.X < 0 || position.X >= frame_width_ ||
            position.Y < 0 || position.Y >= body_rows_)) return;
        if (left_down) {
            if (!selecting_) {
                selection_start_ = pointAt(position.X, position.Y);
                selecting_ = true;
            }
            drag_x_ = position.X; drag_y_ = position.Y;
            drag_scrolling_ = event.dwEventFlags == MOUSE_MOVED &&
                (position.Y <= 0 || position.Y >= body_rows_ - 1);
            if (drag_scrolling_) { drag_tick_ = GetTickCount(); scrollSelection(); }
            selection_end_ = pointAt(position.X, position.Y);
            selected_ = before(selection_end_, selection_start_) || before(selection_start_, selection_end_);
            render();
        } else if (selecting_) {
            selection_end_ = pointAt(position.X, position.Y);
            selected_ = before(selection_end_, selection_start_) || before(selection_start_, selection_end_);
            selecting_ = drag_scrolling_ = false;
            if (selected_) copySelection();
            render();
        }
    }
    static DWORD WINAPI InputThread(LPVOID context) {
        AgentTerminalUi* ui = (AgentTerminalUi*)context;
        HANDLE waits[] = { ui->stop_, ui->input_ };
        for (;;) {
            EnterCriticalSection(&ui->lock_);
            if (ui->working_) {
                int phase = (int)(((GetTickCount() - ui->working_started_) / 500) % 3);
                if (phase != ui->working_phase_) { ui->working_phase_ = phase; ui->render(); }
            }
            if (ui->drag_scrolling_ && GetTickCount() - ui->drag_tick_ >= 100) {
                ui->drag_tick_ = GetTickCount();
                ui->scrollSelection();
            }
            LeaveCriticalSection(&ui->lock_);
            DWORD wait = WaitForMultipleObjects(2, waits, FALSE, 100);
            if (wait == WAIT_TIMEOUT) continue;
            if (wait != WAIT_OBJECT_0 + 1) break;
            INPUT_RECORD record; DWORD read = 0;
            if (!ReadConsoleInputW(ui->input_, &record, 1, &read) || !read) break;
            EnterCriticalSection(&ui->lock_);
            if (record.EventType == MOUSE_EVENT) ui->mouse(record.Event.MouseEvent);
            else if (record.EventType == WINDOW_BUFFER_SIZE_EVENT) ui->render();
            else if (record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown) {
                WORD key = record.Event.KeyEvent.wVirtualKeyCode;
                DWORD modifiers = record.Event.KeyEvent.dwControlKeyState;
                if (key == VK_ESCAPE && ui->working_ && ui->cancel_flag_) {
                    InterlockedExchange(ui->cancel_flag_, 1);
                    ui->render();
                }
                else if (key == 'C' && ui->working_ && ui->cancel_flag_ &&
                    (modifiers & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) &&
                    !(modifiers & SHIFT_PRESSED)) {
                    InterlockedExchange(ui->cancel_flag_, 1);
                    ui->render();
                }
                else if (key == 'C' && (modifiers & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) &&
                    (modifiers & SHIFT_PRESSED)) {
                    if (ui->selected_) ui->copySelection(); else ui->copyTranscript();
                }
                else if (key == VK_PRIOR || key == VK_NEXT) {
                    CONSOLE_SCREEN_BUFFER_INFO info;
                    if (GetConsoleScreenBufferInfo(ui->output_, &info)) {
                        int page = (std::max)(1, (int)info.srWindow.Bottom - info.srWindow.Top - 2);
                        ui->scroll_ = (std::max)(0, ui->scroll_ + (key == VK_PRIOR ? page : -page));
                        ui->render();
                    }
                }
                else if (ui->keys_.size() < 1024) { ui->keys_.push_back(record); SetEvent(ui->ready_); }
            }
            LeaveCriticalSection(&ui->lock_);
        }
        SetEvent(ui->ready_);
        return 0;
    }
    static void addText(std::vector<CHAR_INFO>* cells, const std::wstring& text, WORD color, int limit) {
        for (size_t i = 0; i < text.size() && (int)cells->size() < limit; ++i) {
            wchar_t ch = text[i]; WORD type = 0;
            GetStringTypeW(CT_CTYPE3, &ch, 1, &type);
            bool pair = ch >= 0xd800 && ch <= 0xdbff && i + 1 < text.size() && text[i + 1] >= 0xdc00 && text[i + 1] <= 0xdfff;
            bool wide = pair || (type & (C3_FULLWIDTH | C3_IDEOGRAPH));
            if (wide && (int)cells->size() + 2 > limit) break;
            CHAR_INFO cell = {}; cell.Char.UnicodeChar = ch; cell.Attributes = color;
            if (wide && !pair) cell.Attributes |= COMMON_LVB_LEADING_BYTE;
            cells->push_back(cell);
            if (wide) {
                cell.Char.UnicodeChar = pair ? text[++i] : ch;
                cell.Attributes = color | (pair ? 0 : COMMON_LVB_TRAILING_BYTE);
                cells->push_back(cell);
            }
        }
    }
public:
    AgentTerminalUi() : input_(NULL), output_(NULL), stop_(NULL), ready_(NULL), thread_(NULL),
        input_mode_(0), output_mode_(0), active_(false), vt_(false), hidden_(false), working_(false), working_started_(0), working_phase_(0), cancel_flag_(NULL),
        cursor_(0), scroll_(0), wheel_(0), row_count_(0), columns_(0),
        body_rows_(0), frame_width_(0), input_row_(-1), drag_x_(0), drag_y_(0), drag_tick_(0),
        selecting_(false), selected_(false), right_down_(false), drag_scrolling_(false),
        work_step_(0), work_steps_(0), work_hits_(0), work_hit_target_(0) {
        InitializeCriticalSection(&lock_);
    }
    ~AgentTerminalUi() {
        if (stop_) SetEvent(stop_);
        if (thread_) { WaitForSingleObject(thread_, INFINITE); CloseHandle(thread_); }
        if (active_) {
            if (vt_) { DWORD written; WriteConsoleW(output_, L"\x1b[?1002l\x1b[?1006l\x1b[?1049l", 24, &written, NULL); }
            SetConsoleMode(input_, input_mode_); SetConsoleMode(output_, output_mode_);
        }
        if (stop_) CloseHandle(stop_); if (ready_) CloseHandle(ready_);
        DeleteCriticalSection(&lock_);
    }
    bool begin(HANDLE input, HANDLE output) {
        input_ = input; output_ = output;
        if (!GetConsoleMode(input_, &input_mode_) || !GetConsoleMode(output_, &output_mode_)) return false;
        stop_ = CreateEventW(NULL, TRUE, FALSE, NULL); ready_ = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!stop_ || !ready_) return false;
        vt_ = SetConsoleMode(output_, output_mode_ | 0x0004) != FALSE;
        // Receive wheel events directly; Quick Edit otherwise consumes the
        // mouse wheel before the custom transcript can scroll.
        if (!SetConsoleMode(input_, (input_mode_ | ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT |
            ENABLE_MOUSE_INPUT) & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_QUICK_EDIT_MODE))) {
            SetConsoleMode(output_, output_mode_); return false;
        }
        active_ = true;
        if (vt_) { DWORD written; WriteConsoleW(output_, L"\x1b[?1049h\x1b[?1002h\x1b[?1006h", 24, &written, NULL); }
        thread_ = CreateThread(NULL, 0, InputThread, this, 0, NULL);
        if (!thread_) {
            if (vt_) { DWORD written; WriteConsoleW(output_, L"\x1b[?1002l\x1b[?1006l\x1b[?1049l", 24, &written, NULL); }
            SetConsoleMode(input_, input_mode_); SetConsoleMode(output_, output_mode_); active_ = false;
        }
        return thread_ != NULL;
    }
    bool owns(HANDLE output) const { return active_ && output == output_; }
    std::wstring status() { EnterCriticalSection(&lock_); std::wstring value = status_; LeaveCriticalSection(&lock_); return value; }
    void setStatus(const std::wstring& value) {
        EnterCriticalSection(&lock_);
        status_ = value.substr(0, 160);
        render();
        LeaveCriticalSection(&lock_);
    }
    void working(bool enabled, volatile LONG* cancel_flag = NULL) {
        EnterCriticalSection(&lock_);
        working_ = enabled; cancel_flag_ = enabled ? cancel_flag : NULL;
        activity_ = enabled ? L"Preparing request" : L"";
        work_phase_.clear(); work_step_ = work_steps_ = work_hits_ = work_hit_target_ = 0;
        working_started_ = GetTickCount(); working_phase_ = 0;
        render();
        LeaveCriticalSection(&lock_);
    }
    void activity(const std::wstring& text) {
        EnterCriticalSection(&lock_);
        activity_ = text.substr(0, 160);
        if (working_) render();
        LeaveCriticalSection(&lock_);
    }
    void progress(const std::wstring& phase, const std::wstring& detail,
        int step, int steps) {
        EnterCriticalSection(&lock_);
        work_phase_ = phase.substr(0, 32);
        activity_ = detail.substr(0, 160);
        work_step_ = step; work_steps_ = steps;
        if (working_) render();
        LeaveCriticalSection(&lock_);
    }
    void progressHits(int hits, int target) {
        EnterCriticalSection(&lock_);
        work_hits_ = hits; work_hit_target_ = target;
        if (working_) render();
        LeaveCriticalSection(&lock_);
    }
    void append(const std::wstring& text, WORD color) {
        EnterCriticalSection(&lock_);
        for (size_t i = 0; i < text.size(); ++i) {
            wchar_t ch = text[i];
            if (ch == L'\r') continue;
            if ((ch < L' ' && ch != L'\n' && ch != L'\t') || ch == 0x7f) continue;
            AgentTerminalGlyph glyph = {}; glyph.first = ch; glyph.color = color; glyph.width = 1;
            if (ch >= 0xd800 && ch <= 0xdbff && i + 1 < text.size() && text[i + 1] >= 0xdc00 && text[i + 1] <= 0xdfff) {
                glyph.second = text[++i]; glyph.width = 2;
            }
            else { WORD type = 0; GetStringTypeW(CT_CTYPE3, &ch, 1, &type); if (type & (C3_FULLWIDTH | C3_IDEOGRAPH)) glyph.width = 2; }
            if (ch == L'\t') { glyph.first = L' '; for (int t = 0; t < 3; ++t) transcript_.push_back(glyph); }
            transcript_.push_back(glyph);
        }
        while (transcript_.size() > 512 * 1024) transcript_.pop_front();
        render(); LeaveCriticalSection(&lock_);
    }
    void prompt(const std::wstring& text, size_t cursor, const std::wstring& status, bool hidden = false) {
        EnterCriticalSection(&lock_); prompt_ = text; cursor_ = cursor; status_ = status; hidden_ = hidden;
        render(); LeaveCriticalSection(&lock_);
    }
    void question(const std::wstring& text) {
        EnterCriticalSection(&lock_);
        question_.clear();
        bool space = false;
        for (size_t i = 0; i < text.size(); ++i) {
            wchar_t ch = text[i];
            if (ch <= L' ' || (ch >= 0x7f && ch <= 0x9f)) {
                space = !question_.empty();
                continue;
            }
            if (space) question_ += L' ';
            space = false;
            question_ += ch;
            if (question_.size() >= 256) break;
        }
        render(); LeaveCriticalSection(&lock_);
    }
    void panel(const std::vector<std::wstring>& rows) {
        EnterCriticalSection(&lock_); panel_ = rows;
        if (panel_.size() > 9) panel_.resize(9);
        for (size_t r = 0; r < panel_.size(); ++r) for (size_t c = 0; c < panel_[r].size(); ++c)
            if (panel_[r][c] < L' ' || panel_[r][c] == 0x7f) panel_[r][c] = L' ';
        render(); LeaveCriticalSection(&lock_);
    }
    void follow() { EnterCriticalSection(&lock_); scroll_ = 0; selecting_ = selected_ = false; LeaveCriticalSection(&lock_); }
    bool next(INPUT_RECORD* record) {
        for (;;) {
            EnterCriticalSection(&lock_);
            if (!keys_.empty()) { *record = keys_.front(); keys_.pop_front(); LeaveCriticalSection(&lock_); return true; }
            ResetEvent(ready_); LeaveCriticalSection(&lock_);
            HANDLE waits[] = { thread_, ready_ };
            if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) return false;
        }
    }
    // Both hosts use a screen-sized buffer; only the transcript viewport scrolls.
    void render() {
        CONSOLE_SCREEN_BUFFER_INFO info;
        if (!GetConsoleScreenBufferInfo(output_, &info)) return;
        int width = info.srWindow.Right - info.srWindow.Left + 1;
        int height = info.srWindow.Bottom - info.srWindow.Top + 1;
        if (width < 4 || height < 3) return;
        SMALL_RECT window = { 0, 0, (SHORT)(width - 1), (SHORT)(height - 1) };
        if (info.srWindow.Left || info.srWindow.Top) SetConsoleWindowInfo(output_, TRUE, &window);
        COORD size = { (SHORT)width, (SHORT)height };
        SetConsoleScreenBufferSize(output_, size);
        std::vector<std::vector<CHAR_INFO> > rows(1);
        for (size_t i = 0; i < transcript_.size(); ++i) {
            const AgentTerminalGlyph& glyph = transcript_[i];
            if (glyph.first == L'\n') { rows.push_back(std::vector<CHAR_INFO>()); continue; }
            if ((int)rows.back().size() + glyph.width > width) rows.push_back(std::vector<CHAR_INFO>());
            std::wstring text(1, glyph.first); if (glyph.second) text += glyph.second;
            addText(&rows.back(), text, glyph.color, width);
        }
        int panel_rows = (std::min)((int)panel_.size(), (std::max)(0, height - 4));
        int input_row = height - 2;
        int working_rows = working_ ? (input_row - panel_rows >= 2 ? 2 : 1) : 0;
        int body = input_row - panel_rows - working_rows;
        if (frame_width_ != width || body_rows_ != body) selecting_ = selected_ = drag_scrolling_ = false;
        body_rows_ = body; frame_width_ = width; input_row_ = input_row;
        if (scroll_ && width == columns_ && (int)rows.size() > row_count_) scroll_ += (int)rows.size() - row_count_;
        transcript_rows_.swap(rows);
        row_count_ = (int)transcript_rows_.size(); columns_ = width;
        int maximum = (std::max)(0, row_count_ - body);
        scroll_ = (std::min)(scroll_, maximum);
        int first = maximum - scroll_;
        CHAR_INFO blank = {}; blank.Char.UnicodeChar = L' '; blank.Attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        std::vector<CHAR_INFO> frame(width * height, blank);
        for (int y = 0; y < body && first + y < row_count_; ++y)
            for (size_t x = 0; x < transcript_rows_[first + y].size(); ++x) frame[y * width + x] = transcript_rows_[first + y][x];
        if (selected_) for (int y = 0; y < body; ++y) for (int x = 0; x < width; ++x)
            if (selectedCell(x, y)) {
                WORD color = frame[y * width + x].Attributes;
                frame[y * width + x].Attributes = (color & ~0xff) |
                    ((color & 0x0f) << 4) | ((color >> 4) & 0x0f);
            }
        if (working_) {
            std::vector<CHAR_INFO> cells;
            wchar_t seconds[32];
            StringCchPrintfW(seconds, _countof(seconds), L"%lus",
                (GetTickCount() - working_started_) / 1000);
            std::wstring label = L"  Working" + std::wstring(working_phase_ + 1, L'.');
            label += L" (";
            label += seconds;
            label += cancel_flag_ ?
                (InterlockedCompareExchange(cancel_flag_, 0, 0) ? L" | Interrupting)" :
                    (width < 70 ? L" | Esc)" : L" | Esc to interrupt)")) : L")";
            if (work_steps_ > 0) {
                wchar_t step[48];
                StringCchPrintfW(step, _countof(step), L"  Step %d/%d", work_step_, work_steps_);
                label += step;
            }
            if (work_hit_target_ > 0) {
                wchar_t hits[48];
                StringCchPrintfW(hits, _countof(hits), L"  Hits %d/%d", work_hits_, work_hit_target_);
                label += hits;
            }
            addText(&cells, label,
                FOREGROUND_GREEN | FOREGROUND_INTENSITY, width - 1);
            for (size_t c = 0; c < cells.size(); ++c) frame[body * width + c] = cells[c];
            if (working_rows == 2) {
                cells.clear();
                addText(&cells, L"  \x2514\x2500 " + (work_phase_.empty() ? L"" : work_phase_ + L": ") + activity_,
                    FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY, width - 1);
                for (size_t c = 0; c < cells.size(); ++c) frame[(body + 1) * width + c] = cells[c];
            }
        }
        for (int r = 0; r < panel_rows; ++r) {
            std::vector<CHAR_INFO> cells;
            addText(&cells, panel_[r], FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY, width - 1);
            for (size_t c = 0; c < cells.size(); ++c) frame[(body + working_rows + r) * width + c] = cells[c];
        }
        size_t start = cursor_; int cursor_cells = 0;
        if (!hidden_) while (start > 0) {
            size_t previous = start - 1;
            if (prompt_[previous] >= 0xdc00 && prompt_[previous] <= 0xdfff && previous) --previous;
            WORD type = 0; GetStringTypeW(CT_CTYPE3, &prompt_[previous], 1, &type);
            int cells = start - previous == 2 || (type & (C3_FULLWIDTH | C3_IDEOGRAPH)) ? 2 : 1;
            if (cursor_cells + cells >= width - 3) break;
            cursor_cells += cells; start = previous;
        }
        std::vector<CHAR_INFO> footer;
        addText(&footer, L"> ", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY, width);
        if (!hidden_) addText(&footer, prompt_.substr(start), blank.Attributes, width - 1);
        for (size_t x = 0; x < footer.size(); ++x) frame[input_row * width + x] = footer[x];
        std::vector<CHAR_INFO> question_cells;
        if (width >= 32 && !question_.empty()) {
            int limit = (std::min)(40, width / 2);
            addText(&question_cells, question_, FOREGROUND_GREEN | FOREGROUND_BLUE, limit);
            std::vector<CHAR_INFO> full_question;
            addText(&full_question, question_, FOREGROUND_GREEN | FOREGROUND_BLUE, width);
            if (full_question.size() > question_cells.size() && question_cells.size() >= 3) {
                question_cells.resize(question_cells.size() - 3);
                if (!question_cells.empty() && (question_cells.back().Attributes & COMMON_LVB_LEADING_BYTE))
                    question_cells.pop_back();
                addText(&question_cells, L"...", FOREGROUND_GREEN | FOREGROUND_BLUE, limit);
            }
        }
        int status_limit = question_cells.empty() ? width - 1 : width - (int)question_cells.size() - 2;
        footer.clear(); addText(&footer, status_, FOREGROUND_GREEN | FOREGROUND_INTENSITY, status_limit);
        for (size_t x = 0; x < footer.size(); ++x) frame[(input_row + 1) * width + x] = footer[x];
        std::vector<CHAR_INFO> help;
        addText(&help, L"/h", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY, width);
        addText(&help, L" \u67e5\u770b\u5e2e\u52a9", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE, width);
        int help_start = (int)footer.size() + 2;
        bool show_help = help_start + (int)help.size() + 2 <= status_limit;
        if (show_help)
            for (size_t x = 0; x < help.size(); ++x)
                frame[(input_row + 1) * width + help_start + x] = help[x];
        int question_start = show_help ? help_start + (int)help.size() + 3 : (int)footer.size() + 3;
        int question_space = width - question_start - 1;
        if (question_space < 3) question_cells.clear();
        else if ((int)question_cells.size() > question_space) {
            question_cells.resize(question_space - 3);
            if (!question_cells.empty() && (question_cells.back().Attributes & COMMON_LVB_LEADING_BYTE))
                question_cells.pop_back();
            addText(&question_cells, L"...", FOREGROUND_GREEN | FOREGROUND_BLUE, question_space);
        }
        for (size_t x = 0; x < question_cells.size(); ++x)
            frame[(input_row + 1) * width + question_start + x] = question_cells[x];
        COORD origin = { 0, 0 };
        COORD cursor = { (SHORT)(2 + cursor_cells), (SHORT)input_row };
        if (vt_) {
            // Explicit SGR preserves per-cell colors through ConPTY/Windows Terminal.
            std::wstring display = L"\x1b[?25l\x1b[?7l";
            const int ansi[] = { 0, 4, 2, 6, 1, 5, 3, 7 };
            WORD previous = 0xffff;
            for (int y = 0; y < height; ++y) {
                wchar_t sequence[48]; swprintf_s(sequence, 48, L"\x1b[%d;1H", y + 1); display += sequence;
                for (int x = 0; x < width; ++x) {
                    const CHAR_INFO& cell = frame[y * width + x];
                    if (cell.Attributes & COMMON_LVB_TRAILING_BYTE) continue;
                    WORD color = cell.Attributes & 0xff;
                    if (color != previous) {
                        int foreground = (color & FOREGROUND_INTENSITY ? 90 : 30) + ansi[color & 7];
                        int background = (color & BACKGROUND_INTENSITY ? 100 : 40) + ansi[(color >> 4) & 7];
                        swprintf_s(sequence, 48, L"\x1b[%d;%dm", foreground, background); display += sequence;
                        previous = color;
                    }
                    display += cell.Char.UnicodeChar;
                }
            }
            wchar_t sequence[48];
            swprintf_s(sequence, 48, L"\x1b[0m\x1b[%d;%dH\x1b[?7h\x1b[?25h", cursor.Y + 1, cursor.X + 1);
            display += sequence;
            DWORD written = 0;
            WriteConsoleW(output_, display.c_str(), (DWORD)display.size(), &written, NULL);
        }
        else {
            WriteConsoleOutputW(output_, &frame[0], size, origin, &window);
            SetConsoleCursorPosition(output_, cursor);
        }
    }
};
