#include "../../../Z0BufferPcTools/StdAfx.h"
#include "../../../Z0BufferPcTools/OllyDbgListView.h"
#include "AgentInternalList.h"

// The existing list view implementation is compiled into the plugin unchanged.
#include "../../../Z0BufferPcTools/OllyDbgListView.cpp"

struct AgentInternalList : public COllyDbgListView {
    std::vector<std::wstring> lines;
    std::vector<COLORREF> colors;
    std::vector<std::wstring> visual_lines;
    std::vector<COLORREF> visual_colors;
    std::vector< std::vector<COLORREF> > visual_styles;
    std::vector<size_t> visual_starts;
    std::vector<size_t> visual_offsets;
    std::vector<bool> fence_after;
    HFONT bold_font;
    bool editable;
    UINT submit_command;
    size_t cursor;
    COLORREF background;
    std::wstring prompt;
    std::wstring context;
    std::wstring header;
    int header_width;
    int reflow_width;
    int output_scroll;
    int input_scroll;
    struct TextPosition { size_t line, offset; };
    TextPosition selection_first;
    TextPosition selection_last;
    bool selecting;
    POINT drag_point;
    POINT drag_origin;
    bool selection_dragged;
    bool input_active;
    bool prompt_selected_all;

    explicit AgentInternalList(bool input, const std::wstring& heading, UINT command) : bold_font(NULL),
        editable(input), submit_command(command), cursor(0), background(RGB(255, 251, 240)),
        header(std::wstring(L"  ") + heading),
        header_width(0), reflow_width(0),
        output_scroll(0), input_scroll(0),
        selecting(false), selection_dragged(false),
        input_active(false), prompt_selected_all(false) {
        ClearSelection();
        drag_point.x = drag_point.y = 0;
        drag_origin = drag_point;
    }

    ~AgentInternalList() { if (bold_font) DeleteObject(bold_font); }

    void CreateBoldFont() {
        HFONT regular = (HFONT)::SendMessageW(m_hWnd, WM_GETFONT, 0, 0);
        if (!regular) regular = (HFONT)::GetStockObject(DEFAULT_GUI_FONT);
        LOGFONTW face = {};
        if (GetObjectW(regular, sizeof(face), &face)) {
            face.lfWeight = FW_BOLD;
            bold_font = CreateFontIndirectW(&face);
            if (bold_font) ::SendMessageW(m_hWnd, WM_SETFONT, (WPARAM)bold_font, TRUE);
        }
    }

    HFONT TranscriptFont(COLORREF color, HFONT regular) const {
        return color == RGB(180, 0, 0) && bold_font ? bold_font : regular;
    }

    int HeaderHeight() const {
        HWND heading = GetHeader();
        RECT bounds = {};
        return heading && ::GetWindowRect(heading, &bounds)
            ? bounds.bottom - bounds.top : 0;
    }

    void ResizeHeaderColumn() {
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        if (client.right > 0 && client.right != header_width &&
            SetColumnWidth(0, client.right)) header_width = client.right;
    }

    void ShowHeader() {
        HWND heading = GetHeader();
        if (!heading) return;
        HDITEMW item = {};
        item.mask = HDI_TEXT;
        item.pszText = const_cast<wchar_t*>(header.c_str());
        ::SendMessageW(heading, HDM_SETITEMW, 0, (LPARAM)&item);
        ::ShowWindow(heading, SW_SHOW);
        ::InvalidateRect(heading, NULL, TRUE);
    }

    static bool Before(TextPosition a, TextPosition b) {
        return a.line < b.line || (a.line == b.line && a.offset < b.offset);
    }

    static bool SurrogatePair(wchar_t first, wchar_t second) {
        return first >= 0xD800 && first <= 0xDBFF &&
            second >= 0xDC00 && second <= 0xDFFF;
    }

    bool HasSelection() const {
        return selection_first.line != (size_t)-1 &&
            (Before(selection_first, selection_last) || Before(selection_last, selection_first));
    }

    void ClearSelection() {
        selection_first.line = selection_last.line = (size_t)-1;
        selection_first.offset = selection_last.offset = 0;
    }

    size_t SourceLineAt(size_t visual) const {
        return (size_t)(std::upper_bound(visual_starts.begin(), visual_starts.end(), visual) -
            visual_starts.begin() - 1);
    }

    TextPosition PositionAt(int x, int y, bool character = false) const {
        TextPosition position = { 0, 0 };
        if (visual_lines.empty()) return position;
        int visual = output_scroll + (y - HeaderHeight() - 8) / 21;
        visual = (std::max)(0, (std::min)(visual, (int)visual_lines.size() - 1));
        position.line = SourceLineAt((size_t)visual);
        position.offset = visual_offsets[visual];
        const std::wstring& text = visual_lines[visual];
        if (x <= 12 || text.empty()) return position;
        HDC dc = ::GetDC(m_hWnd);
        HFONT font = (HFONT)::SendMessageW(m_hWnd, WM_GETFONT, 0, 0);
        if (!font) font = (HFONT)::GetStockObject(DEFAULT_GUI_FONT);
        HGDIOBJ old = SelectObject(dc, TranscriptFont(visual_colors[visual], font));
        std::vector<int> extents(text.size());
        SIZE size = {};
        if (GetTextExtentExPointW(dc, text.c_str(), (int)text.size(), 0x7fffffff,
            NULL, &extents[0], &size)) {
            int pixel = x - 12;
            for (size_t i = 0; i < extents.size(); ++i) {
                int left = i ? extents[i - 1] : 0;
                if (pixel < (character ? extents[i] :
                    left + (extents[i] - left) / 2)) break;
                ++position.offset;
            }
        }
        SelectObject(dc, old);
        ::ReleaseDC(m_hWnd, dc);
        const std::wstring& source = lines[position.line];
        if (position.offset && position.offset < source.size() &&
            SurrogatePair(source[position.offset - 1], source[position.offset]))
            --position.offset;
        return position;
    }

    bool SelectedRange(size_t visual, size_t* first, size_t* last) const {
        if (!HasSelection()) return false;
        TextPosition begin = selection_first, end = selection_last;
        if (Before(end, begin)) std::swap(begin, end);
        size_t line = SourceLineAt(visual);
        if (line < begin.line || line > end.line) return false;
        size_t row_start = visual_offsets[visual];
        size_t row_end = row_start + visual_lines[visual].size();
        size_t selected_start = line == begin.line ? (std::max)(begin.offset, row_start) : row_start;
        size_t selected_end = line == end.line ? (std::min)(end.offset, row_end) : row_end;
        if (selected_start >= selected_end) return false;
        *first = selected_start - row_start;
        *last = selected_end - row_start;
        return true;
    }

    void UpdateDragSelection() {
        if (!selection_dragged) {
            if (abs(drag_point.x - drag_origin.x) <= 3 &&
                abs(drag_point.y - drag_origin.y) <= 3) return;
            selection_dragged = true;
        }
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        int top = HeaderHeight() + 8;
        int split = editable ? InputTop() : client.bottom;
        int visible = (std::max)(1, (split - HeaderHeight() - 16) / 21);
        int bottom = (std::min)(split - 8, top + visible * 21);
        if (bottom <= top || visual_lines.empty()) return;
        int direction = drag_point.y < top ? -1 : drag_point.y >= bottom ? 1 : 0;
        if (direction) {
            output_scroll += direction;
            UpdateScroll(false);
            ::SetTimer(m_hWnd, 18, 50, NULL);
        } else ::KillTimer(m_hWnd, 18);
        int y = (std::max)(top, (std::min)((int)drag_point.y, bottom - 1));
        selection_last = PositionAt(drag_point.x, y);
        ::InvalidateRect(m_hWnd, NULL, FALSE);
    }

    void CopyText(const std::wstring& value) const {
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, (value.size() + 1) * sizeof(wchar_t));
        if (!memory) return;
        wchar_t* data = (wchar_t*)GlobalLock(memory);
        if (!data) { GlobalFree(memory); return; }
        memcpy(data, value.c_str(), (value.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(memory);
        if (OpenClipboard(m_hWnd)) {
            EmptyClipboard();
            if (SetClipboardData(CF_UNICODETEXT, memory)) memory = NULL;
            CloseClipboard();
        }
        if (memory) GlobalFree(memory);
    }

    void CopySelection() const {
        if (editable && input_active) {
            CopyText(prompt);
            return;
        }
        if (!HasSelection()) return;
        TextPosition first = selection_first, last = selection_last;
        if (Before(last, first)) std::swap(first, last);
        std::wstring value;
        for (size_t i = first.line; i <= last.line && i < lines.size(); ++i) {
            if (i > first.line) value += L"\r\n";
            size_t begin = i == first.line ? first.offset : 0;
            size_t end = i == last.line ? last.offset : lines[i].size();
            value += lines[i].substr(begin, end - begin);
        }
        CopyText(value);
    }

    void PasteClipboardText() {
        if (!editable || !OpenClipboard(m_hWnd)) return;
        HANDLE data = GetClipboardData(CF_UNICODETEXT);
        if (data) {
            const wchar_t* pasted = (const wchar_t*)GlobalLock(data);
            if (pasted) {
                std::wstring insert;
                for (const wchar_t* p = pasted; *p; ++p)
                    if (*p != L'\r') insert += *p;
                std::wstring value = prompt_selected_all ? L"" : prompt;
                size_t position = prompt_selected_all ? 0 : cursor;
                value.insert(position, insert);
                GlobalUnlock(data);
                SetText(value);
                cursor = position + insert.size();
                UpdateCaret();
            }
        }
        CloseClipboard();
    }

    virtual void SetColumns() {
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        InsertColumn(0, header.c_str(), LVCFMT_LEFT, client.right, 0);
        SetColumnNums(1);
    }

    virtual void OnInitialUpdate() {
        COllyDbgListView::OnInitialUpdate();
        UpdateScroll();
    }

    int InputTop() const {
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        return client.bottom - 124;
    }

    void LayoutInput(HDC dc, int width, std::vector<std::wstring>* rows,
        std::vector<size_t>* starts) const {
        rows->assign(1, L"");
        starts->assign(1, 0);
        int row_width = 0;
        for (size_t i = 0; i < prompt.size(); ++i) {
            if (prompt[i] == L'\n') {
                rows->push_back(L"");
                starts->push_back(i + 1);
                row_width = 0;
                continue;
            }
            SIZE size = {};
            GetTextExtentPoint32W(dc, &prompt[i], 1, &size);
            if (row_width && row_width + size.cx > width) {
                rows->push_back(L"");
                starts->push_back(i);
                row_width = 0;
            }
            rows->back() += prompt[i];
            row_width += size.cx;
        }
    }

    size_t InputCursorRow(const std::vector<size_t>& starts) const {
        return (size_t)(std::upper_bound(starts.begin(), starts.end(), cursor) - starts.begin() - 1);
    }

    static bool CodeWord(const std::wstring& word) {
        static const wchar_t* words[] = {
            L"auto", L"bool", L"break", L"case", L"catch", L"class", L"const",
            L"def", L"do", L"else", L"enum", L"false", L"for", L"from",
            L"function", L"if", L"import", L"int", L"let", L"new",
            L"nullptr", L"null", L"return", L"static", L"struct", L"switch",
            L"this", L"throw", L"true", L"try", L"var", L"void", L"while",
            L"mov", L"lea", L"call", L"jmp", L"push", L"pop", L"cmp", L"test",
            L"je", L"jne", L"jz", L"jnz", L"ret", L"xor", L"add", L"sub"
        };
        for (size_t i = 0; i < _countof(words); ++i)
            if (_wcsicmp(word.c_str(), words[i]) == 0) return true;
        return false;
    }

    static void PaintToken(std::vector<COLORREF>* styles, size_t first, size_t last,
        COLORREF color) {
        for (size_t i = first; i < last && i < styles->size(); ++i)
            (*styles)[i] = color;
    }

    static std::vector<COLORREF> Highlight(const std::wstring& line,
        COLORREF base, bool code) {
        const COLORREF cyan = RGB(0, 96, 125);
        const COLORREF green = RGB(0, 120, 70);
        const COLORREF amber = RGB(153, 91, 0);
        const COLORREF violet = RGB(112, 61, 142);
        std::vector<COLORREF> styles(line.size(), base);
        size_t lead = line.find_first_not_of(L" \t");
        if (lead != std::wstring::npos && line[lead] == L'#')
            PaintToken(&styles, lead, line.size(), cyan);
        if (lead != std::wstring::npos && line.compare(lead, 3, L"```") == 0) {
            PaintToken(&styles, lead, line.size(), cyan);
            return styles;
        }
        bool inline_code = false;
        for (size_t i = 0; i < line.size();) {
            wchar_t ch = line[i];
            if (ch == L'`') {
                inline_code = !inline_code;
                styles[i++] = cyan;
                continue;
            }
            if (inline_code) { styles[i++] = cyan; continue; }
            if (i + 1 < line.size() && ch == L'*' && line[i + 1] == L'*') {
                size_t end = line.find(L"**", i + 2);
                if (end != std::wstring::npos) {
                    PaintToken(&styles, i, end + 2, amber);
                    i = end + 2;
                    continue;
                }
            }
            if (ch == L'"' || (code && ch == L'\'')) {
                size_t end = i + 1;
                while (end < line.size()) {
                    if (line[end] == L'\\' && end + 1 < line.size()) { end += 2; continue; }
                    if (line[end++] == ch) break;
                }
                size_t next = line.find_first_not_of(L" \t", end);
                PaintToken(&styles, i, end,
                    ch == L'"' && next != std::wstring::npos && line[next] == L':' ? cyan : green);
                i = end;
                continue;
            }
            if (ch == L'0' && i + 2 < line.size() && (line[i + 1] == L'x' || line[i + 1] == L'X') &&
                iswxdigit(line[i + 2])) {
                size_t end = i + 3;
                while (end < line.size() && iswxdigit(line[end])) ++end;
                PaintToken(&styles, i, end, amber);
                i = end;
                continue;
            }
            if (iswdigit(ch) || (ch == L'-' && i + 1 < line.size() && iswdigit(line[i + 1]))) {
                size_t end = i + 1;
                while (end < line.size() && (iswdigit(line[end]) || line[end] == L'.')) ++end;
                PaintToken(&styles, i, end, amber);
                i = end;
                continue;
            }
            if (iswalpha(ch) || ch == L'_') {
                size_t end = i + 1;
                while (end < line.size() && (iswalnum(line[end]) || line[end] == L'_')) ++end;
                std::wstring word = line.substr(i, end - i);
                if (word == L"true" || word == L"false" || word == L"null")
                    PaintToken(&styles, i, end, violet);
                else if (code && CodeWord(word))
                    PaintToken(&styles, i, end, cyan);
                else if (end < line.size() && line[end] == L'!' && end + 1 < line.size()) {
                    size_t symbol_end = end + 1;
                    while (symbol_end < line.size() && (iswalnum(line[symbol_end]) || line[symbol_end] == L'_')) ++symbol_end;
                    PaintToken(&styles, i, symbol_end, green);
                    end = symbol_end;
                } else if (end < line.size() && line[end] == L':' && end + 1 < line.size() &&
                    (line[end + 1] == L'\\' || line[end + 1] == L'/')) {
                    size_t path_end = end + 2;
                    while (path_end < line.size() && line[path_end] != L' ' && line[path_end] != L'\t' && line[path_end] != L'"') ++path_end;
                    PaintToken(&styles, i, path_end, green);
                    end = path_end;
                }
                i = end;
                continue;
            }
            if (code && (ch == L'{' || ch == L'}' || ch == L'[' || ch == L']'))
                styles[i] = violet;
            ++i;
        }
        return styles;
    }

    void Reflow(size_t first = 0) {
        if (first >= lines.size()) first = 0;
        if (first && first < visual_starts.size()) {
            size_t count = visual_starts[first];
            visual_lines.resize(count);
            visual_colors.resize(count);
            visual_styles.resize(count);
            visual_offsets.resize(count);
            visual_starts.resize(first);
        } else {
            first = 0;
            visual_lines.clear();
            visual_colors.clear();
            visual_styles.clear();
            visual_offsets.clear();
            visual_starts.clear();
        }
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        reflow_width = client.right;
        int available = client.right - 36;
        if (available < 60) available = 60;
        HDC dc = ::GetDC(m_hWnd);
        HFONT font = (HFONT)::SendMessageW(m_hWnd, WM_GETFONT, 0, 0);
        if (!font) font = (HFONT)::GetStockObject(DEFAULT_GUI_FONT);
        HGDIOBJ old = font ? SelectObject(dc, font) : NULL;
        bool fenced = first ? fence_after[first - 1] : false;
        fence_after.resize(first);
        for (size_t i = first; i < lines.size(); ++i) {
            if (font) SelectObject(dc, TranscriptFont(colors[i], font));
            visual_starts.push_back(visual_lines.size());
            const std::wstring& source = lines[i];
            size_t lead = source.find_first_not_of(L" \t");
            bool fence = lead != std::wstring::npos && source.compare(lead, 3, L"```") == 0;
            bool json = lead != std::wstring::npos &&
                (source[lead] == L'{' || source[lead] == L'}' || source[lead] == L'[' ||
                 source[lead] == L']' || source[lead] == L'"');
            std::vector<COLORREF> styles = Highlight(source, colors[i], fenced || json);
            std::wstring segment;
            std::vector<COLORREF> segment_styles;
            size_t segment_start = 0;
            std::vector<int> extents(source.size());
            SIZE total_extent = {};
            bool measured = source.empty() || GetTextExtentExPointW(dc, source.c_str(),
                (int)source.size(), 0x7fffffff, NULL,
                extents.empty() ? NULL : &extents[0], &total_extent) != FALSE;
            int width = 0;
            for (size_t j = 0; j < source.size(); ++j) {
                int char_width = 0;
                if (measured) char_width = extents[j] - (j ? extents[j - 1] : 0);
                else {
                    SIZE size = {};
                    GetTextExtentPoint32W(dc, &source[j], 1, &size);
                    char_width = size.cx;
                }
                if (!segment.empty() && width + char_width > available &&
                    !(j && SurrogatePair(source[j - 1], source[j]))) {
                    visual_lines.push_back(segment);
                    visual_colors.push_back(colors[i]);
                    visual_styles.push_back(segment_styles);
                    visual_offsets.push_back(segment_start);
                    segment.clear();
                    segment_styles.clear();
                    segment_start = j;
                    width = 0;
                }
                segment += source[j];
                segment_styles.push_back(styles[j]);
                width += char_width;
            }
            visual_lines.push_back(segment);
            visual_colors.push_back(colors[i]);
            visual_styles.push_back(segment_styles);
            visual_offsets.push_back(segment_start);
            if (fence) fenced = !fenced;
            fence_after.push_back(fenced);
        }
        if (old) SelectObject(dc, old);
        ::ReleaseDC(m_hWnd, dc);
    }

    void UpdateScroll(bool reflow = true, size_t first = 0) {
        if (reflow) Reflow(first);
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        int visible = ((editable ? InputTop() : client.bottom) - HeaderHeight() - 16) / 21;
        if (visible < 1) visible = 1;
        int maximum = (int)visual_lines.size() - visible;
        if (maximum < 0) maximum = 0;
        if (output_scroll < 0) output_scroll = 0;
        if (output_scroll > maximum) output_scroll = maximum;
        SCROLLINFO info = {};
        info.cbSize = sizeof(info);
        info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        info.nMin = 0;
        info.nMax = visual_lines.empty() ? 0 : (int)visual_lines.size() - 1;
        info.nPage = visible;
        info.nPos = output_scroll;
        ::SetScrollInfo(m_hWnd, SB_VERT, &info, TRUE);
        ResizeHeaderColumn();
    }

    void PaintComposite() {
        PAINTSTRUCT paint;
        HDC target = ::BeginPaint(m_hWnd, &paint);
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        if (client.right <= 0 || client.bottom <= 0) {
            ::EndPaint(m_hWnd, &paint);
            return;
        }
        HDC dc = CreateCompatibleDC(target);
        HBITMAP bitmap = CreateCompatibleBitmap(target, client.right, client.bottom);
        HGDIOBJ old_bitmap = SelectObject(dc, bitmap);
        HBRUSH fill = CreateSolidBrush(background);
        FillRect(dc, &client, fill);
        DeleteObject(fill);
        HFONT font = (HFONT)::SendMessageW(m_hWnd, WM_GETFONT, 0, 0);
        if (!font) font = (HFONT)::GetStockObject(DEFAULT_GUI_FONT);
        HGDIOBJ old_font = font ? SelectObject(dc, font) : NULL;
        SetBkMode(dc, TRANSPARENT);

        int split = editable ? InputTop() : client.bottom;
        RECT output = { 12, HeaderHeight() + 8, client.right - 12, split - 8 };
        int visible = (split - HeaderHeight() - 16) / 21;
        if (visible < 1) visible = 1;
        if (visual_lines.empty() && editable) {
            RECT empty = { 13, HeaderHeight() + 18, client.right - 13, HeaderHeight() + 46 };
            ::SetTextColor(dc, RGB(112, 121, 124));
            DrawTextW(dc, L"No conversation yet", -1, &empty, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        }
        for (int row = 0; row < visible && output_scroll + row < (int)visual_lines.size(); ++row) {
            int index = output_scroll + row;
            if (font) SelectObject(dc, TranscriptFont(visual_colors[index], font));
            RECT line = { output.left, output.top + row * 21, output.right, output.top + (row + 1) * 21 };
            size_t selected_first = 0, selected_last = 0;
            bool selected = SelectedRange((size_t)index, &selected_first, &selected_last);
            const std::wstring& content = visual_lines[index];
            if (selected) {
                SIZE before = {}, extent = {};
                if (selected_first)
                    GetTextExtentPoint32W(dc, content.c_str(), (int)selected_first, &before);
                GetTextExtentPoint32W(dc, content.c_str(), (int)selected_last, &extent);
                line.left = output.left + before.cx;
                line.right = output.left + extent.cx;
                HBRUSH highlight = CreateSolidBrush(RGB(210, 225, 229));
                FillRect(dc, &line, highlight);
                DeleteObject(highlight);
                line.left = output.left;
                line.right = output.right;
            }
            if (!editable && !visual_lines[index].empty() &&
                visual_colors[index] != RGB(35, 35, 35)) {
                HBRUSH accent = CreateSolidBrush(visual_colors[index]);
                HGDIOBJ old_brush = SelectObject(dc, accent);
                HGDIOBJ old_pen = SelectObject(dc, GetStockObject(NULL_PEN));
                Ellipse(dc, 4, line.top + 8, 10, line.top + 14);
                SelectObject(dc, old_pen);
                SelectObject(dc, old_brush);
                DeleteObject(accent);
            }
            int saved = SaveDC(dc);
            IntersectClipRect(dc, line.left, line.top, line.right, line.bottom);
            TEXTMETRICW metrics = {};
            GetTextMetricsW(dc, &metrics);
            int x = line.left;
            int y = line.top + (21 - metrics.tmHeight) / 2;
            const std::vector<COLORREF>& styles = visual_styles[index];
            for (size_t first = 0; first < content.size();) {
                bool highlighted = selected && first >= selected_first && first < selected_last;
                COLORREF color = highlighted ? RGB(20, 45, 55) : styles[first];
                size_t end = first + 1;
                while (end < content.size() &&
                    (selected && end >= selected_first && end < selected_last) == highlighted &&
                    (highlighted || styles[end] == color)) ++end;
                ::SetTextColor(dc, color);
                TextOutW(dc, x, y, content.c_str() + first, (int)(end - first));
                SIZE extent = {};
                GetTextExtentPoint32W(dc, content.c_str() + first, (int)(end - first), &extent);
                x += extent.cx;
                first = end;
            }
            RestoreDC(dc, saved);
        }
        if (editable) {
            RECT composer = { 0, split, client.right, client.bottom };
            HBRUSH composer_fill = CreateSolidBrush(RGB(248, 250, 249));
            FillRect(dc, &composer, composer_fill);
            DeleteObject(composer_fill);
            HPEN divider = CreatePen(PS_SOLID, 1, RGB(196, 210, 210));
            HGDIOBJ old_pen = SelectObject(dc, divider);
            MoveToEx(dc, 0, split, NULL);
            LineTo(dc, client.right, split);
            SelectObject(dc, old_pen);
            DeleteObject(divider);
            RECT label = { 12, split + 5, client.right - 12, split + 25 };
            SelectObject(dc, font);
            std::wstring heading = context.empty() ? L"PROMPT" : context;
            size_t line_break = heading.find(L'\n');
            std::wstring first = heading.substr(0, line_break);
            size_t separator = first.find(L"  |  ");
            std::wstring mode = first.substr(0, separator);
            ::SetTextColor(dc, RGB(36, 104, 111));
            DrawTextW(dc, mode.c_str(), -1, &label,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            if (separator != std::wstring::npos) {
                SIZE extent = {};
                GetTextExtentPoint32W(dc, mode.c_str(), (int)mode.size(), &extent);
                RECT hint = { label.left + extent.cx + 5, label.top, label.right, label.bottom };
                ::SetTextColor(dc, first.find(L"Running", separator) != std::wstring::npos ?
                    RGB(153, 91, 0) : RGB(0, 120, 70));
                DrawTextW(dc, first.c_str() + separator, -1, &hint,
                    DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            }
            if (line_break != std::wstring::npos) {
                label.top += 19;
                label.bottom += 19;
                std::wstring second = heading.substr(line_break + 1);
                ::SetTextColor(dc, RGB(96, 106, 108));
                DrawTextW(dc, second.c_str(), -1, &label,
                    DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            }
        }
        std::vector<std::wstring> input_lines;
        std::vector<size_t> input_starts;
        if (editable) LayoutInput(dc, (std::max)(1, (int)client.right - 24),
            &input_lines, &input_starts);
        const int input_rows = 3;
        int cursor_row = editable ? (int)InputCursorRow(input_starts) : 0;
        int first = cursor_row >= input_rows ? cursor_row - input_rows + 1 : 0;
        input_scroll = first;
        for (int row = first; editable && row < (int)input_lines.size() && row < first + input_rows; ++row) {
            RECT line = { 12, split + 49 + (row - first) * 21,
                client.right - 12, split + 70 + (row - first) * 21 };
            if (prompt_selected_all) {
                HBRUSH highlight = CreateSolidBrush(RGB(210, 225, 229));
                FillRect(dc, &line, highlight);
                DeleteObject(highlight);
            }
            ::SetTextColor(dc, RGB(35, 35, 35));
            DrawTextW(dc, input_lines[row].c_str(), -1, &line,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        if (editable && prompt.empty() && ::GetFocus() != m_hWnd) {
            RECT hint = { 12, split + 49, client.right - 12, split + 70 };
            ::SetTextColor(dc, RGB(130, 138, 139));
            DrawTextW(dc, L"Type a message...", -1, &hint,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        }
        if (old_font) SelectObject(dc, old_font);
        int saved = SaveDC(target);
        IntersectClipRect(target, 0, HeaderHeight(), client.right, client.bottom);
        BitBlt(target, 0, 0, client.right, client.bottom, dc, 0, 0, SRCCOPY);
        RestoreDC(target, saved);
        SelectObject(dc, old_bitmap);
        DeleteObject(bitmap);
        DeleteDC(dc);
        ::EndPaint(m_hWnd, &paint);
        UpdateCaret();
    }

    void UpdateCaret() {
        if (!editable || ::GetFocus() != m_hWnd) return;
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        HDC dc = ::GetDC(m_hWnd);
        HFONT font = (HFONT)SendMessageW(m_hWnd, WM_GETFONT, 0, 0);
        HGDIOBJ old = font ? SelectObject(dc, font) : NULL;
        std::vector<std::wstring> input_lines;
        std::vector<size_t> input_starts;
        LayoutInput(dc, (std::max)(1, (int)client.right - 24), &input_lines, &input_starts);
        size_t row = InputCursorRow(input_starts);
        size_t offset = cursor - input_starts[row];
        if (offset > input_lines[row].size()) offset = input_lines[row].size();
        int next_scroll = row >= 3 ? (int)row - 2 : 0;
        if (input_scroll != next_scroll) {
            input_scroll = next_scroll;
            RECT composer = { 0, InputTop(), client.right, client.bottom };
            ::InvalidateRect(m_hWnd, &composer, FALSE);
        }
        SIZE size = {};
        GetTextExtentPoint32W(dc, input_lines[row].c_str(), (int)offset, &size);
        if (old) SelectObject(dc, old);
        ::ReleaseDC(m_hWnd, dc);
        SetCaretPos(12 + size.cx, InputTop() + 51 + ((int)row - input_scroll) * 21);
    }

    void SyncRows() {
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        UpdateScroll();
        int visible = (client.bottom - HeaderHeight() - 16) / 21;
        if (visible < 1) visible = 1;
        if (!HasSelection())
            output_scroll = (int)visual_lines.size() > visible ? (int)visual_lines.size() - visible : 0;
        UpdateScroll(false);
        ::InvalidateRect(m_hWnd, NULL, FALSE);
        UpdateCaret();
    }

    void SetText(const std::wstring& text) {
        if (editable) {
            prompt.clear();
            prompt_selected_all = false;
            for (size_t i = 0; i < text.size(); ++i)
                if (text[i] != L'\r') prompt += text[i];
            cursor = prompt.size();
            ::InvalidateRect(m_hWnd, NULL, FALSE);
            UpdateCaret();
            return;
        }
        lines.clear();
        colors.clear();
        ClearSelection();
        lines.push_back(L"");
        colors.push_back(RGB(35, 35, 35));
        for (size_t i = 0; i < text.size(); ++i) {
            if (text[i] == L'\r') continue;
            if (text[i] == L'\n') {
                lines.push_back(L"");
                colors.push_back(RGB(35, 35, 35));
            } else lines.back() += text[i];
        }
        cursor = text.size();
        SyncRows();
    }

    void SetContext(const std::wstring& text) {
        context = text;
        ::InvalidateRect(m_hWnd, NULL, FALSE);
    }

    std::wstring Text() const {
        if (editable) return prompt;
        std::wstring result;
        for (size_t i = 0; i < lines.size(); ++i) {
            if (i) result += L'\n';
            result += lines[i];
        }
        return result;
    }

    void Append(const std::wstring& text, COLORREF color) {
        size_t old_line_count = lines.size();
        RECT client = {};
        ::GetClientRect(m_hWnd, &client);
        int visible = ((editable ? InputTop() : client.bottom) - HeaderHeight() - 16) / 21;
        if (visible < 1) visible = 1;
        int bottom = (int)visual_lines.size() - visible;
        if (bottom < 0) bottom = 0;
        bool follow = !HasSelection() && output_scroll >= bottom;
        if (lines.empty()) {
            lines.push_back(L"");
            colors.push_back(color);
        }
        for (size_t i = 0; i < text.size(); ++i) {
            if (text[i] == L'\r') continue;
            if (text[i] == L'\n') {
                lines.push_back(L"");
                colors.push_back(color);
            } else {
                lines.back() += text[i];
                colors.back() = color;
            }
        }
        UpdateScroll(true, old_line_count ? old_line_count - 1 : 0);
        if (follow)
            output_scroll = (int)visual_lines.size() > visible ?
                (int)visual_lines.size() - visible : 0;
        UpdateScroll(false);
        ::InvalidateRect(m_hWnd, NULL, FALSE);
    }

    virtual LRESULT OnDrawItem(LPDRAWITEMSTRUCT item) {
        HDC dc = item->hDC;
        RECT rect = item->rcItem;
        COLORREF fill = (item->itemState & ODS_SELECTED) ? RGB(220, 230, 234) : background;
        HBRUSH brush = CreateSolidBrush(fill);
        FillRect(dc, &rect, brush);
        DeleteObject(brush);
        if (item->itemID < lines.size()) {
            SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, colors[item->itemID]);
            rect.left += 5;
            DrawTextW(dc, lines[item->itemID].c_str(), -1, &rect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        return TRUE;
    }

    virtual LRESULT WndProc(UINT message, WPARAM wparam, LPARAM lparam) {
        if (message == WM_NCPAINT) {
            LRESULT result = COllyDbgListView::WndProc(message, wparam, lparam);
            RECT window = {};
            ::GetWindowRect(m_hWnd, &window);
            HDC dc = ::GetWindowDC(m_hWnd);
            if (dc) {
                RECT frame = { 0, 0, window.right - window.left, window.bottom - window.top };
                ::FrameRect(dc, &frame, (HBRUSH)::GetStockObject(BLACK_BRUSH));
                ::ReleaseDC(m_hWnd, dc);
            }
            return result;
        }
        if (message == WM_TIMER && wparam == 17) {
            ::KillTimer(m_hWnd, 17);
            UpdateScroll();
            ::InvalidateRect(m_hWnd, NULL, FALSE);
            return 0;
        }
        if (message == WM_TIMER && wparam == 18 && selecting) {
            UpdateDragSelection();
            return 0;
        }
        if (message == WM_DESTROY) {
            ::KillTimer(m_hWnd, 17);
            ::KillTimer(m_hWnd, 18);
        }
        if (message == WM_KEYDOWN && (GetKeyState(VK_CONTROL) & 0x8000)) {
            if (wparam == 'A') {
                if (editable && input_active) {
                    prompt_selected_all = !prompt.empty();
                    ::InvalidateRect(m_hWnd, NULL, FALSE);
                    return 0;
                }
                UpdateScroll();
                selection_first.line = selection_first.offset = 0;
                selection_last.line = lines.empty() ? 0 : lines.size() - 1;
                selection_last.offset = lines.empty() ? 0 : lines.back().size();
                ::InvalidateRect(m_hWnd, NULL, FALSE);
                return 0;
            }
            if (wparam == 'C') { CopySelection(); return 0; }
        }
        if (message == WM_LBUTTONDOWN &&
            (!editable || (short)HIWORD(lparam) < InputTop())) {
            if ((short)HIWORD(lparam) < HeaderHeight()) return 0;
            ::SetFocus(m_hWnd);
            input_active = false;
            prompt_selected_all = false;
            UpdateScroll();
            drag_point.x = (short)LOWORD(lparam);
            drag_point.y = (short)HIWORD(lparam);
            drag_origin = drag_point;
            selection_dragged = false;
            selection_first = PositionAt(drag_point.x, drag_point.y, true);
            selection_last = selection_first;
            if (selection_last.line < lines.size() &&
                selection_last.offset < lines[selection_last.line].size()) {
                size_t offset = selection_last.offset;
                selection_last.offset += offset + 1 < lines[selection_last.line].size() &&
                    SurrogatePair(lines[selection_last.line][offset],
                        lines[selection_last.line][offset + 1]) ? 2 : 1;
            }
            selecting = true;
            ::SetCapture(m_hWnd);
            ::InvalidateRect(m_hWnd, NULL, FALSE);
            return 0;
        }
        if (message == WM_RBUTTONDOWN && editable &&
            (short)HIWORD(lparam) >= InputTop()) {
            input_active = true;
            ClearSelection();
            ::SetFocus(m_hWnd);
            PasteClipboardText();
            return 0;
        }
        if (message == WM_MOUSEMOVE && selecting) {
            drag_point.x = (short)LOWORD(lparam);
            drag_point.y = (short)HIWORD(lparam);
            UpdateDragSelection();
            return 0;
        }
        if (message == WM_LBUTTONUP && selecting) {
            POINT released = { (short)LOWORD(lparam), (short)HIWORD(lparam) };
            if (released.x != drag_point.x || released.y != drag_point.y) {
                drag_point = released;
                UpdateDragSelection();
            }
            selecting = false;
            ::KillTimer(m_hWnd, 18);
            ::ReleaseCapture();
            ::InvalidateRect(m_hWnd, NULL, FALSE);
            return 0;
        }
        if (message == WM_CAPTURECHANGED && selecting) {
            selecting = false;
            ::KillTimer(m_hWnd, 18);
        }
        if (message == WM_PAINT) {
                PaintComposite();
                return 0;
        } else if (message == WM_ERASEBKGND) {
                return 1;
        } else if (message == WM_SIZE) {
                LRESULT result = COllyDbgListView::WndProc(message, wparam, lparam);
                RECT client = {};
                ::GetClientRect(m_hWnd, &client);
                if (client.right != reflow_width) ::SetTimer(m_hWnd, 17, 80, NULL);
                else UpdateScroll(false);
                ::InvalidateRect(m_hWnd, NULL, FALSE);
                return result;
        } else if (message == WM_VSCROLL || message == WM_MOUSEWHEEL) {
                int delta = message == WM_MOUSEWHEEL ?
                    (GET_WHEEL_DELTA_WPARAM(wparam) > 0 ? -3 : 3) :
                    LOWORD(wparam) == SB_LINEUP ? -1 :
                    LOWORD(wparam) == SB_LINEDOWN ? 1 :
                    LOWORD(wparam) == SB_PAGEUP ? -8 :
                    LOWORD(wparam) == SB_PAGEDOWN ? 8 : 0;
                if (message == WM_VSCROLL &&
                    (LOWORD(wparam) == SB_THUMBTRACK || LOWORD(wparam) == SB_THUMBPOSITION)) {
                    SCROLLINFO info = {};
                    info.cbSize = sizeof(info);
                    info.fMask = SIF_TRACKPOS;
                    if (::GetScrollInfo(m_hWnd, SB_VERT, &info)) output_scroll = info.nTrackPos;
                } else output_scroll += delta;
                if (output_scroll < 0) output_scroll = 0;
                UpdateScroll(false);
                ::InvalidateRect(m_hWnd, NULL, FALSE);
                return 0;
        }
        if (editable) {
            if (message == WM_LBUTTONDOWN) {
                if ((short)HIWORD(lparam) >= InputTop()) {
                    input_active = true;
                    prompt_selected_all = false;
                    ClearSelection();
                    ::SetFocus(m_hWnd);
                    ::InvalidateRect(m_hWnd, NULL, FALSE);
                }
                return 0;
            } else if (message == WM_GETDLGCODE) {
                return DLGC_WANTCHARS | DLGC_WANTARROWS | DLGC_WANTALLKEYS;
            } else if (message == WM_SETFOCUS) {
                CreateCaret(m_hWnd, NULL, 2, 15);
                ShowCaret(m_hWnd);
                UpdateCaret();
                ::InvalidateRect(m_hWnd, NULL, FALSE);
            } else if (message == WM_KILLFOCUS) {
                HideCaret(m_hWnd);
                DestroyCaret();
                ::InvalidateRect(m_hWnd, NULL, FALSE);
            } else if (message == WM_CHAR) {
                if (wparam == VK_RETURN && submit_command &&
                    !(GetKeyState(VK_SHIFT) & 0x8000)) {
                    HWND parent = ::GetParent(m_hWnd);
                    ::PostMessageW(parent, WM_COMMAND, MAKEWPARAM(submit_command, BN_CLICKED), 0);
                    return 0;
                }
                std::wstring value = prompt;
                if (prompt_selected_all) {
                    if (wparam == VK_BACK) {
                        SetText(L"");
                        return 0;
                    }
                    value.clear();
                    cursor = 0;
                    prompt_selected_all = false;
                }
                if (wparam == VK_BACK) {
                    if (cursor) { size_t next = cursor - 1; value.erase(next, 1); SetText(value); cursor = next; }
                } else if (wparam == VK_RETURN) {
                    size_t next = cursor + 1; value.insert(cursor, 1, L'\n'); SetText(value); cursor = next;
                } else if (wparam >= 32 || wparam == VK_TAB) {
                    size_t next = cursor + 1; value.insert(cursor, 1, (wchar_t)wparam); SetText(value); cursor = next;
                }
                UpdateCaret();
                return 0;
            } else if (message == WM_KEYDOWN) {
                std::wstring value = prompt;
                if (prompt_selected_all && wparam == VK_DELETE) {
                    SetText(L"");
                    return 0;
                }
                if (wparam == VK_LEFT || wparam == VK_RIGHT) prompt_selected_all = false;
                if (wparam == VK_LEFT && cursor) --cursor;
                else if (wparam == VK_RIGHT && cursor < value.size()) ++cursor;
                else if (wparam == VK_DELETE && cursor < value.size()) {
                    size_t next = cursor; value.erase(cursor, 1); SetText(value); cursor = next;
                } else if (wparam == 'V' && (GetKeyState(VK_CONTROL) & 0x8000)) {
                    PasteClipboardText();
                    return 0;
                }
                UpdateCaret();
                if (wparam == VK_LEFT || wparam == VK_RIGHT || wparam == VK_DELETE) return 0;
            }
        }
        return COllyDbgListView::WndProc(message, wparam, lparam);
    }
};

AgentInternalList* AgentInternalListAttach(HWND window, bool editable,
    const std::wstring& header, UINT submit_command) {
    static CWinApp app;
    AgentInternalList* control = new AgentInternalList(editable, header, submit_command);
    ::SetWindowLongPtrW(window, GWL_STYLE,
        (::GetWindowLongPtrW(window, GWL_STYLE) & ~LVS_NOCOLUMNHEADER) |
        WS_BORDER | WS_CLIPCHILDREN);
    ::SetWindowPos(window, NULL, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    control->Attach(window);
    control->CreateBoldFont();
    control->ShowHeader();
    control->ResizeHeaderColumn();
    control->SetText(L"");
    return control;
}

void AgentInternalListDestroy(AgentInternalList* control) {
    if (control) { control->Detach(); delete control; }
}
void AgentInternalListAppend(AgentInternalList* control, const std::wstring& text, COLORREF color) {
    if (control) control->Append(text, color);
}
void AgentInternalListSetText(AgentInternalList* control, const std::wstring& text) {
    if (control) control->SetText(text);
}
void AgentInternalListSetContext(AgentInternalList* control, const std::wstring& text) {
    if (control) control->SetContext(text);
}
std::wstring AgentInternalListGetText(AgentInternalList* control) {
    return control ? control->Text() : std::wstring();
}
LRESULT AgentInternalListReflect(AgentInternalList* control, UINT message, WPARAM wparam, LPARAM lparam) {
    return control ? control->OnMessageReflect(message, wparam, lparam) : 0;
}
