#pragma once

#include <windows.h>
#include <string>

struct AgentInternalList;

AgentInternalList* AgentInternalListAttach(HWND window, bool editable,
    const std::wstring& header, UINT submit_command = 0);
void AgentInternalListDestroy(AgentInternalList* control);
void AgentInternalListAppend(AgentInternalList* control, const std::wstring& text, COLORREF color);
void AgentInternalListSetText(AgentInternalList* control, const std::wstring& text);
void AgentInternalListSetContext(AgentInternalList* control, const std::wstring& text);
std::wstring AgentInternalListGetText(AgentInternalList* control);
LRESULT AgentInternalListReflect(AgentInternalList* control, UINT message, WPARAM wparam, LPARAM lparam);
