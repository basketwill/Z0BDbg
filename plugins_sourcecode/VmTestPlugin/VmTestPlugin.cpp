#include <windows.h>
#include <wchar.h>
#include <strsafe.h>
#include "../vmdebug.h"

#define PLUGIN_VERSION 201
#define PLUGIN_SHORTNAME 32
#define PWM_MAIN L"MAIN"
#define PWM_DISASM L"DISASM"
#define MENU_VERIFY 0
#define MENU_EXECUTE 1
#define MENU_NORMAL 1
#define MENU_GRAYED 5

typedef int (__cdecl *MENUFUNC)(void*, wchar_t*, unsigned long, int);

#pragma pack(push, 1)
typedef struct VMTEST_MENU
{
    wchar_t* name;
    wchar_t* help;
    int shortcutid;
    MENUFUNC menufunc;
    struct VMTEST_MENU* submenu;
    union
    {
        unsigned long index;
        HMENU hsubmenu;
    };
} VMTEST_MENU;
#pragma pack(pop)

typedef BOOL (__cdecl *PFN_REGISTER_BACKEND)(const Z0B_VM_BACKEND*);
typedef BOOL (__cdecl *PFN_UNREGISTER_BACKEND)(const Z0B_VM_BACKEND*);
typedef BOOL (__cdecl *PFN_OBSERVE_STOP)(unsigned long, unsigned long long, const void*);
typedef BOOL (__cdecl *PFN_ENTER)(const Z0B_VM_PROBE_RESULT*, const Z0B_VM_HOST_STOP*);
typedef BOOL (__cdecl *PFN_EXIT)();
typedef void (__cdecl *PFN_RESET_SESSION)();
typedef void (__cdecl *PFN_SHOW_WINDOW)();
typedef BOOL (__cdecl *PFN_REFRESH)(const Z0B_VM_HOST_STOP*);
typedef BOOL (__cdecl *PFN_GET_SNAPSHOT)(Z0B_VM_SNAPSHOT*);

static HMODULE g_Host;
static PFN_REGISTER_BACKEND g_RegisterBackend;
static PFN_UNREGISTER_BACKEND g_UnregisterBackend;
static PFN_OBSERVE_STOP g_ObserveStop;
static PFN_ENTER g_Enter;
static PFN_EXIT g_Exit;
static PFN_RESET_SESSION g_ResetSession;
static PFN_SHOW_WINDOW g_ShowWindow;
static PFN_GET_SNAPSHOT g_GetSnapshot;
static BOOL g_Registered;
static BOOL g_ModelActive;
static ULONG64 g_VmPc = 0x1000;
static ULONG64 g_Sequence;
static BOOL g_Breakpoints[16];

static const ULONG64 VM_HOST_ENTRY = 0x10000001;
static const ULONG64 VM_HOST_EXIT = 0x10000099;
static const UINT VM_MENU_START_PROBE = Z0B_VM_MENU_COMMAND_BASE + 100;
static const UINT VM_MENU_START_ENTER = Z0B_VM_MENU_COMMAND_BASE + 101;
static const UINT VM_MENU_EXIT = Z0B_VM_MENU_COMMAND_BASE + 102;
static const UINT VM_MENU_RESET = Z0B_VM_MENU_COMMAND_BASE + 103;
static const UINT VM_MENU_COPY_ASM = Z0B_VM_MENU_COMMAND_BASE + 104;

static void CopyText(wchar_t* Dest, size_t Count, const wchar_t* Source)
{
    if (!Dest || Count == 0)
    {
        return;
    }
    Dest[0] = 0;
    if (Source)
    {
        wcsncpy(Dest, Source, Count - 1);
        Dest[Count - 1] = 0;
    }
}

static BOOL CopyAsmInstruction(const Z0B_VM_MENU_CONTEXT* Context)
{
    Z0B_VM_SNAPSHOT* Snapshot;
    wchar_t Text[1024] = {0};
    HGLOBAL Memory;
    wchar_t* Dest;
    const Z0B_VM_INSTRUCTION* Instruction;

    if (!Context || Context->ViewKind != Z0B_VM_VIEW_ASM ||
        Context->Item < 0 || !g_GetSnapshot)
    {
        return FALSE;
    }

    Snapshot = (Z0B_VM_SNAPSHOT*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(Z0B_VM_SNAPSHOT));
    if (!Snapshot)
    {
        return FALSE;
    }

    Snapshot->Size = sizeof(Z0B_VM_SNAPSHOT);
    Snapshot->Version = Z0B_VM_API_VERSION;
    if (!g_GetSnapshot(Snapshot) ||
        (DWORD)Context->Item >= Snapshot->InstructionCount)
    {
        HeapFree(GetProcessHeap(), 0, Snapshot);
        return FALSE;
    }

    Instruction = &Snapshot->Instructions[Context->Item];
    StringCchPrintfW(Text, _countof(Text),
        L"%016I64X  %-24s  %s %s  // %s",
        Instruction->VmAddress,
        Instruction->HexText,
        Instruction->Mnemonic,
        Instruction->Operands,
        Instruction->Comment);

    Memory = GlobalAlloc(GMEM_MOVEABLE,
        (lstrlenW(Text) + 1) * sizeof(wchar_t));
    if (!Memory)
    {
        HeapFree(GetProcessHeap(), 0, Snapshot);
        return FALSE;
    }
    Dest = (wchar_t*)GlobalLock(Memory);
    if (!Dest)
    {
        GlobalFree(Memory);
        HeapFree(GetProcessHeap(), 0, Snapshot);
        return FALSE;
    }
    CopyMemory(Dest, Text, (lstrlenW(Text) + 1) * sizeof(wchar_t));
    GlobalUnlock(Memory);
    HeapFree(GetProcessHeap(), 0, Snapshot);

    if (!OpenClipboard(Context->Window))
    {
        GlobalFree(Memory);
        return FALSE;
    }
    EmptyClipboard();
    if (!SetClipboardData(CF_UNICODETEXT, Memory))
    {
        CloseClipboard();
        GlobalFree(Memory);
        return FALSE;
    }
    CloseClipboard();
    return TRUE;
}

static void SetValue(Z0B_VM_VALUE* Value, ULONG64 Numeric, const wchar_t* Text)
{
    ZeroMemory(Value, sizeof(*Value));
    Value->Size = sizeof(*Value);
    Value->BitWidth = 64;
    Value->NumericValue = Numeric;
    CopyText(Value->Text, _countof(Value->Text), Text);
}

static void SetColumnStyle(
    Z0B_VM_ASM_STYLE* Style, DWORD Column, COLORREF TextColor, COLORREF BkColor)
{
    if (!Style || Column >= Z0B_VM_ASM_COLUMN_COUNT)
    {
        return;
    }
    Style->Size = sizeof(*Style);
    Style->Column[Column].Flags = Z0B_VM_STYLE_TEXT_COLOR | Z0B_VM_STYLE_BK_COLOR;
    Style->Column[Column].TextColor = TextColor;
    Style->Column[Column].BkColor = BkColor;
}

static void AddTextRunStyle(
    Z0B_VM_ASM_STYLE* Style, DWORD Column, DWORD Start, DWORD Length,
    COLORREF TextColor, COLORREF BkColor)
{
    if (!Style || Style->RunCount >= Z0B_VM_ASM_STYLE_RUNS)
    {
        return;
    }
    Z0B_VM_TEXT_RUN* Run = &Style->Runs[Style->RunCount++];
    ZeroMemory(Run, sizeof(*Run));
    Style->Size = sizeof(*Style);
    Run->Size = sizeof(*Run);
    Run->Flags = Z0B_VM_STYLE_TEXT_COLOR | Z0B_VM_STYLE_BK_COLOR;
    Run->Column = Column;
    Run->Start = Start;
    Run->Length = Length;
    Run->TextColor = TextColor;
    Run->BkColor = BkColor;
}

static void FillSnapshot(Z0B_VM_SNAPSHOT* Snapshot)
{
    Z0B_VM_INSTRUCTION* Instruction;
    Snapshot->HostAddress = VM_HOST_ENTRY + g_Sequence * 4;
    Snapshot->VmAddress = g_VmPc;
    Snapshot->VmStackAddress = 0x2000 + g_Sequence * 8;

    Snapshot->RegisterCount = 4;
    CopyText(Snapshot->Registers[0].Name, _countof(Snapshot->Registers[0].Name), L"r1");
    SetValue(&Snapshot->Registers[0].Value, 0x11110000 + g_Sequence, L"0x11110000");
    CopyText(Snapshot->Registers[1].Name, _countof(Snapshot->Registers[1].Name), L"r2");
    SetValue(&Snapshot->Registers[1].Value, 0x22220000 + g_Sequence, L"0x22220000");
    CopyText(Snapshot->Registers[2].Name, _countof(Snapshot->Registers[2].Name), L"flags");
    SetValue(&Snapshot->Registers[2].Value, g_Sequence & 1, (g_Sequence & 1) ? L"ZF=1" : L"ZF=0");
    CopyText(Snapshot->Registers[3].Name, _countof(Snapshot->Registers[3].Name), L"vmsp");
    SetValue(&Snapshot->Registers[3].Value, Snapshot->VmStackAddress, L"0x00002000");
    SetColumnStyle(&Snapshot->RegisterStyles[0], 0, RGB(0, 0, 128), RGB(255, 255, 255));
    AddTextRunStyle(&Snapshot->RegisterStyles[0], 0, 0, 2,
        RGB(255, 0, 0), RGB(255, 255, 255));
    AddTextRunStyle(&Snapshot->RegisterStyles[0], 0, 3, 10,
        RGB(0, 128, 0), RGB(0, 0, 0));
    SetColumnStyle(&Snapshot->RegisterStyles[1], 0, RGB(0, 0, 0), RGB(230, 230, 230));
    AddTextRunStyle(&Snapshot->RegisterStyles[1], 0, 0, 2,
        RGB(0, 0, 255), RGB(255, 255, 0));
    AddTextRunStyle(&Snapshot->RegisterStyles[1], 0, 3, 10,
        RGB(255, 255, 255), RGB(128, 0, 0));

    Snapshot->StackCount = 3;
    Snapshot->Stack[0].Address = Snapshot->VmStackAddress;
    Snapshot->Stack[0].Value = 0xAAAAAAAA + g_Sequence;
    CopyText(Snapshot->Stack[0].AddressText, _countof(Snapshot->Stack[0].AddressText), L"rp1");
    CopyText(Snapshot->Stack[0].ValueText, _countof(Snapshot->Stack[0].ValueText), L"0xAAAAAAAA");
    CopyText(Snapshot->Stack[0].Comment, _countof(Snapshot->Stack[0].Comment), L"virtual stack item");
    SetColumnStyle(&Snapshot->StackStyles[0], 0, RGB(255, 255, 255), RGB(0, 0, 128));
    Snapshot->Stack[1].Address = Snapshot->VmStackAddress + 8;
    Snapshot->Stack[1].Value = 0xCCCCCCCC + g_Sequence;
    CopyText(Snapshot->Stack[1].AddressText, _countof(Snapshot->Stack[1].AddressText), L"rp2");
    CopyText(Snapshot->Stack[1].ValueText, _countof(Snapshot->Stack[1].ValueText), L"0xCCCCCCCC");
    CopyText(Snapshot->Stack[1].Comment, _countof(Snapshot->Stack[1].Comment), L"return value");
    SetColumnStyle(&Snapshot->StackStyles[1], 1, RGB(0, 0, 0), RGB(255, 255, 0));
    AddTextRunStyle(&Snapshot->StackStyles[1], 1, 2, 4, RGB(255, 0, 0), RGB(0, 0, 0));
    Snapshot->Stack[2].Address = Snapshot->VmStackAddress + 16;
    Snapshot->Stack[2].Value = 0x66666666 + g_Sequence;
    CopyText(Snapshot->Stack[2].AddressText, _countof(Snapshot->Stack[2].AddressText), L"rp3");
    CopyText(Snapshot->Stack[2].ValueText, _countof(Snapshot->Stack[2].ValueText), L"0x66666666");

    Snapshot->DataCount = 3;
    Snapshot->Data[0].Size = sizeof(Snapshot->Data[0]);
    Snapshot->Data[0].Address = 0x666666 + g_Sequence * 0x10;
    Snapshot->Data[0].ByteCount = 8;
    CopyText(Snapshot->Data[0].AddressText, _countof(Snapshot->Data[0].AddressText), L"vmdata");
    CopyText(Snapshot->Data[0].BytesText, _countof(Snapshot->Data[0].BytesText), L"11 22 33 44 55 66 77 88");
    CopyText(Snapshot->Data[0].DataText, _countof(Snapshot->Data[0].DataText), L"qword 0x8877665544332211");
    CopyText(Snapshot->Data[0].Comment, _countof(Snapshot->Data[0].Comment), L"custom VM memory row");
    SetColumnStyle(&Snapshot->DataStyles[0], 0, RGB(255, 255, 255), RGB(0, 0, 128));
    SetColumnStyle(&Snapshot->DataStyles[0], 1, RGB(0, 0, 0), RGB(240, 240, 240));
    AddTextRunStyle(&Snapshot->DataStyles[0], 1, 0, 2, RGB(255, 0, 0), RGB(255, 255, 180));
    AddTextRunStyle(&Snapshot->DataStyles[0], 1, 3, 2, RGB(0, 128, 0), RGB(200, 255, 200));
    AddTextRunStyle(&Snapshot->DataStyles[0], 1, 6, 2, RGB(0, 0, 255), RGB(200, 220, 255));
    Snapshot->Data[1].Size = sizeof(Snapshot->Data[1]);
    Snapshot->Data[1].Address = 0x666676 + g_Sequence * 0x10;
    Snapshot->Data[1].ByteCount = 8;
    CopyText(Snapshot->Data[1].BytesText, _countof(Snapshot->Data[1].BytesText), L"CC CC CC CC AA AA AA AA");
    CopyText(Snapshot->Data[1].DataText, _countof(Snapshot->Data[1].DataText), L"rp shadow values");
    CopyText(Snapshot->Data[1].Comment, _countof(Snapshot->Data[1].Comment), L"plugin controlled display");
    SetColumnStyle(&Snapshot->DataStyles[1], 2, RGB(128, 0, 128), RGB(255, 255, 0));
    SetColumnStyle(&Snapshot->DataStyles[1], 3, RGB(0, 100, 0), RGB(230, 255, 230));
    Snapshot->Data[2].Size = sizeof(Snapshot->Data[2]);
    Snapshot->Data[2].Address = 0x666686 + g_Sequence * 0x10;
    Snapshot->Data[2].ByteCount = 6;
    CopyText(Snapshot->Data[2].BytesText, _countof(Snapshot->Data[2].BytesText), L"58 45 31 00 FF 90");
    CopyText(Snapshot->Data[2].DataText, _countof(Snapshot->Data[2].DataText), L"\"XE1\\0\" opcode bytes");
    CopyText(Snapshot->Data[2].Comment, _countof(Snapshot->Data[2].Comment), L"not decoded by host");

    Snapshot->InstructionCount = 4;
    Instruction = &Snapshot->Instructions[0];
    Instruction->VmAddress = g_VmPc;
    Instruction->HostAddress = VM_HOST_ENTRY;
    Instruction->Length = 2;
    CopyText(Instruction->Mnemonic, _countof(Instruction->Mnemonic), L"XE1");
    CopyText(Instruction->Operands, _countof(Instruction->Operands), L"r1, r2");
    CopyText(Instruction->HexText, _countof(Instruction->HexText), L"01 02");
    CopyText(Instruction->Comment, _countof(Instruction->Comment), L"virtual register operation");
    SetColumnStyle(&Snapshot->AsmStyles[0], 0, RGB(255, 0, 0), RGB(0, 0, 0));

    Instruction = &Snapshot->Instructions[1];
    Instruction->VmAddress = g_VmPc + 2;
    Instruction->HostAddress = VM_HOST_ENTRY + 2;
    Instruction->Length = 3;
    CopyText(Instruction->Mnemonic, _countof(Instruction->Mnemonic), L"XMO");
    CopyText(Instruction->Operands, _countof(Instruction->Operands), L"r3, 5");
    CopyText(Instruction->HexText, _countof(Instruction->HexText), L"10 03 05");
    CopyText(Instruction->Comment, _countof(Instruction->Comment), L"custom immediate operation");
    SetColumnStyle(&Snapshot->AsmStyles[1], 1, RGB(0, 160, 0), RGB(255, 255, 0));
    SetColumnStyle(&Snapshot->AsmStyles[1], 2, RGB(0, 0, 0), RGB(255, 255, 0));
    AddTextRunStyle(&Snapshot->AsmStyles[1], 2, 0, 3, RGB(255, 0, 0), RGB(255, 255, 0));
    AddTextRunStyle(&Snapshot->AsmStyles[1], 2, 4, 2, RGB(255, 255, 255), RGB(0, 80, 160));
    AddTextRunStyle(&Snapshot->AsmStyles[1], 2, 6, 1, RGB(128, 0, 128), RGB(255, 255, 255));
    AddTextRunStyle(&Snapshot->AsmStyles[1], 2, 8, 1, RGB(255, 255, 255), RGB(120, 80, 0));

    Instruction = &Snapshot->Instructions[2];
    Instruction->VmAddress = g_VmPc + 5;
    Instruction->HostAddress = VM_HOST_ENTRY + 5;
    Instruction->Length = 2;
    Instruction->BranchTarget = g_VmPc + 0x20;
    CopyText(Instruction->Mnemonic, _countof(Instruction->Mnemonic), L"XJZ");
    CopyText(Instruction->Operands, _countof(Instruction->Operands), L"loc_1020");
    CopyText(Instruction->HexText, _countof(Instruction->HexText), L"20 20");
    CopyText(Instruction->Comment, _countof(Instruction->Comment), L"conditional VM branch");

    Instruction = &Snapshot->Instructions[3];
    Instruction->VmAddress = g_VmPc + 7;
    Instruction->HostAddress = VM_HOST_ENTRY + 7;
    Instruction->Length = 1;
    CopyText(Instruction->Mnemonic, _countof(Instruction->Mnemonic), L"XRET");
    CopyText(Instruction->HexText, _countof(Instruction->HexText), L"FF");
    CopyText(Instruction->Comment, _countof(Instruction->Comment), L"leave simulated VM");
}

static BOOL __cdecl VmProbe(void*, const Z0B_VM_HOST_STOP* Stop, Z0B_VM_PROBE_RESULT* Result)
{
    if (!Stop || !Result)
    {
        return FALSE;
    }
    if (Stop->HostAddress == VM_HOST_ENTRY && !g_ModelActive)
    {
        g_ModelActive = TRUE;
        Result->StopKind = Z0B_VM_STOP_ENTRY;
        Result->Confidence = 100;
        Result->HostEntry = VM_HOST_ENTRY;
        Result->HostAddress = Stop->HostAddress;
        Result->VmAddress = g_VmPc;
        Result->SessionId = 0x564D544553540001;
        return TRUE;
    }
    if (Stop->HostAddress == VM_HOST_EXIT && g_ModelActive)
    {
        Result->StopKind = Z0B_VM_STOP_EXIT;
        return TRUE;
    }
    return FALSE;
}

static BOOL __cdecl VmUpdate(void*, const Z0B_VM_HOST_STOP*, Z0B_VM_SNAPSHOT* Snapshot)
{
    if (!Snapshot || !g_ModelActive)
    {
        return FALSE;
    }
    FillSnapshot(Snapshot);
    return TRUE;
}

static BOOL __cdecl VmStep(void*, DWORD StepKind)
{
    Z0B_VM_HOST_STOP Stop = {0};
    if (!g_ModelActive)
    {
        return FALSE;
    }
    g_VmPc += StepKind == Z0B_VM_STEP_OVER ? 2 : 1;
    g_Sequence++;
    if (StepKind == Z0B_VM_CONTINUE)
    {
        g_VmPc += 0x10;
        g_Sequence += 4;
    }
    Stop.Size = sizeof(Stop);
    Stop.Version = Z0B_VM_API_VERSION;
    Stop.ThreadId = GetCurrentThreadId();
    Stop.HostAddress = VM_HOST_ENTRY + g_Sequence * 4;
    /*
     * Do not call back into the host from a Step callback. The callback is
     * normally reached from a UI key/button handler, so a synchronous host
     * refresh would re-enter MDI and the VM window.
     */
    UNREFERENCED_PARAMETER(Stop);
    return TRUE;
}

static BOOL __cdecl VmBreakpoint(void*, ULONG64 VmAddress, BOOL Enable)
{
    g_Breakpoints[(ULONG)((VmAddress / 2) & 15)] = Enable;
    return TRUE;
}

static BOOL __cdecl VmHasBreakpoint(void*, ULONG64 VmAddress)
{
    return g_Breakpoints[(ULONG)((VmAddress / 2) & 15)];
}

static void __cdecl VmRelease(void*)
{
    g_Registered = FALSE;
    g_ModelActive = FALSE;
}

static BOOL StartByProbe(void)
{
    BOOL Result;
    if (!g_ObserveStop)
    {
        return FALSE;
    }
    Result = g_ObserveStop(GetCurrentThreadId(), VM_HOST_ENTRY, NULL);
    if (!Result)
    {
        g_ModelActive = FALSE;
    }
    else if (g_ShowWindow)
    {
        g_ShowWindow();
    }
    return Result;
}

static BOOL StartByEnter(void)
{
    Z0B_VM_PROBE_RESULT Result = {0};
    Z0B_VM_HOST_STOP Stop = {0};
    if (!g_Enter)
    {
        return FALSE;
    }
    g_ModelActive = TRUE;
    Result.Size = sizeof(Result);
    Result.Version = Z0B_VM_API_VERSION;
    Result.StopKind = Z0B_VM_STOP_ENTRY;
    Result.Confidence = 100;
    Result.HostEntry = VM_HOST_ENTRY;
    Result.HostAddress = VM_HOST_ENTRY;
    Result.VmAddress = g_VmPc;
    Result.SessionId = 0x564D544553540001;
    Stop.Size = sizeof(Stop);
    Stop.Version = Z0B_VM_API_VERSION;
    Stop.ThreadId = GetCurrentThreadId();
    Stop.HostAddress = VM_HOST_ENTRY;
    if (!g_Enter(&Result, &Stop))
    {
        g_ModelActive = FALSE;
        return FALSE;
    }
    if (g_ShowWindow)
    {
        g_ShowWindow();
    }
    return TRUE;
}

static int __cdecl VmMenuFunction(void*, wchar_t*, unsigned long Index, int Mode)
{
    if (Mode == MENU_VERIFY)
    {
        if (Index == VM_MENU_EXIT || Index == VM_MENU_RESET)
        {
            return g_ModelActive ? MENU_NORMAL : MENU_GRAYED;
        }
        return MENU_NORMAL;
    }
    if (Mode != MENU_EXECUTE)
    {
        return MENU_NORMAL;
    }
    if (Index == VM_MENU_START_PROBE)
    {
        StartByProbe();
    }
    else if (Index == VM_MENU_START_ENTER)
    {
        StartByEnter();
    }
    else if (Index == VM_MENU_EXIT)
    {
        if (g_Exit)
        {
            g_Exit();
        }
        g_ModelActive = FALSE;
    }
    else if (Index == VM_MENU_RESET)
    {
        if (g_ResetSession)
        {
            g_ResetSession();
        }
        g_ModelActive = FALSE;
        g_VmPc = 0x1000;
        g_Sequence = 0;
        ZeroMemory(g_Breakpoints, sizeof(g_Breakpoints));
    }
    return MENU_NORMAL;
}

static VMTEST_MENU g_TestMenu[] =
{
    {L"Start through Probe", L"Probe synthetic VM entry", 0, VmMenuFunction, NULL, {VM_MENU_START_PROBE}},
    {L"Start through Enter", L"Enter synthetic VM directly", 0, VmMenuFunction, NULL, {VM_MENU_START_ENTER}},
    {L"Exit simulated VM", L"Leave the simulated VM session", 0, VmMenuFunction, NULL, {VM_MENU_EXIT}},
    {L"Reset simulation", L"Reset VM state and breakpoints", 0, VmMenuFunction, NULL, {VM_MENU_RESET}},
    {NULL, NULL, 0, NULL, NULL, {0}}
};

static VMTEST_MENU g_MainMenu[] =
{
    {L"VM test", L"Simulated VM integration test", 0, NULL, g_TestMenu, {0}},
    {NULL, NULL, 0, NULL, NULL, {0}}
};

static BOOL __cdecl VmBuildMenu(
    void*, HMENU Menu, const Z0B_VM_MENU_CONTEXT* Context)
{
    if (!Menu)
    {
        return FALSE;
    }
    AppendMenuW(Menu, MF_STRING, VM_MENU_START_PROBE, L"Start VM through Probe");
    AppendMenuW(Menu, MF_STRING, VM_MENU_START_ENTER, L"Start VM through Enter");
    AppendMenuW(Menu, MF_STRING, VM_MENU_EXIT, L"Exit simulated VM");
    AppendMenuW(Menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(Menu, MF_STRING, VM_MENU_RESET, L"Reset simulation");
    if (Context && Context->ViewKind == Z0B_VM_VIEW_ASM)
    {
        AppendMenuW(Menu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(Menu, MF_STRING, VM_MENU_COPY_ASM,
            L"Copy current VM instruction");
    }
    return TRUE;
}

static BOOL __cdecl VmExecuteMenu(
    void*, UINT Command, const Z0B_VM_MENU_CONTEXT* Context)
{
    if (Command == VM_MENU_START_PROBE)
    {
        return StartByProbe();
    }
    if (Command == VM_MENU_START_ENTER)
    {
        return StartByEnter();
    }
    if (Command == VM_MENU_EXIT)
    {
        if (g_Exit)
        {
            g_Exit();
        }
        g_ModelActive = FALSE;
        return TRUE;
    }
    if (Command == VM_MENU_RESET)
    {
        VmMenuFunction(NULL, NULL, VM_MENU_RESET, MENU_EXECUTE);
        return TRUE;
    }
    if (Command == VM_MENU_COPY_ASM)
    {
        return CopyAsmInstruction(Context);
    }
    return FALSE;
}

static Z0B_VM_BACKEND g_Backend =
{
    sizeof(Z0B_VM_BACKEND),
    Z0B_VM_API_VERSION,
    0,
    L"VM test backend",
    NULL,
    VmProbe,
    VmUpdate,
    VmStep,
    VmBreakpoint,
    VmRelease,
    VmHasBreakpoint,
    VmBuildMenu,
    VmExecuteMenu
};

extern "C" __declspec(dllexport) int __cdecl ODBG2_Pluginquery(
    int Version, unsigned long*, wchar_t Name[PLUGIN_SHORTNAME],
    wchar_t PluginVersion[PLUGIN_SHORTNAME])
{
    if (Version < PLUGIN_VERSION)
    {
        return 0;
    }
    CopyText(Name, PLUGIN_SHORTNAME, L"VmTestPlugin");
    CopyText(PluginVersion, PLUGIN_SHORTNAME, L"1.0");
    return PLUGIN_VERSION;
}

extern "C" __declspec(dllexport) int __cdecl ODBG2_Plugininit(void)
{
    g_Host = GetModuleHandleW(NULL);
    g_RegisterBackend = (PFN_REGISTER_BACKEND)GetProcAddress(g_Host, "PluginRegisterVmBackend");
    g_UnregisterBackend = (PFN_UNREGISTER_BACKEND)GetProcAddress(g_Host, "PluginUnregisterVmBackend");
    g_ObserveStop = (PFN_OBSERVE_STOP)GetProcAddress(g_Host, "PluginVmObserveStop");
    g_Enter = (PFN_ENTER)GetProcAddress(g_Host, "PluginVmEnter");
    g_Exit = (PFN_EXIT)GetProcAddress(g_Host, "PluginVmExit");
    g_ResetSession = (PFN_RESET_SESSION)GetProcAddress(g_Host, "PluginVmResetSession");
    g_ShowWindow = (PFN_SHOW_WINDOW)GetProcAddress(g_Host, "PluginVmShowWindow");
    g_GetSnapshot = (PFN_GET_SNAPSHOT)GetProcAddress(g_Host,
        "PluginVmGetSnapshot");
    if (!g_RegisterBackend || !g_UnregisterBackend || !g_ObserveStop ||
        !g_Enter || !g_Exit || !g_ResetSession || !g_GetSnapshot)
    {
        return -1;
    }
    g_Registered = g_RegisterBackend(&g_Backend);
    return g_Registered ? 0 : -1;
}

extern "C" __declspec(dllexport) VMTEST_MENU* __cdecl ODBG2_Pluginmenu(wchar_t* Type)
{
    return Type && lstrcmpiW(Type, PWM_MAIN) == 0 ? g_MainMenu : NULL;
}

extern "C" __declspec(dllexport) void __cdecl ODBG2_Plugindestroy(void)
{
    if (g_Registered && g_UnregisterBackend)
    {
        g_UnregisterBackend(&g_Backend);
    }
    g_Registered = FALSE;
    g_ModelActive = FALSE;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}
