#pragma once

// General functions
wstring ToLower(wstring in);
int searchx(wchar_t *SearchBuff, int BuffSize, wchar_t *SearchString, int StringLen, wchar_t wc);
bool GetWildcardBytePositions(wstring bytestring, vector<int>* wildcardpos);
bool RgchContains(wchar_t* container, uint containerlen, wchar_t* containee, uint containeelen);
bool is_hex(wstring& s);
bool is_hexwild(wstring& s);
bool is_dec(wstring &s);
bool is_float(wstring &s);
DWORD rev(DWORD dw);
bool split(vector<wstring> &vec, const wstring &str, const wchar_t delim);
char GetWildcard(wstring &s);
int Str2Rgch(wstring &s, wchar_t* arr, uint size);
int Str2RgchWithWC(wstring &s, wchar_t* arr, uint size, wchar_t wc);
bool UnquoteString(wstring& s, wchar_t cstart, wchar_t cend);
void MsgBox(wstring sMsg, wstring sTitle);
void DbgMsg(int n, wchar_t* title);
void DbgMsg(int n,wstring title=L"");
void DbgMsgHex(int n, wchar_t* title);
void DbgMsgHex(int n,wstring title=L"");
int Str2Hex(wstring &s, wstring &dst);
int Str2Hex(wstring &s, wstring &dst, ulong size);
long double strtof(wstring &s);
int Int2Hex(DWORD dw, wstring &dst);
void ReplaceString(wstring &s, wchar_t* what, wchar_t* with);
wstring CleanString(wstring &s);


bool ESPRun(void);

HWND FindHandle(DWORD dwThreadId, wstring wdwClass, long x, long y);
DWORD getPluginDirectory(wstring &directory);

// PE Dumper
bool SaveDump(wstring fileName, DWORD ep);
bool GetPEInfo(DWORD ep);

DWORD  resizeDW(DWORD dw, DWORD size);
void resizeSTR(wstring &str, DWORD size);

wstring StrLastError(void);
LARGE_INTEGER MyGetTickCount(ULONGLONG oldValue, bool bUseTickCount=0);

HWND GetODBGWindow(wstring &title, wstring &classname);
HWND GetODBGWindow(char * title, char * classname);

//PSAPI.DLL (to get Module name from Handle)
typedef DWORD (WINAPI *lpfGetMappedFileName) (HANDLE, LPVOID, LPTSTR, DWORD);
BOOL get_filename_from_handle (HANDLE h_file, char *target_filename);
BOOL str_filename_from_handle (HANDLE h_file, wstring &target_filename);

//UNICODE FUNCTIONS
wstring w_trim(const wstring& sData);
wstring Str2Unicode(char* s,ulong len);
wstring Str2Unicode(string &s);

wstring w_strtow(string str);
string w_wstrto(wstring wstr);

//ODBG 1.10 compat
void Selectandscroll(t_table* t, int index, int mode);
void Sendshortcut(ulong win,ulong addr,int msg,int ctrl,int shift,int vkcode);
void Sendshortcut(wstring win,ulong addr,int msg,int ctrl,int shift,int vkcode);


//odbg 1.10 compat. (temporary)
#ifdef _MSC_VER

	#define t_hardbpoint t_bphard

	#define Pluginwritestringtoini(h,key,val) Writetoini(NULL,PLUGIN_NAME, key, L"%s", val)

	#define Gettext(T,B,X,Y,F) Getstring(0, T, B,sizeof(B), 0,0, X,Y, 0,0)
	#define Getstatus() _run.status
	#define Infoline(s) Tempinfo(s)

	//STAT_IDLE
	#define STAT_STOPPED STAT_FINISHED

	// to fix...
	#define Findname(n,NM_SOURCE,buffer) wcscpy(buffer,L"")
	#define Insertname(n,NM_SOURCE,buffer)
	#define Painttable(a,b,c)
	#define Tablefunction(T,H,M,W,L) 0
	#define NM_SOURCE (DT_ANYDATA - 0x10)
	#define WM_USER_MENU (WM_USER + 0x66)
	#define D_PATH 'i'
	#define D_GRAYPATH 'j'
	#define BAR_NOSORT 0

	#define MM_RESTORE 0
	#define MM_DELANAL 0

	#define ADC_JUMP   DM_JUMPIMP
	#define ADC_STRING DM_STRING
	#define ADC_ENTRY  DM_ENTRY
	#define ADC_OFFSET DM_OFFSET
	#define ADC_SYMBOL DM_SYMBOL

	#define TABLE_COPYMENU 0
	#define TABLE_APPMENU 0
	#define TABLE_ONTOP 0
	#define TABLE_HILMENU 0
	#define TABLE_WIDECOL 0

	#define PM_MAIN        0               // Main window        (NULL)
	#define PM_DUMP        10              // Any Dump window    (t_dump*)
	#define PM_MODULES     11              // Modules window     (t_module*)
	#define PM_MEMORY      12              // Memory window      (t_memory*)
	#define PM_THREADS     13              // Threads window     (t_thread*)
	#define PM_BREAKPOINTS 14              // Breakpoints window (t_bpoint*)
	#define PM_REFERENCES  15              // References window  (t_ref*)
	#define PM_RTRACE      16              // Run trace window   (int*)
	#define PM_WATCHES     17              // Watches window     (1-based index)
	#define PM_WINDOWS     18              // Windows window     (t_window*)
	#define PM_DISASM      31              // CPU Disassembler   (t_dump*)
	#define PM_CPUDUMP     32              // CPU Dump           (t_dump*)
	#define PM_CPUSTACK    33              // CPU Stack          (t_dump*)
	#define PM_CPUREGS     34              // CPU Registers      (t_reg*)

#endif