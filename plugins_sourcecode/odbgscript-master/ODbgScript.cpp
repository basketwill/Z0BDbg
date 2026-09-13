// ODbgScript.cpp : Defines the entry point for the DLL application.
//
//#define STRICT

#ifndef _WIN64
#define _CHAR_UNSIGNED 1 // huhu
#endif

#include "StdAfx.h"

#ifdef _WIN64
extern "C" void Z0B_InitializeHostImports(void);
#endif

//static HINSTANCE hinst;                // DLL instance
//static HWND      hwmain;               // Handle of main OllyDbg window

// Temp storage
wchar_t buff[65535] = {0};

// Script state
int script_state = SS_NONE;

#ifndef __AFX_H__
// Entry point into a plugin DLL. Many system calls require DLL instance
// which is passed to DllEntryPoint() as one of parameters. Remember it.
BOOL APIENTRY DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved)
{
    switch (reason)
	{
		case DLL_PROCESS_ATTACH:
#ifdef _WIN64
			Z0B_InitializeHostImports();
#endif
			//hinst = hi;        // Mark plugin instance
			//no more used (bug with global vars)
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }

	#ifdef _DEBUG
	//RedirectIOToConsole();
	#endif

    return TRUE;
}
#endif

// OllyDbg calls this obligatory function once during startup. I place all one-time initializations here.
int ODBG_Plugininit(int ollydbgversion, HWND hw, ulong *features) 
{

	if(ollydbgversion < PLUGIN_VERSION) {
		HWND hw = _hwollymain;
		MessageBox(hw, L"Incompatible Ollydbg Version !", PLUGIN_NAME, 
			MB_OK | MB_ICONERROR | MB_TOPMOST);
		return -1;
	}

	// Report plugin in the log window.
	Addtolist(0, 0, PLUGIN_NAME L" v%i.%i.%i " VERSIONCOMPILED ,VERSIONHI,VERSIONLO,VERSIONST);
	Addtolist(0, 0, L"  http://odbgscript.sf.net");

	ollylang = new OllyLang();

	if (Createsorteddata(
			&ollylang->wndLog.sorted,          // Descriptor of sorted data
			sizeof(t_wndlog_data),             // Size of single data item
			20,                                // Initial number of allocated items
			wndlog_sort_function,  // Sorting function
			wndlog_dest_function,  // Data destructor
			0)                                 // Simple data, no special options
	!= 0)	return -1;

	if (Createsorteddata(&(ollylang->wndProg.sorted), sizeof(t_wndprog_data), 50,
		wndprog_sort_function, wndprog_dest_function, 0) != 0)	return -1;

//2	HINSTANCE hinst = (HINSTANCE)GetModuleHandleW(PLUGIN_NAME L".dll");

//2	if (Registerpluginclass(wndprogclass,NULL,hinst,wndprog_winproc)<0) {
//2		return -1;
//2	}
//2	if (Registerpluginclass(wndlogclass,NULL,hinst,wndlog_winproc)<0) {
//2		return -1;
//2	}
//2 if (Plugingetvalue(VAL_RESTOREWINDOWPOS)!=0 && Pluginreadintfromini(hinst, L"Restore Script Log",0)!=0)
//		initLogWindow();

//2 if (Plugingetvalue(VAL_RESTOREWINDOWPOS)!=0 && Pluginreadintfromini(hinst, L"Restore Script window",0)!=0)
//		initProgTable();

	return 0;
}

// This function is called each time OllyDbg passes main Windows loop. When
// debugged application stops, b ring command line window in foreground.
void ODBG_Pluginmainloop(DEBUG_EVENT *debugevent) 
{	
	t_status status = Getstatus();
	script_state = ollylang->script_state;
	
    // module load event. kept for future use. http://www.openrce.org/articles/full_view/25
    /*if (debugevent && debugevent->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
		string filename;
		if (str_filename_from_handle(debugevent->u.LoadDll.hFile, filename)) {
			MsgBox(filename,""); 
		}
	}
	*/

	if (debugevent && debugevent->dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT && debugevent->u.DebugString.nDebugStringLength>0
		&& !IsBadCodePtr((FARPROC)debugevent->u.DebugString.lpDebugStringData)) {
		string msg = debugevent->u.DebugString.lpDebugStringData;
		MsgBox(w_strtow(msg),L"");
	}

	// Check for breakpoint jumps
	if(script_state == SS_RUNNING && debugevent && debugevent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{

		EXCEPTION_DEBUG_INFO edi = debugevent->u.Exception;
		if(edi.ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP)
			ollylang->OnException(edi.ExceptionRecord.ExceptionCode);
/*		else if(edi.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
			ollylang->OnBreakpoint(PP_EXCEPTION,EXCEPTION_DEBUG_EVENT);
		else	
			if(script_state == SS_RUNNING)
			{
				t_thread* t;
				t = Findthread(Getcputhreadid());
				CONTEXT context;
				context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				GetThreadContext(t->thread, &context);

				//Hardware Breakpoints...
				if(t->reg.ip == context.Dr0 || t->reg.ip == context.Dr1 || t->reg.ip == context.Dr2 || t->reg.ip == context.Dr3) {
					ollylang->OnBreakpoint(PP_HWBREAK,t->reg.ip);
				}

			}
*/
	}

	if(status == STAT_STOPPED && (script_state == SS_RUNNING || script_state == SS_LOADED || script_state == SS_PAUSED))
	{

		if (ollylang->require_addonaction) {
			try
			{
				ollylang->ProcessAddonAction();
			}
			catch( ... )
			{
				HWND hw = _hwollymain;
				MessageBox(hw, L"An error occured in the plugin!", PLUGIN_NAME, MB_OK | MB_ICONERROR | MB_TOPMOST);
			}
		}

	}


	if(status == STAT_STOPPED && (script_state == SS_RUNNING || script_state == SS_LOADED))
	{

		try
		{
			ollylang->Step(0);
			script_state = ollylang->script_state;
		}
		catch( ... )
		{
			HWND hw = _hwollymain;
			MessageBox(hw, L"An error occured in the plugin!", PLUGIN_NAME, MB_OK | MB_ICONERROR | MB_TOPMOST);
			delete ollylang;
		}

	}

	//Refocus script windows (ex: when using "Step")
	if (ollylang->wndProg.hw
		&& (status == STAT_FINISHED || status == STAT_IDLE)
		&& (script_state != SS_RUNNING)
		)
	{
		if (focusonstop>0) { 
//			InvalidateProgWindow();
			SetForegroundWindow(ollylang->wndProg.hw);
			SetFocus(ollylang->wndProg.hw);
			focusonstop--;
		}
	}	

}

int ODBG_Pausedex(int reasonex, int dummy, t_reg* reg, DEBUG_EVENT* debugevent)
{
	EXCEPTION_DEBUG_INFO edi;
	if(debugevent)
		edi = debugevent->u.Exception;

	script_state = ollylang->script_state;

//cout << hex << reasonex << endl;

	// Handle events
	if(script_state == SS_RUNNING || script_state == SS_PAUSED) 
	//PAUSED also TO PROCESS "BPGOTO" BREAKPOINTS
	{
		switch(reasonex) 
		{
//2		case PP_INT3BREAK:
//2		case PP_HWBREAK:
//2		case PP_MEMBREAK:
//2			ollylang->OnBreakpoint(reasonex,dummy);
//2			break;
//2		case PP_EXCEPTION:
//2		case PP_ACCESS:
//2		case PP_GUARDED:
//2		case PP_SINGLESTEP | PP_BYPROGRAM:
//2			ollylang->OnException(edi.ExceptionRecord.ExceptionCode);
//2			break;
		}
		if (ollylang->wndProg.hw) {
			Selectandscroll(&ollylang->wndProg,ollylang->pgr_scriptpos,2);
			InvalidateProgWindow();
		}
	}

	return 0;
}

// Function adds items to main OllyDbg menu (origin=PWM_MAIN).
int ODBG_Pluginmenu(int origin, wchar_t data[4096], void *item)
{
    t_dump *pd;

	switch (origin) {

	case PM_DISASM:
	  pd=(t_dump *)item;
      if (pd==NULL || pd->size==0)
          return 0; 

		ZeroMemory(buff, sizeof(buff));
		wcscpy(buff, L"# Run Scri&pt{0 Open...|");
		mruGetCurrentMenu(&buff[wcslen(buff)]);
 		wcscpy(&buff[wcslen(buff)],
			L"}"
			L"Script &Functions...{"
			L"30  Script &Window	"
			L",31  Script &Log	"
			L"|"
			L",4 Step	"
			L",2 Pause	PAUSE"
			L",3 Resume	"
			L",1 Abort	"
			L"|"
			L",32 Edit Script..."
			L"}"

		);
		
		wcscpy(data,buff);
		return 1;

	}
	return 0; // No pop-up menus in OllyDbg's windows
}

extc int _export cdecl ExecuteScript(const char* filename)
{
	string file = filename;
	ollylang->LoadScript(w_strtow(file));
	ollylang->Step(0);
	return 0;
}

// Needed by OllyscriptEditor
extc HWND _export cdecl DebugScript(const char* filename)
{
	string file = filename;
	if (file.length() > 0)
	{
		ollylang->LoadScript(w_strtow(file));
		ollylang->Pause();
		script_state = ollylang->script_state;
		initProgTable();
		SetForegroundWindow(ollylang->wndProg.hw);
		SetFocus(ollylang->wndProg.hw);     
	}
	return ollylang->wndProg.hw;
}

// Old Pluginaction
void ODBG_Pluginaction(int origin, int action, void *item) 
{
  HINSTANCE hinst  = (HINSTANCE)GetModuleHandleW(PLUGIN_NAME L".dll");
  HWND      hwmain = _hwollymain;
  OPENFILENAME ofn={0};
  switch (action) 
  {
	case 0: // Run script
		       // common dialog box structure
		wchar_t szFile[260];       // buffer for file name
		
		// Initialize OPENFILENAME
		//ZeroMemory(&ofn, sizeof(ofn));
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = hwmain;
		ofn.lpstrFile = szFile; 
		//
		// Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
		// use the contents of szFile to initialize itself.
		//
		ofn.lpstrFile[0] = '\0';
		ofn.nMaxFile = sizeof(szFile);
		ofn.lpstrFilter = L"Olly Scripts\0*.osc;*.txt\0All\0*.*\0";
		ofn.nFilterIndex = 1;
		ofn.lpstrFileTitle = NULL;
		ofn.nMaxFileTitle = 0;
		Getfromini(NULL,PLUGIN_NAME, L"ScriptDir", L"%s", buff);
		ofn.lpstrInitialDir = buff;
		ofn.lpstrTitle = L"Select Script";
		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
		

		// Display the Open dialog box. 
		if (GetOpenFileName(&ofn)==TRUE) //Comdlg32.lib
		{
			// Load script
			ollylang->LoadScript(ofn.lpstrFile);
			if (ollylang->wndProg.hw) {
				SetForegroundWindow(ollylang->wndProg.hw);
				SetFocus(ollylang->wndProg.hw);
			}
			// Start script
			ollylang->Resume();
		}
		break;

	case 1: // Abort
		MessageBox(hwmain, L"Script aborted!", PLUGIN_NAME, MB_OK|MB_ICONEXCLAMATION );
		ollylang->Reset();
		ollylang->Pause();
		break;

	case 2: // Pause
		ollylang->Pause();
		break;

	case 3: // Resume
		ollylang->Resume();
		break;

	case 4: // Step
		ollylang->Step(1);
		script_state = ollylang->script_state;
		break;

	case 5: // Force Pause (like Pause Key)
		focusonstop=4;
		ollylang->Pause();
		script_state = ollylang->script_state;
    	break;

	case 21: // MRU List in CPU Window
	case 22:
	case 23:
	case 24:
	case 25:
	case 26:
	case 27:
	case 28:
	case 29:
		{
			action-=20; 
			wchar_t key[5]=L"NRU ";
			key[3]=action+0x30;
						
			ZeroMemory(&buff, sizeof(buff));
			Getfromini(NULL,PLUGIN_NAME, key, L"%s", buff);

			// Load script
			ollylang->LoadScript(buff);

			mruAddFile(buff);
 
			// Save script directory
			wchar_t* buf2;
			GetFullPathName(buff,sizeof(buff),buff,&buf2); *buf2=0;			
			Pluginwritestringtoini(hinst, L"ScriptDir", buff);

			ollylang->Resume();
			if (ollylang->wndProg.hw) {
				SetForegroundWindow(ollylang->wndProg.hw);
				SetFocus(ollylang->wndProg.hw);
			}

			break;
		}
	case 30:
		{
			initProgTable();
			break;
		}
	case 31:
		{
			initLogWindow();
			break;
		}
	case 32: // Edit Script
		{
			HWND hw = _hwollymain;
			ShellExecute(hw,L"open",ollylang->scriptpath.c_str(),NULL,ollylang->currentdir.c_str(),SW_SHOWDEFAULT);
			break;
		}
	case 11:
		{
//			string x = "Hej";
//			string y = ToLower(x);
//			__asm nop;
		}
	case 12:
		{
//			Broadcast(WM_USER_CHGALL, 0, 0);
		}
//			t_thread* thr = Findthread(Getcputhreadid());
//			byte buffer[4];
//			ulong fs = thr->reg.limit[2]; // BUG IN ODBG!!!
//			fs += 0x30;
//			Readmemory(buffer, fs, 4, MM_RESTORE);
//			fs = *((ulong*)buffer);
//			fs += 2;
//			buffer[0] = 0;
//			Writememory(buffer, fs, 1, MM_RESTORE);
//			cout << endl;
		
//			ulong addr = t->reg.s[SEG_FS];
//			Readmemory(buffer, addr, 4, MM_RESTORE);
//			cout << hex << &buffer;

			/*
			HMODULE hMod = GetModuleHandle("OllyScript.dll");
			if(hMod) // Check that the other plugin is present and loaded
			{
				// Get address of exported function
				int (*pFunc)(char*) = (int (*)(char*)) GetProcAddress(hMod, "ExecuteScript");
				if(pFunc) // Check that the other plugin exports the correct function
					pFunc("xxx"); // Execute exported function
			}

			cout << hex << hMod << endl;*/
			//403008 401035
			/*DWORD pid = Plugingetvalue(VAL_PROCESSID);
			DebugSetProcessKillOnExit(FALSE);
			DebugActiveProcessStop(pid);
			break;*/
			//t_module* mod = Findmodule(0x401000);
			//cout << hex << mod->codebase;
			
			//cout << hex << mod->codebase;
		
		break;

    default: 
		break;
  }
}

int ODBG_Pluginshortcut(int origin,int ctrl,int alt,int shift,int key,void *item) {

	switch (origin) {
	case PM_MAIN:
		if (key==VK_PAUSE) {
			//will pause when running on give focus to script window
			focusonstop=4;
			ollylang->Pause();
			script_state = ollylang->script_state;
		//	SetForegroundWindow(ollylang->wndProg.hw);
		//	SetFocus(ollylang->wndProg.hw);
		}
		break; //This function is usually called twice
	case PM_DISASM:

		break; 
/*
PWM_MAIN	item is always NULL	Main window
PM_DUMP	(t_dump *)	Any Dump window
PM_MODULES	(t_module *)	Modules window
PM_MEMORY	(t_memory *)	Memory window
PM_THREADS	(t_thread *)	Threads window
PM_BREAKPOINTS	(t_bpoint *)	Breakpoints window
PM_REFERENCES	(t_ref *)	References window
PM_RTRACE	(int *)	Run trace window
PM_WATCHES	(1-based index)	Watches window
PM_WINDOWS	(t_window *)	Windows window
PWM_DISASM	(t_dump *)	CPU Disassembler
PM_CPUDUMP	(t_dump *)	CPU Dump
PM_CPUSTACK	(t_dump *)	CPU Stack
PM_CPUREGS	(t_reg *)	CPU Registers
*/
	case PM_DUMP:
	{
		if (key==VK_F5) {
			//Used to retrieve t_dump after OPENDUMP
			t_dump * pd;
			pd=(t_dump *)item;
			if (pd && pd->table.hw != 0) {
				ollylang->dumpWindows[pd->table.hw] = pd;
			}
			return 1;
		}
	}
	default:
			//if (key==VK_F8 && shift==0 && ctrl==0) {
#ifdef _DEBUG
			wchar_t* data = new wchar_t[256];
			wsprintf(data,L"ODBG_Pluginshortcut %d %d",origin,key);
			Addtolist(0, -1, data );
			delete[] data;
			return 0;
#endif
;
	}
	return 0;

}

// OllyDbg calls this optional function when user restarts debugged app
void ODBG_Pluginreset()
{	
	if (ollylang == NULL)
		return;

	//we keep the script state on restart (paused or not)
	if (ollylang->script_state == SS_PAUSED) {
		ollylang->Reset();
		ollylang->Pause();
	} 
	else 
		ollylang->Reset();
}

int ODBG_Plugincmd(int reason,t_reg *reg,wchar_t *cmd)
/*
OllyDbg will call it each time the debugged application pauses on conditional logging breakpoint that specifies commands to be passed to plugins

reason - reason why program was paused, currently always PP_EVENT;
reg - pointer to registers of thread that caused application to pause, may be NULL;
cmd - null-terminated command to plugin.
*/
{
//2	if (reason!=PP_EVENT)
//		return 0;

	int p;
	wstring scmd,args;
	scmd.assign(cmd);
	if ((p=scmd.find_first_of(L" 	\r\n")) != wstring::npos) {
		args=w_trim(scmd.substr(p+1));
		scmd=w_trim(scmd.substr(0,p));
	}
	if (ollylang->isCommand(scmd)) {
		ollylang->callCommand(scmd,args);
		return 1;
	}

	return 0; //dont stop to other plugins
}

// OllyDbg calls this optional function when user wants to terminate OllyDbg.
int ODBG_Pluginclose() 
{
	if (ollylang == NULL) return 0;

	if (ollylang->hwndinput != 0) {
		EndDialog(ollylang->hwndinput, 0);
		ollylang->hwndinput=0;
	}

	ollylang->SaveBreakPoints(ollylang->scriptpath);
	Writetoini(NULL,PLUGIN_NAME, L"Restore Script window", L"%i", (ollylang->wndProg.hw!=NULL));
	Writetoini(NULL,PLUGIN_NAME, L"Restore Script Log", L"%i", (ollylang->wndLog.hw!=NULL));
	return 0;
}

// OllyDbg calls this optional function once on exit. At this moment, all
// windows created by plugin are already destroyed (and received WM_DESTROY
// messages). Function must free all internally allocated resources, like
// window classes, files, memory and so on.
void ODBG_Plugindestroy()
{
	delete ollylang;
	//Unregisterpluginclass(wndprogclass);
	//Unregisterpluginclass(wndlogclass);
}


////////////////////////////////////////////////////////////////////////////////
//////////////////////////// PLUGIN INITIALIZATION /////////////////////////////

// Report plugin name and return version of plugin interface.
extc int _export cdecl _ODBG2_Plugindata(char shortname[32]) 
{
	wstring name= PLUGIN_NAME;
	strcpy(shortname, w_wstrto(name).c_str());
	return PLUGIN_VERSION;
}
static int Mrunscript(t_table *pt,wchar_t *name,ulong index,int mode) {
	switch (mode) { 
	case MENU_VERIFY:
		return MENU_NORMAL;                // Always available
	case MENU_EXECUTE:
		ODBG_Pluginaction(PM_MAIN, 0, NULL);
		return MENU_NOREDRAW;
	default:
	  return MENU_ABSENT;
	};
};
static int Mscriptwindow(t_table *pt,wchar_t *name,ulong index,int mode) {
	switch (mode) { 
	case MENU_VERIFY:
		return MENU_NORMAL;                // Always available
	case MENU_EXECUTE:
		//ODBG_Pluginaction(PM_MAIN, 30, NULL);
		initProgTable();
		return MENU_NOREDRAW;
	default:
	  return MENU_ABSENT;
	};
};
static int Mlogwindow(t_table *pt,wchar_t *name,ulong index,int mode) {
	switch (mode) { 
	case MENU_VERIFY:
		return MENU_NORMAL;                // Always available
	case MENU_EXECUTE:
		//ODBG_Pluginaction(PM_MAIN, 31, NULL);
		initLogWindow();
		return MENU_NOREDRAW;
	default:
	  return MENU_ABSENT;
	};
};
static int Mhelp(t_table *pt,wchar_t *name,ulong index,int mode) {
  if (mode == MENU_VERIFY)
    return MENU_NORMAL;                // Always available
  else if (mode == MENU_EXECUTE) {
		wstring directory, helpfile;
		getPluginDirectory(directory);
		helpfile = directory + L"\\ODbgScript.txt";
		HWND hw = _hwollymain;
		ShellExecute(hw,L"open",helpfile.c_str(),NULL,directory.c_str(),SW_SHOWDEFAULT);
  };
  return MENU_ABSENT;
};
// Menu function of main menu, displays About dialog.
static int Mabout(t_table *pt,wchar_t *name,ulong index,int mode) {
	HWND hw = _hwollymain;

	switch (mode) { 
	case MENU_VERIFY:
		return MENU_NORMAL;
	case MENU_EXECUTE:
		// Debuggee should continue execution while message box is displayed.
		Resumeallthreads();
		wchar_t s[256];
		wsprintf(s,L"ODbgScript plugin v%i.%i.%i\n"
			      L"by tpruvot@github\n\n"
				  L"Based on OllyScript by SHaG\n"
				  L"PE dumper by R@dier\n"
				  L"Byte replacement algo by Hex\n\n"
				  L"http://odbgscript.sf.net/ \n\n"
				  L"Compiled %s %s \n"
			       VERSIONCOMPILED L"\n",
			VERSIONHI,VERSIONLO,VERSIONST, w_strtow(__DATE__).c_str(), w_strtow(__TIME__).c_str());

		MessageBox(hw, s, PLUGIN_NAME, MB_OK|MB_ICONINFORMATION );

		// Suspendallthreads() and Resumeallthreads() must be paired, even if they are called in inverse order!
		Suspendallthreads();
		return MENU_NOREDRAW;
	default:
	  return MENU_ABSENT;
	};
};

// manual command
static int Mcommand(t_table *pt,wchar_t *name,ulong index,int mode) {
	HWND hw = _hwollymain;

	switch (mode) {
	case MENU_VERIFY:
		return MENU_NORMAL;
	case MENU_EXECUTE:
		ollylang->execCommand();
/*
		ollylang->callCommand(L"mov",L"test, 0");
		ollylang->callCommand(L"add",L"test, 50");
		ollylang->callCommand(L"log",L"test");
		ollylang->callCommand(L"log",L"\"-10 result:\"");
		ollylang->callCommand(L"add",L"test, -10");
		ollylang->callCommand(L"log",L"test");
		ollylang->callCommand(L"mov",L"e, eip");
		ollylang->callCommand(L"log",L"e");
		ollylang->callCommand(L"bp",L"e");
		ollylang->callCommand(L"bc",L"e");
*/
		return MENU_NOREDRAW;
	default:
	  return MENU_ABSENT;
	};
};

// Plugin menu that will appear in the main OllyDbg menu. Note that this menu
// must be static and must be kept for the whole duration of the debugging
// session.
static t_menu mainmenu[] = {

  { L"&Run &Script...",
       L"Open &Script window",
       KK_DIRECT|KK_SHIFT|'R', Mrunscript, NULL, 0 },
  { L"&Script Window",
       L"Open &Script window",
       KK_DIRECT|KK_SHIFT|'S', Mscriptwindow, NULL, 0 },
  { L"&Log Window",
       L"Open Script &Log window",
	   KK_DIRECT|KK_SHIFT|'L', Mlogwindow, NULL, 0 },
  { L"|&Command...",
       L"Execute manual &command",
       KK_DIRECT|KK_SHIFT|'C', Mcommand, NULL, 0 },
  { L"|&Help",
       L"&Help",
       K_NONE, Mhelp, NULL, 0 },
  { L"|About",
       L"About ODBGScript",
       K_NONE, Mabout, NULL, 0 },
  { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

extc _export t_menu* _ODBG2_Pluginmenu(wchar_t *type)
{
  if (wcscmp(type,PWM_MAIN)==0)
    // Main menu.
    return mainmenu;
  else if (wcscmp(type,PWM_DISASM)==0)
    // Disassembler pane of CPU window.
    return mainmenu;

  return NULL; // No menu
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// DUMP WINDOW HOOK ///////////////////////////////

// Dump windows display contents of memory or file as bytes, characters,
// integers, floats or disassembled commands. Plugins have the option to modify
// the contents of the dump windows. If ODBG2_Plugindump() is present and some
// dump window is being redrawn, this function is called first with column=
// DF_FILLCACHE, addr set to the address of the first visible element in the
// dump window and n to the estimated total size of the data displayed in the
// window (n may be significantly higher than real data size for disassembly).
// If plugin returns 0, there are no elements that will be modified by plugin
// and it will receive no other calls. If necessary, plugin may cache some data
// necessary later. OllyDbg guarantees that there are no calls to
// ODBG2_Plugindump() from other dump windows till the final call with
// DF_FREECACHE.
// When OllyDbg draws table, there is one call for each table cell (line/column
// pair). Parameters s (UNICODE), mask (DRAW_xxx) and select (extended DRAW_xxx
// set) contain description of the generated contents of length n. Plugin may
// modify it and return corrected length, or just return the original length.
// When table is completed, ODBG2_Plugindump() receives final call with
// column=DF_FREECACHE. This is the time to free resources allocated on
// DF_FILLCACHE. Returned value is ignored.
// Use this feature only if absolutely necessary, because it may strongly
// impair the responsiveness of the OllyDbg. Always make it switchable with
// default set to OFF!
extc int _export _ODBG2_Plugindump(t_dump *pd,
  wchar_t *s,uchar *mask,int n,int *select,ulong addr,int column) {
  int i,j;
  wchar_t w[TEXTLEN];

  return n;
}

// ODBG_Pluginquery() is a "must" for valid OllyDbg plugin. First it must check
// whether given OllyDbg version is correctly supported, and return 0 if not.
// Then it should make one-time initializations and allocate resources. On
// error, it must clean up and return 0. On success, if should fill plugin name
// and plugin version (as UNICODE strings) and return version of expected
// plugin interface. If OllyDbg decides that this plugin is not compatible, it
// will call ODBG2_Plugindestroy() and unload plugin. Plugin name identifies it
// in the Plugins menu. This name is max. 31 alphanumerical UNICODE characters
// or spaces + terminating L'\0' long. To keep life easy for users, this name
// should be descriptive and correlate with the name of DLL. This function
// replaces ODBG_Plugindata() and ODBG_Plugininit() from the version 1.xx.
extc int _export _ODBG2_Pluginquery(int ollydbgversion,
	wchar_t pluginname[SHORTNAME],wchar_t pluginversion[SHORTNAME]) {
	int restore;
#ifdef _WIN64
	Z0B_InitializeHostImports();
#endif
	// Check whether OllyDbg has compatible version. This plugin uses only the
	// most basic functions, so this check is done pro forma, just to remind of
	// this option.
	if (ollydbgversion<201)
		return 0;

	ulong features = _cpufeatures;
	HWND hw = _hwollymain;
	ODBG_Plugininit(ollydbgversion, hw, &features);

	// Report name and version to OllyDbg.
	wcscpy(pluginname,PLUGIN_NAME);
	wsprintf(pluginversion,L"%d.%d.%d", VERSIONHI,VERSIONLO,VERSIONST);
	return PLUGIN_VERSION;
};

// Function is called when user opens new or restarts current application.
// Plugin should reset internal variables and data structures to initial state.
extc void _export _ODBG2_Pluginreset(void) {
	ODBG_Pluginreset();
};

// If you define ODBG2_Pluginmainloop, this function will be called each time
// from the main Windows loop in OllyDbg. If there is some (real) debug event
// from the debugged application, debugevent points to it, otherwise it's NULL.
// If fast command emulation is active, it does not receive all (emulated)
// exceptions, use ODBG2_Pluginexception() instead. Do not declare this
// function unnecessarily, as this may negatively influence the overall speed!
extc void _export _ODBG2_Pluginmainloop(DEBUG_EVENT *debugevent) {
	ODBG_Pluginmainloop(debugevent);
};

extc void _export _ODBG2_Pluginexception(t_reg *preg) {
	ODBG_Pluginmainloop(NULL);
};

// Optional entry, called each time OllyDbg analyses some module and analysis
// is finished. Plugin can make additional analysis steps. Debugged application
// is paused for the time of processing. Bookmark plugin, of course, does not
// analyse code. If you don't need this feature, remove ODBG2_Pluginanalyse()
// from the plugin code.
extc void _export _ODBG2_Pluginanalyse(t_module *pmod) {
    ODBG_Pluginmainloop(NULL);
};
////////////////////////////////////////////////////////////////////////////////


// OllyDbg calls this optional function when user wants to terminate OllyDbg.
// All MDI windows created by plugins still exist. Function must return 0 if
// it is safe to terminate. Any non-zero return will stop closing sequence. Do
// not misuse this possibility! Always inform user about the reasons why
// termination is not good and ask for his decision! Attention, don't make any
// unrecoverable actions for the case that some other plugin will decide that
// OllyDbg should continue running.
extc int _export _ODBG2_Pluginclose(void) {
  return ODBG_Pluginclose();
};

// OllyDbg calls this optional function once on exit. At this moment, all MDI
// windows created by plugin are already destroyed (and received WM_DESTROY
// messages). Function must free all internally allocated resources, like
// window classes, files, memory etc.
extc void _export _ODBG2_Plugindestroy(void) {
	ODBG_Plugindestroy();
};


#include "Dialogs.cpp"
#include "Progress.cpp"
#include "LogWindows.cpp"
#include "Search.cpp"

