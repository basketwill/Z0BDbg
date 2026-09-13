#pragma once

using namespace std;

//static wchar_t	wndprogclass[32];	   // Name of progress window class
//static wchar_t	wndlogclass[32];	   // Name of log window class
//static wchar_t	wndwatchclass[32];
static int		focusonstop;             // Foreground on pause

static bool		dbgfocus=false;

static void*	pmemforexec;

#define STRING_READSIZE 256

extc HWND _export cdecl DebugScript(const char* const filename);

#include "version.h"
#include "mru.h"

//For unique vars btw processes
//#pragma data_seg( ".GLOBALS" )
//#pragma data_seg()

// ODBG2 stuff :

int Mrunscript(t_table *pt,wchar_t *name,ulong index,int mode);
int Mscriptwindow(t_table *pt,wchar_t *name,ulong index,int mode);
int Mlogwindow(t_table *pt,wchar_t *name,ulong index,int mode);
int Mcommand(t_table *pt,wchar_t *name,ulong index,int mode);
int Mabout(t_table *pt,wchar_t *name,ulong index,int mode);

int Mtest(t_table *pt,wchar_t *name,ulong index,int mode);

// OllyLang object
static OllyLang* ollylang;
