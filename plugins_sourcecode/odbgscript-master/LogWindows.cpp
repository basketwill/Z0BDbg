// Custom table function of bookmarks window. Here it is used only to process
// doubleclicks (custom message WM_USER_DBLCLK). This function is also called
// on WM_DESTROY, WM_CLOSE (by returning -1, you can prevent window from
// closing), WM_SIZE (custom tables only), WM_CHAR (only if TABLE_WANTCHAR is
// set) and different custom messages WM_USER_xxx (depending on table type).
// See documentation for details.

long cdecl wndlog_func(t_table *pt,HWND hw,UINT msg,WPARAM wp,LPARAM lp) {
  t_logwnd_data *pmark;
  wchar_t wbuf[30];
  Addtolist(msg,0,_itow(msg,wbuf,16));
  switch (msg) {
    case WM_USER_DBLCLK:               // Doubleclick
      // Get selection.
      pmark=(t_logwnd_data *)Getsortedbyselection(
        &ollylang->wndLog.sorted,ollylang->wndLog.sorted.selected);
      // Follow address in CPU Disassembler pane. Actual address is added to
      // the history, so that user can easily return back to it.
      if (pmark!=NULL) Setcpu(0,pmark->eip,0,0,0,
        CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
      return 1;
    default: break;
  };
  return 0;
};

/*
LRESULT CALLBACK wndlog_winproc(t_table *pt,HWND hw,UINT msg,WPARAM wp,LPARAM lp) {
t_logwnd_data *pll;
HMENU menu;
int i,shiftkey,controlkey;

	switch (msg) {
		case WM_DESTROY:
		case WM_MOUSEMOVE:
		case WM_LBUTTONDOWN:
		case WM_LBUTTONDBLCLK:
		case WM_LBUTTONUP:
		case WM_RBUTTONDOWN:
		case WM_RBUTTONDBLCLK:
		case WM_HSCROLL:
		case WM_VSCROLL:
		case WM_TIMER:
		case WM_SYSKEYDOWN:
			Tablefunction(&ollylang->wndLog,hw,msg,wp,lp);
			break;                           // Pass message to DefMDIChildProc()
			// Custom messages responsible for scrolling and selection. User-drawn
			// windows must process them, standard OllyDbg windows without extra
			// functionality pass them to Tablefunction()
//2		case WM_USER_SCR:
//2		case WM_USER_VABS:
//2		case WM_USER_VREL:
		case WM_USER_VBYTE:
//2		case WM_USER_STS:
		case WM_USER_CNTS:
//2		case WM_USER_CHGS:
		case WM_WINDOWPOSCHANGED:
			return Tablefunction(&ollylang->wndLog,hw,msg,wp,lp);
		case WM_USER_MENU:
			menu=CreatePopupMenu();

//			AppendMenu(menu,MF_SEPARATOR,0,L"-"); 

			pll=(t_logwnd_data *)Getsortedbyselection(&(ollylang->wndLog.sorted),ollylang->wndLog.sorted.selected);
			if (menu!=NULL && pll!=NULL) {
				AppendMenu(menu,MF_STRING, 10,L"Cl&ear window");
				AppendMenu(menu,MF_STRING, 20,L"&Find\tCtrl+F");
			};

			// Even when menu is NULL, call to Tablefunction is still meaningful.
			i=Tablefunction(&ollylang->wndLog,hw,WM_USER_MENU,0,(LPARAM)menu);

			if (menu!=NULL) DestroyMenu(menu);
			switch (i) { 
				case 10:
					clearLogLines();
					InvalidateRect(hw, NULL, FALSE);
					return 1;
				case 20: //Search
				{
					wchar_t buffer[TEXTLEN]={0};
					Findname(1,NM_SOURCE,buffer);
					i = Gettext(L"Search in log...",buffer,0,NM_SOURCE,FIXEDFONT);
					if (i != -1) {
						wstring s; s.assign(buffer);
						Insertname(1,NM_SOURCE,buffer);
						i = SearchInLog(s,ollylang->wndLog.sorted.selected+1);
						if (i >= 0) {
							Selectandscroll(&ollylang->wndLog,i,1);
							InvalidateRect(hw, NULL, FALSE);
						}
					}
					return 1;
				}
				default:;
			}
			return 0;

		case WM_USER_DBLCLK:
			pll=(t_wndlog_data *)Getsortedbyselection(&(ollylang->wndLog.sorted),ollylang->wndLog.sorted.selected);
			if (pll!=NULL) {
				if (pll->line) Setcpu(0,pll->line,0,0,0,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
				InvalidateRect(hw, NULL, FALSE);
				return 1;
			}

		case WM_KEYDOWN:
			shiftkey=GetKeyState(VK_SHIFT) & 0x8000;
			controlkey=GetKeyState(VK_CONTROL) & 0x8000;
			if (wp==VK_RETURN && shiftkey==0 && controlkey==0) {
				// Return key follows in Disassembler.
				pll=(t_wndlog_data *)Getsortedbyselection(&(ollylang->wndLog.sorted),ollylang->wndLog.sorted.selected);
				if (pll!=NULL) {
					if (pll->line) Setcpu(0,pll->line,0,0,0,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
					InvalidateRect(hw, NULL, FALSE);
				}
				return 1;
			} 
			else if (wp=='F' && controlkey) //Search
			{				
				wchar_t buffer[TEXTLEN]={0};
				Findname(1,NM_SOURCE,buffer);
				i = Gettext(L"Search in log...",buffer,0,NM_SOURCE,FIXEDFONT);
				if (i != -1) {
					wstring s; s.assign(buffer);
					Insertname(1,NM_SOURCE,buffer);
					i = SearchInLog(s,ollylang->wndLog.sorted.selected+1);
					if (i >= 0) {
						Selectandscroll(&ollylang->wndLog,i,1);
						InvalidateRect(hw, NULL, FALSE);
					}
				}
				return 1;
			}
			Tablefunction(&ollylang->wndLog,hw,msg,wp,lp);
			break;
        case WM_USER_CHGALL:
        case WM_USER_CHGMEM:
            InvalidateRect(hw, NULL, FALSE);
            return 0;
        case WM_PAINT:
            Painttable(hw, &ollylang->wndLog, wndlog_get_text);
			return 0;
		default:
		break;
	}
	return DefMDIChildProc(hw,msg,wp,lp);
}
*/

void initLogWindow() {

	HINSTANCE hinst;

  	if (ollylang->wndLog.bar.nbar==0) {

    ollylang->wndLog.bar.visible=1;

	ollylang->wndLog.bar.name[0]=L"Address";
	ollylang->wndLog.bar.expl[0]=L"Address";
    ollylang->wndLog.bar.mode[0]=BAR_NOSORT;
    ollylang->wndLog.bar.defdx[0]=9;

	ollylang->wndLog.bar.name[1]=L"Message";
	ollylang->wndLog.bar.expl[1]=L"Message"; 
    ollylang->wndLog.bar.mode[1]=BAR_NOSORT;
    ollylang->wndLog.bar.defdx[1]=130;

	ollylang->wndLog.bar.nbar=2;
    ollylang->wndLog.mode=TABLE_SAVEALL; //TABLE_COPYMENU|TABLE_APPMENU|TABLE_SAVEPOS|TABLE_ONTOP|TABLE_HILMENU;
    ollylang->wndLog.drawfunc = wndlog_get_text;
	ollylang->wndLog.tabfunc  = wndlog_func;
	ollylang->wndLog.custommode=0;
	ollylang->wndLog.customdata=NULL;
	ollylang->wndLog.updatefunc=NULL;
	ollylang->wndLog.tableselfunc=NULL;

	ollylang->wndLog.menu = mainmenu;

	//hinst = (HINSTANCE)GetModuleHandleW(PLUGIN_NAME L".dll");

	}

	if (ollylang->wndLog.hw == NULL || !IsWindow(ollylang->wndLog.hw)) {
		ollylang->wndLog.hw = NULL;
		hinst = _hollyinst;
		Createtablewindow(&(ollylang->wndLog),0,2,hinst,L"ICO_L",PLUGIN_NAME);
	}

	//1. Quicktablewindow(&ollylang->wndLog,15,2,wndlogclass,L"Script Log Window");

	if (ollylang->wndLog.hw) {
    	Activatetablewindow(&ollylang->wndLog);
		hinst = (HINSTANCE)GetModuleHandleW(PLUGIN_NAME L".dll");
		HICON ico=LoadIcon(hinst,MAKEINTRESOURCE(IDI_ICON_LOG)); 
		SendMessage(ollylang->wndLog.hw,WM_SETICON,false,(long)ico);
	}
}

int cdecl wndlog_sort_function(const t_sorthdr *sh1,const t_sorthdr *sh2,const int n) {
	t_wndlog_data *lline1 = (t_wndlog_data *)sh1;
	t_wndlog_data *lline2 = (t_wndlog_data *)sh2;

	if (lline1->line > lline2->line) 
		return 1;
	else if (lline1->line < lline2->line) 
		return -1;
	return 0;
}

// destructor
void cdecl wndlog_dest_function(t_sorthdr *p) {
}

// drawfunc
int cdecl wndlog_get_text(wchar_t *s,uchar *mask,int *select,struct t_table *pt, t_sorthdr *ph,int column,void *cache) {

	int ret=0;
	t_wndlog_data *lline;

	switch (column) {

		case DF_CACHESIZE:                 // Request for draw cache size
			// Columns 3 and 4 (disassembly and comment) both require calls to
			// Disasm(). To accelerate processing, I call disassembler once per line
			// and cache data between the calls. Here I inform the drawing routine
			// how large the cache must be.
			// return sizeof(t_disasm);
			return sizeof(t_wndlog_data);
		case DF_FILLCACHE:                 // Request to fill draw cache
			// We don't need to initialize cache when drawing begins. Note that cache
			// is initially zeroed.
			return 0;
		case DF_FREECACHE:                 // Request to free cached resources
			// We don't need to free cached resources when drawing ends.
			return 0;
		case DF_NEWROW:                    // Request to start new row in window
			// New row starts. Let us disassemble the command at the pointed address.
			// I assume that bookmarks can't be set on data. First of all, we need to
			// read the contents of memory. Length of 80x86 commands is limited to
			// MAXCMDSIZE bytes.
			// length=Readmemory(cmd,pmark->addr,sizeof(cmd),MM_SILENT|MM_PARTIAL);
			// if (length==0) {
			// 	// Memory is not readable.
			// 	StrcopyW(pasm->result,TEXTLEN,L"???");
			// 	StrcopyW(pasm->comment,TEXTLEN,L""); }
			// else
			// 	Disasm(cmd,length,pmark->addr,Finddecode(pmark->addr,NULL),pasm,DA_TEXT|DA_OPCOMM|DA_MEMORY,NULL,NULL);
			return 0;

		case 0:
			lline = (t_wndlog_data *)ph;
			ret = Simpleaddress(s,lline->eip,mask,select);
			break;
		case 1:
			lline = (t_wndlog_data *)ph;
			ret = wsprintf(s, L"%s", lline->message);
			break;
	}
	return ret;
}

void clearLogLines() {

	if (!ollylang->tLogLines.empty()) {
		Deletesorteddatarange(&(ollylang->wndLog.sorted),0,0xffffffff);
		ollylang->tLogLines.clear();
		if (ollylang->wndLog.hw!=NULL)	InvalidateRect(ollylang->wndLog.hw, NULL, FALSE);
	}
}

int add2log(wchar_t* message) {

	t_dump *cpuasm;
	t_wndlog_data lline={0};
	
	cpuasm = Getcpudisasmdump();

	lline.line = ollylang->tLogLines.size()+1;
	lline.eip = cpuasm->sel0;
	lline.size = 1;
	wcsncpy(lline.message,message,LOG_MSG_LEN-1);

	ollylang->tLogLines.push_back(lline);

	Addsorteddata(&(ollylang->wndLog.sorted),&(ollylang->tLogLines.back()));

	if (ollylang->wndLog.hw!=NULL) {
		Selectandscroll(&ollylang->wndLog,lline.line-1,2);
		InvalidateRect(ollylang->wndLog.hw, NULL, FALSE);
	}
	return 1;
}

int add2log(wstring & message) {

	wstring s;
	vector<wstring> v;
	int i;

	if (split(v, message, '\n'))
	{
		for (i=0;i<v.size();i++) {
			add2log((wchar_t*)v[i].c_str());
		}
		return 1;
	} 
	else
		return add2log((wchar_t*)message.c_str());

}

int add2logMasked(wchar_t* message,wchar_t* mask) {
return 1;
}

int SearchInLog(wstring text, ulong fromPos)
{
	vector<t_wndlog_data>::iterator iter;
	wstring s;
	int loc = 0;
	bool oneTime = true;

	int (*pf)(int) = tolower; 
	transform(text.begin(), text.end(), text.begin(), pf);

	SearchFromLogStart:
	iter = ollylang->tLogLines.begin();

	while(iter != ollylang->tLogLines.end())
	{
		if (loc >= fromPos) {
			s.assign(iter->message);
			transform(s.begin(), s.end(), s.begin(), pf);
			if(s.length() > 0) {
				if(s.find(text) != wstring::npos) {
					return loc;
				}
			}
		}
		iter++;
		loc++;
	}
	if (fromPos > 0 && oneTime) {
		fromPos = 0; loc = 0;
		oneTime = false;
		goto SearchFromLogStart;
	}

	return -1;
}
