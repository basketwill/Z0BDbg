long wndprog_func(t_table *pt,HWND hw,UINT msg,WPARAM wp,LPARAM lp) {
  return 0;
}

/*
LRESULT CALLBACK wndprog_winproc(HWND hw,UINT msg,WPARAM wp,LPARAM lp) {
int i,m,shiftkey,controlkey;
BYTE keystate;
WORD key;
ulong u;
HMENU menu,mLoad,mCmd,mRun,mLabels=NULL,mVars=NULL;
t_wndprog_data *ppl;

	//HWND hw = _hwollymain;

	switch (msg)
	{
		case WM_LBUTTONDBLCLK:
			i=ollylang->wndProg.sorted.selected;
			//ppl=(t_wndprog_data *)Getsortedbyselection(&ollylang->wndProg.sorted,ollylang->wndProg.sorted.selected);
			if (i > 0)
			{
				i=ollylang->GetFirstCodeLine(i-1)+1;
				ollylang->jumpToLine(i);
				InvalidateRect(hw, NULL, FALSE);
			}
		break;

		case WM_DESTROY:
		case WM_MOUSEMOVE:
		case WM_LBUTTONDOWN:
		case WM_LBUTTONUP:
		case WM_RBUTTONDOWN:
		case WM_RBUTTONDBLCLK:
		case WM_HSCROLL:
		case WM_VSCROLL:
		case WM_TIMER:
		case WM_SYSKEYDOWN:
			Tablefunction(&(ollylang->wndProg),hw,msg,wp,lp);
			break;                           // Pass message to DefMDIChildProc()
			// Custom messages responsible for scrolling and selection. User-drawn
			// windows must process them, standard OllyDbg windows without extra
			// functionality pass them to Tablefunction()
//2		case WM_USER_SCR:
//2		case WM_USER_VABS:
//2		case WM_USER_VREL:
//2		case WM_USER_STS:
//2		case WM_USER_CHGS:
		case WM_USER_VBYTE:
		case WM_USER_CNTS:
		case WM_WINDOWPOSCHANGED:
			return Tablefunction(&(ollylang->wndProg),hw,msg,wp,lp);
		case WM_USER_MENU:
			menu=CreatePopupMenu();

			mRun=CreatePopupMenu();
			AppendMenu(menu,MF_POPUP,(DWORD) mRun,L"Run Script");
			AppendMenu(mRun,MF_MENUBREAK,20,L"Open...");
			AppendMenu(mRun,MF_SEPARATOR,0,L"-");
			mruGetCurrentMenu(mRun,20);

			mLoad=CreatePopupMenu();
			AppendMenu(menu,MF_POPUP,(DWORD) mLoad,L"Load Script");
			AppendMenu(mLoad,MF_MENUBREAK,10,L"Open...");
			AppendMenu(mLoad,MF_SEPARATOR,0,L"-");
			mruGetCurrentMenu(mLoad,10);

			AppendMenu(menu,MF_SEPARATOR,0,L"-");
			AppendMenu(menu,MF_STRING, 1,L"&Help");

			//mCmd=CreatePopupMenu();
			//AppendMenu(mCmd,MF_SEPARATOR,0,"-");
			//mruCmdMenu(mCmd,50);

			ppl=(t_wndprog_data *)Getsortedbyselection(&ollylang->wndProg.sorted,ollylang->wndProg.sorted.selected);
			if (menu!=NULL && ppl!=NULL)
			{
				AppendMenu(menu,MF_STRING, 30,L"Edit Script...");
				AppendMenu(menu,MF_SEPARATOR,0,L"-");
				AppendMenu(menu,MF_DEFAULT,31,L"&Follow\tEnter");
				AppendMenu(menu,MF_STRING, 32,L"Toggle Script BP\tF2");
				AppendMenu(menu,MF_STRING, 36,L"Run until cursor\tF4");
				AppendMenu(menu,MF_STRING, 33,L"Step\tTAB");

				if (script_state==SS_PAUSED)
					AppendMenu(menu,MF_STRING, 34,L"Resume\tSPC");
				else
					AppendMenu(menu,MF_STRING, 34,L"Pause\tSPC");

				AppendMenu(menu,MF_STRING, 35,L"Abort\tESC");

				AppendMenu(menu,MF_DEFAULT,37,L"&Edit line\tE");
			}
			if (ollylang->labels.size() > 0)
			{
				mLabels=CreatePopupMenu();
				AppendMenu(menu,MF_SEPARATOR,0,L"-");
				AppendMenu(menu,MF_POPUP,(DWORD) mLabels,L"Scroll to Label");
				ollylang->menuListLabels(mLabels,MASK_POPUP_LABEL);
			}

			if (ollylang->variables.size() > 0)
			{
				mVars=CreatePopupMenu();
				AppendMenu(menu,MF_SEPARATOR,0,L"-");
				AppendMenu(menu,MF_POPUP,(DWORD) mVars,L"Edit Variables");
				ollylang->menuListVariables(mVars,MASK_POPUP_VAR);
			}
			if (Getstatus() == STAT_STOPPED)
			{
				AppendMenu(menu,MF_SEPARATOR,0,L"-");
				AppendMenu(menu,MF_STRING, 39,L"Execute Command...\tX");
			}

			// Even when menu is NULL, call to Tablefunction is still meaningful.
			i=Tablefunction(&ollylang->wndProg,hw,WM_USER_MENU,0,(LPARAM)menu);

			if (menu!=NULL) DestroyMenu(menu);
			if (mLoad!=NULL) DestroyMenu(mLoad);
			//if (mCmd!=NULL) DestroyMenu(mCmd);
			if (mRun!=NULL) DestroyMenu(mRun);
			if (mLabels!=NULL) DestroyMenu(mLabels);
			if (mVars!=NULL) DestroyMenu(mVars);

			if (i>10 && i<=29 && i!=20)
			{

				wchar_t key[5]=L"NRU ";
				key[3]=(i%10)+0x30;

				ZeroMemory(&buff, sizeof(buff));
				Getfromini(NULL,PLUGIN_NAME, key, L"%s", buff);

				// Load script
				ollylang->LoadScript(buff);

				mruAddFile(buff);

				// Save script directory
				wchar_t* buf2;
				GetFullPathName(buff,sizeof(buff),buff,&buf2);
				*buf2=0;
				Pluginwritestringtoini(0, L"ScriptDir", buff);

				// Pause script (From Load Script MRU)
				if (i<20)
				{
					ollylang->Pause();
				}
				return 1;
			}
			else if (i & MASK_POPUP_VAR)
			{
				if (i & CMD_POPUP_MASK)
					ollylang->followVariable(i-MASK_POPUP_VAR);
				else
					ollylang->editVariable(i-MASK_POPUP_VAR);
				InvalidateRect(hw, NULL, FALSE);
				return 1;
			}
			else if (i & MASK_POPUP_LABEL)
			{
				Selectandscroll(&ollylang->wndProg,i-MASK_POPUP_LABEL,2);
				InvalidateRect(hw, NULL, FALSE);
				return 1;
			}
			else

			switch (i)
			{
				case 1:
				{
					wstring directory, helpfile;
					getPluginDirectory(directory);
					helpfile = directory + L"\\ODbgScript.txt";
					ShellExecuteW(hw,L"open",helpfile.c_str(),NULL,directory.c_str(),SW_SHOWDEFAULT);
				}
				break;
				case 20: // Open Run
					ODBG_Pluginaction(PM_MAIN,0,NULL);
					return 1;
				case 10: // Open Load
					ODBG_Pluginaction(PM_MAIN,0,NULL);
					ollylang->Pause();
					return 1;
				case 30: // Edit Script
					ShellExecute(hw,L"open",ollylang->scriptpath.c_str(),NULL,ollylang->currentdir.c_str(),SW_SHOWDEFAULT);
					return 1;
				case 31: // Follow in Disassembler
					if (ppl!=NULL) Setcpu(0,ppl->eip,0,0,0,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
					InvalidateRect(hw, NULL, FALSE);
					return 1;
				case 32: // Toggle Script BP
					if (ppl!=NULL) if (ppl->pause) ppl->pause=0; else ppl->pause=1;
					InvalidateRect(hw, NULL, FALSE);
					return 1;
				case 36:
					if (ppl!=NULL) ppl->pause=1;
					ollylang->Resume();
					return 1;
				case 37:
					if (ppl!=NULL) editProgLine(ppl);
					return 1;
				case 33: // Step
					ollylang->Pause(); //for right click step when running
					ollylang->Step(1);
					script_state = ollylang->script_state;
					focusonstop=5;
					return 1;
				case 34: // Pause/Resume
					if (script_state==SS_PAUSED)
					{
						ollylang->Resume();
					}
					else
					{
						ollylang->Pause();
						script_state = ollylang->script_state;
					}
					return 1;
				case 35: // Abort
					ollylang->Reset();
					ollylang->Pause();
					return 1;
			case 39: // Execute Command
					if (Getstatus() == STAT_STOPPED)
					{
						ollylang->execCommand();
						InvalidateRect(hw, NULL, FALSE);
					}
					return 1;
				case 51:
					if (Getstatus() == STAT_STOPPED)
					{
						ESPRun();
					}
					return 1;
				default:;
			}
			return 0;

		case WM_USER_DBLCLK:
			ppl=(t_wndprog_data *)Getsortedbyselection(&(ollylang->wndProg.sorted),ollylang->wndProg.sorted.selected);
			if (ppl!=NULL)
			{
				if (ppl->eip) Setcpu(0,ppl->eip,0,0,0,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
				InvalidateRect(hw, NULL, FALSE);
				return 1;
			}

		case WM_KEYDOWN:
			shiftkey=GetKeyState(VK_SHIFT) & 0x8000;
			controlkey=GetKeyState(VK_CONTROL) & 0x8000;
			if (wp==VK_RETURN && shiftkey==0 && controlkey==0)
			{
				// Return key follows in Disassembler.
				ppl=(t_wndprog_data *)Getsortedbyselection(&(ollylang->wndProg.sorted),ollylang->wndProg.sorted.selected);
				if (ppl!=NULL)
				{
					if (ppl->eip) Setcpu(0,ppl->eip,0,0,0,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
					InvalidateRect(hw, NULL, FALSE);
				}
			}
			else if (wp==VK_F2)
			{ // && shiftkey==0 && controlkey==0) {
				// Toggle Script BP
				ppl=(t_wndprog_data *)Getsortedbyselection(&(ollylang->wndProg.sorted),ollylang->wndProg.sorted.selected);
				if (ppl!=NULL)
				{
					if (ppl->pause) ppl->pause=0; else ppl->pause=1;
					InvalidateRect(hw, NULL, FALSE);
				}
			}
			else if (wp==VK_F4)
			{
				// go Script BP
				ppl=(t_wndprog_data *)Getsortedbyselection(&(ollylang->wndProg.sorted),ollylang->wndProg.sorted.selected);
				if (ppl!=NULL)
				{
					if (ppl->pause) ppl->pause=0; else ppl->pause=1;
					InvalidateRect(hw, NULL, FALSE);
				   ollylang->Resume();
				}
			}
			else if (wp==VK_TAB || wp=='S')
			{

				// Step
				ollylang->Pause();
				ollylang->Step(1);
				script_state = ollylang->script_state;
				focusonstop=4;
				return 1;

			}
			else if (wp=='X')
			{
				// Command
				if (Getstatus() == STAT_STOPPED)
				{
					ollylang->execCommand();
					InvalidateRect(hw, NULL, FALSE);
				}
				return 1;
			}
			else if (wp=='E')
			{
				ppl=(t_wndprog_data *)Getsortedbyselection(&(ollylang->wndProg.sorted),ollylang->wndProg.sorted.selected);
				if (ppl!=NULL)
					editProgLine(ppl);
				return 1;

			}
			else if (wp==' ')
			{ // Pause/Resume

				if (script_state==SS_PAUSED)
				{
					ollylang->Resume();
				}
				else
				{
					ollylang->Pause();
					script_state = ollylang->script_state;
				}
				return 1;
			}
			else if (wp==VK_ESCAPE)
			{
				// Resume
				ollylang->Reset();
				ollylang->Pause();
				return 1;
			}
			else if (wp==VK_LEFT)
			{
				if (ollylang->execCursor > 0) {
					ollylang->execCursor--;
					u = ollylang->execHistory.at(ollylang->execCursor).line;
					Selectandscroll(&ollylang->wndProg,u,1);
					InvalidateRect(hw, NULL, FALSE);
				}
				return 1;
			}
			else if (wp==VK_RIGHT)
			{
				if (ollylang->execCursor < ollylang->execHistory.size() -1 ) {
					ollylang->execCursor++;
					u = ollylang->execHistory.at(ollylang->execCursor).line;
					Selectandscroll(&ollylang->wndProg,u,1);
					InvalidateRect(hw, NULL, FALSE);
				}
				return 1;
			}
			else if (wp=='F' && controlkey) //Search
			{
				wchar_t buffer[TEXTLEN]={0};
				Findname(1,NM_SOURCE,buffer);
				//i = Gettext("Search in script...",buffer,0,NM_SOURCE,FIXEDFONT);
				i = Getstring(hw, L"Search in script...", buffer,TEXTLEN, 0,0, 0,0, 0,0);
				if (i != -1) {
					Insertname(1,NM_SOURCE,buffer);
					wstring s; s.assign(buffer);
					m = ollylang->SearchInScript(s,ollylang->wndProg.sorted.selected);
					if (m >= 0) {
						Selectandscroll(&ollylang->wndProg,m+1,1);
						InvalidateRect(hw, NULL, FALSE);
					}
				}
				return 1;
			}
			else if (wp=='G' && controlkey) //Goto Line
			{
				u = 0;
				Getinteger(hw, L"Goto line...", &u,0,0,0,0,0);
				if (u != 0) {
					Selectandscroll(&ollylang->wndProg,u,1);
					InvalidateRect(hw, NULL, FALSE);
				}
				return 1;
			}
			Tablefunction(&ollylang->wndProg,hw,msg,wp,lp);
			break;
		case WM_CHAR:
			if (wp==';')
			{
				ppl=(t_wndprog_data *)Getsortedbyselection(&(ollylang->wndProg.sorted),ollylang->wndProg.sorted.selected);
				if (ppl!=NULL) {
					wstring cmd = ppl->command;
					int lvl = ppl->type & PROG_ATTR_IFLEVELS;
					if (! (ppl->type & PROG_TYPE_COMMENT) ) {
						cmd = L" ;"+w_trim(cmd);
					} else {
						cmd = w_trim(cmd);
						cmd = L" "+w_trim(cmd.substr(1));
					}
					ollylang->script.erase(ollylang->script.begin()+ppl->line-1);
					ollylang->script.insert(ollylang->script.begin()+ppl->line-1,cmd);

					wcscpy(ppl->command, cmd.c_str());

					cmd=w_trim(cmd);
					ppl->type = analyseProgLineType(cmd,ppl->line);
					ppl->type |= lvl;
					InvalidateProgWindow();
				}
				return 1;

			}
			Tablefunction(&ollylang->wndProg,hw,msg,wp,lp);
			break;
		case WM_USER_CHGALL:
		case WM_USER_CHGMEM:
			InvalidateRect(hw, NULL, FALSE);
			return 0;
		case WM_PAINT:
			ollylang->pgr_scriptpos_paint=ollylang->pgr_scriptpos;
			Painttable(hw, &ollylang->wndProg, wndprog_get_text);
			return 0;
		default:
		break;
	}
	return DefMDIChildProc(hw,msg,wp,lp);
}
*/
void initProgTable() {

	HINSTANCE hinst;

	if (ollylang->wndProg.bar.nbar==0)
	{

	ollylang->wndProg.bar.name[0]=L"Line";
	ollylang->wndProg.bar.defdx[0]=5;
	ollylang->wndProg.bar.mode[0]=BAR_NOSORT;

	ollylang->wndProg.bar.name[1]=L"Command";
	ollylang->wndProg.bar.defdx[1]=40;
	ollylang->wndProg.bar.mode[1]=BAR_NOSORT;

	ollylang->wndProg.bar.name[2]=L"Result";
	ollylang->wndProg.bar.defdx[2]=15;
	ollylang->wndProg.bar.mode[2]=BAR_NOSORT;

	ollylang->wndProg.bar.name[3]=L"EIP";
	ollylang->wndProg.bar.defdx[3]=9;
	ollylang->wndProg.bar.mode[3]=BAR_NOSORT;

	ollylang->wndProg.bar.name[4]=L"Values <---";
	ollylang->wndProg.bar.defdx[4]=100;
	ollylang->wndProg.bar.mode[4]=BAR_NOSORT;

	//ollylang->wndProg.bar.name[5]="Comments";
	//ollylang->wndProg.bar.defdx[5]=40;
	//ollylang->wndProg.bar.mode[5]=BAR_NOSORT;

	ollylang->wndProg.bar.nbar=5;
	ollylang->wndProg.mode=TABLE_COPYMENU|TABLE_APPMENU|TABLE_SAVEPOS|TABLE_ONTOP|TABLE_HILMENU|TABLE_WIDECOL;
	ollylang->wndProg.drawfunc = wndprog_get_text;
	ollylang->wndProg.tabfunc  = wndprog_func;
	ollylang->wndProg.bar.visible=1;

	ollylang->wndProg.menu = mainmenu;

	}

	if (ollylang->wndProg.hw == NULL || !IsWindow(ollylang->wndProg.hw)) {
		ollylang->wndProg.hw = NULL;
		hinst = (HINSTANCE)GetModuleHandleW(PLUGIN_NAME L".dll");
		Createtablewindow(&ollylang->wndProg, 15,5, hinst, L"ICO_P", L"Script Execution");
	}

	if (ollylang->wndProg.hw) {
		Activatetablewindow(&ollylang->wndProg);
		hinst = (HINSTANCE)GetModuleHandleW(PLUGIN_NAME L".dll");
		HICON ico=LoadIcon(hinst,MAKEINTRESOURCE(IDI_ICON_SCRIPT));
		SendMessage(ollylang->wndProg.hw,WM_SETICON,false,(long)ico);
	}
}

int __cdecl wndprog_sort_function(const t_sorthdr *p1,const t_sorthdr *p2,const int sort)
{
	t_wndprog_data *pline1 = (t_wndprog_data *)p1;
	t_wndprog_data *pline2 = (t_wndprog_data *)p2;

	if (pline1->line > pline2->line)
		return 1;
	else if (pline1->line < pline2->line)
		return -1;
	return 0;
}

// destructor
void __cdecl wndprog_dest_function(t_sorthdr *p) {
}


//int wndprog_get_text(char *s, char *mask, int *select, t_sorthdr *ph, int column)
int __cdecl wndprog_get_text(wchar_t *s,uchar *mask,int *select,struct t_table *tb, t_sorthdr *ph,int column,void *cache)
{
	unsigned int ret;
	t_wndprog_data * pline = (t_wndprog_data *)ph;
	t_wndprog_data * plineBf;
	t_dump * cpuasm;

	if (column == 2 || column == 3) {
		plineBf = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),pline->line-1);
		if (plineBf != NULL)
			while (plineBf->type == PROG_TYPE_COMMENT && plineBf->line > 1)
				plineBf = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),plineBf->line-1);

		//t_wndprog_data *plineAf = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),pline->line+1);
		//if (plineAf != NULL)
		//	while (plineAf->type == PROG_TYPE_COMMENT && plineAf->line < ollylang->script.size())
		//		plineAf = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),plineAf->line+1);
	}

	int p;

	ret = wsprintf(s,L"");

	switch (column)
	{
		case DF_CACHESIZE:                 // Request for draw cache size
			return 0;
		case DF_FILLCACHE:                 // Request to fill draw cache
			return 0;
		case DF_FREECACHE:                 // Request to free cached resources
			// We don't need to free cached resources when drawing ends.
			return 0;
		case DF_NEWROW:                    // Request to start new row in window
			return 0;

		case 0:
			if (pline->line>0)
			  ret = wsprintf(s, L"%d", pline->line);
			else if (pline->line==-1)
			  ret = wsprintf(s, L"LOAD");

			if (pline->type & PROG_TYPE_COMMENT) //comment
			{
				*select=DRAW_MASK;
				memset(mask,DRAW_GRAY,ret);
			}
			if (pline->pause)
			{
				//Hilite Breakpoint
				*select=DRAW_MASK;
				memset(mask,DRAW_BREAK,ret);

			}
			else if (pline->line == ollylang->pgr_scriptpos)
			{
				//Hilite Current Line
				*select=DRAW_MASK;
				memset(mask,DRAW_EIP,ret);

			}
			else if (pline->type & PROG_TYPE_LABEL)
			{
				*select=DRAW_MASK;
				memset(mask,DRAW_GRAY,ret);
			}
			break;
		case 1:
			if (pline->type & PROG_TYPE_COMMENT)
			{
				ret = wsprintf(s, L"%s", &pline->command);
				*select=DRAW_MASK;
				memset(mask,DRAW_GRAY,ret);
			}
			else if ((pline->type & PROG_TYPE_LABEL) || pline->line == 0)
			{
				ret = wsprintf(s, L"%s", &pline->command[1]);
				memset(&s[ret],'_',PROG_CMD_LEN-ret);
				ret=PROG_CMD_LEN;
				*select=DRAW_MASK;
				memset(mask,DRAW_GRAY,ret);
			}
			else if (pline->type & PROG_TYPE_ASM) {
				ret = wsprintf(s, L" %s", pline->command);
				*select=DRAW_MASK;
				memset(mask,DRAW_GRAY,ret);
			}
			else
			{
				if (pline->type & PROG_ATTR_IFLEVEVN) {
					ret = wsprintf(s, L" %s", pline->command);
				} else if (pline->type & PROG_ATTR_IFLEVODD) {
					ret = wsprintf(s, L"  %s", pline->command);
				} else
					ret = wsprintf(s, L"%s", pline->command);
				*select=DRAW_MASK;
				memset(mask,DRAW_NORMAL,ret);
			}

			if (pline->line == ollylang->pgr_scriptpos && ret>0)
			{
				//Hilite Current Line
				*select=DRAW_MASK;
				memset(mask,DRAW_EIP,ret);
			}
			else if ((pline->type & PROG_ATTR_EXECUTED) && !(pline->type & PROG_TYPE_COMMENT) && ret>0)
			{
				//Hilite executed lines
				*select=DRAW_MASK;
				memset(mask,DRAW_HILITE,ret);
			}

			//if else endif
			if ((pline->type & PROG_ATTR_IFLEVELS) && (pline->type & PROG_TYPE_COMMAND)) {
				mask[1]=DRAW_GRAPH;
				s[1]=D_GRAYPATH;
			}

			//Error warning
			if (pline->type & PROG_ATTR_ERROR) //error
			{
				*s='!';
				*select=DRAW_MASK;
				*mask=DRAW_BREAK;
			}

			//DRAW JUMP ARROWS
			if (pline->jumpto > 0)
			{

				if (pline->jumpto < pline->line)
				{
					*s='U';
				}
				else
				{
					*s='D';
				}
				*select=DRAW_MASK;
				*mask=DRAW_GRAPH;

			}
			break;
		case 2:
			if (pline->type & PROG_TYPE_LABEL)
			{
				ret=PROG_RES_LEN;
				memset(s,'_',ret);
				*select=DRAW_MASK;
				memset(mask,DRAW_GRAY,ret);
			}
			else if (*pline->result != NULL)
			{
				if (plineBf)
				{
					if (wcscmp(plineBf->result,pline->result)==0)
					{
						//Same result as previous line
						*select=DRAW_MASK;
						*s=' ';	s[1]=D_GRAYPATH;
						ret=2;
						memset(mask,DRAW_GRAPH,ret);
						break;
					}
				}
				ret = wsprintf(s, L"%s", pline->result);
			}
			else if ((plineBf != NULL) && pline->type == PROG_TYPE_COMMENT)
			{
				if (*plineBf->result != NULL)
				{
					//Same result as previous line
					*select=DRAW_MASK;
					*s=' ';	s[1]=D_GRAYPATH;
					ret=2;
					memset(mask,DRAW_GRAPH,ret);
					break;
				}
			}
			break;
		case 3:
			if (pline->type & PROG_TYPE_LABEL)
			{
				memset(s,'_',9);
				ret=9;
				*select=DRAW_MASK;
				memset(mask,DRAW_GRAY,ret);
			}
			else if (pline->eip != 0)
			{
				cpuasm =  Getcpudisasmdump();

				if (plineBf)
				{
					if (plineBf->eip == pline->eip)
					{

						//if (plineAf)
						//	if (plineAf->eip != pline->eip) goto draw_normal_eip;

						*select=DRAW_MASK;
						*s=' ';
						if (cpuasm->sel0 == pline->eip)
							s[1]=D_PATH;
						else
							s[1]=D_GRAYPATH;
						ret=2;
						memset(mask,DRAW_GRAPH,ret);
						break;
					}
				}

				//draw_normal_eip:
				ret = wsprintf(s, L"%08X", pline->eip);

				if (cpuasm->sel0 == pline->eip)
				{
					//Hilite current eip
					*select=DRAW_MASK;
					memset(mask,DRAW_HILITE,ret);
				}
			}
			else if ((plineBf != NULL) && pline->type == PROG_TYPE_COMMENT)
			{
				if (plineBf->eip != 0)
				{
					//Same result as previous line
					*select=DRAW_MASK;
					*s=' ';
					cpuasm = Getcpudisasmdump();;
					if (cpuasm->sel0 == plineBf->eip)
						s[1]=D_PATH;
					else
						s[1]=D_GRAYPATH;
					ret=2;
					memset(mask,DRAW_GRAPH,ret);
					break;
				}
			}
			break;
		case 4:
			if (pline->type & PROG_TYPE_LABEL)
			{
				memset(s,'_',PROG_VAL_LEN);
				ret=PROG_VAL_LEN;
				*select=DRAW_MASK;
				memset(mask,DRAW_GRAY,ret);
			}
			else if (*pline->values != NULL)
			{
				if (pline->values[0] != ',')
					ret = wsprintf(s, L"%s", pline->values);
				else
				{
					ret = wsprintf(s, L"%s", &pline->values[1]);
					p = wcschr(&pline->values[1],',') - pline->values;
					if (p>0)
					{
						*select=DRAW_MASK;
						memset(mask,DRAW_NORMAL,ret);
						memset(mask,DRAW_HILITE,p-1);
					}
				}
			}
			break;

	}

	if (!ret) ret=wcslen(s);

  return ret;
}

void InvalidateProgWindow(void)
{
	if (ollylang->wndProg.hw!=NULL)
		InvalidateRect(ollylang->wndProg.hw, NULL, FALSE);
}

void FocusProgWindow(void)
{
	if (ollylang->wndProg.hw!=NULL)	{
		SetForegroundWindow(ollylang->wndProg.hw);
		SetFocus(ollylang->wndProg.hw);
	}
}

bool editProgLine(t_wndprog_data *ppl)
{
	wchar_t buffer[PROG_CMD_LEN]={0};
	wstring s=ollylang->script[ppl->line-1];

	wcscpy(buffer,(wchar_t*)w_trim(s).c_str());

	if (Gettext(L"Edit script line...",buffer,0,0,FIXEDFONT) != -1) {

		int lvl = ppl->type & PROG_ATTR_IFLEVELS;
		wcscpy(ppl->command, L" ");
		wcsncat(ppl->command, buffer, PROG_CMD_LEN-2);
		s.assign(buffer);

		ollylang->script.erase(ollylang->script.begin()+ppl->line-1);
		ollylang->script.insert(ollylang->script.begin()+ppl->line-1,s);

		ppl->type = analyseProgLineType(s,ppl->line);
		ppl->type |= lvl;
		if (ppl->type & PROG_TYPE_COMMAND) {
			s=w_trim(s);
		}
		if (ppl->type & PROG_ATTR_IFLEVELS) {
			s=L" "+w_trim(s);
		}

		InvalidateProgWindow();
		return true;
	}
	return false;
}

int analyseProgLineType(wstring &scriptline, int linenumber)
{

	bool bComment=false;
	int p, result;

	wstring cleanline=scriptline;
	p=scriptline.find(L"//");
	if (p > 0) {
		if (scriptline.find(L"\"")!=wstring::npos) {

			if (p > scriptline.rfind(L"\"") || p < scriptline.find(L"\""))
				scriptline.erase(p,scriptline.length()-p);

		} else
			scriptline.erase(p,scriptline.length()-p);
	}
	if (w_trim(scriptline).empty()) {
		scriptline = cleanline;
		bComment = true;
	}

	if (scriptline.find(L";")==0) {
		bComment = true;
	}

	if (bComment) {
		result = PROG_TYPE_COMMENT;
	}
	else {
		if (scriptline.length() > 0) {
			if(scriptline.at(scriptline.length() - 1) == ':') {
				ollylang->labels.insert(pair<wstring, int>(scriptline.substr(0, scriptline.length() - 1), linenumber));
				result = PROG_TYPE_LABEL;
			}
		}
		if (result != PROG_TYPE_LABEL) {
			result = PROG_TYPE_COMMAND;
		}
	}

	return result;
}

int addProgLine(int line, wstring & command, int type)
{

	t_wndprog_data pline={0};

	pline.line = line;
	pline.size = 1;
	wcscpy(pline.command,L" ");
	wcsncat(pline.command,command.c_str(),PROG_CMD_LEN-2);
	wcscpy(pline.result,L"");
	wcscpy(pline.values,L"");

	pline.type = type;

	if (!(type & PROG_TYPE))
		pline.type |= PROG_TYPE_COMMAND;

	pline.eip = 0;

	ollylang->tProgLines.push_back(pline);

	Addsorteddata(&(ollylang->wndProg.sorted),&(ollylang->tProgLines.back()));

	InvalidateProgWindow();

	return 1;
}

//Change type to 2 to hilite executed commands
int setProgLineEIP(int line, int eip)
{

	if (line>ollylang->script.size()) return false;

	t_wndprog_data *ppl;

	ppl = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),line);

	if (!(ppl->type & PROG_TYPE_ASM))
		ppl->type |= PROG_ATTR_EXECUTED;

	//if (!(ppl->type & PROG_TYPE_COMMAND)
	//	return true;

	ppl->eip = eip;

	if (ollylang->wndProg.hw!=NULL)
	{
		if (!ollylang->require_ollyloop) {
			Selectandscroll(&ollylang->wndProg,ollylang->pgr_scriptpos,2);
			InvalidateProgWindow();
		}
	}

	return true;
}

int setProgLineValue(int line, DWORD value)
{
	wchar_t buf[17];
	wsprintf(buf, L"%X", value);
	wstring str(buf);
	return setProgLineValue(line, str);
}

int setProgLineValue(int line, wstring  &value)
{

	if (line>ollylang->script.size()) return 0;

	t_wndprog_data *ppl;
	ppl = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),line);

	if (!(ppl->type & PROG_TYPE_COMMAND))
		return 1;

	wstring values;

	values = CleanString(value);

	//Variable History

	if (ollylang->showVarHistory && wcscmp(ppl->values,L"")) {
		if ( values.length() < PROG_VAL_LEN-2) {
			if (ppl->values[0] != ',' && ppl->values[0] != '?' && value.compare(L"?") != 0)
				values += L" ";
			values.append(ppl->values);
		}
	}

	wcsncpy(ppl->values,values.c_str(),PROG_VAL_LEN-1);

	ppl->values[PROG_VAL_LEN-1] = 0;

	InvalidateProgWindow();

	return 1;
}

int setProgLineValueFloat(int line, long double value)
{
	wchar_t buf[128];
	wsprintf(buf, L"%lf", value);
	wstring str(buf);
	while (true)
	{
		if (str.length() <= 3) break;
		if (str[str.length()-1] == '0')
			str.erase(str.length()-1,1);
		else
			break;
	}
	return setProgLineValue(line, str);
}

int setProgLineResult(int line, var& result)
{
	if (result.vt == DW)
		setProgLineResult(line,result.dw);
	else if (result.vt == FLT)
		setProgLineResultFloat(line,result.flt);
	else {
		if(result.str.length() && !result.isbuf)
			setProgLineResult(line,L"\""+result.str+L"\"");
		else {
			setProgLineResult(line,result.str);
		}
	}
	InvalidateProgWindow();
	return true;
}

int setProgLineResult(int line, DWORD result)
{
	wchar_t buf[17];
	wsprintf(buf, L"%X", result);
	wstring str(buf);
	return setProgLineResult(line, str);
}

int setProgLineResultFloat(int line, long double result) {
	wchar_t buf[128];
	wsprintf(buf, L"%lf", result);
	wstring str(buf);
	while (true)
	{
		if (str.length() <= 3) break;
		if (str[str.length()-1] == '0')
			str.erase(str.length()-1,1);
		else
			break;
	}
	return setProgLineResult(line, str);
}

int setProgLineResult(int line, wstring& result)
{

	if (line > ollylang->script.size()) return 0;

	wchar_t values[PROG_VAL_LEN];
	t_wndprog_data *ppl;

	ppl = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),line);

	if (ppl->type & PROG_TYPE_LABEL)
		return false;

	wcsncpy(ppl->result,CleanString(result).c_str(),PROG_RES_LEN);
	if (wcscmp(ppl->values,L""))
	{
		if (ppl->values[0] != ',')
		{
			wcscpy(values,ppl->values);
			wcsncpy(&ppl->values[1],values,PROG_VAL_LEN-2);
			ppl->values[0]=',';
		}
	}

	return true;
}

void clearProgLines()
{
	ollylang->pgr_scriptpos=0;
	if (!ollylang->tProgLines.empty())
	{
		Deletesorteddatarange(&(ollylang->wndProg.sorted),0,0xffffffff);
		ollylang->tProgLines.clear();
		InvalidateProgWindow();
	}
}

void resetProgLines()
{
	vector<t_wndprog_data>::iterator iter=ollylang->tProgLines.begin();
	int line=0;
	t_wndprog_data *ppl;

	while (iter!=ollylang->tProgLines.end())
	{
		ppl = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),line);

		//reset executed color
		if ((ppl->type & PROG_TYPE_COMMAND)) //ignore labels/comments
			ppl->type &= PROG_TYPE_COMMAND | PROG_ATTR_IFLEVELS;

		wcscpy(ppl->result,L"");
		wcscpy(ppl->values,L"");

		//ppl->jumpto = 0;
		ppl->eip = 0;

		line++;
		iter++;
	}
	InvalidateProgWindow();
}


int getProgLineType(int line)
{
	t_wndprog_data *ppl;
	ppl = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),line);
	if (ppl==NULL)
		return false;

	return (ppl->type & PROG_TYPE);

}

int setProgLineAttr(int line,int attr)
{
	t_wndprog_data *ppl;
	ppl = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),line);
	if (ppl==NULL)
		return false;

	ppl->type &= PROG_TYPE | PROG_ATTR_IFLEVELS;
	ppl->type |= attr;

	return true;
}

int isProgLineComment(int line)
{

	t_wndprog_data *ppl;
	ppl = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),line);
	if (ppl==NULL)
		return false;

	if (ppl->type & PROG_TYPE_COMMENT)
	{
		return true;
	}

	return false;

}

int isProgLineBP(int line)
{

	t_wndprog_data *ppl;
	ppl = (t_wndprog_data *) Getsortedbyselection(&(ollylang->wndProg.sorted),line);
	if (ppl==NULL)
		return false;

	if (ppl->pause && ollylang->wndProg.hw)
	{
		focusonstop=4;
	}

	return ppl->pause;

}


