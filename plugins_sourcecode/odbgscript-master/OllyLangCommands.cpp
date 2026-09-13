
// Temp storage
wchar_t buffer[32000] = {0};

#define V_RES   L"$RESULT"
#define V_RES_1 L"$RESULT_1"
#define V_RES_2 L"$RESULT_2"

// -------------------------------------------------------------------------------
// COMMANDS
// -------------------------------------------------------------------------------
bool OllyLang::DoADD(wstring args)
{
	wstring ops[2];
    wchar_t wbuf[32] = {0};

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2 ;
	wstring str1, str2;

	if (GetDWOpValue(ops[0], dw1) 
		&& GetDWOpValue(ops[1], dw2))
	{
		// "0" to force hexa constant
		args = ops[0] + L",0" + _ultow(dw1 + dw2, wbuf, 16); 
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	else if (GetSTROpValue(ops[0], str1) 
		&& GetDWOpValue(ops[1], dw2))
	{
		//concate wstring with _ultow or buffer with hex value
		var v1=str1, v2=dw2;
		v1+=v2;

		args = ops[0] + L", \"" + v1.str + L"\"";
		nIgnoreNextValuesHist++;
	    return DoMOV(args);
	}
	else if (GetSTROpValue(ops[0], str1) 
		     && GetANYOpValue(ops[1], str2))
	{
		//Class var for buffer/str concate support
		var v1=str1, v2=str2;
		v1+=v2;

		args = ops[0] + L", " + L"\"" + v1.str + L"\"";
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	else if (GetANYOpValue(ops[0], str1) 
		     && GetANYOpValue(ops[1], str2))
	{
		//Class var for buffer/str concate support
		var v1=str1, v2=str2;
		v1+=v2;

		args = ops[0] + L", " + L"\"" + v1.str + L"\"";
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}

bool OllyLang::DoAI(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F7); 
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoALLOC(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	ulong addr, size;
	if(GetDWOpValue(ops[0], size))
	{

		HANDLE hDbgPrc = _process;
		addr = (DWORD) VirtualAllocEx(hDbgPrc,NULL,size,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
		variables[V_RES] = addr;
		//Refresh Memory Window
		Listmemory();
		require_ollyloop=1;

		regBlockToFree((void *)addr, size, false);
		return true;
	}
	return false;
}

bool OllyLang::DoANA(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	ulong dw;

	if(GetDWOpValue(ops[0], dw))
	{
//2.		Analysecode(Findmodule(dw));
//2.		Broadcast(K_ANALYSE)
		
		require_ollyloop = 1;
		return true;
	}
	return false;
}

bool OllyLang::DoAND(wstring args)
{
	wstring ops[2];
	wchar_t wbuf[32];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;
	if (GetDWOpValue(ops[0], dw1) 
		&& GetDWOpValue(ops[1], dw2))
	{
		args = ops[0] + L", 0" + _ultow(dw1 & dw2, wbuf, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}

bool OllyLang::DoAO(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F8); 
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoASK(wstring args)
{
	wstring ops[1];
	wstring title;

	//Reset $RESULT, (when dialog closed)
	variables[V_RES] = 0;
	variables[V_RES_1] = 0;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetSTROpValue(ops[0], title))
	{
		if (wndProg.hw!=NULL)
			InvalidateRect(wndProg.hw, NULL, FALSE);

		HWND hw = 0; //not modal but dialog need to be closed on plugin close.
		HINSTANCE hinst = (HINSTANCE)GetModuleHandleW(PLUGIN_NAME L".dll");
		wchar_t* returned_buffer = (wchar_t*)DialogBoxParamW(hinst, MAKEINTRESOURCE(IDD_INPUT), hw, (DLGPROC) InputDialogProc, (LPARAM)title.c_str());
		if (returned_buffer != NULL)
		{
			wstring returned = returned_buffer;
			delete[] returned_buffer;
			
			if(is_hex(returned)) 
			{
				variables[V_RES] = wcstoul(returned.c_str(), 0, 16);
				variables[V_RES_1] = (int) (returned.length() / 2);            //size
			}
			else 
			{
				UnquoteString(returned, '"', '"'); // To Accept input like "FFF" (forces wstring)
				variables[V_RES] = returned.c_str();
				variables[V_RES_1] = (int) returned.length();
			}
		}
		else
		{
			Pause();
		}
		return true;
	}
	return false;
} 

bool OllyLang::DoASM(wstring args)
{
	wstring ops[3],cmd;
	ulong addr, attempt=0;

	if(!CreateOperands(args, ops, 3))
		if(!CreateOperands(args, ops, 2))
			return false;

	t_asmmod model={0};
	uchar umodel[255] = {0};
	wchar_t error[255] = {0};
	int len = 0;

	if(GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1], cmd))
	{
		cmd=FormatAsmDwords(cmd);

		GetDWOpValue(ops[2], attempt);
//2. TO DEBUG
		if((len = Assemble((wchar_t*) cmd.c_str(), addr, umodel, attempt, 3, error)) <= 0)
		{
			errorstr = error;
			return false;
		}
		else
		{ 
			Writememory(model.code, addr, len, MM_SILENT|MM_DELANAL);
			Broadcast(WM_USER_CHGALL, 0, 0);
			variables[V_RES] = len;
			require_ollyloop = 1;
			return true;
		}
	}

	return false;
}

bool OllyLang::DoASMTXT(wstring args)
{
	wstring ops[2];

	if (!CreateOp(args, ops, 2))
	   return false;

	FILE *fp = NULL;
    t_asmmod model={0};
	wstring asmfile;
    uchar opcode[4096]={0};
    uchar umodel[4096]={0};
	wchar_t error[256]={0};
	long len = 0,line = 0;
	ulong addr, p, lens = 0,attempt = 0;


	if(GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1],asmfile))
	{
		if(fopen(w_wstrto(asmfile).c_str(), "rb")){
			
			wstring asmline,asmdoc;
			std::wifstream fin;
			(asmfile.c_str(), ios::in);
			fin.open(w_wstrto(asmfile).c_str());

			p = (ulong) opcode;
			while(getline(fin, asmline))
			{
				line++;
				asmline=FormatAsmDwords(asmline);
//2. TO DEBUG
				len=Assemble((wchar_t*) asmline.c_str(), addr+lens, umodel, attempt, 3, error);
				memcpy(&model.code,umodel,len);
				memcpy((void*) (p + lens),&model.code,len);
				lens += len;
			} 
			Writememory(opcode, addr, lens, MM_DELANAL);
			Broadcast(WM_USER_CHGALL, 0, 0);
			variables[V_RES]   = lens;
			variables[V_RES_1] = line;
			require_ollyloop = 1;
			fin.close();
		}	
		return true;
	}
	return false;
}

bool OllyLang::DoATOI(wstring args)
{
	wstring ops[2];

	if (!CreateOperands(args, ops, 2)) 
	{
		ops[1] = L"10"; //10h=(16.) : Default Hexa number
		if (!CreateOperands(args, ops, 1))
			return false;
	}

	wstring str;
	ulong base, dw;

	if(GetSTROpValue(ops[0], str) 
		&& GetDWOpValue(ops[1], base) )
	{
		variables[V_RES] = wcstoul(str.c_str(),0,base);
		return true;
	}
	return false;
}
/*
bool OllyLang::DoBACKUP(wstring args)
{
	if (DoOPENDUMP(args)) {

		HWND wnd = (HWND) variables[V_RES].dw;
		t_dump * dump = dumpWindows[wnd];

		if (dump) {
			Dumpbackup(dump, BKUP_CREATE);
			//Dumpbackup(dump, BKUP_VIEWCOPY);
			return true;
		}
	}

	return false;
}
*/
bool OllyLang::DoBC(wstring args)
{
	if (args.empty())
		return DoBCA(args);

	wstring ops[1];

	if (!CreateOperands(args, ops, 1))
		return false;

	ulong dw;
	if (GetDWOpValue(ops[0], dw))
	{
		t_table *bptable;
		t_bpoint *bpoint;
		
		bptable=(t_table*) &_bpoint;
		if (bptable==NULL)
			return false;
		for (int b=bptable->sorted.n-1; b>=0;b--) {
			bpoint=(t_bpoint *)Getsortedbyselection(&(bptable->sorted),b);
			if (bpoint!=NULL && bpoint->addr == dw) {
				Deletesorteddata(&(bptable->sorted),bpoint->addr,0);
			}
		}
		Broadcast(WM_USER_CHGALL, 0, 0);
		require_ollyloop = 1;
		return true;
	}
	return false;
}

//clear all loaded breakpoints
bool OllyLang::DoBCA(wstring args)
{
	t_table*  bptable=(t_table*) &_bpoint;
	if (bptable==NULL)
		return false;

	Deletesorteddatarange(&(bptable->sorted),0,0xFFFFFFFF);
	Updatetable(bptable, 0);

	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoBD(wstring args)
{
	if (args.empty())
		return DoBDA(args);

	wstring ops[1];
	if (!CreateOperands(args, ops, 1))
		return false;

	ulong dw;
	if(GetDWOpValue(ops[0], dw))
	{
		//Setbreakpoint(dw, TY_DISABLED, 0);
		t_bpoint upd_bpoint, *bpoint;
		t_table* bptable=(t_table*) &_bpoint;
		if (bptable==NULL)
			return false;
		for (int b=bptable->sorted.n-1; b>=0;b--) {
			bpoint=(t_bpoint *)Getsortedbyindex(&(bptable->sorted),b);
			if (bpoint!=NULL && bpoint->addr == dw) {
				memcpy(&upd_bpoint,bpoint,sizeof(t_bpoint));
				upd_bpoint.type = BP_DISABLED;
				Addsorteddata(&(bptable->sorted),&upd_bpoint);
			}
		}
		Updatetable(bptable, 0);
		require_ollyloop = 1;
		return true;
	}
	return false;
}

//disable all loaded breakpoints
bool OllyLang::DoBDA(wstring args)
{
	t_bpoint upd_bpoint, *bpoint;
	t_table* bptable=(t_table*) &_bpoint;
	if (bptable==NULL)
		return false;
	for (int b=bptable->sorted.n-1; b>=0;b--) {
		bpoint=(t_bpoint *)Getsortedbyselection(&(bptable->sorted),b);
		if (bpoint!=NULL) {
			memcpy(&upd_bpoint,bpoint,sizeof(t_bpoint));
			upd_bpoint.type = BP_DISABLED;
			Addsorteddata(&(bptable->sorted),&upd_bpoint);
		}
	}
	Updatetable(bptable, 0);
	require_ollyloop = 1;

	return true;
}

bool OllyLang::DoBEGINSEARCH(wstring args)
{
	wstring ops[1];
	ulong start;

	if (!CreateOperands(args, ops, 1))
		start=0;
	else
		if (!GetDWOpValue(ops[0], start)) 
			return false;

	t_memory* tm;
	t_table* tt;

	tt=(t_table*) &_memory;
	if (tt==NULL)
		return false;

	if (start==0) {
		//get first mem block addr.
		tm=(t_memory*) Getsortedbyselection(&tt->sorted, 0);
		if (tm==NULL)
			return false;
		start=tm->base;
	} else {
		//get block at addr
		tm=(t_memory*) Findmemory(start);
		if (tm==NULL)
			return false;
	}

	//Last Memory Bloc

	tm=(t_memory*) Getsortedbyselection(&tt->sorted, tt->sorted.n-1);
	if (tm==NULL)
		return false;
 
	int fullsize = tm->base+tm->size - start;

	search_buffer = new unsigned char[fullsize];
	fullsize = Readmemory(search_buffer,start,fullsize,MM_SILENT);
//2	Havecopyofmemory(search_buffer,start,fullsize);
	//Havecopyofmemory(search_buffer,tm->base,tm->size);
	return true;
}

bool OllyLang::DoENDSEARCH(wstring args)
{
	if (search_buffer!=NULL) {
//2		Havecopyofmemory(NULL,0,0);
		delete [] search_buffer;
		search_buffer=NULL;
	}
	return true;
}

bool OllyLang::DoBP(wstring args)
{
	wstring ops[1];

	if (!CreateOperands(args, ops, 1))
		return false;

	ulong dw;
	if(GetDWOpValue(ops[0], dw))
	{
		//Setbreakpoint(dw, TY_ACTIVE, 0);
		t_table* bptable=(t_table*) &_bpoint;
		if (bptable != NULL) {
			t_bpoint bpoint={0};
			bpoint.addr = dw;
			bpoint.size = 1;
			bpoint.type = BP_MANUAL+TY_NEW;
			Addsorteddata(&bptable->sorted, &bpoint);
		}
		Redrawcpudisasm();
		//Broadcast(WM_USER_CHGALL, 0, 0);//PWM_BPOINT
		require_ollyloop = 1;
		return true;
	}
	return false;
}

/*
bool OllyLang::DoBPCND(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong addr = 0;
	wstring condition;
	if(GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1], condition))
	{
		wchar_t* buffer = new wchar_t[condition.length() + 1];
		StrCpyW(buffer, condition.c_str());
		//Setbreakpoint(addr, TY_ACTIVE, 0);
		Membreakpoint(0, addr,0, 0,0, 0, BP_COND);
		Insertname(addr, NM_BREAK, buffer);
		Deletenamerange(addr, addr + 1, NM_BREAKEXPL);
		Deletenamerange(addr, addr + 1, NM_BREAKEXPR);
		Broadcast(WM_USER_CHGALL,0,0);
		delete buffer;
		return true;
	}
	return false;
}

bool OllyLang::DoBPD(wstring args)
{
  	wstring ops[1];

	if (!CreateOp(args, ops, 1))
		return false;

	return DoBPX(ops[0] + L", 1");

}

//Set On Breakpoint Goto Script Label (addr, label)
bool OllyLang::DoBPGOTO(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong addr = 0;
	if(GetDWOpValue(ops[0], addr))
	{
		if(labels.find(ops[1]) != labels.end()) {
			AddBPJump(addr,labels[ops[1]]);
			return true;
		}
	}
	return false;
}

bool OllyLang::DoBPHWCA(wstring args)
{
	int i = 0;
	while(i < 4)
	{
		if (Deletehardwarebreakpoint(i) == -1)
		{return false;}
		i++;
	}
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoBPHWC(wstring args)
{
	if (args.empty())
		return DoBPHWCA(args);

	wstring ops[1];

	if (!CreateOperands(args, ops, 1))
		return false;

	ulong dw1;
	if(GetDWOpValue(ops[0], dw1))
	{
		Deletehardwarebreakbyaddr(dw1);
		require_ollyloop = 1;
		return true;
	}
	return false;
}

bool OllyLang::DoBPHWS(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2)){
		if(!CreateOperands(args, ops, 1))
			return false;
		else ops[1]=L"\"x\"";
	}

	ulong dw1;
	wstring str1;
	if(GetDWOpValue(ops[0], dw1) 
		&& GetSTROpValue(ops[1], str1))
	{
		int type;
		if(str1 == L"r")
			type = HB_ACCESS;
		else if(str1 == L"w")
			type = HB_WRITE;
		else if(str1 == L"x")
			type = HB_CODE;
		else
			return false;

		Sethardwarebreakpoint(dw1, 1, type);
		require_ollyloop = 1;
		return true;
	}
	return false;
}

bool OllyLang::DoBPL(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong addr = 0;
	wstring expression;
	if(GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1], expression))
	{
		sprintf(buffer, "%c%s", 0x45, expression.c_str()); // 0x45 = COND_NOBREAK | COND_LOGALWAYS | COND_ARGALWAYS | COND_FILLING
		//Setbreakpoint(addr, TY_ACTIVE, 0);
		Membreakpoint(0, addr,0, 0,0, 0, BP_LOG);
		Deletenamerange(addr, addr + 1, NM_BREAK);
		Deletenamerange(addr, addr + 1, NM_BREAKEXPL);
		Insertname(addr, NM_BREAKEXPR, buffer);
		Broadcast(WM_USER_CHGALL,0,0);
		return true;
	}
	return false;
}

bool OllyLang::DoBPLCND(wstring args)
{
	wstring ops[3];

	if(!CreateOperands(args, ops, 3))
		return false;

	ulong addr = 0;
	wstring expression, condition;
	if (GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1], expression) 
		&& GetSTROpValue(ops[2], condition))
	{
		//Setbreakpoint(addr, TY_ACTIVE, 0);
		Membreakpoint(0, addr,0, 0,0, 0, BP_CONDLOG);
		Deletenamerange(addr, addr + 1, NM_BREAKEXPL);
		sprintf(buffer, "%s", condition.c_str());
		Insertname(addr, NM_BREAK, buffer);
		sprintf(buffer, "%c%s", 0x43, expression.c_str());
		Insertname(addr, NM_BREAKEXPR, buffer);
		Broadcast(WM_USER_CHGALL,0,0);
		return true;
	}
	return false;
}

bool OllyLang::DoBPMC(wstring args)
{
	Setmembreakpoint(0, 0, 0);
	return true;
}

bool OllyLang::DoBPRM(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong addr, size;
	if(GetDWOpValue(ops[0], addr) 
		&& GetDWOpValue(ops[1], size))
	{
		Setmembreakpoint(MEMBP_READ, addr, size);
		return true;
	}
	return false;
}

bool OllyLang::DoBPWM(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong addr, size;
	if(GetDWOpValue(ops[0], addr) 
		&& GetDWOpValue(ops[1], size))
	{
		Setmembreakpoint(MEMBP_WRITE, addr, size);
		return true;
	}
	return false;
}

//Breakpoint on DLL Calls in current module
//ex: BPX "GetModuleHandleA"
bool OllyLang::DoBPX(wstring args)
{

    wstring ops[2];
	int i;
	int bpnmb=0;
	ulong del=0;
	wstring callname;
	wstring module;
	bool closeWindow=false;
 
	if(CreateOp(args, ops, 2))
	{
		GetDWOpValue(ops[1], del);
	}
	else
	if(!CreateOp(args, ops, 1))
		return false;


	if (GetSTROpValue(ops[0],callname))
	{
		t_table *reftable;
		t_ref *pref;
  
		char findname[TEXTLEN]={0};
		
		variables[V_RES]=0;

		if(callname.length()==0) 
		{
			errorstr=L"Function name missed";
			return false;
		}
		
		if (callname.find(L".") != wstring::npos)
		{
			module = callname.substr(0, callname.find(L"."));
			callname = callname.substr(callname.find(L".")+1);
		}

		reftable=(t_table *)Plugingetvalue(VAL_REFERENCES);

		//Hide window after if was closed
		if(reftable->hw == 0)
			closeWindow = true;

		Findalldllcalls(Getcpudisasmdump(),0,L"Intermodular calls");
		reftable=(t_table *)Plugingetvalue(VAL_REFERENCES);

		if(reftable==NULL || reftable->sorted.n==0)
		{
			errorstr=L"No references";
			return false;
		}

		if(reftable->sorted.itemsize < sizeof(t_ref))
		{
			errorstr=L"Old version of OllyDbg";
			return false;
		}

		for(i=0; i<reftable->sorted.n; i++)
		{
			// The safest way: size of t_ref may change in the future!
			pref=(t_ref *)((char *)reftable->sorted.data + reftable->sorted.itemsize*i);

			if(Findlabel(pref->dest,findname)==0)
			{   // Unnamed destination
				continue;
			}
   
			if(_wcsicmp(callname.c_str(),findname)!=0)
			{   // Different function
				continue;
			} 

			if(!del) 
			{	// Set breakpoint
				//Setbreakpoint(pref->addr,TY_ACTIVE,0);
				Membreakpoint(0, pref->addr,0, 0,0, 0, BP_MANUAL);
				Deletenamerange(pref->addr,pref->addr+1,NM_BREAK);
				Deletenamerange(pref->addr,pref->addr+1,NM_BREAKEXPL);
				Deletenamerange(pref->addr,pref->addr+1,NM_BREAKEXPR);
				bpnmb++;
			}
			else 
			{
				 Deletebreakpoints(pref->addr,pref->addr + 1,true);
				 bpnmb++;
			}
		}
        variables[V_RES]=bpnmb;

		if (closeWindow && reftable->hw != 0) 
			DestroyWindow(reftable->hw);

        Broadcast(WM_USER_CHGALL,0,0);
        return true;
	}
   return false;
}

bool OllyLang::DoBUF(wstring args)
{
	wstring op[1];

	if(!CreateOp(args, op, 1))
		return false;

	if (is_variable(op[0])) {
		if (variables[op[0]].vt == STR) {

			if (!variables[op[0]].isbuf)
				variables[op[0]] = L"#"+variables[op[0]].strbuffhex()+L"#";

			return true;

		} else if (variables[op[0]].vt == DW) {

			var v; v=L"##";
			v+=variables[op[0]].dw;
			variables[op[0]]=v;

			return true;

		}
	}
	return false;
}

bool OllyLang::DoCALL(wstring args)
{
	wstring ops[1];
	wstring str = args;
	
	if (args.empty()) return false;

	str = args;
	if(CreateOperands(args, ops, 1)) {
		if(! GetSTROpValue(ops[0], str) )
			str = args;
	}

	if (str.empty()) return false;

	if (labels.find(str)!=labels.end()) 
	{
		calls.push_back(script_pos);
		return DoJMP(args);
	}
	errorstr=L"Label not found";
	return false;
}

bool OllyLang::DoCLOSE(wstring args)
{

	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	HWND hwnd = 0;
	wstring str;
	bool bOk = false;

	t_table * tbl = NULL;
	t_dump * dmp = NULL;

	if( GetSTROpValue(L"\""+ops[0]+L"\"", str) )
	{
		transform(str.begin(), str.end(), str.begin(), toupper);
		
		if(str == L"SCRIPT")
		{ 			
			hwnd = wndProg.hw;
			bOk = true;
		}
		else if(str == L"SCRIPTLOG")
		{ 
			hwnd = wndLog.hw;
			bOk = true;
		}
		else if(str == L"MODULES")
		{ 
			tbl = (t_table *) Plugingetvalue(VAL_MODULES);
			hwnd = tbl->hw;
		}
		else if(str == L"MEMORY")
		{
			tbl = _memory;
			hwnd = tbl->hw;
		}
		else if(str == L"THREADS")
		{
			tbl = (t_table *) Plugingetvalue(VAL_THREADS);
			hwnd = tbl->hw;
		}
		else if(str == L"BREAKPOINTS")
		{
			tbl = _bpoint;
			hwnd = tbl->hw;
		}
		else if(str == L"REFERENCES")
		{
			tbl = (t_table *) Plugingetvalue(VAL_REFERENCES);
			hwnd = tbl->hw;
		}
		else if(str == L"SOURCELIST")
		{
			tbl = (t_table *) Plugingetvalue(VAL_SOURCELIST);
			hwnd = tbl->hw;
		}
		else if(str == L"WATCHES")
		{
			tbl = (t_table *) Plugingetvalue(VAL_WATCHES);
			hwnd = tbl->hw;
		}
		else if(str == L"PATCHES")
		{
			tbl = (t_table *) Plugingetvalue(VAL_PATCHES);
			hwnd = tbl->hw;
		}
		else if(str == L"CPU")
		{
			dmp = Getcpudisasmdump();
			hwnd = dmp->table.hw;
			if (hwnd != 0) hwnd = GetParent(hwnd);
		}
		else if(str == L"RUNTRACE")
		{						
			hwnd = GetODBGWindow(NULL,L"ARTRACE");
			bOk = true;
		}
		else if(str == L"WINDOWS")
		{
			hwnd = GetODBGWindow(NULL,L"AWINDOWS");
			bOk = true;
		}
		else if(str == L"CALLSTACK")
		{
			hwnd = GetODBGWindow(NULL,L"ACALLSTK");
			bOk = true;
		}
		else if(str == L"LOG")
		{
			hwnd = GetODBGWindow(NULL,L"ALIST");
			bOk = true;
		}
		else if(str == L"TEXT")
		{
			hwnd = GetODBGWindow(NULL,L"ASHOWTEXT");
			bOk = true;
		}
		else if(str == L"FILE")
		{
			hwnd = GetODBGWindow(NULL,L"ADUMPFILE");
			bOk = true;
		}
		else if(str == L"HANDLES")
		{
			hwnd = GetODBGWindow(NULL,L"AHANDLES");
			bOk = true;
		}
		else if(str == L"SEH")
		{
			hwnd = GetODBGWindow(NULL,L"ASEH");
			bOk = true;
		}
		else if(str == L"SOURCE")
		{
			hwnd = GetODBGWindow(NULL,L"ASOURCE");
			bOk = true;
		}

		if (hwnd != 0) {
			DestroyWindow(hwnd);
		}
		if (tbl || dmp || hwnd || bOk)
			return true;
	} 

	if(hwnd==0 && GetDWOpValue(ops[0], (ulong &) hwnd) ) {
		if (hwnd != 0) {
			DestroyWindow(hwnd);
			return true;
		}
	}

	errorstr = L"Bad operand";
	return false;
}

bool OllyLang::DoCMP(wstring args)
{
	wstring ops[3];
	ulong dw1=0, dw2=0, size=0;
	wstring s1, s2;

	if(!CreateOperands(args, ops, 3)) {
		if(!CreateOperands(args, ops, 2))
			return false;
	} else {
		GetDWOpValue(ops[2], size);
	}

	if(GetDWOpValue(ops[0], dw1) 
		&& GetDWOpValue(ops[1], dw2))
	{
		if (size==1) {
			dw1&=0xFF;
			dw2&=0xFF;
		}
		else if (size==2) {
			dw1&=0xFFFF;
			dw2&=0xFFFF;
		}

		if(dw1 == dw2)
		{
			zf = 1;
			cf = 0;
		}
		else if(dw1 > dw2)
		{
			zf = 0;
			cf = 0;
		}
		else if(dw1 < dw2)
		{
			zf = 0;
			cf = 1;
		}
		return true;
	}
	else if(GetANYOpValue(ops[0], s1, true) // see also SCMP command, code is not finished here...
		    && GetANYOpValue(ops[1], s2, true))
	{
		var v1=s1,v2=s2;
		if (size>0) {
			v1.resize(size);
			v2.resize(size);
		}
		int res = v1.compare(v2); //Error if -2 (type mismatch)
		if(res == 0)
		{
			zf = 1;
			cf = 0;
		}
		else if(res > 0)
		{
			zf = 0;
			cf = 0;
		}
		else if(res < 0)
		{
			zf = 0;
			cf = 1;
		}
		return true;
	}
	return false;
}

bool OllyLang::DoCMT(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	wstring cmt;
	ulong addr;

	if(GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1], cmt))
	{
		if(!cmt.empty())
		{
            char cmtt[1024]={0};
			strcpy(cmtt, cmt.c_str());
			Insertname(addr, NM_COMMENT, cmtt);
			Broadcast(WM_USER_CHGALL, 0, 0);
		}
		else
		{
			Deletenamerange(addr, addr + 1, NM_COMMENT);
			Broadcast(WM_USER_CHGALL, 0, 0);
		}
		return true;
	}
	return false;
}

bool OllyLang::DoCOB(wstring args)
{
	EOB_row = -1;
	return true;
}

bool OllyLang::DoCOE(wstring args)
{
	EOE_row = -1;
	return true;
}

bool OllyLang::DoCRET(wstring args)
{
	if (calls.size() > 0) {
		calls.clear();
	}
	return true;
}

bool OllyLang::DoDBH(wstring args)
{
	t_thread* thr = Findthread(Getcputhreadid());
	BYTE buf[4];
	ulong fs = thr->reg.limit[2]; // BUG IN ODBG!!!
	fs += 0x30;
	Readmemory(buf, fs, 4, MM_RESTORE);
	fs = *((ulong*)buf);
	fs += 2;
	buffer[0] = 0;
	Writememory(buf, fs, 1, MM_RESTORE);
	return true;   
}

bool OllyLang::DoDBS(wstring args)
{
	t_thread* thr = Findthread(Getcputhreadid());
	BYTE buffer[4];
	ulong fs = thr->reg.limit[2]; // BUG IN ODBG!!!
	fs += 0x30;
	Readmemory(buffer, fs, 4, MM_RESTORE);
	fs = *((ulong*)buffer);
	fs += 2;
	buffer[0] = 1;
	Writememory(buffer, fs, 1, MM_RESTORE);
	return true;   
}

bool OllyLang::DoDEC(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	return DoSUB(ops[0] + ", 1");
}

bool OllyLang::DoDIV(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;
	if(GetDWOpValue(ops[0], dw1) && GetDWOpValue(ops[1], dw2))
	{
		if(dw2==0)
		{
			errorstr = L"Division by 0";
			return false;
		}
		args = ops[0] + ", 0" + _ultow(dw1 / dw2, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}




bool OllyLang::DoDM(wstring args)
{
	wstring ops[3];
	if(!CreateOperands(args, ops, 3))
		return false;

    wchar_t spath[MAX_PATH];
    wcscpy(spath, _executable);
    wstring path = spath;

    path = path.substr(0, path.rfind('\\') + 1);
	
	ulong addr, size;
	wstring filename;
	if (GetDWOpValue(ops[0], addr) 
		&& GetDWOpValue(ops[1], size) 
		&& GetSTROpValue(ops[2], filename))
	{
        if (filename.find(L":\\") != wstring::npos)
			path = filename;
		else
			path += filename;
		char* membuf = new char[size];
		int memlen = Readmemory(membuf, addr, size, MM_RESILENT);

		ofstream fout;
        fout.open(path.c_str(), ios::binary);
		if(!fout.fail())
		{
			for(int i = 0; i < memlen; i++)
				fout << membuf[i];
			fout.close();
			delete [] membuf;
            variables[V_RES] = memlen;
			return true;
		}
		else
		{
			errorstr = L"Couldn't create file!";
			delete [] membuf;
			return false;
		}
	}
	return false;
}

bool OllyLang::DoDMA(wstring args)
{
	wstring ops[3];
	if(!CreateOperands(args, ops, 3))
		return false;

    wchar_t spath[MAX_PATH];
    wcscpy(spath, _executable);
    wstring path = spath;

    path = path.substr(0, path.rfind('\\') + 1);

	ulong addr, size;
	wstring filename;
	if(GetDWOpValue(ops[0], addr) 
		&& GetDWOpValue(ops[1], size) 
		&& GetSTROpValue(ops[2], filename))
	{
		char* membuf = new char[size];
		int memlen = Readmemory(membuf, addr, size, MM_RESILENT);

        if (filename.find(L":\\") != wstring::npos)
			path = filename;
		else
			path += filename;
		ofstream fout;
        fout.open(path.c_str(), ios::app | ios::binary);
		if(!fout.fail())
		{
			for(int i = 0; i < memlen; i++)
				fout << membuf[i];
			fout.close();
			delete [] membuf;
            variables[V_RES] = memlen;
			return true;
		}
		else
		{
			errorstr = L"Couldn't create file!";
			delete [] membuf;
			return false;
		}
	}
	return false;
}

bool OllyLang::DoDPE(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

    wchar_t spath[MAX_PATH];
    wcscpy(spath, _executable);
    wstring path = spath;

    path = path.substr(0, path.rfind('\\') + 1);

	wstring filename;
	ulong ep;
	if(GetSTROpValue(ops[0], filename) 
		&& GetDWOpValue(ops[1], ep))
	{
        if (filename.find(L":\\") != wstring::npos)
			path = filename;
		else
			path += filename;
		bool result = false;
		result = GetPEInfo(ep);
		if (!result)
			return result;
		result = SaveDump(path, ep);
		return result;
	}
	return false;
}

bool OllyLang::DoELSE(wstring args)
{
	int pos = script_pos;
	int condlevel=0;
	//goto endif
	while(ToLower(script[pos]) != "endif" || condlevel > 0) {
		if (ToLower(script[pos]) == L"endif") {
			condlevel--;
		}
		if (ToLower(script[pos]).substr(0,2) == L"if") {
			condlevel++;
		}
		pos++;
		if (pos>script.size()) {
			DoENDIF("");
			errorstr = L"ELSE needs ENDIF command !";
			return false;
		}
	}
	script_pos = pos-1;
	setProgLineResult(pos,variables[V_RES]);
	return true;
}

bool OllyLang::DoENDE(wstring args)
{
	// Free memory
	if (pmemforexec!=NULL)
		DelProcessMemoryBloc((DWORD) pmemforexec);
	pmemforexec=NULL;
	return true;
}

bool OllyLang::DoENDIF(wstring args)
{
	if (conditions.size() > 0) {
		conditions.pop_back();
	}
	return true;
}
*/
bool OllyLang::DoERUN(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 0, 1, VK_F9); 
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoESTI(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 0, 1, VK_F7); 
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoESTEP(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 0, 1, VK_F8); 
	require_ollyloop = 1;
	return true;
}
/*
bool OllyLang::DoEOB(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	if(ops[0] == L"") // Go interactive
		EOB_row = -1;
	else if(labels.find(ops[0]) != labels.end()) // Set label to go to
		EOB_row = labels[ops[0]];
	else
		return false;
	return true;
}

bool OllyLang::DoEOE(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	if(ops[0] == L"") // Go interactive
		EOE_row = -1;
	else if(labels.find(ops[0]) != labels.end()) // Set label to go to
		EOE_row = labels[ops[0]];
	else
		return false;
	return true;
}

bool OllyLang::DoEVAL(wstring args)
{
	wstring ops[1];

	if (!CreateOperands(args, ops, 1))
		return false;

	wstring to_eval;

	if (GetSTROpValue(ops[0], to_eval))
	{
		wstring res = ResolveVarsForExec(to_eval,false);
		variables[V_RES] = res;
		return true;
	}
	return false;
}

bool OllyLang::DoEXEC(wstring args)
{
	// Old eip
	ulong eip;
	// For Assemble API
	t_asmmod model;
	char error[255] = {0};
	char buffer[255] = {0};
	// Bytes assembled
	int len = 0, totallen = 0;
	bool res = true;
	// Temp storage
	wstring tmp;

	// Get process handle and save eip
	HANDLE hDebugee = (HANDLE)Plugingetvalue(VAL_HPROCESS);
	t_thread* thr = Findthread(Getcputhreadid());
	eip = thr->reg.ip;

	// Allocate memory for code
	pmemforexec = VirtualAllocEx(hDebugee, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Pass EXECs
	script_pos++;
	setProgLineResult(script_pos,variables[V_RES]);

	// Assemble and write code to memory (everything between EXEC and ENDE)
	while(ToLower(script[script_pos]) != "ende")
	{
		tmp = ResolveVarsForExec(script[script_pos],true);
		sprintf(buffer, tmp.c_str());
		len = Assemble(buffer, (ulong)pmemforexec + totallen, &model, 0, 0, error);
		if (len < 0) {
			errorstr = tmp+"\n"+error;
			return false;
		} else {
			WriteProcessMemory(hDebugee, (LPVOID)((ulong)pmemforexec + totallen), model.code, len, 0);
			totallen += len;
		}
		script_pos++;
		setProgLineEIP(script_pos,eip);
		setProgLineResult(script_pos,variables[V_RES]);
		if (script_pos>script.size()) {
			DoENDE("");
			errorstr = L"EXEC needs ENDE command !";
			return false;
		}
	}

	//return before ENDE command
	script_pos--;

	// Assemble and write jump to original EIP
	sprintf(buffer, "JMP 0%lX", eip);
	len = Assemble(buffer, (ulong)pmemforexec + totallen, &model, 0, 0, error);
	if (len < 0) {
		errorstr = error;
		return false;
	} else {
		WriteProcessMemory(hDebugee, (LPVOID)((ulong)pmemforexec + totallen), model.code, len, 0);
	}

	// Set new eip and run to the original one
	thr->reg.ip = (ulong)pmemforexec;
	thr->reg.status = RV_MODIFIED;
	thr->regvalid = 1;

	// tell to odbgscript to ignore next breakpoint
	bInternalBP=true;

	Redrawcpureg();
	Go(Getcputhreadid(), eip, STEP_RUN, 0, 1);
	
	t_dbgmemblock block={0};
	block.hmem = pmemforexec;
	block.size = 0x1000;
	block.script_pos = script_pos;
	block.free_at_eip = eip;
	block.autoclean = true;

	regBlockToFree(block);
	require_addonaction = 1;
	require_ollyloop = 1;

	return true;
}

bool OllyLang::DoFILL(wstring args)
{
	wstring ops[3];

	if(!CreateOperands(args, ops, 3))
		return false;
	ulong start, len, val;

	if(GetDWOpValue(ops[0], start) 
		&& GetDWOpValue(ops[1], len) 
		&& GetDWOpValue(ops[2], val))
	{
		BYTE* buffer = new BYTE[len];
		FillMemory(buffer,len,val);
		Writememory(buffer, start, len, MM_SILENT);
		delete []buffer;
		Broadcast(WM_USER_CHGALL, 0, 0);
		require_ollyloop = 1;
		return true;
	}
	return false;
}

bool OllyLang::DoFIND(wstring args)
{
	wstring ops[3];
	ulong maxsize=0;
	if(CreateOp(args, ops, 3)){
		GetDWOpValue(ops[2], maxsize);
	}
	else if(!CreateOp(args, ops, 2))
		return false;

	ulong addr,dw;
	wstring data=ops[1];
	wstring finddata=ops[1];

	if(UnquoteString(ops[1], '#', '#')) 
	{
		if(ops[1].length() % 2 != 0)
		{
			errorstr = L"Hex wstring must have an even number of characters!";
			return false;
		}
		finddata=ops[1];
	}
	else if (UnquoteString(ops[1], '"', '"'))
	{
	   wstring wilddata;
	   wilddata=ops[1];
       Str2Hex(ops[1],finddata);
	   ReplaceString(finddata,"3f","??");
	}
	else if(GetDWOpValue(ops[1], dw) && !is_variable(ops[1])) 
	{
		_itow(rev(dw),buffer,16);
		wstring data1=buffer;
		transform( data1.begin(),data1.end(), data1.begin(),(int(*)(int)) toupper );
		while(data1.length() < data.length())
			data1.insert(0,"0");
		while (data1.length() > data.length())
			data1.erase(data1.length()-1,1);
		
		finddata=data1;		
	}
	else if(is_variable(ops[1]))
	{   
        GetANYOpValue(ops[1], data);
		if (UnquoteString(data, '#', '#'))
		{
		  finddata=data;	
		}
   	    else if(GetSTROpValue(ops[1],data))
		{
		  Str2Hex(data,finddata);
		}
        else if(GetDWOpValue(ops[1], dw))
		{
			_itow(rev(dw),buffer,16);
			wstring data1=buffer;
			while(data1.length() < data.length())
				data1.insert(0,"0");
			while (data1.length() > data.length())
				data1.erase(data1.length()-1,1);

			finddata=data1;
		}
	}

	if(GetDWOpValue(ops[0], addr) && is_hexwild(finddata))
	{

		t_memory* tmem = Findmemory(addr);

		if (tmem==NULL) {
			// search in current mem block
			variables[V_RES] = 0;
			return true;
		}

		if(finddata.find('?') != -1)
		{
			// Wildcard search
			char *membuf = 0;
			int memlen = tmem->size - (addr - tmem->base);
			membuf = new char[memlen];

			memlen = Readmemory(membuf, addr, memlen, MM_RESILENT);
            int pos;

			if (maxsize && maxsize <= memlen)
				pos = FindWithWildcards(membuf, finddata.c_str(), maxsize);
			else
				pos = FindWithWildcards(membuf, finddata.c_str(), memlen);

			delete [] membuf;

			if(pos > -1)
				variables[V_RES] = addr + pos;
			else
				variables[V_RES] = 0;
		}
		else
		{
			// Regular search
			char *membuf = 0;
			int memlen = tmem->size - (addr - tmem->base);

			int len = Str2Rgch(finddata, buffer, sizeof(buffer));
            if (maxsize && maxsize <= memlen)
			{
				memlen = maxsize;
			}
			membuf = new char[memlen];
			memlen = Readmemory(membuf, addr, memlen, MM_RESILENT);
			char *p = search(membuf, membuf + memlen, buffer, buffer + len);

			delete[] membuf;

			if(p < membuf + memlen)
				variables[V_RES] = addr + p - membuf;
			else
				variables[V_RES] = 0;
		}
		return true;
	}
	return false;
}

bool OllyLang::DoFINDCALLS(wstring args)
{
	wstring ops[2];
	if(!CreateOp(args, ops, 2))
		if (args.empty())
			return false;

	bool bRefVisible=false,bResetDisam=false;
	ulong addr,base,size,disamsel=0;

	Getdisassemblerrange(&base,&size);

	//Get initial Ref Window State
	t_table* tt;
	tt=(t_table*) Plugingetvalue(VAL_REFERENCES);
	if (tt!=NULL)
		bRefVisible=(tt->hw!=0);

	t_dump* td;
	td=Getcpudisasmdump();;
	if (td==NULL)
		return false;

	if (GetDWOpValue(ops[0], addr))
	{
		if (addr<base || addr>=(base+size)) {
			//outside debugger window range
			disamsel=td->sel0;
			Setdisasm(addr,0,0);
			bResetDisam=true;
		}

		variables[V_RES]=0;
		if (Findalldllcalls(td,addr,NULL)>0) {
			
			if (tt==NULL)
				tt=(t_table*) Plugingetvalue(VAL_REFERENCES);

			if (tt!=NULL) 
			{
				t_ref* tr;

				if (tt->data.n > 1) 
				{ 
					//Filter results
					wstring filter;
					if (GetSTROpValue(ops[1], filter) && filter!="") {
						//filter=ToLower(filter);
						(char*) buffer[TEXTLEN+1];
						for (int nref=tt->data.n-1;nref>0;nref--) {
							tr=(t_ref*) Getsortedbyselection(&tt->data, nref);
							if (tr!=NULL && tr->dest!=0) {
								//ZeroMemory(buffer,TEXTLEN+1);
								//Decodename(tr->dest,NM_LABEL,buffer);
								Findlabel(tr->dest,buffer);
								if (_wcsicmp(buffer,filter.c_str())!=0)
									Deletesorteddata(&tt->data,tr->addr);
							}
						}
					}

					tr=(t_ref*) Getsortedbyselection(&tt->data, 1); //0 is CPU initial
					if (tr!=NULL)
						variables[V_RES]=tr->addr;
				}

				if (tt->hw && !bRefVisible) {
					DestroyWindow(tt->hw);
					tt->hw=0;
				}
			}
		}
		if (bResetDisam)
			Setdisasm(disamsel,0,0);
		return true;
	}
	return false;
}

//search for asm command in disasm window
bool OllyLang::DoFINDCMD(wstring args)
{
	wstring ops[2];
	if(!CreateOp(args, ops, 2))
		return false;

	bool bRefVisible=false,bResetDisam=false;
	wstring cmd, cmds;
	int len,pos;
	ulong addr,base,size,attempt,opsize=3,disamsel=0;
	int startadr=0,endadr=0,lps=0,length,ncmd=0,cmdpos=0;
	char error[256]={0};

	Getdisassemblerrange(&base,&size);

	//Get initial Ref Window State
	t_table* tt;
	tt=(t_table*) Plugingetvalue(VAL_REFERENCES);
	if (tt!=NULL)
		bRefVisible=(tt->hw!=0);

	t_dump* td;
	td=Getcpudisasmdump();;
	if (td==NULL)
		return false;

	ulong tmpaddr=AddProcessMemoryBloc(0x100,PAGE_EXECUTE_READWRITE);

	if (GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1], cmds))
	{
		if (addr<base || addr>=(base+size)) {
			//outside debugger window range
			disamsel=td->sel0;
			Setdisasm(addr,0,0);
			bResetDisam=true;
		}

		t_asmmod model={0};
		t_extmodel models[NSEQ][NMODELS]={0};

		length = cmds.length();
		while (cmdpos<length && ncmd<NSEQ)
		{

			endadr= cmds.find(L";",startadr);
			if (endadr==-1)
			{
				endadr=length;
			}
			lps=endadr-startadr;

			cmd=cmds.substr(startadr,lps);
			
			attempt=0;
			strcpy(buffer, cmd.c_str());

			do {

				if((len = Assemble(buffer, tmpaddr, &model, attempt, opsize, error)) <= 0)
				{
					if (attempt!=0) {
						break;
					}

					pos=(cmd.length()+len);
					if (pos>=0 && pos<cmd.length())
						errorstr = L"\nFINDCMD error at \""+cmd.substr(pos,cmd.length()-pos)+"\"!\n\n";
					else
						errorstr = L"\nFINDCMD error !\n\n";
					errorstr.append(error);
					goto return_false;
				}
				memcpy(&models[ncmd][attempt],&model,sizeof(model));
				attempt++;

			} while (len>0 && attempt<NMODELS);

			startadr=endadr+1;
			cmdpos+=lps+1;

			ncmd++;
		}

		variables[V_RES]=0;
		if (Findallsequences(td,models,addr,NULL)>0) {
			
			if (tt==NULL)
				tt=(t_table*) Plugingetvalue(VAL_REFERENCES);

			if (tt!=NULL) 
			{
				t_ref* tr;
				if (tt->data.n > 1)
				{
					tr=(t_ref*) Getsortedbyselection(&tt->data, 1); //0 is CPU initial
					if (tr!=NULL)
						variables[V_RES]=tr->addr;
				}

				if (tt->hw && !bRefVisible) {
					DestroyWindow(tt->hw);
					tt->hw=0;
				}
			}
		}
		DelProcessMemoryBloc(tmpaddr);
		if (bResetDisam)
			Setdisasm(disamsel,0,0);
		return true;

	}
return_false:
	if (bResetDisam)
		Setdisasm(disamsel,0,0);
	DelProcessMemoryBloc(tmpaddr);
	return false;
}
*/

/*
//Buggy, could assemble different command code bytes, (from chinese code)
bool OllyLang::DoFINDCMDS(wstring args)
{

	wstring ops[2];
	t_asmmod model;
	ulong addr;
	wstring cmds,args1,cmd;
	char opcode[256]={0},buff[32]={0},tmp[64]={0},error[64]={0};
	int i,pos,len=0,length=0,startadr=0,endadr=0,lps=0,codelen=0;
	int attempt=0,opsize=3;

	if(!CreateOp(args, ops, 2))
		return false;

	if (GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1], cmds))
	{

	  if (cmds.find(L";")==-1)
	  {
		nIgnoreNextValuesHist++;
		return DoFINDoneCMD(args);
	  }

	  length = cmds.length();
 
	  ulong tmpaddr=AddProcessMemoryBloc(0x100,PAGE_EXECUTE_READWRITE);

	  while (len<length)
	  {
		endadr= cmds.find(L";",startadr);
		if (endadr==-1)
		{
			endadr=length;
		}
		lps=endadr-startadr;
		cmd=cmds.substr(startadr,lps);
       
		strcpy(buffer, cmd.c_str());
		if((codelen = Assemble(buffer, tmpaddr, &model, attempt, opsize, error)) <= 0)
		{
			pos=(cmd.length()+codelen);
			if (pos>=0 && pos<cmd.length())
				errorstr = L"\nFINDCMDS error on \""+cmd.substr(pos,cmd.length()-pos)+"\"!\n\n";
			else
				errorstr = L"\nFINDCMDS error !\n\n";
			errorstr.append(error);
			DelProcessMemoryBloc(tmpaddr);
			return false;
		}
		else
		{
			sprintf(buff, "%s", (model.code));
		}

		i=0;
		while(i<codelen)
		{
			_itow(buff[i],tmp,16);
			i++;
			strcat(opcode,tmp);
		}

		startadr=endadr+1;
		len=len+lps+1;
	  }
	  DelProcessMemoryBloc(tmpaddr);

	  args1 = ops[0] + ", " + "#" + opcode + "#";
	  nIgnoreNextValuesHist++;
	  return DoFIND(args1);
	}
	return false;
}
*/

/*
bool OllyLang::DoFINDMEM(wstring args)
{

	if (args.empty())
		return false;

	wstring ops[2];

	if (args.find(',') == -1)
		args+=",0";

	if(!CreateOperands(args, ops, 2))
		return false;

	t_table* tt;
	tt=_memory;
	if (tt==NULL)
		return false;

	t_memory* tm;
	char szBase[9];
	ulong start=0; 
	wstring sArgs;
	bool bSkip;

	if (!GetDWOpValue(ops[1], start))
		return false;

	for (int m=0; m < tt->data.n; m++) {
		tm=(t_memory*) Getsortedbyselection(&tt->data, m);
		if (tm==NULL) {
			return false;
		}

		_itow(tm->base,szBase,16);

		bSkip=false;

		if (start > tm->base + tm->size)
			bSkip=true;
		else if (start >= tm->base) 
			_itow(start,szBase,16);

		if (!bSkip) {
			sArgs="";
			sArgs.append(szBase);
			sArgs+=","+ops[0];
			if (DoFIND(sArgs)) {
				if (variables[V_RES].dw!=0 || variables[V_RES].str!="") {
					var_logging=true;
					return true;
				}
			}
			//Display value in ollyscript wdw only once
			var_logging=false;
		}
	}

	var_logging=true;
	variables[V_RES] = 0;
	return true;
}

bool OllyLang::DoFINDOP(wstring args)
{
	wstring ops[3];
	ulong maxsize=0;
	if(CreateOp(args, ops, 3)){
		GetDWOpValue(ops[2], maxsize);
	}
	else if(!CreateOp(args, ops, 2))
		return false;

	ulong addr, dw, endaddr;
	wstring data=ops[1];
	wstring finddata=ops[1];

	if (UnquoteString(ops[1], '#', '#')) 
	{
		if(ops[1].length() % 2 != 0)
		{
			errorstr = L"Hex wstring must have an even number of characters!";
			return false;
		}
	}
	else if (GetDWOpValue(ops[1], dw) && !is_variable(ops[1]))
	{
//		DoREV(ops[1]);
		_itow(dw,buffer,16);
        wstring data1=buffer;
		while(data1.length() < data.length())
			data1.insert(0,"0");
		while (data1.length() > data.length())
			data1.erase(data1.length()-1,1);

		ops[1]=data1;
	}
	else if(is_variable(ops[1]))
	{   
        GetANYOpValue(ops[1], data);
		if (UnquoteString(data, '#', '#'))
		{
		  ops[1]=data;	
		 }
   	    else if(GetSTROpValue(ops[1],data))
		{
			errorstr = L"findop: incorrect data !";
			return false;
		}
        else if(GetDWOpValue(ops[1], dw))
		{
	//		DoREV(ops[1]);
			_itow(dw,buffer,16);
			wstring data1=buffer;
			while(data1.length() < data.length())
				data1.insert(0,"0");
			while (data1.length() > data.length())
				data1.erase(data1.length()-1,1);
			
			ops[1]=data1;
		}
	}

	int result = -1;
	int ok = 0;
	ulong addrsize;
	if(GetDWOpValue(ops[0], addr) && is_hexwild(ops[1]))
	{
		t_memory* tmem = Findmemory(addr);
		char cmd[MAXCMDSIZE] = {0};

		if(maxsize && maxsize <= tmem->size)
		{
			tmem->base = addr;
			tmem->size = maxsize;
		}

		do 
		{
			ulong nextaddr = Disassembleforward(0, tmem->base, tmem->size, addr, 1, 0); 
//			endaddr = Disassembleforward(0, tmem->base, tmem->size, addr, 1, 0); 
			ok = Readcommand(addr, cmd);

			addrsize = nextaddr -addr;
            addr=nextaddr;

			if(addr >= tmem->base + tmem->size)
				ok = 0;

			if(ok)
				result = FindWithWildcards(cmd, ops[1].c_str(),addrsize);

		} while(result != 0 && ok != 0);
	}
	if(ok != 0){
		variables[V_RES] = addr - addrsize;
	    variables[V_RES_1] = addrsize;
	}


	else
		variables[V_RES] = 0;
	return true;
}

bool OllyLang::DoFINDOPREV(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	if(ops[1].length() % 2 != 0)
	{
		errorstr = L"Hex wstring must have an even number of characters!";
		return false;
	}

	DWORD addr, endaddr;
	int result = -1;
	int ok = 0;

	if(GetDWOpValue(ops[0], addr) && UnquoteString(ops[1], '#', '#'))
	{
		t_memory* tmem = Findmemory(addr);
		char cmd[MAXCMDSIZE] = {0};
		do 
		{
			addr = Disassembleback(0, tmem->base, tmem->size, addr, 1, 0); 
			endaddr = Disassembleback(0, tmem->base, tmem->size, addr, 1, 0); 
			ok = Readcommand(addr, cmd);

			if(addr == tmem->base + tmem->size)
				ok = 0;

			if(ok)
				result = FindWithWildcards(cmd, ops[1].c_str(), endaddr - addr);
		} while(result != 0 && ok != 0);
	}
	if(ok != 0)
		variables[V_RES] = addr;
	else
		variables[V_RES] = 0;
	return true;

}


bool OllyLang::DoFREE(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2)) {
		ops[1]="0";
		if(!CreateOperands(args, ops, 1))
		return false;
	}

	void * hMem;
	ulong addr, size;

	if(GetDWOpValue(ops[0], addr) && GetDWOpValue(ops[1], size))
	{
		hMem = (void*)addr;
		//To Refresh Memory Window
		require_ollyloop=1;
		if (size==0) {
			if (DelProcessMemoryBloc(addr)) {
				unregMemBlock(hMem);
				Listmemory();
				return true;
			}
		}
		else {
			
			HANDLE hDbgPrc = (HANDLE) Plugingetvalue(VAL_HPROCESS);
			variables[V_RES] = (DWORD) VirtualFreeEx(hDbgPrc,hMem,size,MEM_DECOMMIT);
			unregMemBlock(hMem);
			Listmemory();
			return true;
		}
	}
	return false;
}

bool OllyLang::DoGAPI(wstring args)
{
    wstring ops[1];
	ulong addr,size,test,addr2;

	if(!CreateOp(args, ops, 1))
		return false;

	if(GetDWOpValue(ops[0], addr)){
		BYTE buffer[MAXCMDSIZE];
		//size=Readmemory(buffer, addr, MAXCMDSIZE, MM_SILENT);
		size=Readcommand(addr,(char *) buffer);

		
		if (size>0) {
			t_disasm disasm;
			size=Disasm(buffer,size,addr,NULL,&disasm,DISASM_CODE,NULL);
			test=disasm.jmpaddr;

			if (size>0) {
//				variables[V_RES] = disasm.result; //asm command text
//				variables[V_RES_1] = disasm.dump;     //command bytes
				variables[L"$RESULT_3"] = disasm.addrdata;
				variables[L"$RESULT_4"] = disasm.jmpaddr; 

			}
		}
		if (test!=NULL)   {
			t_disasm disasm;
			size=Disasm(buffer,size,addr,NULL,&disasm,DISASM_CODE,NULL);
		 	char sym[4096] = {0};
		    char buf[TEXTLEN] = {0};
			addr2 = disasm.addrdata;
            int res = Decodeaddress(addr2, 0, ADC_JUMP | ADC_STRING | ADC_ENTRY | ADC_OFFSET | ADC_SYMBOL, sym, 4096, buf);
		    if(res)
			{
			variables[V_RES] = sym;
			char *tmp = strstr(sym, ".");
			if(tmp)
			{
				strtok(sym, ">");                          //buxfix
				*tmp = '\0';
				variables[V_RES_1] = sym + 2;          //bugfix
				variables[V_RES_2] = tmp + 1;
			}
		}
		    return true;
		}
		variables[V_RES] = NULL;
		return true;
	}
    return false;
}

bool OllyLang::DoGBPM(wstring args)
{
	variables[V_RES]=break_memaddr;
	return true;
}

//Get Breakpoint Reason
bool OllyLang::DoGBPR(wstring args)
{
	wstring ops[1];

	if (break_reason == PP_MEMBREAK) {
		//Mem Breakpoint Reason

		break_memaddr=0;
		t_thread* t;
		t = Findthread(Getcputhreadid());
		CONTEXT context;
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		GetThreadContext(t->thread, &context);

		ulong tHwBpAddr[4];
		tHwBpAddr[0]=context.Dr0;
		tHwBpAddr[1]=context.Dr1;
		tHwBpAddr[2]=context.Dr2;
		tHwBpAddr[3]=context.Dr3;

		BYTE buffer[MAXCMDSIZE];
		ulong size=Readmemory(buffer, t->reg.ip, MAXCMDSIZE, MM_SILENT);
		if (size>0) {
			t_disasm disasm;
			size=Disasm(buffer,size,t->reg.ip,NULL,&disasm,DISASM_DATA,NULL);
			if (size>0) {
				char i,j;
				for (j=0;j<3;j++)
					if (disasm.opaddr[j]!=0 && disasm.opgood[j]) 
					{
						break_memaddr=disasm.opaddr[j];
						for (i=0;i<4;i++) 
						if (tHwBpAddr[i]==disasm.opaddr[j])
							break;
					}
			}
		}
	}

	if(CreateOp(args, ops, 1))
	{
		if (is_variable(ops[0])) {
			variables[ops[0]] = break_reason;
			return true;
		}
	} 
	variables[V_RES] = break_reason;
	return true;
}

//Get Code Information
bool OllyLang::DoGCI(wstring args)
{
    wstring ops[2], param;
	ulong addr,size;

	if(!CreateOp(args, ops, 2))
		return false;

	if ( GetDWOpValue(ops[0], addr) 
	   && GetSTROpValue("\""+ops[1]+"\"", param) )
	{

		transform(param.begin(), param.end(), param.begin(), toupper);

		BYTE buffer[MAXCMDSIZE];
//		size=Readmemory(buffer, addr, MAXCMDSIZE, MM_SILENT);
		size=Readcommand(addr,(char *) buffer);

		if (size>0) 
		{
			t_disasm disasm;
			size=Disasm(buffer,size,addr,NULL,&disasm,DISASM_CODE,NULL);

			if (size<=0)
				return false;
			else if (param == L"COMMAND")
			{
				wstring s;
				s.assign(disasm.result);
				while (s.find(L"  ") != wstring::npos) ReplaceString(s,"  "," ");
				variables[V_RES] = s; 
				return true;
			}
			else if (param == L"CONDITION") 
			{
				variables[V_RES] = disasm.condition; 
				return true;
			}
			else if (param == L"DESTINATION") 
			{
				variables[V_RES] = disasm.jmpaddr; 
				return true;
			}
			else if (param == L"SIZE") 
			{
				variables[V_RES] = size; 
				return true;
			}
			else if (param == L"TYPE") 
			{
				variables[V_RES] = disasm.cmdtype; 
				return true;
			}
		}
	}
	return false;
}

bool OllyLang::DoGCMT(wstring args)
{
	wstring comment;
	ulong addr,size;

	if(GetDWOpValue(args, addr))
	{
		if(addr != 0)
		{
			size = Findname(addr, NM_COMMENT, buffer);
			if (size==0)
				size = Findname(addr, NM_LIBCOMM, buffer);
			if (size==0)
				size = Findname(addr, NM_ANALYSE, buffer);		
			comment = buffer;
			if(comment==""){
			   variables[V_RES] = " ";
               return true;
			}  
			variables[V_RES] = comment;
			return true;
		}
	}
	return false;
}

bool OllyLang::DoGFO(wstring args)
{
	wstring comment;
	ulong addr;

	if(GetDWOpValue(args, addr))
	{
		if(addr != 0)
		{
			t_module* mod = (t_module*) Findmodule(addr);
			if (mod!=NULL) {
				variables[V_RES] = Findfileoffset(mod, addr);
			} else {
				variables[V_RES] = 0;
			}
			return true;
		}
	}
	return false;
}

// Get Label
// returns label from address
// glbl 
bool OllyLang::DoGLBL ( wstring args )
{
	wstring comment;
	ulong addr, type;
	char buffer[TEXTLEN]={0};

	if (!GetDWOpValue(args, addr))
		return false;
	{
		variables[V_RES] = 0;

		if (addr != 0)
		{
			if (Findlabel ( addr, buffer ) != NM_LABEL)
				variables[V_RES] = 0;

			comment.assign(buffer);
			if (comment == L"")
				variables[V_RES] = 0;

			variables[V_RES] = comment;
		}
	}
	return true;
}

bool OllyLang::DoGMA(wstring args)
{
	wstring str,ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	if(GetSTROpValue(ops[0], str)) {

		if (str.length() > 8)
			str = str.substr(0,8);

		//Module names : Spaces to underscores
		while(str.find(L" ")!=wstring::npos)
			str.replace(str.find(L" "),1,"_");

		Listmemory();

		int t=_memory;
		if (t<=0)
			return false;

		t_table* ttab=(t_table*) t;
		t_memory* mem;
		t_module* mod;
		wstring sMod;

		for (int n=0;n<ttab->data.n;n++) {
	
			mem = (t_memory*) Getsortedbyselection(&ttab->data,n);
			mod = (t_module*) Findmodule(mem->base);
			if (mod!=NULL) {
				sMod.assign(mod->name,SHORTLEN);
				if (_wcsicmp(sMod.c_str(),str.c_str())==0) {
					Int2Hex(mem->base, str);
					nIgnoreNextValuesHist++;
					return DoGMI(str+","+ops[1]);		
				}
			}
		}
	}

	variables[V_RES] = 0;

	return true;

}

bool OllyLang::DoGMEMI(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong addr = 0;
	wstring str;

	if(GetDWOpValue(ops[0], addr) && GetSTROpValue("\""+ops[1]+"\"", str) )
	{
		transform(str.begin(), str.end(), str.begin(), toupper);

		t_memory* mem = Findmemory(addr);
		if(str == L"MEMORYBASE" && mem != NULL)
		{
			variables[V_RES] = (DWORD)mem->base;
			return true;
		}
		else if(str == L"MEMORYSIZE" && mem != NULL)
		{
			variables[V_RES] = (DWORD)mem->size;
			return true;
		}
		else if(str == L"MEMORYOWNER" && mem != NULL)
		{
			variables[V_RES] = (DWORD)mem->owner;
			return true;
		}
		else if(mem == NULL)
		{
			variables[V_RES] = 0;
			return true;
		}
		else
		{			
			//DoGMI(Int2Str(mem->base)+" ops[1]);
			variables[V_RES] = 0;
			errorstr = L"Second operand bad";
			return false;
		}
	}

	errorstr = L"Bad operand";
	return false;
}

bool OllyLang::DoElse()
{
	int condlevel = 0;
	int pos = script_pos+1;
	//goto to else or endif
	while(ToLower(script[pos]) != "endif" || condlevel > 0) {
		if (ToLower(script[pos]) == L"endif") {
			condlevel--;
		}
		if (ToLower(script[pos]).substr(0,2) == L"if") {
			condlevel++;
		}
		if (condlevel == 0 && ToLower(script[pos]) == L"else") {
			pos++;
			break;
		}
		pos++;
		if (pos>script.size()) {
			DoENDIF("");
			errorstr = L"IF needs ENDIF command !";
			return false;
		}
	}
	script_pos = pos-1;
	setProgLineResult(pos,variables[V_RES]);
	return true;
}

bool OllyLang::DoIFA(wstring args)
{
	conditions.push_back(args);
	if (args != "" && !DoCMP(args)) {
		return false;
	}
	if(zf == 1 || cf == 1) {
		return DoElse();
	}
	return true;
}

bool OllyLang::DoIFAE(wstring args)
{
	conditions.push_back(args);
	if (args != "" && !DoCMP(args)) {
		return false;
	}
	if(cf == 1) {
		return DoElse();
	}
	return true;
}

bool OllyLang::DoIFB(wstring args)
{
	conditions.push_back(args);
	if (args != "" && !DoCMP(args)) {
		return false;
	}
	if(cf == 0) {
		return DoElse();
	}
	return true;
}

bool OllyLang::DoIFBE(wstring args)
{
	conditions.push_back(args);
	if (args != "" && !DoCMP(args)) {
		return false;
	}
	if(zf == 0 && cf == 0) {
		return DoElse();
	}
	return true;
}

bool OllyLang::DoIFEQ(wstring args)
{
	conditions.push_back(args);
	if (args != "" && !DoCMP(args)) {
		return false;
	}
	if (zf == 0) {
		return DoElse();
	}
	return true;
}

bool OllyLang::DoIFNEQ(wstring args)
{
	conditions.push_back(args);
	if (args != "" && !DoCMP(args)) {
		return false;
	}
	if (zf == 1) {
		return DoElse();
	}
	return true;
}

bool OllyLang::DoGMEXP(wstring args)
{
	wstring ops[3];

	if(!CreateOperands(args, ops, 3)) {
		ops[2]="0";
		if(!CreateOperands(args, ops, 2))
			return false;
	}

	ulong i, num, addr, count=0;
	wstring str;
	bool cache=false, cached=false;

	if(GetDWOpValue(ops[0], addr) && GetSTROpValue("\""+ops[1]+"\"", str) && GetDWOpValue(ops[2], num) )
	{
		transform(str.begin(), str.end(), str.begin(), toupper);

		t_module * mod = Findmodule(addr);
		if (!mod) {
			variables[V_RES] = 0;
			return true;
		}

		t_export exp={0};

		if (str == L"COUNT") {
			cache = true;
			tExportsCache.clear();
			exportsCacheAddr = addr;
		} else {
			if (exportsCacheAddr == addr && num < tExportsCache.size()) {
				exp = tExportsCache[num];
				count = tExportsCache.size();
				cached = true;
			}
		}

		if (!cached)
		for(i = 0; i < mod->codesize ; i++) {
			if (Findname(mod->codebase + i, NM_EXPORT, exp.label))
			{
				count++;
				exp.addr=mod->codebase + i;
				if (count==num && !cache) break;
				if (cache) {
					tExportsCache.push_back(exp);
				}
			}
		}

		if (num > count) //no more
		{
			variables[V_RES] = 0;
			return true;
		}

		if(str == L"COUNT")
		{
			variables[V_RES] = count;
			return true;
		}
		else if(str == L"ADDRESS")
		{
			variables[V_RES] = exp.addr;
			return true;
		}
		else if(str == L"LABEL")
		{
			variables[V_RES] = exp.label;
			return true;
		}
		else
		{
			variables[V_RES] = 0;
			errorstr = L"Second operand bad";
			return false;
		}
	}

	errorstr = L"Bad operand";
	return false;
}

bool OllyLang::DoGMI(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong addr = 0;
	wstring str;

	if(GetDWOpValue(ops[0], addr) && GetSTROpValue("\""+ops[1]+"\"", str) )
	{
		t_module* mod = Findmodule(addr);

		transform(str.begin(), str.end(), str.begin(), toupper);
		
		if(mod == NULL)
		{
			variables[V_RES] = 0;
			return true;
		}
		else if(str == L"MODULEBASE")
		{ 
			variables[V_RES] = (DWORD)mod->base;
			return true;
		}
		else if(str == L"MODULESIZE")
		{
			variables[V_RES] = (DWORD)mod->size;
			return true;
		}
		else if(str == L"CODEBASE")
		{
			variables[V_RES] = (DWORD)mod->codebase;
			return true;
		}
		else if(str == L"CODESIZE")
		{
			variables[V_RES] = (DWORD)mod->origcodesize;
			return true;
		}
		else if(str == L"ENTRY")
		{
			variables[V_RES] = (DWORD)mod->entry;
			return true;
		}
		else if(str == L"NSECT")
		{
			variables[V_RES] = (DWORD)mod->nsect;
			return true;
		}
		else if(str == L"DATABASE")
		{
			variables[V_RES] = (DWORD)mod->database;
			return true;
		}
		else if(str == L"EDATATABLE")
		{
			variables[V_RES] = (DWORD)mod->edatatable;
			return true;
		}
		else if(str == L"EDATASIZE")
		{
			variables[V_RES] = (DWORD)mod->edatasize;
			return true;
		}
		else if(str == L"IDATABASE")
		{
			variables[V_RES] = (DWORD)mod->idatabase;
			return true;
		}
		else if(str == L"IDATATABLE")
		{
			variables[V_RES] = (DWORD)mod->idatatable;
			return true;
		}
		else if(str == L"RESBASE")
		{
			variables[V_RES] = (DWORD)mod->resbase;
			return true;
		}
		else if(str == L"RESSIZE")
		{
			variables[V_RES] = (DWORD)mod->ressize;
			return true;
		}
		else if(str == L"RELOCTABLE")
		{
			variables[V_RES] = (DWORD)mod->reloctable;
			return true;
		}
		else if(str == L"RELOCSIZE")
		{
			variables[V_RES] = (DWORD)mod->relocsize;
			return true;
		}
		else if(str == L"NAME")
		{
			variables[V_RES] = (char*)mod->name;
			if (variables[V_RES].str.length() >	SHORTLEN)
				variables[V_RES].str = variables[V_RES].str.substr(0,SHORTLEN);
			return true;
		}
		else if(str == L"PATH")
		{
			variables[V_RES] = (char[MAX_PATH])mod->path;
			return true;
		}
		else if(str == L"VERSION")
		{
			variables[V_RES] = (char*)mod->version;
			return true;
		}
		else
		{
			variables[V_RES] = 0;
			errorstr = L"Second operand bad";
			return false;
		}
	}
	errorstr = L"Bad operand";
	return false;
}

bool OllyLang::DoGMIMP(wstring args)
{
	wstring ops[3];

	if(!CreateOperands(args, ops, 3)) {
		ops[2]="0";
		if(!CreateOperands(args, ops, 2))
			return false;
	}

	ulong i, num, addr, count=0;
	wstring str;
	bool cache=false, cached=false;

	if(GetDWOpValue(ops[0], addr) && GetSTROpValue("\""+ops[1]+"\"", str) && GetDWOpValue(ops[2], num) )
	{
		transform(str.begin(), str.end(), str.begin(), toupper);

		t_module * mod = Findmodule(addr);
		if (!mod) {
			variables[V_RES] = 0;
			return true;
		}

		t_export exp={0};

		if (str == L"COUNT") {
			cache = true;
			tImportsCache.clear();
			importsCacheAddr = addr;
		} else {
			if (importsCacheAddr == addr && num < tImportsCache.size()) {
				exp = tImportsCache[num];
				count = tImportsCache.size();
				cached = true;
			}
		}

		if (!cached)
		for(i = 0; i < mod->codesize ; i++) {
			if (Findname(mod->codebase + i, NM_IMPORT, exp.label))
			{
				count++;
				exp.addr=mod->codebase + i;
				if (count==num && !cache) break;
				if (cache) {
					tImportsCache.push_back(exp);
				}
			}
		}

		if (num > count) //no more
		{
			variables[V_RES] = 0;
			return true;
		}

		if(str == L"COUNT")
		{
			variables[V_RES] = count;
			return true;
		}
		else if(str == L"ADDRESS")
		{
			variables[V_RES] = exp.addr;
			return true;
		}
		else if(str == L"LABEL")
		{
			variables[V_RES] = exp.label;
			return true;
		}
		else if(str == L"NAME")
		{
			wstring s = exp.label;
			if (s.find(L".") != wstring::npos) {
				variables[V_RES] = s.substr(s.find(L".")+1);
			}
			else 
				variables[V_RES] = exp.label;

			return true;
		}
		else if(str == L"MODULE")
		{
			wstring s = exp.label;
			if (s.find(L".") != wstring::npos) {
				variables[V_RES] = s.substr(0,s.find(L"."));
			}
			else 
				variables[V_RES] = "";
			return true;
		}
		else
		{
			variables[V_RES] = 0;
			errorstr = L"Second operand bad";
			return false;
		}
	}

	errorstr = L"Bad operand";
	return false;
}

bool OllyLang::DoGN(wstring args)
{
	wstring ops[1];
	ulong addr;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetDWOpValue(ops[0], addr))
	{
		char sym[4096] = {0};
		char buf[TEXTLEN] = {0};
//		int res = Decodeaddress(addr, 0, ADC_STRING, sym, 4096, buf);
		int res = Decodeaddress(addr, 0, ADC_JUMP | ADC_STRING | ADC_ENTRY | ADC_OFFSET | ADC_SYMBOL, sym, 4096, buf);
		if(res)
		{
			variables[V_RES] = sym;
			char* tmp = strstr(sym, ".");
			if(tmp)
			{
				strtok(sym, ">");                      
				*tmp = '\0';
				variables[V_RES_1] = sym; //+ 2 ... not a bug Charset pb ?
				variables[V_RES_2] = tmp + 1;
			}
		}
		else
		{
			variables[V_RES] = 0;
			variables[V_RES_1] = 0;
			variables[V_RES_2] = 0;
		}

		return true;
	}

	return false;
}

bool OllyLang::DoGO(wstring args)
{
	wstring ops[1];
	ulong addr;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetDWOpValue(ops[0], addr))
	{
		Go(Getcputhreadid(), addr, STEP_RUN, 1, 1);
		require_ollyloop = 1;
      return true;
	}

	return false;
}

//Get Code Information
bool OllyLang::DoGOPI(wstring args)
{
    wstring ops[3], param;
	ulong addr,size,index;

	if(!CreateOp(args, ops, 3))
		return false;

	if ( GetDWOpValue(ops[0], addr) 
	   && GetDWOpValue(ops[1], index) 
	   && GetSTROpValue("\""+ops[2]+"\"", param) )
	{

		index--;
		if (index < 0 || index > 2) {
			errorstr = L"Bad operand index (1-3) !";
			return false;
		}

		transform(param.begin(), param.end(), param.begin(), toupper);

		BYTE buffer[MAXCMDSIZE]={0};
//		size=Readmemory(buffer, addr, MAXCMDSIZE, MM_SILENT);
		size=Readcommand(addr,(char *) buffer);

		if (size>0) 
		{
			t_disasm disasm;
			size=Disasm(buffer,size,addr,NULL,&disasm,DISASM_ALL,Getcputhreadid());

			if (size<=0)
				return false;
			else if (param == L"TYPE")
			{
				variables[V_RES] = disasm.optype[index]; // Type of operand (extended set DEC_xxx)
				return true;
			}
			else if (param == L"SIZE") 
			{
				variables[V_RES] = disasm.opsize[index]; // Size of operand, bytes
				return true;
			}
			else if (param == L"GOOD") 
			{
				variables[V_RES] = disasm.opgood[index]; // Whether address and data valid
				return true;
			}
			else if (param == L"ADDR") 
			{
				variables[V_RES] = disasm.opaddr[index]; // Address if memory, index if register
				return true;
			}
			else if (param == L"DATA") 
			{
				variables[V_RES] = disasm.opdata[index]; // Actual value (only integer operands)
				return true;
			}
		}
	}
	return false;
}


//gpa "LoadLibraryA","kernel32.dll"
bool OllyLang::DoGPA(wstring args)
{
	wstring ops[3];
	ulong dontfree=0;

	if(CreateOperands(args, ops, 3))
		GetDWOpValue(ops[2], dontfree);
	else
		if(!CreateOperands(args, ops, 2))
			return false;

	variables[V_RES] = 0;
	DropVariable("$RESULT_1");
	DropVariable("$RESULT_2");

	wstring proc, lib;
	FARPROC p;

	if(GetSTROpValue(ops[0], proc) && GetSTROpValue(ops[1], lib))
	{
		HMODULE hMod=LoadLibraryEx(lib.c_str(),NULL,LOAD_WITH_ALTERED_SEARCH_PATH);

		if(hMod==0)	{
			variables[V_RES] = 0;
			errorstr = L"GPA: "+StrLastError();

			if (dontfree) {

				nIgnoreNextValuesHist++;
				DoGPA("\"LoadLibraryA\",\"kernel32.dll\"");

				HANDLE hDebugee = (HANDLE)Plugingetvalue(VAL_HPROCESS);

				ulong pmem = AddProcessMemoryBloc(lib);

				wstring tmp;
				sprintf(buffer,"0%lX",pmem);
				tmp.assign(buffer);

				if (DoPUSH(tmp)) {

					sprintf(buffer,"0%lX",variables[V_RES].dw);

					ExecuteASM("call "+tmp);
				
				}

				regBlockToFree((void*)pmem,0x1000,true);
				//VirtualFreeEx(hDebugee, pmem, 0x1000, MEM_DECOMMIT);

			}
			return true;
		}

		variables[V_RES_1] = lib;

		//if (proc != "")
		p = GetProcAddress(hMod, proc.c_str());
		//else
		//:	GetModu

		if (!dontfree) {
			FreeLibrary(hMod);
			require_ollyloop=1;
		}

		if(p == 0) {
			errorstr = L"GPA: No such procedure: " + proc;
			return true;
		}

		variables[V_RES] = (DWORD) p;
		variables[V_RES_2] = proc;
		return true;
	}
	return false;
}

bool OllyLang::DoGPI(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	wstring str;

	if(GetSTROpValue("\""+ops[0]+"\"", str))
	{
 
		if(str == L"HPROCESS") //(HANDLE) Handle of debugged process 
		{
			variables[V_RES] = (DWORD)Plugingetvalue(VAL_HPROCESS);
			return true;
		}
		else if(str == L"PROCESSID") //Process ID of debugged process 
		{
			variables[V_RES] = (DWORD)Plugingetvalue(VAL_PROCESSID);
			return true;
		}
		else if(str == L"HMAINTHREAD") //(HANDLE) Handle of main thread of debugged process 
		{
			variables[V_RES] = (DWORD)Plugingetvalue(VAL_HMAINTHREAD);
			return true;
		}
		else if(str == L"MAINTHREADID") //Thread ID of main thread of debugged process 
		{
			variables[V_RES] = (DWORD)Plugingetvalue(VAL_MAINTHREADID);
			return true;
		}
		else if(str == L"MAINBASE") //Base of main module in the debugged process 
		{
			variables[V_RES] = (DWORD)Plugingetvalue(VAL_MAINBASE);
			return true;
		}
		else if(str == L"PROCESSNAME") //Name of the debugged process 
		{
			variables[V_RES] = (char *)Plugingetvalue(VAL_PROCESSNAME);
			return true;
		}
		else if(str == L"EXEFILENAME") //Name of the main debugged file 
		{
			variables[V_RES] = _executable;
			return true;
		}
		else if(str == L"CURRENTDIR") //Current directory for debugged process 
		{
			variables[V_RES] = (char *)Plugingetvalue(VAL_CURRENTDIR);
			if (variables[V_RES].str.length()==0) {
				wchar_t spath[MAX_PATH];
				wcscpy(spath, _executable);
				wstring path = spath;
				variables[V_RES] = path.substr(0, path.rfind('\\') + 1);				
			}
			return true;
		}
		else if(str == L"SYSTEMDIR") //Windows system directory 
		{
			variables[V_RES] = (char *)Plugingetvalue(VAL_SYSTEMDIR);
			return true;
		}
	}
	errorstr = L"Bad operand";
	return false;
}

//in dev... i try to find API parameters count and types
bool OllyLang::DoGPP(wstring args)
{
	if (!DoGPA(args))
		return false;

	ulong addr = variables[V_RES].dw;
	if (addr==0)
		return false;

	wstring sAddr = _itow(addr,buffer,16);
	if (!DoREF(sAddr))
		return false;

	int t=Plugingetvalue(VAL_REFERENCES);
	if (t<=0)
		return false;

	int size;
	t_table* tref=(t_table*) t;
	for (int n=0;n<tref->data.n;n++) {
	
		t_ref* ref= (t_ref*) Getsortedbyselection(&tref->data,n);
			
		if (ref->addr == addr)
			continue; 

		//Disasm origin to get comments
		BYTE buffer[MAXCMDSIZE];
		size=Readmemory(buffer, ref->addr, MAXCMDSIZE, MM_SILENT);					
		if (size>0) {

			t_disasm disasm;
			t_module* mod = Findmodule(ref->addr);
			Analysecode(mod);

			size=Disasm(buffer,size,ref->addr,NULL,&disasm,DISASM_ALL,NULL);
            DbgMsg(disasm.nregstack,disasm.comment);

			if (size>0) {
				variables[V_RES] = ref->addr;
				variables[V_RES_1] = disasm.result; //command text
				variables[V_RES_2] = disasm.comment;
				return true; 
			}
		}
	}
	return true;
}

//Get Reference Window Address at Offset
bool OllyLang::DoGREF(wstring args)
{
	wstring ops[1];
	ulong line;

	CreateOperands(args, ops, 1);

	t_table* tt;
	tt=(t_table*) Plugingetvalue(VAL_REFERENCES);

	variables[V_RES] = 0;

	//Get Ref. Addr
	if (tt!=NULL) 
	{
		if(ops[0]!="" && GetDWOpValue(ops[0], line))
		{
			if (line < tt->data.n) 
			{
				t_ref* tr;
				tr=(t_ref*) Getsortedbyselection(&tt->data, line); //0 is CPU initial sel.
				if (tr!=NULL)
					variables[V_RES]=tr->addr;
			}
		} else {
			//Get Ref. Count
			variables[V_RES] = tt->data.n-1;
		}
		return true;
	}
	return false;
}

//Get Relative Offset
bool OllyLang::DoGRO(wstring args)
{
	wstring ops[1];
	ulong addr;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetDWOpValue(ops[0], addr))
	{
		char sym[4096] = {0};

		int size = Decoderelativeoffset(addr, ADC_NONTRIVIAL, sym, 4096);
		if (size > 0)
		{
			variables[V_RES] = sym;
		}
		else
		{
			variables[V_RES] = 0;
		}

		return true;
	}

	return false;
}

// Get Selection Limits
// returns START/END address from currently selected line in CPUASM | DUMP | STACK window in $RESULT & $RESULT_1
// arg can be either : CPUDASM, CPUDUMP, CPUSTACK 
// ex		:	gsl CPUDUMP
bool OllyLang::DoGSL ( wstring args )
{
	wstring str;
	t_dump* td;

	variables[V_RES] = 0;
	variables[V_RES_1] = 0;
	variables[V_RES_2] = 0;
	
	GetSTROpValue("\""+args+"\"", str);
	if (str == L"") str = "CPUDASM";

	transform(str.begin(), str.end(), str.begin(), toupper);

	if(str == L"CPUDASM")
		td = (t_dump*) Plugingetvalue (VAL_CPUDASM);
	else if (str == L"CPUDUMP")
		td = (t_dump*) Plugingetvalue(VAL_CPUDDUMP);
	else if (str == L"CPUSTACK")
		td = (t_dump*) Plugingetvalue(VAL_CPUDSTACK);
	else
		return false;
	
	if (td)
	{
		variables[V_RES] = (DWORD)td->sel0;
		variables[V_RES_1] =  (DWORD)td->sel1-1;
		variables[V_RES_2] =  (DWORD)td->sel1-(DWORD)td->sel0;
	}
	else
	{
		variables[V_RES] = 0;
		variables[V_RES_1] = 0;
		variables[V_RES_2] = 0;
	}

	return true;
}

// Get String
// returns a null terminated wstring from addr, the wstring is at least arg1 charachters
// gstr addr, [arg1]
// returns in   :
// - $RESULT    : the wstring
// - $RESULT_1  : len of wstring
//
// ex       : gstr 401000     ; arg1 in this case is set to default (5 chars)
//          : gstr 401000, 20 ; must be at least 20 chars
bool OllyLang::DoGSTR(wstring args)
{
	wstring str;
	char buf[TEXTLEN]={0};
	ulong addr, size, tmpSize;
	char c;
	bool bUseDef = false;
	uint iDashNum;

	wstring ops[2];


	if (!CreateOperands(args, ops, 2))
	{
		if (!CreateOperands(args, ops, 1))
			return false;
		else
			bUseDef = true;
	}

	if (GetDWOpValue (ops[0], addr))
	{
		variables[V_RES] = 0;
		variables[V_RES_1] = 0;
		if (addr != 0)
		{
			buffer[0] = '\0';
			tmpSize = Decodeascii(addr, buf, TEXTLEN, DASC_ASCII);
			if (tmpSize > 2 && buf[0]=='"') {
				tmpSize -= 2;
				lstrcpyn(buffer, (char *)(buf+1), tmpSize+1);
			}
			else {
				return true;
			}

			//tmpSize = Readmemory(buf, addr, TEXTLEN, MM_RESILENT);
			//if (!tmpSize)
			//	return true;

			//lstrcpy(buffer, buf);
			tmpSize = lstrlen(buffer);

			if (!bUseDef)
				GetDWOpValue(ops[1], size);
			else
				size = 2;

			if (tmpSize < size)
				return true;

			str.assign(buffer);
			variables[V_RES] = str;
			variables[V_RES_1] = tmpSize;			
		}
		return true;
	}
	return false;
}

// Get String
// returns a null terminated wstring from addr, the wstring is at least arg1 charachters
// gstr addr, [arg1]
// returns in   :
// - $RESULT    : the wstring
// - $RESULT_1  : len of wstring
//
// ex       : gstr 401000     ; arg1 in this case is set to default (5 chars)
//          : gstr 401000, 20 ; must be at least 20 chars
bool OllyLang::DoGSTRW(wstring args)
{
	wstring str,wstr;
	char buf[TEXTLEN*2]={0};
	ulong addr, size, tmpSize;
	char c;
	bool bUseDef = false;
	uint iDashNum;

	wstring ops[2];


	if (!CreateOperands(args, ops, 2))
	{
		if (!CreateOperands(args, ops, 1))
			return false;
		else
			bUseDef = true;
	}

	if (GetDWOpValue (ops[0], addr))
	{
		variables[V_RES] = 0;
		variables[V_RES_1] = 0;
		if (addr != 0)
		{
			buffer[0] = '\0';
			tmpSize = Decodeunicode(addr, buf, TEXTLEN*2);
			if (tmpSize > 2 && buf[0]=='"') {
				tmpSize -= 2;
				lstrcpyn(buffer, (char *)(buf+1), tmpSize+1);				
			}
			else {
				return true;
			}

			str.assign(buffer);
			tmpSize = str.length();//lstrlen(buffer);

			if (tmpSize < Readmemory(buf, addr, TEXTLEN*2, MM_RESILENT)) {
				wcsncpy((wchar_t *)buffer, (wchar_t *) buf, tmpSize);
				wstr.assign(buffer,tmpSize*2);
			}

			if (!bUseDef)
				GetDWOpValue(ops[1], size);
			else
				size = 2;

			if (tmpSize < size)
				return true;

			variables[V_RES] = str;
			variables[V_RES_1] = tmpSize;
			variables[V_RES_2] = wstr;
		}
		return true;
	}
	return false;
}

bool OllyLang::DoHANDLE(wstring args)
{
	wstring ops[3];
	bool useCaption=true;

	if(!CreateOperands(args, ops, 3)) {
			return false;
	}

	wstring sClassName;
	ulong x,y;
	ulong thid = Plugingetvalue(VAL_MAINTHREADID);

	if(GetDWOpValue(ops[0], x) 
		&& GetDWOpValue(ops[1], y) 
		&& GetSTROpValue(ops[2], sClassName)) 
	{
		variables[V_RES] = (DWORD) FindHandle(thid, sClassName, x, y);
		return true;
	}

	return false;

}

bool OllyLang::DoINC(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	return DoADD(ops[0] + ", 1");
}
*/
bool OllyLang::DoINIR(wstring args)
{
	wstring ops[2],key,str;
	ulong val,valdef;
	wchar_t bufkey[256];
	wchar_t bufdef[256];

	if(!CreateOperands(args, ops, 2)) {
		errorstr = L"Default value needed to get type";
		return false;
	}

	if(!GetSTROpValue(ops[0], key)) {
		return false;
	}

	wcscpy(bufkey,key.c_str());

	if(GetDWOpValue(ops[1], valdef)) {
		variables[V_RES_1] = Getfromini(NULL,PLUGIN_NAME, bufkey, L"%i", &val);
		if (0 == variables[V_RES_1].dw)
			variables[V_RES] = val;
		else
			variables[V_RES] = valdef;
		return true;
	}

	if(GetSTROpValue(ops[1], str)) {
		wcscpy(bufdef,str.c_str());
		variables[V_RES_1] = Getfromini(NULL,PLUGIN_NAME, bufkey, L"%s", buffer);
		if (0 == variables[V_RES_1].dw)
			variables[V_RES] = buffer;
		else
			variables[V_RES] = bufdef;
		return true;
	}

	return false;
}

bool OllyLang::DoINIW(wstring args)
{
	wstring ops[2],key,str;
	ulong val;
	wchar_t bufkey[256];

	if(!CreateOperands(args, ops, 2))
		return false;

	if(!GetSTROpValue(ops[0], key)) {
		return false;
	}

	wcscpy(bufkey,key.c_str());
	
	if(GetDWOpValue(ops[1], val)) {
		Writetoini(NULL,PLUGIN_NAME, bufkey, L"%i", val);
		return true;
	}

	if(GetSTROpValue(ops[1], str)) {
		wcscpy(buffer,str.c_str());
		Writetoini(NULL,PLUGIN_NAME, bufkey, L"%s", buffer);
		return true;
	}

	return false;
}
/*
bool OllyLang::DoHISTORY(wstring args)
{
	wstring ops[1];
	ulong dw;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetDWOpValue(ops[0], dw)) {
		showVarHistory=(dw!=0);
		return true;
	}

	return false;
}

bool OllyLang::DoITOA(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2)) {
		ops[1] = "16.";
		if(!CreateOperands(args, ops, 1))
			return false;
	}

	ulong base, dw;

	if(GetDWOpValue(ops[0], dw) 
		&& GetDWOpValue(ops[1], base) )
	{
		char buffer [20]={0};
		_itow(dw,buffer,base);
		variables[V_RES] = buffer;
		return true;
	}
	return false;
}

bool OllyLang::DoJA(wstring args)
{
	if(zf == 0 && cf == 0)
		return DoJMP(args);
	return true;
}

bool OllyLang::DoJAE(wstring args)
{
	if(cf == 0)
		return DoJMP(args);
	return true;
}

bool OllyLang::DoJB(wstring args)
{
	if(cf == 1)
		return DoJMP(args);
	return true;
}

bool OllyLang::DoJBE(wstring args)
{
	if(zf == 1 || cf == 1)
		return DoJMP(args);
	return true;
}

bool OllyLang::DoJE(wstring args)
{
	if(zf == 1)
		return DoJMP(args);
	return true;
}

bool OllyLang::DoJMP(wstring args)
{
	wstring str, ops[1];

	if(!CreateOperands(args, ops, 1) )
		return false;

	if(!GetSTROpValue(ops[0], str) )
		str = ops[0];

	if (str=="")
		return false;

	if(labels.find(str) == labels.end() )
		return false;

	//Store jump destination to display it
	t_wndprog_data *pline;
	pline = (t_wndprog_data *) Getsortedbyselection(&wndProg.sorted,pgr_scriptpos);
	if (pline != NULL) {
		pline->jumpto = labels[str];
	}

	script_pos = labels[str];
	return true;
}

bool OllyLang::DoJNE(wstring args)
{
	if(zf == 0)
		return DoJMP(args);
	return true;
}


bool OllyLang::DoKEY(wstring args)
{
	wstring ops[3];
	ulong key,shift,ctrl;

	if(!CreateOperands(args, ops, 3)) {
		ops[2]="0";
		if(!CreateOperands(args, ops, 2)) {
			ops[1]="0";
			if(!CreateOperands(args, ops, 1))
				return false;
		}
	}
	
	if(GetDWOpValue(ops[0], key) 
		&& GetDWOpValue(ops[1], shift) 
		&& GetDWOpValue(ops[2], ctrl)) 
	{
		Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, ctrl, shift, key); 
		require_ollyloop = 1;
		return true;
	}
	return false;
}

bool OllyLang::DoLBL(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	wstring lbl;
	ulong addr;

	if(GetDWOpValue(ops[0], addr) 
		&& GetSTROpValue(ops[1], lbl))
	{
		if(lbl != "")
		{
			strcpy(buffer, lbl.c_str());
			Insertname(addr, NM_LABEL, buffer);
			Broadcast(WM_USER_CHGALL, 0, 0);
		}
		else
		{
			Deletenamerange(addr, addr + 1, NM_COMMENT);
			Broadcast(WM_USER_CHGALL, 0, 0);
		}
		return true;
	}
	return false;
}

bool OllyLang::DoLM(wstring args)
{
    wstring ops[3];
    if(!CreateOperands(args, ops, 3))
        return false;

    streamsize sum = 0;

    wchar_t spath[MAX_PATH];
    wcscpy(spath, _executable);
    wstring path = spath;

    path = path.substr(0, path.rfind('\\') + 1);

    ulong addr, size;
    wstring filename;
    if(GetDWOpValue(ops[0], addr) 
		&& GetDWOpValue(ops[1], size) 
		&& GetSTROpValue(ops[2], filename))
    {

        if (filename.find(L":\\") != wstring::npos)
			path = filename;
		else
			path += filename;

		std::wifstream fin(path.c_str(),ios::in | ios::binary);

		if(fin.fail()) {
	        variables[V_RES] = 0;
            errorstr = TEXT("Couldn't open file!");
			fin.close();
            return false;
		}

        char buf[4096];
		int gotten;
		while (!fin.eof() && (sum<size || size==0) )
        {
			if (size==0) 
				fin.read(buf, sizeof buf);			
			else
				fin.read(buf, min(size-sum, sizeof buf));
			gotten=fin.gcount();
			sum += Writememory(buf, addr+sum, gotten, MM_RESILENT);
        }
        fin.close();

		if (sum) {
	        variables[V_RES] = sum;
            return true;
        }
        else
        {
            errorstr = L"Couldn't load file!";
            return false;
        }
    }
    return false;
}

bool OllyLang::DoLC(wstring args)
{
	//Clear Main Log Window

	HWND hwndLog=Createlistwindow();
	if (hwndLog==0)
		return false;

	//open context menu to clear main log wdw
	PostMessage(hwndLog,WM_USER+101,17,0);
	PostMessage(hwndLog,WM_KEYDOWN,'C',0);

	return true;
}

bool OllyLang::DoLCLR(wstring args)
{
	clearLogLines();
	return true;
}

bool OllyLang::DoLEN(wstring args)
{
	wstring ops[1],str;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(!GetSTROpValue(ops[0], str))
		return false;

	variables[V_RES] = (int) str.length();
	return true;
}

bool OllyLang::DoLOADLIB(wstring args)
{
	wstring ops[1],str;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(!GetSTROpValue(ops[0], str))
		return false;

	ulong fnload;

	SaveRegisters(true);
	variables[V_RES] = 0;

	DoGPA("\"LoadLibraryA\",\"kernel32.dll\"");
	fnload = variables[V_RES].dw;

	//alloc memory bloc to store DLL name
	HANDLE hDbgPrc = (HANDLE) Plugingetvalue(VAL_HPROCESS);
	void * hMem = VirtualAllocEx(hDbgPrc,NULL,0x1000,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);

	char bfdlladdr[10]={0};
	sprintf(bfdlladdr, "0%lX", hMem);
	
	Writememory((void*)str.c_str(), (ulong) hMem, str.length(), MM_DELANAL|MM_SILENT);

	if (DoPUSH(bfdlladdr)) {

		char bffnloadlib[10]={0};
		sprintf(bffnloadlib,"0%lX",fnload);
		wstring libPtrToLoad = bffnloadlib;

		ExecuteASM("call "+libPtrToLoad);	

		variables[V_RES] = 0;

		// result returned after process
		// variables[V_RES] = pt->reg.r[REG_EAX];
		t_dbgmemblock block={0};
		block.hmem = hMem;
		block.size = 0x1000;
		block.script_pos = script_pos;
		block.free_at_eip = reg_backup.eip;
		block.result_register = true;
		block.reg_to_return = REG_EAX;
		block.restore_registers = true;
		block.listmemory = true;
		block.autoclean = true;

		// Free memory block after next ollyloop
		regBlockToFree(block);
		require_addonaction = 1;
		require_ollyloop = 1;
		
		return true;
	}
	

	return false;
}
*/
bool OllyLang::DoLOG(wstring args)
{
	wstring prefix, ops[2];

	if(CreateOp(args, ops, 2))
	{
		if (!GetSTROpValue(ops[1], prefix))
			return false;
	} 
	else 
	{
		prefix=L"DEFAULT";
		if(!CreateOperands(args, ops, 1))
			return false;
	}

	ulong dw=0;
	wstring str;
	long double flt=0;

	if(UnquoteString(ops[0], '"', '"'))
	{
		//wstring constant
		if (prefix.compare(L"DEFAULT") == 0) 
		{
			wcsncpy(buffer, ops[0].c_str(),TEXTLEN-1);
		} 
		else 
		{
			prefix = prefix + ops[0];
			wcsncpy(buffer, prefix.c_str(),TEXTLEN-1);
		}
		buffer[TEXTLEN-1]=0;
		Infoline(buffer);
		Addtolist(0, 1, buffer);
		add2log(buffer);
		return true;
	}
	else 
	{
		vtype vt=EMP;
		if (is_variable(ops[0]))
			vt = variables[ops[0]].vt;

		if (vt==DW || vt==EMP) {
			if(GetDWOpValue(ops[0], dw))
			{
				//ulong constant
				if (prefix.compare(L"DEFAULT") == 0) {

					wchar_t sym[4096] = {0};
					wchar_t buf[TEXTLEN-1] = {0};
					int res = Decodeaddress(dw, 0, DM_JUMPIMP | DM_STRING | DM_ENTRY | DM_OFFSET | DM_SYMBOL, sym, 4096, buf);
					wsprintf(buffer, L"%s: %08lX", ops[0].c_str(), dw);

					if(wcscmp(buf, L""))
						wsprintf(buffer, L"%s | %s", buffer, buf);

					if(wcscmp(sym, L"") && dw !=  wcstoul(sym, 0, 16))
						wsprintf(buffer, L"%s | %s", buffer, sym);
				
				} 
				else 
				{
					wsprintf(buffer, L"%s%08lX", prefix.c_str(), dw);
				}

				buffer[TEXTLEN-1]=0;
				str.assign(buffer);
				//Infoline and Addtolist need parameters if %s %d... is present in wstring
				if (str.find(L"%") == wstring::npos) {
					Infoline(buffer);
					Addtolist(0, 1, buffer);
				}
				add2log(buffer);
				return true;
			}
		}

		if (vt==FLT || vt==EMP) {
			if(GetFLTOpValue(ops[0], flt))
			{
				//ulong constant
				if (prefix == L"DEFAULT") {
					wsprintf(buffer, L"%s: %2lf", ops[0].c_str(), flt);				
				} else {
					wsprintf(buffer, L"%s%2lf", prefix.c_str(), flt);
				}

				buffer[TEXTLEN-1]=0;
				Infoline(buffer);
				Addtolist(0, 1, buffer);
				add2log(buffer);
				return true;
			}
		}

		if (vt==STR || vt==EMP) {
			if(GetSTROpValue(ops[0], str))
			{
				var v=str;

				if(v.isbuf) {

					//log a buffer
					if (prefix.compare(L"DEFAULT") == 0) 
					{
						if (str.length()+ops[0].length() < 4094)
							wsprintf(buffer, L"%s: %s", ops[0].c_str(), str.c_str());
						else
							wcsncpy(buffer, variables[ops[0]].str.c_str(), TEXTLEN-1);
					} 
					else 
					{
						prefix = prefix + str;
						wcsncpy(buffer, prefix.c_str(), TEXTLEN-1);
					}
				} 
				else 
				{

					//log a wstring
					if (prefix.compare(L"DEFAULT") == 0) 
					{
						if (variables[ops[0]].str.length()+ops[0].length() < 4094)
							wsprintf(buffer, L"%s: %s", ops[0].c_str(), variables[ops[0]].strclean().c_str());
						else
							wcsncpy(buffer, variables[ops[0]].strclean().c_str(), TEXTLEN-1);
					} 
					else 
					{
						prefix = prefix + CleanString(str);
						wcsncpy(buffer, prefix.c_str(), TEXTLEN-1);
					}
				}
				buffer[TEXTLEN-1]=0;
				str.assign(buffer);
				//Infoline and Addtolist need parameters if %s %d... is present in wstring
				if (str.find(L"%") == wstring::npos) {
					Addtolist(0, 1, buffer);
				}
				add2log(str);
				return true;
			}
		}
	}
	return false;
}

bool OllyLang::DoLOGBUF(wstring args)
{
	wstring sSep,ops[3];

	if(!CreateOperands(args, ops, 3)) {
		ops[2]=L"\" \"";
		if(!CreateOperands(args, ops, 2)) {
			ops[0]=args;
			ops[1]=L"0";
		}
	}

	GetSTROpValue(ops[2], sSep);

	if (!is_variable(ops[0]))
		return false;
	
	ulong dw;
	if(GetDWOpValue(ops[1], dw))
	{
		if (dw==0) dw=16;

		wstring sLine=L"";
		wstring data = variables[ops[0]].strbuffhex();
		for (int n=0; n < variables[ops[0]].size; n++)
		{
			sLine=sLine + data.substr(n*2,2) + sSep;
			if (n>0 && !((n+1) % dw)) { 
				DoLOG(L"\"" +sLine+ L"\",\"\"");
				sLine=L"";
			}
		}
		if (sLine.length()) DoLOG(L"\"" +sLine+ L"\",\"\"");
		return true;
	}
	return false;
}

bool OllyLang::DoMEMCOPY(wstring args)
{
	wstring ops[3];

	if(!CreateOperands(args, ops, 3))
		return false;

	args=L"["+ ops[0] +L"],["+ ops[1] +L"],"+ ops[2];

	return DoMOV(args);
}

bool OllyLang::DoMOV(wstring args)
{
	wstring ops[3];
	bool bDeclared=false;
	ulong addr=0,maxsize=0;

	if(CreateOperands(args, ops, 3)){
		GetDWOpValue(ops[2], maxsize);
	}
	else
		if(!CreateOperands(args, ops, 2))
			return false;

	//resolve address with operands
	if(UnquoteString(ops[1], '[', ']')) {
		if (!CreateOperands(ops[1],&ops[1],1))
			return false;
		ops[1]=L"["+ops[1]+L"]";
	}

	// Check source
	ulong dw = 0; addr=0;
	wstring str = L"";
	wstring tmpops=ops[0];
	long double flt;

	// Used to retry after automatic variable declaration 
	retry_DoMOV:

	// Check destination
	if(is_variable(ops[0]))
	{
		// Dest is variable
		if(maxsize <= 4 && variables[ops[0]].vt != STR && GetDWOpValue(ops[1], dw) )
		{
			// DW to DW/FLT var
			if (maxsize==0) maxsize=4;
			dw = resizeDW(dw,maxsize);
			variables[ops[0]] = dw;
			variables[ops[0]].size = maxsize;
		}
		else if(GetSTROpValue(ops[1], str, maxsize))
		{
			// STR to any var
			variables[ops[0]] = str;
		}
		else if(maxsize <= 4 && GetDWOpValue(ops[1], dw) )
		{
			// DW to STR var
			if (maxsize==0) maxsize=4;
			dw = resizeDW(dw,maxsize);
			variables[ops[0]] = dw;
			variables[ops[0]].size = maxsize;
		}
		else if(GetFLTOpValue(ops[1], flt))
		{
			variables[ops[0]] = flt;
		}
		else 
			return false;

		return true;
	}
	else if(is_register(ops[0]))
	{
		// Dest is register
		if(GetDWOpValue(ops[1], dw))
		{
			t_thread* pt = Findthread(Getcputhreadid());
			int regnr = GetRegNr(ops[0]);			
			if(regnr != -1) {
				if (ops[0].length()==2) 
				{
					if (ops[0][1] == 'l') {
						//R8
						dw &= 0xFF;
						pt->reg.r[regnr] &= 0xFFFFFF00;
						pt->reg.r[regnr] |= dw;
					} 
					else if ( ops[0][1] == 'h') 
					{
						//R8
						dw &= 0xFF;
						pt->reg.r[regnr] &= 0xFFFF00FF;
						pt->reg.r[regnr] |= dw * 0x100;
					} 
					else
					{
						//R16
						dw &= 0xFFFF;
						pt->reg.r[regnr] &= 0xFFFF0000;
						pt->reg.r[regnr] |= dw;
					}
				} 
				else
				{
						//R32
						pt->reg.r[regnr] = dw;
				}
			}
			else
				if(ops[0] == L"eip") {
					pt->reg.ip = dw;
					//synch disasm window position
					//2.Setdisasm(dw,1,CPU_ASMHIST);
					Redrawcpudisasm();
				}

			pt->reg.status = RV_MODIFIED;
			pt->regvalid = 1;
			Redrawcpureg();
			require_ollyloop = 1;
			dw = resizeDW(dw,maxsize);
			return true;
		}
		return false;
	}
	else if(is_flag(ops[0]))
	{
		// Dest is flag
		if(GetDWOpValue(ops[1], dw))
		{
			if(dw != 0 && dw != 1)
			{
				errorstr = L"Invalid flag value";
				return false;
			}

			eflags flags;
			ZeroMemory(&flags, sizeof DWORD);
			t_thread* pt = Findthread(Getcputhreadid());
			flags.dwFlags = pt->reg.flags;

			if(_wcsicmp(ops[0].c_str(), L"!af") == 0)
				flags.bitFlags.AF = dw;
			else if(_wcsicmp(ops[0].c_str(), L"!cf") == 0)
				flags.bitFlags.CF = dw;
			else if(_wcsicmp(ops[0].c_str(), L"!df") == 0)
				flags.bitFlags.DF = dw;
			else if(_wcsicmp(ops[0].c_str(), L"!of") == 0)
				flags.bitFlags.OF = dw;
			else if(_wcsicmp(ops[0].c_str(), L"!pf") == 0)
				flags.bitFlags.PF = dw;
			else if(_wcsicmp(ops[0].c_str(), L"!sf") == 0)
				flags.bitFlags.SF = dw;
			else if(_wcsicmp(ops[0].c_str(), L"!zf") == 0)
				flags.bitFlags.ZF = dw;

			pt->reg.flags = flags.dwFlags;
			pt->reg.status = RV_MODIFIED;
			pt->regvalid = 1;
			Redrawcpureg();
			require_ollyloop = 1;
			return true;
		}
		return false;
	}
	else if(is_floatreg(ops[0]))
	{
		// Dest is float register
		if(GetFLTOpValue(ops[1], flt))
		{
			t_thread* pt = Findthread(Getcputhreadid());
			pt->reg.f[(ops[0][3]-0x30)] = flt;
			pt->reg.status = RV_MODIFIED;
			pt->regvalid = 1;
			Redrawcpureg();
			require_ollyloop = 1;
			return true;
		}
		return false;
	}
	else if(UnquoteString(ops[0], '[', ']'))
	{
		// Destination is memory address
		// Get Address from Operators (+_*...)
		nIgnoreNextValuesHist++;
		CreateOperands(ops[0], &ops[0], 1);

		if(GetDWOpValue(ops[0], addr))
		{ 
			if (addr==0)
			{
				DoLOG(L"\"WARNING: writing to address 0 !\"");
				return true;
			}

			tmpops=ops[1];
			if (maxsize > 8 && UnquoteString(ops[1], '[', ']'))
			{
				//Get Addr from Operators
				CreateOperands(ops[1], &ops[1], 1);

				//Optimized Mem Copy
				ulong src;
				if (!GetDWOpValue(ops[1], src) || src==0) {
					DoLOG(L"\"WARNING: copy from address 0 !\"");
					return true;
				}
				char* copybuffer= new char[maxsize];
				if (maxsize != Readmemory((void*) copybuffer, src, maxsize, MM_RESTORE)) {
					delete[] copybuffer;
					return false;
				}
				Writememory((void*) copybuffer, addr, maxsize, MM_DELANAL);
				delete[] copybuffer;
				Broadcast(WM_USER_CHGALL, 0, 0);
			}
			else if (GetDWOpValue(ops[1], dw) && maxsize <= 4)
			{
				if (maxsize==0) maxsize=4;
				dw = resizeDW(dw,maxsize);
				Writememory(&dw, addr, maxsize, MM_DELANAL|MM_SILENT);
				Broadcast(WM_USER_CHGALL, 0, 0);
			}
			else if (GetSTROpValue(ops[1], str, maxsize))
			{
				var v=str;
				if (maxsize==0) maxsize=v.size;
				maxsize=min(maxsize,v.size);
				Writememory((void*)v.strbuff().c_str(), addr, maxsize, MM_DELANAL|MM_SILENT);			
				Broadcast(WM_USER_CHGALL, 0, 0);
			}
			else if (GetFLTOpValue(ops[1], flt))
			{
				Writememory(&flt, addr, 8, MM_DELANAL|MM_SILENT);				
				Broadcast(WM_USER_CHGALL, 0, 0);
			}
			else
			{
				errorstr = L"Bad operator \"" + ops[1] + L"\"";
				return false;
			}
			Broadcast(WM_USER_CHGMEM, 0, 0);
			return true;
		}
		return false;

	} 
	else if (!bDeclared && ops[0][0] >= 'A' ) 
	{

		bDeclared=true;
		DoVAR(ops[0]);
		//DoLOG(L"\"automatic declaration of variable "+ops[0]+L"\"");
		goto retry_DoMOV;

	}

	//errorstr = L"Variable '" + ops[0] + L"' is not declared";
	return false;
}

bool OllyLang::DoMSG(wstring args)
{
	wstring ops[1];

	if(!CreateOp(args, ops, 1))
		return false;

	wstring msg;
	if(GetANYOpValue(ops[0], msg))
	{
		if (wndProg.hw!=NULL)
			InvalidateRect(wndProg.hw, NULL, FALSE);
		
		//_hwollymain or 0: modal or not
		HWND hw = _hwollymain;
		int ret = MessageBox(hw, msg.c_str(), L"MSG ODbgScript", MB_ICONINFORMATION | MB_OKCANCEL | MB_TOPMOST | MB_SETFOREGROUND);
		FocusProgWindow();
		if(ret == IDCANCEL) {
			return Pause();
		} 
		return true;
	}
	return false;
}

bool OllyLang::DoMSGYN(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	wstring msg;
	if(GetSTROpValue(ops[0], msg))
	{
		if (wndProg.hw!=NULL)
			InvalidateRect(wndProg.hw, NULL, FALSE);

		HWND hw = _hwollymain;
		int ret = MessageBox(hw, msg.c_str(), L"MSG " PLUGIN_NAME, MB_ICONQUESTION | MB_YESNOCANCEL | MB_TOPMOST | MB_SETFOREGROUND);
		FocusProgWindow();
		if(ret == IDCANCEL)
		{
			variables[V_RES] = 2;
			return Pause();
		}
		else if(ret == IDYES)
			variables[V_RES] = 1;
		else
			variables[V_RES] = 0;

		return true;
	}
	return false;
}

bool OllyLang::DoOLLY(wstring args)
{
    wstring ops[1], param;
	wchar_t buf[MAX_PATH];
	ulong value;
	wstring str;

	if(!CreateOp(args, ops, 1))
		return false;

	if ( GetSTROpValue(L"\"" +ops[0]+ L"\"", param) )
	{

		transform(param.begin(), param.end(), param.begin(), toupper);

		if (param == L"PID")
		{
			value = GetCurrentProcessId();
			variables[V_RES] = value; 
			return true;
		}
		else if (param == L"HWND")
		{
			value = (ulong) _hwollymain;
			variables[V_RES] = value;
			return true;
		}
		else if (param == L"THREADID")
		{
			value = GetCurrentThreadId();
			variables[V_RES] = value;
			return true;
		}
		else if (param == L"THREAD")
		{
			value = (ulong) GetCurrentThread();
			variables[V_RES] = value;
			return true;
		}
		else if (param == L"PATH")
		{
			buffer[0] = 0;
			GetModuleFileName(0,buffer,sizeof(buffer));
			str = buffer;
			variables[V_RES] = str;
			return true;
		}
		else if (param == L"EXE")
		{
			//buffer[0] = 0;
			//GetModuleFileName(0,buffer,sizeof(buffer));
			//_wsplitpath(buffer,NULL,NULL,buf,NULL);
			str = _ollyfile;
			variables[V_RES] = str + L".EXE";
			return true;
		}
		else if (param == L"INI")
		{
			buffer[0] = 0;
			GetModuleFileName(0,buffer,sizeof(buffer));
			_wsplitpath(buffer,NULL,NULL,buf,NULL);
			str = buf;
			variables[V_RES] = str + L".ini";
			return true;
		}
		else if (param == L"DIR")
		{
			//buffer[0] = 0;
			//GetModuleFileName(0,buffer,sizeof(buffer));
			//_wsplitpath(buffer,NULL,buf,NULL,NULL);
			str = _ollydir;
			variables[V_RES] = str;
			return true;
		}
		

	}
	return false;
}

bool OllyLang::DoMUL(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;
	if(GetDWOpValue(ops[0], dw1) && GetDWOpValue(ops[1], dw2))
	{
		args = ops[0] + L", 0" + _ultow(dw1 * dw2, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}

bool OllyLang::DoNAMES(wstring args)
{
	wstring ops[1];
	ulong addr;
	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetDWOpValue(ops[0], addr)) {
		t_module* mod = Findmodule(addr);
//2.	Setdisasm(mod->codebase,1,0);
		Setcpu(0,mod->codebase,0,0,0, CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
		Sendshortcut(PWM_DISASM, 0, WM_KEYDOWN, 1, 0, 'N');  //"Ctrl + N"
		require_ollyloop = 1;
		return true;
	}

	return false;
}

bool OllyLang::DoNEG(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	ulong dw1;
	if(GetDWOpValue(ops[0], dw1))
	{
		dw1 = (ulong)(0 - dw1);
		args = ops[0] + L", " +_ultow(dw1, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}


bool OllyLang::DoNOT(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	ulong dw1;
	if(GetDWOpValue(ops[0], dw1))
	{
		dw1 = ~dw1;
		args = ops[0] + L", " +_ultow(dw1, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}

bool OllyLang::DoOR(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;
	if(GetDWOpValue(ops[0], dw1) && GetDWOpValue(ops[1], dw2))
	{
		args = ops[0] + L", 0" + _ultow(dw1 | dw2, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}
/*
//see also GCI
bool OllyLang::DoOPCODE(wstring args)
{
	wstring ops[1];
	if(!CreateOperands(args, ops, 1))
		return false;

	ulong addr,size;
	if(GetDWOpValue(ops[0], addr))
	{
		BYTE buffer[MAXCMDSIZE];
//		size=Readmemory(buffer, addr, MAXCMDSIZE, MM_SILENT);
		size=Readcommand(addr,(char *) buffer);
		
		if (size>0) 
		{
			t_disasm disasm;
			size=Disasm(buffer,size,addr,NULL,&disasm,DISASM_CODE,NULL);

			if (size>0) 
			{
				variables[V_RES] = disasm.dump;     //command bytes
				variables[V_RES_1] = disasm.result; //asm command text
				variables[V_RES_2] = size;
				return true;
			}
		}
		variables[V_RES] = 0;
		variables[V_RES_1] = 0;
		variables[V_RES_2] = 0;
		return true;

	}
	return false;
}

bool OllyLang::DoOPENDUMP(wstring args)
{
	wstring ops[3];

	if(!CreateOperands(args, ops, 3))
	if(!CreateOperands(args, ops, 2))
	if(!CreateOperands(args, ops, 1))
		return false;

	ulong addr, base, size;
	if(!GetDWOpValue(ops[0], addr))
		return false;
	if(!GetDWOpValue(ops[1], base))
		return false;
	if(!GetDWOpValue(ops[2], size))
		return false;

	variables[V_RES] = 0;

	if (addr==0)
		return true; //do nothing

	t_memory* mem = Findmemory(addr);

	if (base==0) base=mem->base;
	if (size==0) size=mem->size;
	
	HWND wndDump = Createdumpwindow(NULL,base,size,addr,0x01081,NULL);

//dont work: need to ask Olleh to have a function 
//	t_dump * dump = (t_dump *) &wndDump;

	//So i created a special key message to grab it
	if (wndDump!=NULL) {
		ulong res = SendMessage(wndDump,WM_KEYDOWN,VK_F5,0);
		//can now grab (t_dump *) dumpWindows[wndDump];
		variables[V_RES] = (ulong) wndDump;		
	}
	return true;

	return false;
}

bool OllyLang::DoOPENTRACE(wstring args)
{
	ulong threadid = Getcputhreadid();
	if(threadid == 0)
		threadid = Plugingetvalue(VAL_MAINTHREADID);
	t_thread* pthr = Findthread(threadid);
	if(pthr != NULL)
		Startruntrace(&(pthr->reg)); 

	//Show Trace Window
	HWND wndTrace = Creatertracewindow();
	//SetWindowPos(wndTrace,HWND_TOP,0,0,0,0,SWP_NOSIZE+SWP_NOMOVE);

	return true;
}
*/
bool OllyLang::DoPAUSE(wstring args)
{
	Pause();
	FocusProgWindow();
	return true;
}

bool OllyLang::DoPOP(wstring args)
{
	wstring ops[1];

	nIgnoreNextValuesHist++;
	var_logging=false;
	if(!CreateOperands(args, ops, 1))
		return false;

	args = ops[0] + L", [esp], 4";
	nIgnoreNextValuesHist+=2;
	DoMOV(args);

	args = L"esp, esp+4";
	nIgnoreNextValuesHist+=1;
	return DoMOV(args);
}

bool OllyLang::DoPOPA(wstring args)
{
	bool result = RestoreRegisters(true);
	if (result)
		require_ollyloop=1;
	return result;
}
/*
bool OllyLang::DoPREOP(wstring args)
{
	wstring ops[1];

	CreateOperands(args, ops, 1);
	if (ops[0]=="")
		ops[0]="eip";

	ulong addr,base;
	if(!GetDWOpValue(ops[0], addr))
		return false;

	t_memory* mem = Findmemory(addr);
	if(mem != NULL)	
	{
		variables[V_RES] = Disassembleback(NULL,mem->base,mem->size,addr,1,true);
		return true;
	} 
	else 
	{
		variables[V_RES] = 0;
		return true;
	}
	return false;
}
*/
bool OllyLang::DoPUSH(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	ulong dw,dw1;

	//var_logging=false;
	if(GetDWOpValue(ops[0], dw1))
	{
		args = L"esp, esp-4";
		nIgnoreNextValuesHist+=2;
		DoMOV(args);

		args = L"[esp], " + ops[0];
		nIgnoreNextValuesHist++;
		DoMOV(args);

		t_thread* pt = Findthread(Getcputhreadid());	
     	dw1 = pt->reg.r[4];
		Readmemory(&dw, dw1, 4, MM_DELANAL|MM_SILENT);
		if (nIgnoreNextValuesHist==0)
			setProgLineValue(script_pos+1,dw);
		return true;
	}
	return false;
}

bool OllyLang::DoPUSHA(wstring args)
{
	return SaveRegisters(true);
}
/*
bool OllyLang::DoREADSTR(wstring args)
{
	wstring ops[2],s;
    ulong maxsize=0;

	ulong dw = 0, addr = 0;
	wstring str = "";
	if(CreateOperands(args, ops, 2)) 
	{
		GetDWOpValue(ops[1], maxsize);
        GetSTROpValue(ops[0], str, maxsize);

        variables[V_RES] = str;
		return true;
	}
    return false;
}

// Restore Break Points
// restores all hardware and software breakpoints
// (if arg1 == 'STRICT', all soft bp set by script will be deleted and only those have been set before it runs
// will be restored
// if no argument set, previous soft bp will be appended to those set by script)

// rbp [arg1]
// arg1 = may be STRICT or nothing

// return in:
// - $RESULT number of restored swbp
// - $RESULT_1 number of restored hwbp

// ex     : rbp
//        : rbp STRICT
bool OllyLang::DoRBP ( wstring args )
{
	t_table* bpt = 0;
	t_bpoint* bpoint = 0;
	uint n,i=0;
	wstring ops[1];

	CreateOperands ( args, ops, 1 );
	
	variables[V_RES] = 0;

	if ( saved_bp )
	{
		bpt = _bpoint;
		if ( bpt != NULL )
		{
			bpoint = ( t_bpoint * ) bpt->data.data;

			if ( ops[0] == L"STRICT" )
			{
				int dummy;
				dummy = bpt->data.n;
				for ( n = 0; n < dummy; n++ )
				{
					Deletebreakpoints ( bpoint->addr, ( bpoint->addr ) + 1, 1 );
					//Removemembreakpoint
				}
			}

			for ( n=0; n < sortedsoftbp_t.n; n++ ) {
				//Setbreakpoint ( softbp_t[n].addr, ( softbp_t[n].type | TY_KEEPCODE ) ^ TY_KEEPCODE, 0 );
				Membreakpoint(0, softbp_t[n].addr,0, 0,0, 0, BP_MANUAL);
			}

			variables[V_RES] = ( DWORD ) sortedsoftbp_t.n;

			Broadcast ( WM_USER_CHGALL, 0, 0 );
		}

	}

	//Hardware Bps
	for ( n=0; n < 4; n++ ) {
		if (hwbp_t[n].addr) {
			//Sethardwarebreakpoint ( hwbp_t[n].addr, hwbp_t[n].size, hwbp_t[n].type );
			Sethardbreakpoint(n, softbp_t[n].size, hwbp_t[n].type , hwbp_t[n].fnindex, 
				hwbp_t[n].addr, hwbp_t[n].limit, hwbp_t[n].count,
				NULL,NULL,NULL);
			i++;
		}
	}
	variables[V_RES_1] = ( DWORD ) i;

	return true;
}

bool OllyLang::DoREF(wstring args)
{
	wstring ops[2];
	if (!CreateOperands(args, ops, 2)){
		ops[1]="MEMORY"; 
		if(!CreateOperands(args, ops, 1))
		return false;
	}

	char title[256]="Reference to Command - ODbgScript REF";	
	ulong addr,size;
	wstring str;
	if(GetDWOpValue(ops[0], addr) && GetSTROpValue("\""+ops[1]+"\"", str) )
	{
		variables[V_RES] = 0;
		variables[V_RES_1] = 0; //command bytes
		variables[V_RES_2] = 0;

		if (adrREF!=addr) 
		{
			curREF=-1;

			//Reset REF
			if (addr == 0) {
				adrREF=0;
				return true;
			}

			//Info to get destination address
			BYTE buffer[MAXCMDSIZE];
//			size=Readmemory(buffer, addr, MAXCMDSIZE, MM_SILENT);
			size=Readcommand(addr,(char *) buffer);

			t_disasm disasm;
			size=Disasm(buffer, size, addr, NULL, &disasm, DISASM_SIZE, NULL);
			if (size==0)
				return true;

			transform(str.begin(), str.end(), str.begin(), toupper);

			//Search for references
			if(str == L"MEMORY") // Compatibility (before v1.71) Search in the memory bloc
			{
				t_memory* mem = Findmemory(addr);

				if (Findreferences(mem->base,mem->size,addr,addr+size,addr,16,title) > 0)
					adrREF=addr;
				else
					return true;
			}
			else if(str == L"CODE") // Search in the code part of module
			{
				t_module* mod = Findmodule(addr);

				if (Findreferences(mod->codebase,mod->codesize,addr,addr+size,addr,16,title) > 0)
					adrREF=addr;
				else
					return true;
			}
			else if(str == L"MODULE") // Search in the whole module
			{
				t_module* mod = Findmodule(addr);

				if (Findreferences(mod->base,mod->size,addr,addr+size,addr,16,title) > 0)
					adrREF=addr;
				else
					return true;
			}
			else
				return false;

		}
		t_table* tref=(t_table*) Plugingetvalue(VAL_REFERENCES);
		
		if (tref != NULL) 
		{
			ignore_origin:
			curREF++;
			if (curREF > tref->data.n)
				adrREF=0;
			else 
			{
				t_ref* ref= (t_ref*) Getsortedbyselection(&tref->data,curREF);
				if (ref != NULL) 
				{

					if (ref->addr == addr)
						goto ignore_origin;

					//Disasm origin to get comments
					BYTE buffer[MAXCMDSIZE];
					size=Readmemory(buffer, ref->addr, MAXCMDSIZE, MM_SILENT);					
					if (size>0) 
					{
						t_disasm disasm;
						size=Disasm(buffer,size,ref->addr,NULL,&disasm,DISASM_ALL,NULL);

						if (size>0) 
						{
							variables[V_RES] = ref->addr;
							variables[V_RES_1] = disasm.result; //command text
							variables[V_RES_2] = disasm.comment;
							return true;
						}
					}
				}
			}			
		}
		return true;

	}
	return false;
}
*/

bool OllyLang::DoREFRESH(wstring args)
{
	//Refresh Memory Map
	Listmemory();

	//Refresh Executable Modules (no other way found to do this)
/*	if (_module.hw!=0) {
		//was visible
		Sendshortcut(PM_MAIN,0,WM_SYSKEYDOWN,0,0,'E');
	} else {
		//was hidden, hide it after
		Sendshortcut(PM_MAIN,0,WM_SYSKEYDOWN,0,0,'E');
		if (_module.hw!=0)
			DestroyWindow(_module.hw);
	}
*/
	//Refresh DISASM
	Redrawcpudisasm();
	Redrawcpureg();
	Redrawlist();

	require_ollyloop=1;
	return true;
}

/*
bool OllyLang::DoREPL(wstring args)
{
	wstring ops[4];
	if(!CreateOperands(args, ops, 4))
		return false;

	if(ops[1].length() % 2 != 0 || ops[2].length() % 2 != 0)
	{
		errorstr = L"Hex wstring must have an even number of characters!";
		return false;
	}

	ulong addr, len;
	if(GetDWOpValue(ops[0], addr) && UnquoteString(ops[1], '#', '#') && UnquoteString(ops[2], '#', '#') && GetDWOpValue(ops[3], len))
	{
		// Replace
		char *membuf = 0;
		t_memory* tmem = Findmemory(addr);
		membuf = new char[len];
		int memlen = Readmemory(membuf, addr, len, MM_RESILENT);
		bool replaced = false;

		try
		{
			int i = 0;
			while(i < len)
			{
				replaced = Replace(membuf + i, ops[1].c_str(), ops[2].c_str(), ops[2].length()) || replaced;
				i++;
			}
		}
		catch(char* str)
		{
			errorstr = errorstr.append(str);
			delete [] membuf;
			return false;
		}
		
		if(replaced)
		{
			Writememory(membuf, addr, len, MM_DELANAL | MM_SILENT);
			Broadcast(WM_USER_CHGALL, 0, 0);
		}

		delete [] membuf;

		return true;
	}

	return false;
}

bool OllyLang::DoRESET(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F2); 
	return true;
}

bool OllyLang::DoRET(wstring args)
{
	if (calls.size() > 0) {
		script_pos = calls[calls.size()-1];
		calls.pop_back(); 
	} else {
		MessageBox(0, "Script finished", "ODbgScript", MB_ICONINFORMATION | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);
		Reset();
		FocusProgWindow();
	}
	return true;
}

bool OllyLang::DoREV(wstring args)
{
	wstring ops[1];
	ulong dw;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(!GetDWOpValue(ops[0], dw))
		return false;

	dw=rev(dw);

	variables[V_RES] = dw;
	return true;
}

bool OllyLang::DoROL(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1;
	BYTE dw2;
	if(GetDWOpValue(ops[0], dw1) && GetBYTEOpValue(ops[1], dw2))
	{
		DWORD shift = dw2 & 31;
		if (shift != 0)
			dw1 = (dw1 << shift) | (dw1 >> (32 - shift));
		args = ops[0] + ", 0" + _ultow(dw1, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}

bool OllyLang::DoROR(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1;
	BYTE dw2;
	if(GetDWOpValue(ops[0], dw1) 
		&& GetBYTEOpValue(ops[1], dw2))
	{
		DWORD shift = dw2 & 31;
		if (shift != 0)
			dw1 = (dw1 >> shift) | (dw1 << (32 - shift));
		args = ops[0] + ", 0" + _ultow(dw1, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}


bool OllyLang::DoRTR(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F9); 
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoRTU(wstring args)
{
	Sendshortcut(PM_MAIN,0,WM_SYSKEYDOWN,0,0,VK_F9);
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoRUN(wstring args)
{
	Go(Getcputhreadid(), 0, STEP_RUN, 0, 1);
	require_ollyloop = 1;
	return true;
}

// Store Break Points
// stores all hardware and software breakpoints

// return in:
// - $RESULT number of restored swbp
// - $RESULT_1 number of restored hwbp

// ex 	: sbp
// 		: no argument
bool OllyLang::DoSBP ( wstring args )
{
	uint n = 0, i;
	bool success;
	t_table *bpt;
	t_bpoint *bpoint;

	variables[V_RES] = 0;
	variables[V_RES_1] = 0;

	bpt = _bpoint;
	if ( bpt != NULL )
	{
		bpoint = ( t_bpoint * ) ( bpt->data.data );
		if ( bpoint != NULL )
		{
			n = bpt->data.n;

			if ( n > alloc_bp )
			{
				//FreeBpMem();
				success = AllocSwbpMem ( n );
			}

			if ( n > alloc_bp && !success ) {
				errorstr = L"Can't allocate enough memory to copy all breakpoints";
				return false;
			}
			else if (n > 0)
			{
				memcpy ( ( void* ) softbp_t, bpt->data.data, n*sizeof ( t_bpoint ) );
				memcpy ( ( void* ) &sortedsoftbp_t, ( void* ) &bpt->data, sizeof ( t_sorted ) );
				
			} 

			saved_bp = n;
			variables[V_RES] =  ( DWORD ) n;
		}
	}

	memcpy ( ( void* ) &hwbp_t, ( void* ) ( Plugingetvalue ( VAL_HINST ) +0xD8D70 ), 4 * sizeof ( t_hardbpoint ) );

	n = i = 0;
	while ( n < 4 )
	{
		if ( hwbp_t[n].addr )
			i++;
		n++;
	}
	variables[V_RES_1] =  ( DWORD ) i;

	return true;
}

bool OllyLang::DoSCMP(wstring args)
{
	wstring ops[3];
	ulong size=0;
	wstring s1, s2;

	if(!CreateOperands(args, ops, 3)) {
		if(!CreateOperands(args, ops, 2))
			return false;
	} else {
		GetDWOpValue(ops[2], size);
	}

	if(GetSTROpValue(ops[0], s1, size) 
		&& GetSTROpValue(ops[1], s2, size))
	{
		int res = s1.compare(s2);
		if(res == 0)	
		{
			zf = 1;
			cf = 0;
		}
		else if(res > 0)
		{
			zf = 0;
			cf = 0;
		}
		else //if(res < 0)
		{
			zf = 0;
			cf = 1;
		}
		return true;
	}
	return false;
}

bool OllyLang::DoSCMPI(wstring args)
{
	wstring ops[3];
	ulong size=0;
	wstring s1, s2;

	if(!CreateOperands(args, ops, 3)) {
		if(!CreateOperands(args, ops, 2))
			return false;
	} else {
		GetDWOpValue(ops[2], size);
	}

	if(GetSTROpValue(ops[0], s1, size) 
		&& GetSTROpValue(ops[1], s2, size) )
	{
		int res = _wcsicmp (s1.c_str(), s2.c_str());//s1.compare(s2,false);
		if(res == 0)		
		{
			zf = 1;
			cf = 0;
		}
		else if(res > 0)
		{
			zf = 0;
			cf = 0;
		}
		else //if(res < 0)
		{
			zf = 0;
			cf = 1;
		}
		return true;
	}
	return false;
}

bool OllyLang::DoSETOPTION(wstring args)
{
    Sendshortcut(PM_MAIN,0,WM_SYSKEYDOWN,0,0,'O');
	require_ollyloop = 1;
    return true;
}

bool OllyLang::DoSHL(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;
	if(GetDWOpValue(ops[0], dw1) 
		&& GetDWOpValue(ops[1], dw2))
	{
		args = ops[0] + ", 0" + _ultow(dw1 << dw2, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}

bool OllyLang::DoSHR(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;
	if(GetDWOpValue(ops[0], dw1) 
		&& GetDWOpValue(ops[1], dw2))
	{
		args = ops[0] + ", 0" + _ultow(dw1 >> dw2, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}
*/
bool OllyLang::DoSTI(wstring args)
{
	//Go(Getcputhreadid(), 0, STEP_IN, 0, 1);
	Run(STAT_STEPIN,1);
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoSTO(wstring args)
{
	//Go(Getcputhreadid(), 0, STEP_OVER, 0, 1);
	Run(STAT_STEPOVER,1);
	require_ollyloop = 1;
	return true;
}
/*
bool OllyLang::DoSTR(wstring args)
{
	wstring op[1];

	if(!CreateOp(args, op, 1))
		return false;

	if (is_variable(op[0])) {
		if (variables[op[0]].vt == STR) {

			if (variables[op[0]].isbuf)
				variables[op[0]] = variables[op[0]].strbuff();

			return true;

		} else if (variables[op[0]].vt == DW) {

			var v; v="##";
			v+=variables[op[0]].dw;
			variables[op[0]]=v.strbuff();

			return true;
		}
	}
	return false;
}

bool OllyLang::DoSUB(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;
	if(GetDWOpValue(ops[0], dw1) 
		&& GetDWOpValue(ops[1], dw2))
	{
		args = ops[0] + ", 0" + _ultow(dw1 - dw2, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}

bool OllyLang::DoTC(wstring args)
{
	Deleteruntrace();
	return true;
}


bool OllyLang::DoTEST(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;

	if(GetDWOpValue(ops[0], dw1) && GetDWOpValue(ops[1], dw2))
	{
		zf = 0;

		if (!(dw1 & dw2)) {
			zf = 1;
		}
		setProgLineValue(script_pos+1,zf);
	}
	return true;

}


bool OllyLang::DoTI(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F11); 
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoTICK(wstring args)
{
	wstring ops[2];
	if(!CreateOperands(args, ops, 2))
		if(args=="" || !CreateOperands(args, ops, 1)) {
			char tmpbuf[256]={0};
			sprintf(tmpbuf,"%u ms",this->tickcount/1000);
			wstring s; s.assign(tmpbuf);
			variables[V_RES]=s;
			return true;
		}

	if (!is_variable(ops[0])) {
		DoVAR(ops[0]);
	}

	ulong timeref;
	GetDWOpValue(ops[1], timeref);

	if (is_variable(ops[0])) {
		variables[ops[0]] = tickcount;
		if (timeref)
			variables[V_RES]=tickcount-timeref;
		return true;
	}
	return false;
}

bool OllyLang::DoTICND(wstring args)
{
	wstring ops[1];
	wstring condition;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetSTROpValue(ops[0], condition))
	{
		char* buffer = new char[condition.length() + 1];
		strcpy(buffer, condition.c_str());
		if(Runtracesize() == 0) 
		{
			ulong threadid = Getcputhreadid();
			if(threadid == 0)
				threadid = Plugingetvalue(VAL_MAINTHREADID);
			t_thread* pthr = Findthread(threadid);
			if(pthr != NULL)
				Startruntrace(&(pthr->reg)); 
		}
		Settracecondition(buffer, 0, 0, 0, 0, 0);
		Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F11); 
		require_ollyloop = 1;
		return true;
	}
	return false;
}

bool OllyLang::DoTO(wstring args)
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F12); 
	require_ollyloop = 1;
	return true;
}

bool OllyLang::DoTOCND(wstring args)
{
	wstring ops[1];
	wstring condition;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetSTROpValue(ops[0], condition))
	{
		char* buffer = new char[condition.length() + 1];
		strcpy(buffer, condition.c_str());
		if(Runtracesize() == 0) 
		{
			ulong threadid = Getcputhreadid();
			if(threadid == 0)
				threadid = Plugingetvalue(VAL_MAINTHREADID);
			t_thread* pthr = Findthread(threadid);
			if(pthr != NULL)
				Startruntrace(&(pthr->reg)); 
		}
		Settracecondition(buffer, 0, 0, 0, 0, 0);
		Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F12); 
		require_ollyloop = 1;
		return true;
	}
	return false;
}

bool OllyLang::DoUNICODE(wstring args)
{
	wstring ops[1];
	ulong dw;

	if(!CreateOperands(args, ops, 1))
		return false;

	if(GetDWOpValue(ops[0], dw)) {
		bUnicode=(dw!=0);
		return true;
	}

	return false;
}
*/
bool OllyLang::DoVAR(wstring args)
{
	wstring ops[1];

	if(!CreateOperands(args, ops, 1))
		return false;

	if(reg_names.find(ops[0]) == reg_names.end()){
		variables.insert(pair<wstring, var> (ops[0], 0));
		return true;
	}
	errorstr = L"Bad variable name: " + ops[0];
	return false;
}

bool OllyLang::DoXCHG(wstring args)
{
	wstring ops[2];

	if (!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;

	if (GetDWOpValue(ops[0], dw1) && GetDWOpValue(ops[1], dw2)) {
		args = ops[0] + L", 0" + _ultow(dw2, buffer, 16);
		nIgnoreNextValuesHist++;
		DoMOV(args);
		args = ops[1] + L", 0" + _ultow(dw1, buffer, 16);
		nIgnoreNextValuesHist++;
		DoMOV(args);
		return true;
	}
	return false;

}

bool OllyLang::DoXOR(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

	ulong dw1, dw2;
	if(GetDWOpValue(ops[0], dw1) 
		&& GetDWOpValue(ops[1], dw2))
	{
		args = ops[0] + L", 0" + _ultow(dw1 ^ dw2, buffer, 16);
		nIgnoreNextValuesHist++;
		return DoMOV(args);
	}
	return false;
}

bool OllyLang::DoWRT(wstring args)
{
	wstring ops[2];

	if(!CreateOperands(args, ops, 2))
		return false;

    wstring path;
	path.assign(_executable);

    path = path.substr(0, path.rfind('\\') + 1);
 
	wstring filename,data;

	if(GetSTROpValue(ops[0], filename) 
		&& GetANYOpValue(ops[1], data))
	{
        if ((filename.find(L":\\") != wstring::npos) || (filename.find(L"\\\\") != wstring::npos)) //hard disk or network
		  path = filename;
		else
		  path += filename;
		
		HANDLE hFile;
		ulong dwAccBytes=0;

		hFile = CreateFile(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hFile != INVALID_HANDLE_VALUE) 
		{
			//SetFilePointer(hFile, 0, 0, FILE_BEGIN);
//			if (bUnicode) {
//				if (data.length()>1 && data[1]!=0)
//					data=Str2Unicode(data);
//				WriteFile(hFile, data.c_str(), data.length(), &dwAccBytes, NULL);
//			} else
				WriteFile(hFile, data.c_str(), data.length(), &dwAccBytes, NULL);
			CloseHandle(hFile);
		}
		return dwAccBytes;
	}
	return false;
}

bool OllyLang::DoWRTA(wstring args)
{
	wstring ops[3];

	if(!CreateOperands(args, ops, 3)) {
		ops[2]=L"\"\r\n\"";
		if(!CreateOperands(args, ops, 2))
			return false;
	}
	
    wstring path;
	path.assign(_executable);

    path = path.substr(0, path.rfind('\\') + 1);

	wstring filename,data,sSep;

	if(GetSTROpValue(ops[0], filename) 
		&& GetANYOpValue(ops[1], data))
	{
        if ((filename.find(L":\\") != wstring::npos) || (filename.find(L"\\\\") != wstring::npos))
		  path = filename;
		else
		  path += filename;
		
		HANDLE hFile;
		ulong dwAccBytes=0;

		if (!GetSTROpValue(ops[2],sSep))
			return false;	

		data=sSep+data;	

		hFile = CreateFile(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hFile != INVALID_HANDLE_VALUE) 
		{
			SetFilePointer(hFile, 0, 0, FILE_END);
//			if (bUnicode) {
//				if (data.length()>1 && data[1]!=0)
//					data=Str2Unicode(data);
//				WriteFile(hFile, data.c_str(), data.length(), &dwAccBytes, NULL);
//			} else
				WriteFile(hFile, data.c_str(), data.length(), &dwAccBytes, NULL);

			CloseHandle(hFile);
		}
		return dwAccBytes;
	}
	return false;
}
