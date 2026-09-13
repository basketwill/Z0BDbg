// OllyLang.cpp : Defines the entry point for the console application.
//
#include "StdAfx.h"

using namespace std;

OllyLang::OllyLang()
{
	memset(&wndProg,0,sizeof(wndProg));
	memset(&wndLog,0,sizeof(wndLog));
	StrcopyW(wndLog.name,SHORTNAME,PLUGIN_NAME);
	wndLog.mode=TABLE_SAVEALL;

	script_state = SS_NONE;

	// Init array with register names
	reg_names.clear();
	reg_names.insert(L"eax");
	reg_names.insert(L"ebx");
	reg_names.insert(L"ecx");
	reg_names.insert(L"edx");
	reg_names.insert(L"esi");
	reg_names.insert(L"edi");
	reg_names.insert(L"esp");
	reg_names.insert(L"ebp");
	reg_names.insert(L"eip");
//  new reg

	reg_names.insert(L"ax");
	reg_names.insert(L"bx");
	reg_names.insert(L"cx");
	reg_names.insert(L"dx");
	reg_names.insert(L"bp");
	reg_names.insert(L"si");
	reg_names.insert(L"di");

	reg_names.insert(L"al");
	reg_names.insert(L"ah");
	reg_names.insert(L"bl");
	reg_names.insert(L"bh");
	reg_names.insert(L"cl");
	reg_names.insert(L"ch");
	reg_names.insert(L"dl");
	reg_names.insert(L"dh");

	// Segments
	seg_names.clear();
	seg_names.insert(L"es");
	seg_names.insert(L"cs");
	seg_names.insert(L"ss");
	seg_names.insert(L"ds");
	seg_names.insert(L"fs");
	seg_names.insert(L"gs");

	// Init array of flag names
	flag_names.clear();
	flag_names.insert(L"!CF");
	flag_names.insert(L"!PF");
	flag_names.insert(L"!AF");
	flag_names.insert(L"!ZF");
	flag_names.insert(L"!SF");
	flag_names.insert(L"!DF");
	flag_names.insert(L"!OF");

	// Init command array
	commands[L"add"] = &OllyLang::DoADD;					//ok v2
	commands[L"ai"] = &OllyLang::DoAI;
	commands[L"alloc"] = &OllyLang::DoALLOC;
	commands[L"ana"] = &OllyLang::DoANA;
	 commands[L"an"] = &OllyLang::DoANA;					//todo K_ANALYSE
	commands[L"and"] = &OllyLang::DoAND;
	commands[L"ao"] = &OllyLang::DoAO;
	commands[L"ask"] = &OllyLang::DoASK;					//ok v2
	commands[L"asm"] = &OllyLang::DoASM;	
	commands[L"asmtxt"] = &OllyLang::DoASMTXT;	
	commands[L"atoi"] = &OllyLang::DoATOI;
//	commands[L"backup"] = &OllyLang::DoBACKUP;
	commands[L"bc"] = &OllyLang::DoBC;						//ok v2
	commands[L"bd"] = &OllyLang::DoBD;						//ok v2
	commands[L"beginsearch"] = &OllyLang::DoBEGINSEARCH;
	commands[L"bp"] = &OllyLang::DoBP;						//ok v2
//	commands[L"bpcnd"] = &OllyLang::DoBPCND;
//	commands[L"bpd"] = &OllyLang::DoBPD;
//	commands[L"bpgoto"] = &OllyLang::DoBPGOTO;
//	 commands[L"bphwcall"] = &OllyLang::DoBPHWCA;
//	commands[L"bphwc"] = &OllyLang::DoBPHWC;
//	commands[L"bphws"] = &OllyLang::DoBPHWS;
//	commands[L"bpl"] = &OllyLang::DoBPL;
//	commands[L"bplcnd"] = &OllyLang::DoBPLCND;
//	commands[L"bpmc"] = &OllyLang::DoBPMC;
//	commands[L"bprm"] = &OllyLang::DoBPRM;
//	commands[L"bpwm"] = &OllyLang::DoBPWM;
//	commands[L"bpx"] = &OllyLang::DoBPX;
//	commands[L"buf"] = &OllyLang::DoBUF;
//	commands[L"call"] = &OllyLang::DoCALL;
//	commands[L"close"] = &OllyLang::DoCLOSE;
//	commands[L"cmp"] = &OllyLang::DoCMP;
//	commands[L"cmt"] = &OllyLang::DoCMT;
//	commands[L"cob"] = &OllyLang::DoCOB;
//	commands[L"coe"] = &OllyLang::DoCOE;
//	commands[L"cret"] = &OllyLang::DoCRET;
//	commands[L"dbh"] = &OllyLang::DoDBH;
//	commands[L"dbs"] = &OllyLang::DoDBS;
//	commands[L"dec"] = &OllyLang::DoDEC;
//	commands[L"div"] = &OllyLang::DoDIV;
//	commands[L"dm"] = &OllyLang::DoDM;
//	commands[L"dma"] = &OllyLang::DoDMA;
//	commands[L"dpe"] = &OllyLang::DoDPE;
//	commands[L"else"] = &OllyLang::DoELSE;
//	commands[L"ende"] = &OllyLang::DoENDE;
//	commands[L"endif"] = &OllyLang::DoENDIF;
//	commands[L"endsearch"] = &OllyLang::DoENDSEARCH;
	commands[L"erun"] = &OllyLang::DoERUN;
	commands[L"esti"] = &OllyLang::DoESTI;
	 commands[L"esto"] = &OllyLang::DoERUN;
	commands[L"estep"] = &OllyLang::DoESTEP;
//	commands[L"eob"] = &OllyLang::DoEOB;
//	commands[L"eoe"] = &OllyLang::DoEOE;
//	commands[L"eval"] = &OllyLang::DoEVAL;
//	commands[L"exec"] = &OllyLang::DoEXEC;
//	commands[L"fill"] = &OllyLang::DoFILL;
//	commands[L"find"] = &OllyLang::DoFIND;
//	commands[L"findcalls"] = &OllyLang::DoFINDCALLS;
//	commands[L"findcmd"] = &OllyLang::DoFINDCMD;
//	 commands[L"findcmds"] = &OllyLang::DoFINDCMD;
//	commands[L"findop"] = &OllyLang::DoFINDOP;
//	commands[L"findoprev"] = &OllyLang::DoFINDOPREV;	
//	commands[L"findmem"] = &OllyLang::DoFINDMEM;
//	commands[L"free"] = &OllyLang::DoFREE;
//	commands[L"gapi"] = &OllyLang::DoGAPI;
//	commands[L"gbpm"] = &OllyLang::DoGBPM;
//	commands[L"gbpr"] = &OllyLang::DoGBPR;
//	commands[L"gci"] = &OllyLang::DoGCI;
//	commands[L"gcmt"] = &OllyLang::DoGCMT;
//	commands[L"gfo"] = &OllyLang::DoGFO;
//	commands[L"glbl"] = &OllyLang::DoGLBL;
//	commands[L"gmemi"] = &OllyLang::DoGMEMI;
//	commands[L"gmexp"] = &OllyLang::DoGMEXP;
//	commands[L"gma"] = &OllyLang::DoGMA;
//	commands[L"gmi"] = &OllyLang::DoGMI;
//	commands[L"gmimp"] = &OllyLang::DoGMIMP;
//	commands[L"gn"] = &OllyLang::DoGN;
//	commands[L"go"] = &OllyLang::DoGO;
//	commands[L"gopi"] = &OllyLang::DoGOPI;	
//	commands[L"gpa"] = &OllyLang::DoGPA;
//	commands[L"gpi"] = &OllyLang::DoGPI;
//	commands[L"gpp"] = &OllyLang::DoGPP;
//	commands[L"gro"] = &OllyLang::DoGRO;
//	commands[L"gref"] = &OllyLang::DoGREF;
//	commands[L"gsl"] = &OllyLang::DoGSL;
//	commands[L"gstr"] = &OllyLang::DoGSTR;
//	commands[L"gstrw"] = &OllyLang::DoGSTRW;
//	commands[L"handle"] = &OllyLang::DoHANDLE;
//	commands[L"history"] = &OllyLang::DoHISTORY;
//	commands[L"ifeq"] = &OllyLang::DoIFEQ;
//	 commands[L"ife"] = &OllyLang::DoIFEQ;
//	commands[L"ifneq"] = &OllyLang::DoIFNEQ;
//	 commands[L"ifne"] = &OllyLang::DoIFNEQ;
//	commands[L"ifa"] = &OllyLang::DoIFA;
//	commands[L"ifae"] = &OllyLang::DoIFAE;
//	commands[L"ifb"] = &OllyLang::DoIFB;
//	commands[L"ifbe"] = &OllyLang::DoIFBE;
//	 commands[L"ifg"] = &OllyLang::DoIFA;
//	 commands[L"ifge"] = &OllyLang::DoIFAE;
//	 commands[L"ifl"] = &OllyLang::DoIFB;
//	 commands[L"ifle"] = &OllyLang::DoIFBE;
//	commands[L"inc"] = &OllyLang::DoINC;
	commands[L"inir"] = &OllyLang::DoINIR;
	commands[L"iniw"] = &OllyLang::DoINIW;
//	commands[L"_itow"] = &OllyLang::DoITOA;
//	commands[L"ja"] = &OllyLang::DoJA;
//	commands[L"jae"] = &OllyLang::DoJAE;
//	commands[L"jb"] = &OllyLang::DoJB;
//	commands[L"jbe"] = &OllyLang::DoJBE;
//	commands[L"je"] = &OllyLang::DoJE;
//	 commands[L"jg"] = &OllyLang::DoJA;
//	 commands[L"jge"] = &OllyLang::DoJAE;
//	 commands[L"jl"] = &OllyLang::DoJB;
//	 commands[L"jle"] = &OllyLang::DoJBE;
//	commands[L"jmp"] = &OllyLang::DoJMP;
//	 commands[L"goto"] = &OllyLang::DoJMP;
//	commands[L"jne"] = &OllyLang::DoJNE;
//	 commands[L"jnz"] = &OllyLang::DoJNE;
//	 commands[L"jz"] = &OllyLang::DoJE;
//	commands[L"key"] = &OllyLang::DoKEY;
//	commands[L"lbl"] = &OllyLang::DoLBL;
//	commands[L"lc"] = &OllyLang::DoLC;
//	commands[L"lclr"] = &OllyLang::DoLCLR;
//	commands[L"len"] = &OllyLang::DoLEN;
//	commands[L"loadlib"] = &OllyLang::DoLOADLIB;
//	commands[L"lm"] = &OllyLang::DoLM;
	commands[L"log"] = &OllyLang::DoLOG;					//ok v2
	commands[L"logbuf"] = &OllyLang::DoLOGBUF;
	commands[L"memcpy"] = &OllyLang::DoMEMCOPY;
	commands[L"mov"] = &OllyLang::DoMOV;					//ok v2
	commands[L"msg"] = &OllyLang::DoMSG;					//ok v2
	commands[L"msgyn"] = &OllyLang::DoMSGYN;
	commands[L"mul"] = &OllyLang::DoMUL;
	commands[L"names"] = &OllyLang::DoNAMES;	
	commands[L"neg"] = &OllyLang::DoNEG;
	commands[L"not"] = &OllyLang::DoNOT;
	commands[L"or"] = &OllyLang::DoOR;
	commands[L"olly"] = &OllyLang::DoOLLY;
//	commands[L"opcode"] = &OllyLang::DoOPCODE;
//	commands[L"opendump"] = &OllyLang::DoOPENDUMP;
//	commands[L"opentrace"] = &OllyLang::DoOPENTRACE;
	commands[L"pause"] = &OllyLang::DoPAUSE;
//	commands[L"pop"] = &OllyLang::DoPOP;
	commands[L"popa"] = &OllyLang::DoPOPA;					//ok v2
//	commands[L"preop"] = &OllyLang::DoPREOP;
//	commands[L"push"] = &OllyLang::DoPUSH;
	commands[L"pusha"] = &OllyLang::DoPUSHA;				//ok v2
//	commands[L"rbp"] = &OllyLang::DoRBP;
//	commands[L"readstr"] = &OllyLang::DoREADSTR;
	commands[L"refresh"] = &OllyLang::DoREFRESH;
//	commands[L"ref"] = &OllyLang::DoREF;
//	commands[L"repl"] = &OllyLang::DoREPL;
//	commands[L"reset"] = &OllyLang::DoRESET;
//	commands[L"ret"] = &OllyLang::DoRET;
//	commands[L"rev"] = &OllyLang::DoREV;
//	commands[L"rol"] = &OllyLang::DoROL;
//	commands[L"ror"] = &OllyLang::DoROR;
//	commands[L"rtr"] = &OllyLang::DoRTR;
//	commands[L"rtu"] = &OllyLang::DoRTU;
//	commands[L"run"] = &OllyLang::DoRUN;
//	commands[L"sbp"] = &OllyLang::DoSBP;
//	commands[L"scmp"] = &OllyLang::DoSCMP;
//	commands[L"scmpi"] = &OllyLang::DoSCMPI;
//	commands[L"setoption"] = &OllyLang::DoSETOPTION;
//	commands[L"shl"] = &OllyLang::DoSHL;
//	commands[L"shr"] = &OllyLang::DoSHR;
	 commands[L"step"] = &OllyLang::DoSTO;
	commands[L"sti"] = &OllyLang::DoSTI;
	commands[L"sto"] = &OllyLang::DoSTO;
//	commands[L"str"] = &OllyLang::DoSTR;
//	commands[L"sub"] = &OllyLang::DoSUB;
//	commands[L"tc"] = &OllyLang::DoTC;
//	commands[L"test"] = &OllyLang::DoTEST;
//	commands[L"ti"] = &OllyLang::DoTI;
//	commands[L"tick"] = &OllyLang::DoTICK;
//	commands[L"ticnd"] = &OllyLang::DoTICND;
//	commands[L"to"] = &OllyLang::DoTO;
//	commands[L"tocnd"] = &OllyLang::DoTOCND;
//	 commands[L"ubp"] = &OllyLang::DoBP;
//	commands[L"unicode"] = &OllyLang::DoUNICODE;
	commands[L"var"] = &OllyLang::DoVAR;					//ok v2
	commands[L"xor"] = &OllyLang::DoXOR;					//ok v2
	commands[L"xchg"] = &OllyLang::DoXCHG;
	commands[L"wrt"] = &OllyLang::DoWRT;
	commands[L"wrta"] = &OllyLang::DoWRTA;

	script_state = SS_INITIALIZED;
	script_pos = 0;
	EOB_row = -1;
	EOE_row = -1;
	zf = 0;
	cf = 0;
	enable_logging = true;
	var_logging = true;

	search_buffer=NULL;

	hwmain = _hwollymain;
	hwndinput = 0;

	require_ollyloop = 0;
	require_addonaction = 0;
	nIgnoreNextValuesHist = 0;

	showVarHistory=true;
	bUnicode=false;

	saved_bp = 0;
	alloc_bp = 0;
	softbp_t = NULL;

	for (int n=0; n < 4; n++ ) hwbp_t[n].addr = 0;

}

OllyLang::~OllyLang()
{
	if (search_buffer!=NULL)
		DoENDSEARCH(L"");

	FreeBpMem();
	labels.clear();
	script.clear();
	clearProgLines();
	clearLogLines();
	Reset();

}

bool OllyLang::Reset()
{
	freeMemBlocks();
	variables.clear();
	bpjumps.clear();
	calls.clear();
	conditions.clear();
	wchar_t s[10] = {0};
	wsprintf(s,L"%i.%i", VERSIONHI, VERSIONLO);
	wstring str(s);
	variables[L"$VERSION"] = str;
	EOB_row = -1;
	EOE_row = -1;
	script_state = SS_LOADED;
	enable_logging = false;
	script_pos = GetFirstCodeLine(0);
	pgr_scriptpos = script_pos+1; 
	resetProgLines();
	tickcount_startup=0;
	tickcount=0;
	tickcounthi=0;
	break_memaddr=0;
	break_reason=0;
	require_ollyloop = 0;
	require_addonaction = 0;
	nIgnoreNextValuesHist = 0;

	tExportsCache.clear();
	exportsCacheAddr = 0;
	tImportsCache.clear();
	importsCacheAddr = 0;

	dumpWindows.clear();
	execHistory.clear();
	execCursor=0;

	if (wndProg.hw!=NULL)
		Selectandscroll(&wndProg,pgr_scriptpos,2);
	return true;
}

vector<wstring> OllyLang::GetScriptFromFile(wstring file)
{
	currentdir = file;
	currentdir = currentdir.substr(0, currentdir.rfind('\\') + 1);
	
	vector<wstring> script;
	wstring scriptline;

	wifstream fin(w_wstrto(file).c_str(), ios::in);

	while(getline(fin, scriptline))
		script.push_back(scriptline);

	fin.close();

	return script;
}

int OllyLang::InsertScript(vector<wstring> toInsert, int posInScript)
{
	vector<wstring>::iterator iter = toInsert.begin();

	wstring scriptline, cleanline;
	int inc_pos = -1, linesAdded = 0;
	int p;
	bool comment_todisplay, in_asm=false, in_comment=false;
	int in_cond = 0;

	while(iter != toInsert.end())
	{
		comment_todisplay=0;
		scriptline = w_trim(*iter);
		// Handle comments
		if(scriptline == L"/*")
		{
			in_comment = true;
			comment_todisplay=1;
			//iter++;
			//continue;
		}
		else if(scriptline == L"*/")
		{
			in_comment = false;
			comment_todisplay=1;
			//iter++;
			//continue;
		}
		else if (scriptline.find(L"/*")==0 && scriptline.find(L"*/")==wstring::npos) {
			in_comment = true;
			comment_todisplay=1;
		}
		else if (scriptline.find(L"*/")==(scriptline.length()-2) ) {
			in_comment = false;
			comment_todisplay=1;
		}
		else if (scriptline.find(L"/*")!=wstring::npos && scriptline.find(L"*/")==wstring::npos) 
		{
			p=scriptline.find(L"/*");
			scriptline.erase(p,scriptline.length()-p);
			in_comment = true;
		}
		else if (scriptline.find(L"*/")!=wstring::npos && scriptline.find(L"/*")==wstring::npos) 
		{
			p=scriptline.find(L"*/");
			scriptline.erase(0,p+2);
			in_comment = false;
		}
		else if (scriptline.find(L"/*")!=wstring::npos && scriptline.find(L"*/")!=wstring::npos) 
		{
			p=scriptline.find(L"/*");
			scriptline.erase(p,scriptline.find(L"*/")-p+2);
		}
		// Check for comments at the end of rows and erase those
		else if(!in_comment && scriptline.find(L"//")!=wstring::npos) 
		{
			cleanline=scriptline;
			p=scriptline.find(L"//");
			if (scriptline.find(L"\"")!=wstring::npos) {

				if (p > scriptline.rfind(L"\"") || p < scriptline.find(L"\""))
					scriptline.erase(p,scriptline.length()-p);

			} else
				scriptline.erase(p,scriptline.length()-p);

			if (w_trim(scriptline).empty()) {
				scriptline = cleanline;
				comment_todisplay=1;
			}
		}
		else if(!in_comment && scriptline.find(L";")!=wstring::npos) 
		{
			p=scriptline.find(L";");
			if (p==0) {
				comment_todisplay=1;
				scriptline.erase(p,1);
				scriptline = L";" + w_trim(scriptline);
				while(scriptline.find(L"\t")!=wstring::npos)
					scriptline.replace(scriptline.find(L"\t"),1,L" ");

			}
			else if (scriptline.find(L"\"")!=wstring::npos) {

				if (p > scriptline.rfind(L"\"") || p < scriptline.find(L"\""))
					scriptline.erase(p,scriptline.length()-p);

			} else
				scriptline.erase(p,scriptline.length()-p);
		}
		else if(in_comment) //Comment Block, ignored
		{
			comment_todisplay=1;
//			iter++;
//			continue;
		} 
		// ASM Blocks

		scriptline = w_trim(scriptline);
		if (scriptline.empty()) {
			comment_todisplay=1;
//			iter++;
//			continue;
		}

		wstring lcline = scriptline;
		int (*pf)(int)=tolower;
		transform(lcline.begin(), lcline.end(), lcline.begin(), pf);

		// Check for #inc and include file if it exists, else add line
		if((inc_pos = lcline.find(L"#inc")) != wstring::npos)
		{
			cout << inc_pos;
			wstring args = w_trim(scriptline.substr(inc_pos + 4, scriptline.length()));
			wstring filename;
			if(GetSTROpValue(args, filename))
			{
				if (filename.find('\\')==wstring::npos)
					filename = currentdir+filename;
				vector<wstring> newScript = GetScriptFromFile(filename);				
				posInScript += InsertScript(newScript, posInScript);

				iter++;
				continue;
			}
			else
			{
				MessageBox(hwmain, L"Bad #inc directive!", PLUGIN_NAME L" error", MB_OK | MB_ICONERROR | MB_TOPMOST);
			}
		}
		// Logging
		else if((inc_pos = lcline.find(L"#log")) > -1 && !in_comment)
		{
			enable_logging = true;
		}
		else
		{
			script.insert(script.begin() + posInScript, scriptline);
			linesAdded++;
			posInScript++;

			if(!in_comment && in_asm && lcline == L"ende") {
				in_asm = false;
			}

			if (!in_comment && ToLower(scriptline) == L"endif") {
				in_cond--;
			} else if (!in_comment && ToLower(scriptline) == L"else") {
				in_cond--;
			}

			addProgLine(posInScript,scriptline,	(comment_todisplay * PROG_TYPE_COMMENT)
											|	(in_asm * PROG_TYPE_ASM)
											|	((in_cond & 1)*PROG_ATTR_IFLEVEVN)
											|	((in_cond && !(in_cond & 1))*PROG_ATTR_IFLEVODD)
						);

			if (!in_comment && ToLower(scriptline).substr(0,2) == L"if") {
				in_cond++;
			} else if (!in_comment && ToLower(scriptline) == L"else") {
				in_cond++;
			}

			if(!in_comment && lcline == L"exec") {
				in_asm = true;
			}

		}
	
		iter++;
	}
	return linesAdded;
}

/*
int OllyLang::GetState()
{
	return script_state;
}
*/

int OllyLang::GetFirstCodeLine(int from)
{
	int nline=from;
	int ltype;

	// Check for label after (skip it/them)
	if(nline < script.size()) {
		
		ltype = getProgLineType(nline+1);
		// Check if its a label or comment
		while(nline < script.size() && (ltype & PROG_TYPE_COMMAND) == 0)
		{
			nline++;
			ltype = getProgLineType(nline+1);
		} 

	}
	//if (nline>=script.size())
	//	return false;

	return nline;
}

bool OllyLang::SaveBreakPoints(wstring fileName) {

	if (fileName.empty())
		return false;

	Writetoini(NULL,PLUGIN_NAME, L"BP_FILE", L"%s", fileName);

	int i,bpcnt=1;
	wchar_t buffer[5]={0};
	wstring s,sline;

	t_wndprog_data *ppl;
	for (i=1;i<script.size();i++) {
		ppl = (t_wndprog_data *) Getsortedbyselection(&wndProg.sorted,i);
		if (ppl==NULL)
			return false; 
		if (ppl->pause) {
			s=L"BP_";
			wsprintf((wchar_t*)buffer,L"%04u",bpcnt);
			s.append((wchar_t*)buffer);
			wsprintf((wchar_t*)buffer,L"%u",i);
			sline.assign((wchar_t*)buffer);
			sline.append(L",");
			sline.append(ppl->command);
			
			Writetoini(NULL,PLUGIN_NAME, (wchar_t*)s.c_str(), L"%s", sline.c_str());
			bpcnt++;
		}
	}
	//clean last one
	s=L"BP_";
	wsprintf((wchar_t*)buffer,L"%04u",bpcnt);
	s.append((wchar_t*)buffer);
	Writetoini(NULL,PLUGIN_NAME, (wchar_t*)s.c_str(), L"");			
	return true;
}

bool OllyLang::LoadBreakPoints(wstring fileName) {

	wstring s;
	wchar_t sbuffer[MAX_PATH]={0};
	Getfromini(NULL,PLUGIN_NAME, L"BP_FILE", L"%s", sbuffer);
	s.assign((wchar_t*)sbuffer);

	if (StrCmpIW(fileName.c_str(),s.c_str())!=0)
		return false;

	int i,bpcnt=0,p;
	wchar_t ibuffer[5]={0};

	t_wndprog_data *ppl;
	do {
		bpcnt++;
		s=L"BP_";
		wsprintf((wchar_t*)ibuffer,L"%04u",bpcnt);
		s.append((wchar_t*)ibuffer);
		//Pluginreadstringfromini(, (wchar_t*)s.c_str(), (wchar_t*)sbuffer, L"");	
		Getfromini(NULL,PLUGIN_NAME, (wchar_t*)s.c_str(), L"%s", sbuffer);	
		s.assign((wchar_t*)sbuffer);
		if (s!=L"") {

			if ((p=s.find(L","))!=wstring::npos) {
				swscanf(s.substr(0,p).c_str(),L"%u",&i);
				s.erase(0,p+1);
				ppl = (t_wndprog_data *) Getsortedbyselection(&wndProg.sorted,i);
				if (ppl!=NULL) {
					if (s.compare(ppl->command)==0)
						ppl->pause=1; 
				}
			}

		}

	} while (s.length());

	return true;
}

bool OllyLang::LoadScript(wstring file)
{

	SaveBreakPoints((wchar_t*)scriptpath.c_str());

	script.clear();
	labels.clear();
	clearProgLines(); 
	Reset();

	scriptpath = file;	
	
	addProgLine(0,scriptpath);

	vector<wstring> unparsedScript = GetScriptFromFile(file);
	InsertScript(unparsedScript, 0);

	// Find all labels
	ParseLabels();

	Writetoini(NULL,PLUGIN_NAME, L"ScriptDir", (wchar_t*) file.c_str());
	mruAddFile(file);

	pgr_scriptpos=GetFirstCodeLine(0)+1;
	setProgLineEIP(pgr_scriptpos,0);

	LoadBreakPoints(file);

	return true;
}

bool OllyLang::Pause()
{
	script_state = SS_PAUSED;
	return true;
}

bool OllyLang::Resume()
{
	Pause();
	Step(1);
	script_state = SS_RUNNING;
	return true;
}

bool OllyLang::Step(int forceStep)
{
	require_ollyloop = 0;
	t_dump *cpuasm;
	PFCOMMAND func;
	LARGE_INTEGER i64;
	int refresh=1;
	wchar_t lastchar;
	bool jumped;
	int old_pos;

	while(!require_ollyloop && Getstatus() == STAT_STOPPED && (script_state == SS_RUNNING || script_state == SS_LOADED || (forceStep && script_state == SS_PAUSED)))
	{
		jumped=false;

		if (tickcount_startup==0) {
			i64.QuadPart= MyGetTickCount(0).QuadPart;
			tickcount_startup=i64.QuadPart;
		}

		// Set state to RUNNING
		if(forceStep == 0)
			script_state = SS_RUNNING;

		script_pos=GetFirstCodeLine(script_pos);

		// Check if script out of bounds
		DumpScript();
		if(script.size() <= script_pos)
			return false;

		// Get code line
		wstring codeLine = w_trim(script[script_pos]);

		pgr_scriptpos=script_pos+1;
		cpuasm = Getcpudisasmdump();
		setProgLineEIP(pgr_scriptpos,cpuasm->sel0);

		//HANDLE SCRIPT BREAKPOINTS
		if (isProgLineBP(pgr_scriptpos) && script_state!=SS_PAUSED) {
			script_state=SS_PAUSED;
			break;
		}

		// Log line of code if that is enabled
		if(enable_logging)
		{
			wchar_t buffer[4096] = {0};
			wsprintf(buffer, L"--> %d", codeLine);
			Addtolist(0, -1, buffer);
		}

		// Create command and arguments
		wstring command = codeLine;
		wstring args = L"";
		int (*pf)(int)=tolower; 
		size_t pos = codeLine.find_first_of(L" \t\r\n");
		if(pos != wstring::npos)
		{
			command = w_trim(codeLine.substr(0, pos));
			transform(command.begin(), command.end(), command.begin(), pf);
			args = w_trim(codeLine.substr(pos));

		} else {

			transform(command.begin(), command.end(), command.begin(), pf);
		}

		bool result = false;

		// Find command and execute it
		if(commands.find(command) != commands.end())
		{
		
			// Command found, execute it
			func = commands[command];
			old_pos = script_pos;

			if (tickcount==0 && command==L"tick") {
				//for first tick.
				i64 = MyGetTickCount(tickcount_startup);
				tickcount = i64.LowPart;
				tickcounthi = i64.HighPart;
			}

			result = (this->*func)(args);
			i64 = MyGetTickCount(tickcount_startup);
			this->tickcount = i64.LowPart;
			this->tickcounthi = i64.HighPart;

			if (old_pos>script_pos || old_pos+1<script_pos) {
				jumped=true;
			}
 
		}
		else 
		{
			// No such command
			errorstr = L"No such command: " + codeLine;
			Pause();
			InvalidateProgWindow();
		}
//		if (Getstatus() != STAT_RUNNING)
//			pgr_scriptpos=script_pos+1;
		
		// Error in processing, show error and die
		if(!result)
		{
			wstring message = L"Error on line ";
			wchar_t buffer[32] = {0};
			message.append(_itow(script_pos + 1, buffer, 10));
			message.append(L"\n");
			message.append(L"Text: ");
			message.append(script.at(script_pos));
			message.append(L"\n");
			setProgLineAttr(script_pos+1,PROG_ATTR_ERROR);
			if(errorstr != L"")
			{
				message += errorstr;
			}
			MessageBox(0, message.c_str(), PLUGIN_NAME L" error", MB_ICONERROR | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);
			errorstr = L"";
			script_pos++;
			pgr_scriptpos=script_pos+1;
			Pause();
			InvalidateProgWindow();
			return false;
		} else {
			setProgLineResult(script_pos+1,variables[L"$RESULT"]);
		}

		if (script_state == SS_LOADED) {
			//After a reset (ret)
			script_state = SS_PAUSED;
			//display start of script
			Selectandscroll(&wndProg,0,2);
			break;
		}
		
		script_pos++;

		//Next code Line
		script_pos=GetFirstCodeLine(script_pos);

		if (jumped) { 
			if(++refresh % 128 == 0) {
				//refresh every xxxx jumps (loop anti freeze)
				if (wndProg.hw) {
					Selectandscroll(&wndProg,pgr_scriptpos,2);
					//refresh only on proc exit
					InvalidateRect(wndProg.hw, NULL, FALSE);
				}
				return true; 
				//will continue after main loop...redraw etc
			}
		}

		//Highlight next instr. not if app running... or if stepping
//		if (Getstatus() != STAT_RUNNING || forceStep==1)
//			pgr_scriptpos=script_pos+1;

		cpuasm = Getcpudisasmdump();
		setProgLineEIP(pgr_scriptpos,cpuasm->sel0);			
		
		addHistoryStep(pgr_scriptpos);

		if(forceStep == 1) {
			InvalidateProgWindow();
			break;
		}

	}

	if (wndProg.hw!=NULL) //Visible && Not a RUN command 
		Selectandscroll(&wndProg,pgr_scriptpos,2);
	return true;
}

//Executed after some commands to clean memory or to get something after ollydbg processing
bool OllyLang::ProcessAddonAction()
{

	t_thread* thr = Findthread(Getcputhreadid());	 

	t_dbgmemblock todo={0};

	vector<t_dbgmemblock>::iterator block;
	
	block = tMemBlocks.end();

	for (int b=tMemBlocks.size(); b>0; b--) {
		
		block--;
		if (block->free_at_eip == thr->reg.ip) {
			HANDLE hDbgPrc = _process;
			VirtualFreeEx(hDbgPrc, block->hmem, block->size, MEM_DECOMMIT);
			
			//DbgMsgHex((ulong)block->hmem,"VirtualFreeEx");

			if (block->result_register) {
				variables[L"$RESULT"] = thr->reg.r[block->reg_to_return];
				setProgLineResult(block->script_pos+1,variables[L"$RESULT"].dw);
			}

			if (block->listmemory) todo.listmemory=true;
			if (block->restore_registers) todo.restore_registers=true;

			tMemBlocks.erase(block);

			require_addonaction=0;
			//return true;
		}
		if (block == tMemBlocks.begin())
			break;
	}

	if (todo.listmemory) DoREFRESH(L""); //Listmemory();	
	if (todo.restore_registers) RestoreRegisters(true);
	
	return true;
}


bool OllyLang::OnBreakpoint(int reason, int details)
{
	break_reason=reason;
	
	//debug hint
//	if(reason&&!PP_HWBREAK)
//		break_reason=reason;

	if(bInternalBP) {
		//dont process temporary bp (exec/ende Go command)
		bInternalBP=false;
	}
	else if(EOB_row > -1)
	{
		script_pos = GetFirstCodeLine(EOB_row);
		return true;
	}
	else 
	{
//		if (reason != PP_EXCEPTION) {
			t_dump* cpuasm = Getcpudisasmdump();
			DWORD addr = cpuasm->sel0;
			if(bpjumps.find(addr) != bpjumps.end())
			{
				if (bpjumps[addr]) {
					script_pos = GetFirstCodeLine(bpjumps[addr] + 1);
					pgr_scriptpos = script_pos + 1;
					setProgLineEIP(pgr_scriptpos,addr);
					Selectandscroll(&wndProg,pgr_scriptpos,2);
					if (script_state == SS_PAUSED) {
						InvalidateProgWindow();
					}
					return true;
				}
			}
			//pgr_scriptpos = script_pos + 1;
			if (pgr_scriptpos_paint!=pgr_scriptpos && script_state == SS_PAUSED) {
				Selectandscroll(&wndProg,pgr_scriptpos,2);
				InvalidateProgWindow();
			}
//		}
	}

	return false;
}

bool OllyLang::OnException(DWORD ExceptionCode)
{
	if(EOE_row > -1)
	{
		script_pos = EOE_row;
		return true;
	}
	else
		return false;
}

int OllyLang::getStringOperatorPos(wstring &ops) {
	
	wstring cache=ops;
	wstring operators = L"+";
	int b=0,e=0,p=0,c;

	//hide [pointer operations]
	while ( (p=cache.find_first_of(L"[",p)) != wstring::npos) {
		if ( (e=cache.find_first_of(L"]",p)) != wstring::npos) {
			for (c=p;c<=e;c++) cache[c] = 'X';
		}
	}
	e=0;p=0;

	//Search for operator(s) outside "quotes" 
	while ( (b=cache.find_first_of(L"\"",b)) != wstring::npos) {

		//Check Before
		if ((p=cache.find_first_of(operators),e) != wstring::npos) {
			if (p<b) return p;
		}

		if ( (e=cache.find_first_of(L"\"",b+1)) != wstring::npos) {
	
			//Check between
			if ((p=cache.find_first_of(operators,e+1)) != wstring::npos) {
				if (p<cache.find_first_of(L"\"",e+1)) return p;
			}
			b=e;
		}
		b++;
	}

	//Check after
	return cache.find_first_of(operators,e);

}

int OllyLang::getDWOperatorPos(wstring &ops) {
	
	wstring operators = L"+-*/&|^<>";
	int b=0,e=0,p;

	//Search for operator(s) outside [pointers]
	while ( (b=ops.find(L"[",b)) != wstring::npos) {

		//Check Before
		if ((p=ops.find_first_of(operators),e) != wstring::npos) {
			if (p<b) return p;
		}

		if ( (e=ops.find(L"]",b+1)) != wstring::npos) {
	
			//Check between
			if ((p=ops.find_first_of(operators,e+1)) != wstring::npos) {
				if (p<ops.find(L"[",e+1)) return p;
			}
			b=e;
		}
		b++;
	}

	//Check after
	return ops.find_first_of(operators,e);
}

int OllyLang::getFLTOperatorPos(wstring &ops) {
	
	wstring operators = L"+-*/";
	int b=0,e=0,p;

	//Search for operator(s) outside [pointers]
	while ( (b=ops.find(L"[",b)) != wstring::npos) {

		//Check Before
		if ((p=ops.find_first_of(operators),e) != wstring::npos) {
			if (p<b) return p;
		}

		if ( (e=ops.find(L"]",b+1)) != wstring::npos) {
	
			//Check between
			if ((p=ops.find_first_of(operators,e+1)) != wstring::npos) {
				if (p<ops.find(L"[",e+1)) return p;
			}
			b=e;
		}
		b++;
	}

	//Check after
	return ops.find_first_of(operators,e);
}

bool OllyLang::CreateOperands(wstring &args, wstring ops[], uint len, bool preferstr)
{

	vector<wstring> v;
	bool bResult = true;

	if (len==1 || (split(v, args, ',') && v.size() == len))
	{
		if (len==1) v.push_back(args);

		int p;
		DWORD dw,result=0;
		long double flt=0, fltresult=0;
		wstring str;
		wstring svar,op,oper=L"";

		var vResult;

		for(uint i = 0; i < len; i++) 
		{
			op = w_trim(v[i]);
			ops[i] = op;

			if ((p=getFLTOperatorPos(op)) != wstring::npos) 
			{
				do {
					if (op.find_first_of(L"\"") != wstring::npos || preferstr)
						goto try_str_operation;
					
					svar=w_trim(op.substr(0,p));

					var_logging=false;
					if (!GetFLTOpValue(svar,flt)) 
						//Convert integer to float (but not for first operand)
						if (oper.length()!=0 && GetDWOpValue(svar,dw))
							flt = dw;
						else
							goto try_dw_operation;

					if (oper.length()==0)
						//first value
						fltresult += flt;
					else if (oper[0]=='+')
						fltresult += flt;
					else if (oper[0]=='-')
						fltresult -= flt;
					else if (oper[0]=='*')
						fltresult *= flt;
					else if (oper[0]=='/')
						fltresult /= flt;
			
					oper = op[p];

					op.erase(0,p+1);

				} while ( (p=getFLTOperatorPos(op)) != wstring::npos);

				svar=w_trim(op);
				var_logging=false;
				if (!GetFLTOpValue(svar,flt)) 
					//Convert integer to float (but not for first operand)
					if (oper.length()!=0 && GetDWOpValue(svar,dw))
						flt = dw;
					else
						goto operation_failed;

				if (oper[0]=='+')
					fltresult += flt;
				else if (oper[0]=='-')
					fltresult -= flt;
				else if (oper[0]=='*')
					fltresult *= flt;
				else if (oper[0]=='/')
					fltresult /= flt;

				wchar_t value[128];
				wsprintf(value,L"%lf",fltresult);

				ops[i]=value;
				while (true) 
				{
					if (ops[i].length() <= 3) break; 
					if (ops[i][ops[i].length()-1] == '0')
						ops[i].erase(ops[i].length()-1,1);
					else 
						break;
				}
				if (nIgnoreNextValuesHist==0)
					var_logging=true;
//				if (!sub_operand)
					setProgLineValueFloat(script_pos+1,fltresult);
				goto operation_ok;

			} 
			else if ( (p=getDWOperatorPos(op)) != wstring::npos)
			{	
				do {
			
			try_dw_operation:

					if (op.find_first_of(L"\"") != wstring::npos || preferstr)
						goto try_str_operation;
					
					svar=w_trim(op.substr(0,p));

					var_logging=false;
					if (!GetDWOpValue(svar,dw)) 
						goto try_str_operation;

					if (oper.length()==0)
						//first value
						result += dw;
					else if (oper[0]=='+')
						result += dw;
					else if (oper[0]=='-')
						result -= dw;
					else if (oper[0]=='*')
						result *= dw;
					else if (oper[0]=='/')
						result /= dw;
					else if (oper[0]=='&')
						result &= dw;
					else if (oper[0]=='|')
						result |= dw;
					else if (oper[0]=='^')
						result ^= dw;
					else if (oper[0]=='>')
						result >>= dw;
					else if (oper[0]=='<')
						result <<= dw;
			
					oper = op[p];

					op.erase(0,p+1);

				} while ( (p=getDWOperatorPos(op)) != wstring::npos);

				svar=w_trim(op);
				var_logging=false;
				if (!GetDWOpValue(svar,dw)) 
					goto operation_failed;

				if (oper[0]=='+')
					result += dw;
				else if (oper[0]=='-')
					result -= dw;
				else if (oper[0]=='*')
					result *= dw;
				else if (oper[0]=='/')
					result /= dw;
				else if (oper[0]=='&')
					result &= dw;
				else if (oper[0]=='|')
					result |= dw;
				else if (oper[0]=='^')
					result ^= dw;
				else if (oper[0]=='>')
					result >>= dw;
				else if (oper[0]=='<')
					result <<= dw;

				wchar_t value[16];
				_itow(result,value,16);

				ops[i]=value;

				if (nIgnoreNextValuesHist==0) {
					var_logging=true;
//				if (!sub_operand)
					setProgLineValue(script_pos+1,result);
				}
				goto operation_ok;

			//STRING OPERATIONS
			try_str_operation:
				
				oper=L"";
				while ((p = getStringOperatorPos(op)) != wstring::npos) 
				{
					
					svar=w_trim(op.substr(0,p));
					var_logging=false;
					if (!GetSTROpValue(svar,str)) 
						goto operation_failed;

					if (oper.length()==0)
						//first value
						vResult = str;
					else if (oper[0]=='+')
						vResult += str; 

					oper = op[p];

					op.erase(0,p+1);
				} 

				svar=w_trim(op);

				var_logging=false;
				if (!GetSTROpValue(svar,str)) 
					goto operation_failed;
				
				if (oper.length()==0)
					//first value
					vResult = str;
				if (oper[0]=='+')
					vResult += str;

				if (!vResult.isbuf)
					ops[i]=L"\"" +vResult.str+ L"\"";
				else
					ops[i]=vResult.str;

				if (!sub_operand && var_logging) 
					setProgLineValue(script_pos+1,ops[i]);
				goto operation_ok;

			operation_failed:
				bResult = false;
				break;

			operation_ok:
				bResult = bResult;

			} //if find_first_of

		} //for

		if (nIgnoreNextValuesHist>0)
			nIgnoreNextValuesHist--;
		if (nIgnoreNextValuesHist==0)
			var_logging=true;

		return bResult;
	}
	return false;
}

bool OllyLang::CreateOp(wstring &args, wstring ops[], uint len, bool preferstr)
{
	vector<wstring> v;
	if (len==1 || (split(v, args, ',') && v.size() == len))
	{
		if (len==1) v.push_back(args);

		int p;
		DWORD dw,result=0;
		long double flt=0, fltresult=0;
		wstring str,vResult=L"";
		wstring op,oper=L"";

		for(uint i = 0; i < len; i++)
		{
			op = w_trim(v[i]);
			ops[i] = op;
		}
		return true;
	}
	return false;
}

bool OllyLang::ParseLabels()
{
	vector<wstring>::iterator iter;
	iter = script.begin();
	wstring s;
	int loc = 0;
	t_wndprog_data *ppl;

	while(iter != script.end())
	{
		s = *iter;
		if(s.length() > 0) {
			if(s.at(s.length() - 1) == ':') {

				ppl = NULL;
				if ((size_t)(loc + 1) < tProgLines.size())
				    ppl = &tProgLines[loc + 1];
				if (ppl == NULL)
				    ppl = (t_wndprog_data *) Getsortedbyselection(&wndProg.sorted, loc + 1);
				if (ppl != NULL && ppl->type != PROG_TYPE_COMMENT) {
					ppl->type = PROG_TYPE_LABEL;
					labels.insert(pair<wstring, int>(s.substr(0, s.length() - 1), loc));
				}
			}
		}
		iter++;
		loc++;
	}

	return false;
}

int OllyLang::SearchInScript(wstring text, ulong fromPos)
{
	vector<wstring>::iterator iter;
	wstring s;
	int loc = 0;
	bool oneTime = true;

	int (*pf)(int) = tolower; 
	transform(text.begin(), text.end(), text.begin(), pf);

	SearchFromStart:
	iter = script.begin();

	while(iter != script.end())
	{
		if (loc >= fromPos) {
			s = *iter;
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
		goto SearchFromStart;
	}

	return -1;
}

bool OllyLang::AddBPJump(int bpaddr,int labelpos)
{
	map<int,int>::iterator iter;
	pair<int,int> p;
	iter = bpjumps.begin();
	int loc = 0;

	while(iter != bpjumps.end())
	{
		p = *iter;
		if(p.first == bpaddr) {
			p.second=labelpos;
			return true;
		}
		iter++;
		loc++;
	}

	bpjumps.insert(pair<int, int>(bpaddr,labelpos));

	return true;
}

bool OllyLang::GetANYOpValue(wstring op, wstring &value, bool hex8forExec)
{
	if(is_variable(op))
	{
		// We have a declared variable
		if(variables[op].vt == STR)
		{
			// It's a string var, return value
			value = variables[op].str;
			goto values_ok_str;
		}
		else if(variables[op].vt == DW)
		{
			wchar_t buffer[12] = {0};
			if (hex8forExec)
				//For Assemble Command (EXEC/ENDE) ie "0DEADBEEF"
				wsprintf(buffer, L"%09X", variables[op].dw);
			else 
				wsprintf(buffer, L"%X", variables[op].dw);
			value = buffer;
			goto values_ok;
		}
		return false;
	} 
	if(is_hex(op))
	{
		if (hex8forExec)
			value = L"0"+op;
		else
			value = op;
		return true;
	}
	else if(UnquoteString(op, '"', '"')) 
	{
		value = op;
		return true;
	}
	else if(UnquoteString(op, '#', '#')) 
	{
		value = L"#"+op+L"#";
		return true;
	}
	else if(is_dec(op))
	{
		op.erase(op.length()-1,1);
		Int2Hex(wcstoul(op.c_str(), 0, 10),value);
		return true;
	}
	else if(is_float(op))
	{
		value = op;
		return true;
	}
	else if(UnquoteString(op, '[', ']'))
	{
		// We read a string (max 256) at memory address
		DWORD addr = 0;
		sub_operand=true;
		if (!CreateOp(op,&op,1)) {
			DbgMsg(0,L"failed to create pointer suboperand "+op);
			sub_operand=false;
			return false;
		}
		sub_operand=false;

		if(GetDWOpValue(op, addr)) 
		{
			if (addr!=0) {

				//Pointer Mark in Values column (open quote char '<<')
				setProgLineValue(script_pos+1, (wstring) L"\xAE");
				
				wchar_t buffer[STRING_READSIZE] = {0};
				Readmemory(&buffer[0], addr, STRING_READSIZE, MM_SILENT);

				if (wcslen(buffer) >= STRING_READSIZE-1) 
				{
					buffer[STRING_READSIZE-1] = 0;
				}

				value.assign(buffer);
			} else 
				value = L"0";

			goto values_ok_str;
		}
		
	}
	else
	{
		DWORD dw=0;
		if (GetDWOpValue(op,dw)) 
		{
			wchar_t buffer[12] = {0};
			if (hex8forExec)
				wsprintf(buffer, L"%09X", dw);
			else 
				wsprintf(buffer, L"%X", dw);
			value = buffer;
			goto values_ok;
		}
	}
	return false;

values_ok:
	if (var_logging)
		setProgLineValue(script_pos+1,value);
	return true;

values_ok_str:
	if (var_logging) {
		var val=value;
		if(val.isbuf) 
			setProgLineValue(script_pos+1,value);
		else
			setProgLineValue(script_pos+1,L"\""+value+L"\"");
	}
	return true;

}

bool OllyLang::GetSTROpValue(wstring op, wstring &value, int size)
{
//	if (size>0)
//		DbgMsg(size,op);

	if(is_variable(op))
	{
		// We have a declared variable
		if(variables[op].vt == STR)
		{
			// It's a string var, return value
			if (size<variables[op].size && (size != 0))
				value = variables[op].strbuff().substr(0,size);
			else
				value = variables[op].str;
			goto values_ok2;
		}
		return false;
	}
	else if(UnquoteString(op, '"', '"')) 
	{
		if (size<op.length() && (size != 0))
			value = op.substr(0,size);
		else
			value = op;
		return true; 
	}
	else if(UnquoteString(op, '#', '#')) 
	{
		if ((size*2)<op.length() && (size != 0))
			value = L"#"+op.substr(0,size*2)+L"#";
		else
			value = L"#"+op+L"#";
		return true;
	}
	else if(UnquoteString(op, '[', ']'))
	{
		// We read a string (max STRING_READSIZE) at memory address
		DWORD addr = 0;

		sub_operand=true;
		if (!CreateOp(op,&op,1)) {
			DbgMsg(0,L"failed to create pointer suboperand "+op);
			sub_operand=false;
			return false;
		}

		sub_operand=false;

		if(GetDWOpValue(op, addr)) {

			//Pointer Mark in Values column (open quote char '<<')
			setProgLineValue(script_pos+1, (wstring) L"\xAE");

			if (size>0) {
				
				wchar_t* buffer = new wchar_t[size+1];
				Readmemory(buffer, addr, size, MM_SILENT);
				buffer[size] = 0;
				value.assign(buffer,size);
				if (wcslen(buffer) != size) {
					var v=value;
					value=L"#"+v.strbuffhex()+L"#";
				}
				delete[] buffer;

			} else {
				wchar_t buffer[STRING_READSIZE] = {0};
				Readmemory(buffer, addr, STRING_READSIZE, MM_SILENT);
			
				if (wcslen(buffer) >= STRING_READSIZE-1) {
					buffer[STRING_READSIZE-1] = 0;
				}
				value = buffer;
			}

			goto values_ok2;

		}
		
	}
	return false;

values_ok2:
	if (var_logging) {
		var val=value;
		if(val.isbuf) 
			setProgLineValue(script_pos+1,value);
		else
			setProgLineValue(script_pos+1,L"\""+value+L"\"");
	}
	return true;
}

int OllyLang::GetRegNr(wstring& name)
{
	wstring r16=name;

	//R16
	if (r16.length()==3)
		r16.erase(0,1);

	//R8
	if (r16[1] == 'l' || r16[1] == 'h')	r16[1]='x';

	if(r16 == L"ax")
		return REG_EAX;
	else if(r16 == L"bx")
		return REG_EBX;
	else if(r16 == L"cx")
		return REG_ECX;
	else if(r16 == L"dx")
		return REG_EDX;
	else if(r16 == L"sp")
		return REG_ESP;
	else if(r16 == L"bp")
		return REG_EBP;
	else if(r16 == L"si")
		return REG_ESI;
	else if(r16 == L"di")
		return REG_EDI;
	else 
		return -1;
}

int OllyLang::GetSegNr(wstring& name)
{
	if(name == L"es")
		return SEG_ES;
	else if(name == L"cs")
		return SEG_CS;
	else if(name == L"ss")
		return SEG_SS;
	else if(name == L"ds")
		return SEG_DS;
	else if(name == L"fs")
		return SEG_FS;
	else if(name == L"gs")
		return SEG_GS;
	else 
		return SEG_UNDEF;
}

bool OllyLang::GetBYTEOpValue(wstring op, BYTE &value)   //new add
{
	if(is_hex(op))
	{
		op = L"0" + op;
		if (op.length() > 3) {
			errorstr = L"GetBYTEOpValue : Too Long";
			return false;
		}
		value = wcstoul(op.c_str(), 0, 16);
		if (var_logging)
			setProgLineValue(script_pos+1,value);
		return true;
	}
	else if(is_variable(op))
	{
		if (variables[op].dw > 0xff){
			errorstr = L"GetBYTEOpValue : Too High";
			return false;
			}
		// We have a declared variable
		if(variables[op].vt == DW)
		{
			// It's a DWORD var, return value
			value = variables[op].dw;            
			if (var_logging)
				setProgLineValue(script_pos+1,value);
			return true;
		}
		return false;
	}
  return false;
}

bool OllyLang::GetAddrOpValue(wstring op, DWORD &value)
{
		if(UnquoteString(op, '[', ']'))
		{
		// We have a memory address
			DWORD addr = 0;
//			sub_operand=true;
				if (!CreateOperands(op,&op,1)) {
					DbgMsg(0,L"GetAddrOpValue "+op);
					sub_operand=false;
					return false;
				}
//			sub_operand=false;
			value=wcstoul(op.c_str(),0,16);
			
			return true;
		}
		return true;
}

bool OllyLang::GetDWOpValue(wstring op, DWORD &value, DWORD default_val)
{
	value=default_val;

	if(is_register(op))
	{
		// We have a register
		int regnr = GetRegNr(op);

		t_thread* pt = Findthread(Getcputhreadid());
		
		if(regnr != -1)
		{
			// It's a usual register
			value = pt->reg.r[regnr];
			if (op.length()==2) {
				if (op[1] == 'l')
					value &= 0xFF;
				else if (op[1] == 'h') {
					value &= 0xFF00;
					value /= 0x100;
				} else
					value &= 0xFFFF;
			}

			if (var_logging)
				setProgLineValue(script_pos+1,value);
			return true;
		}
		else if(op == L"eip")
		{
			//cpuasm = Getcpudisasmdump();
			//value = cpuasm->sel0;
			// It's EIP
			value = pt->reg.ip;
			if (var_logging)
				setProgLineValue(script_pos+1,value);
			return true;
		}
		return false;
	}
	else if(is_flag(op))
	{
		eflags flags;
		ZeroMemory(&flags, sizeof DWORD);
		t_thread* pt = Findthread(Getcputhreadid());
		flags.dwFlags = pt->reg.flags;

		if(_wcsicmp(op.c_str(), L"!af") == 0)
			value = flags.bitFlags.AF;
		else if(_wcsicmp(op.c_str(), L"!cf") == 0)
			value = flags.bitFlags.CF;
		else if(_wcsicmp(op.c_str(), L"!df") == 0)
			value = flags.bitFlags.DF;
		else if(_wcsicmp(op.c_str(), L"!of") == 0)
			value = flags.bitFlags.OF;
		else if(_wcsicmp(op.c_str(), L"!pf") == 0)
			value = flags.bitFlags.PF;
		else if(_wcsicmp(op.c_str(), L"!sf") == 0)
			value = flags.bitFlags.SF;
		else if(_wcsicmp(op.c_str(), L"!zf") == 0)
			value = flags.bitFlags.ZF;

		if (var_logging)
			setProgLineValue(script_pos+1,value);
		
		return true;
	}
	else if(is_variable(op))
	{
		// We have a declared variable
		if(variables[op].vt == DW)
		{
			// It's a DWORD var, return value
			value = variables[op].dw;
			if (var_logging)
				setProgLineValue(script_pos+1,value);
			return true;
		}
		return false;
	}
	else if(is_segment(op))
	{
		// We have a register
		int segnr = GetSegNr(op);

		t_thread* pt = Findthread(Getcputhreadid());
		
		if(segnr != SEG_UNDEF)
		{
			// It's a segment register 
			// Note: plugin.h constants were bad before v1.83
			switch (segnr) {
				case SEG_SS:
				case SEG_DS:
				case SEG_FS:
				case SEG_GS:
					value = pt->reg.base[segnr];
					break;
				case SEG_ES:
				case SEG_CS:
					value = pt->reg.s[segnr];
					break;
			}

			if (var_logging)
				setProgLineValue(script_pos+1,value);
			return true;
		}
		return false;
	}
	else if(is_hex(op))
	{
		// We have a HEX constant
//		op = L"0" + op;
		value = wcstoul(op.c_str(), 0, 16);
		return true;
	}
	else if(is_dec(op))
	{
		// We have a DEC constant
		op.erase(op.length()-1,1);
		value = wcstoul(op.c_str(), 0, 10);
		return true;
	}
	else if(UnquoteString(op, '[', ']'))
	{
		// We have a memory address
		DWORD addr = 0;
		sub_operand=true;
		if (!CreateOperands(op,&op,1)) {
			DbgMsg(0,L"failed to create pointer suboperand "+op);
			sub_operand=false;
			return false;
		}
		sub_operand=false;

		if(GetDWOpValue(op, addr)) {

			//Pointer Mark in Values column (open quote char '<<')
			setProgLineValue(script_pos+1, (wstring) L"\xAE");

			Readmemory(&value, addr, 4, MM_SILENT);
			if (var_logging)
				setProgLineValue(script_pos+1,value);
			return true;

		}
	}
	return false;
}

bool OllyLang::GetFLTOpValue(wstring op, long double &value)
{

	if(is_float(op))
	{
		value = strtof(op);
		return true;
	}
	else if(is_floatreg(op))
	{
		t_thread* pt = Findthread(Getcputhreadid());
		value =  pt->reg.f[(op[3]-0x30)];
		if (var_logging)
			setProgLineValueFloat(script_pos+1,value);
		return true;
	}
	else if(is_variable(op))
	{
		// We have a declared variable
		if(variables[op].vt == FLT)
		{
			// It's a DWORD var, return value
			value = variables[op].flt;

			if (var_logging)
				setProgLineValueFloat(script_pos+1,value);
			return true;
		}
		return false;
	}
	else if(UnquoteString(op, '[', ']'))
	{
		// We have a memory address
		DWORD addr = 0;
		sub_operand=true;
		if (!CreateOp(op,&op,1)) {
			DbgMsg(0,L"failed to create pointer suboperand "+op);
			sub_operand=false;
			return false;
		}
		sub_operand=false;

		if(GetDWOpValue(op, addr)) {

			//Pointer Mark in Values column (open quote char '<<')
			wstring openquote = L"?";
			setProgLineValue(script_pos+1, openquote);

			Readmemory(&value, addr, 8, MM_SILENT);
			if (var_logging)
				setProgLineValueFloat(script_pos+1,value);
			return true;

		}
	}
	return false;
}

bool OllyLang::is_register(wstring s)
{
	int (*pf)(int) = tolower; 
	transform(s.begin(), s.end(), s.begin(), pf);

	if(reg_names.find(s) != reg_names.end())
		return true;

	return false;
}

bool OllyLang::is_segment(wstring s)
{
	int (*pf)(int) = tolower; 
	transform(s.begin(), s.end(), s.begin(), pf);

	if(seg_names.find(s) != seg_names.end())
		return true;

	return false;
}

bool OllyLang::is_floatreg(wstring s)
{
	int (*pf)(int) = tolower; 
	transform(s.begin(), s.end(), s.begin(), pf);

	//st(0) to st(7)
	if(s.length()==5)
		if (s[0]=='s' && s[1]=='t' && s[2]=='(' && s[4]==')') 
			if (s[3] >= '0' && s[3] <= '7') 
				return true;

	return false;
}

bool OllyLang::is_flag(wstring s)
{
	int (*pf)(int) = toupper; 
	transform(s.begin(), s.end(), s.begin(), pf);

	if(flag_names.find(s) != flag_names.end())
		return true;
	return false;
}

bool OllyLang::is_variable(wstring &s)
{
	if(variables.find(s) != variables.end())
		return true;
	return false;
}

wstring OllyLang::ResolveVarsForExec(wstring in, bool hex8forExec)
{
	wstring out, varname;
	bool in_var = false;
	in = w_trim(in);

	for(int i = 0; i < in.length(); i++)
	{
		if(in[i] == '{')
		{
			in_var = true;
		}
		else if(in[i] == '}')
		{
			in_var = false;
			GetANYOpValue(varname, varname, hex8forExec);
			out += varname;
			varname = L"";
		}
		else
		{
			if(in_var)
				varname += in[i];
			else
				out += in[i];
		}
	}				
	return out;

}

void OllyLang::menuListLabels(HMENU mLabels,int cmdIndex) {

	map<wstring, int>::iterator iter;
	iter = labels.begin();
	
	vector<HMENU>::iterator imenu;

	char buffer[32];
	wstring str;

	pair<wstring, int> p;
	while(iter != labels.end())
	{
		p = *iter;

		AppendMenu(mLabels,MF_STRING,cmdIndex+p.second,p.first.c_str());		
		iter++;
		//cmdIndex++;
	}
}

void OllyLang::menuListVariables(HMENU mVars,int cmdFirst) {

	//0x000-0x0FF > vars
	//0x100-0xF00 > cmd flags

	map<wstring, var>::iterator iter;
	iter = variables.begin();
	
	vector<HMENU> Popups;
	vector<HMENU>::iterator imenu;
	HMENU menu;

	wchar_t buffer[32];
	wstring str;

	pair<wstring, var> p;

	int nIndex=0, cmdIndex=0;

	while(iter != variables.end())
	{
		cmdIndex = cmdFirst + nIndex;
		p = *iter;
		menu = CreateMenu();
		Popups.push_back(menu);
		AppendMenu(mVars,MF_POPUP,(DWORD) menu,p.first.c_str());
		if (p.second.vt == STR) {

			if (p.second.size < 50) {
				AppendMenu(menu,MF_STRING,cmdIndex,(L"\""+p.second.strclean()+L"\"").c_str());
				AppendMenu(menu,MF_STRING,cmdIndex,(L"#"+p.second.strbuffhex()+L"#").c_str());
			} else {
				AppendMenu(menu,MF_STRING,cmdIndex,(L"\""+p.second.strclean().substr(0,50)+L"...").c_str());
				AppendMenu(menu,MF_STRING,cmdIndex,(L"#"+p.second.strbuffhex().substr(0,50)+L"...").c_str());
			}
			wsprintf(buffer,L"Length: %d.", p.second.size);
			AppendMenu(menu,MF_STRING,cmdIndex,buffer);

		} else if (p.second.vt == FLT) {
		
			wsprintf(buffer,L"%.2f",p.second.flt);
			AppendMenu(menu,MF_STRING,cmdIndex,buffer);
		
		} else {

			wsprintf(buffer,L"0x%x", p.second.dw);
			AppendMenu(menu,MF_STRING,cmdIndex,buffer);
			wsprintf(buffer,L"%d.", p.second.dw);
			AppendMenu(menu,MF_STRING,cmdIndex,buffer);

			if (p.second.dw != 0) {
				AppendMenu(menu,MF_SEPARATOR,0,L"-");
				StrCpyW(buffer,L"Follow in disassembler");
				AppendMenu(menu,MF_STRING,CMD_POPUP_FDISASM + cmdIndex, buffer);
				StrCpyW(buffer,L"Follow in dump");
				AppendMenu(menu,MF_STRING,CMD_POPUP_FDUMP   + cmdIndex, buffer);
				StrCpyW(buffer,L"Follow in stack");
				AppendMenu(menu,MF_STRING,CMD_POPUP_FSTACK  + cmdIndex, buffer);
				StrCpyW(buffer,L"Open memory dump");
				AppendMenu(menu,MF_STRING,CMD_POPUP_ODUMP   + cmdIndex, buffer);
			}
		}
		
		iter++;
		nIndex++;
		//256 vars max.
		if (nIndex > 0xFF)
			break;
	}
	imenu = Popups.begin();
	while(imenu != Popups.end())
	{
		DestroyMenu(*imenu);
		imenu++;
	}
}

bool OllyLang::editVariable(int nVar) {

	map<wstring, var>::iterator iter;
	pair<wstring, var> p;
	int n=0;
	iter = variables.begin();

	while(iter != variables.end()) {
		if (n==nVar) {

			RECT Rect={0};
			if (wndProg.hw)	GetWindowRect(wndProg.hw,&Rect);

/* ODBG2: missing Gethexstringxy, Getlongxy, Plugingetvalue(VAL_WINDOWFONT)
			p = *iter;
			if (p.second.vt == STR) {
				
				t_hexstr hexbuf;
				hexbuf.n=min(p.second.size,TEXTLEN);
				ZeroMemory(hexbuf.data,TEXTLEN);
				ZeroMemory(hexbuf.mask,TEXTLEN);
				FillMemory(hexbuf.mask,hexbuf.n,0xFF);
				memcpy(hexbuf.data,p.second.strbuff().c_str(),hexbuf.n);

				int font = Plugingetvalue(VAL_WINDOWFONT);

				if (Gethexstringxy("Edit variable...",&hexbuf, DIA_DEFHEX, font, 0, Rect.left,Rect.bottom)!=-1) {
					wstring s;
					s.assign((wchar_t*) hexbuf.data,hexbuf.n);

					if (variables[p.first].isbuf) {
						var v = s;
						variables[p.first] = L"#"+v.strbuffhex()+L"#";
					} else {
						variables[p.first] = s;
					}
				}

			} else if (p.second.vt == DW) {

				Getlongxy("Edit variable...",&p.second.dw, 4, 0, 0, Rect.left,Rect.bottom);
				variables[p.first] = p.second.dw;

			} else if (p.second.vt == FLT) {

				Getfloatxy("Edit variable...",&p.second.flt, 8, 0, 0, Rect.left,Rect.bottom);
				variables[p.first] = p.second.flt;
			}
			
			return true;
*/
		}
		iter++;
		n++;
	}
	return false;
}

bool OllyLang::followVariable(int nVar) {

	map<wstring, var>::iterator iter;
	pair<wstring, var> p;
	int n=0;
	iter = variables.begin();
	ulong addr, base=0, size=0;
	t_memory* mem = {0};

	while(iter != variables.end()) {
		if (n == (nVar & 0xFF)) {
			p = *iter;
			addr = p.second.dw;
			switch (nVar & CMD_POPUP_MASK) {
				case 0: //do nothing
						return false;
				case CMD_POPUP_FDISASM:
					if (addr) Setcpu(0,addr,0,0,0,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
					break;
				case CMD_POPUP_FDUMP:
					if (addr) Setcpu(0,0,addr,0,0,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
					break;
				case CMD_POPUP_FSTACK:
					if (addr) Setcpu(0,0,0,0,addr,CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
					break;
				case CMD_POPUP_ODUMP:
					if (addr==0) //do nothing
						return false;
					mem = Findmemory(addr);
					if (mem==NULL)
						return false;
					if (base==0) base=mem->base;
					if (size==0) size=mem->size;
					Createdumpwindow(NULL,base,size,NULL,0x01081,addr,NULL,NULL);
					break;
				default:
					break;
			}
		}
		iter++;
		n++;
	}
	return false;
}

void OllyLang::execCommand() {
	wstring codeLine;
	RECT Rect={0};
	if (&wndProg.hw) GetWindowRect(wndProg.hw,&Rect);

	wstring title = L"Execute Script Command...";
	HWND hw = 0; //not modal but dialog need to be closed on plugin close.
	HINSTANCE hinst = (HINSTANCE)GetModuleHandleW(PLUGIN_NAME L".dll");
	//wchar_t buffer[TEXTLEN]={0};
	//if (Gettextxy("Execute Script Command...",buffer, 0, 201, font, Rect.left,Rect.bottom)!=-1) {
	wchar_t* buffer = (wchar_t*)DialogBoxParamW(hinst, MAKEINTRESOURCE(IDD_INPUT), hw, (DLGPROC) InputDialogProc, (LPARAM)title.c_str());

	if (buffer != NULL && wcslen(buffer) > 0) {
		codeLine.assign(buffer);
		delete[] buffer;

		// Create command and arguments
		wstring command = codeLine;
		wstring args = L"";
		size_t pos = codeLine.find_first_of(L" \t\r\n");
		if(pos != -1)
		{
			command = w_trim(codeLine.substr(0, pos));
			int (*pf)(int)=tolower; 
			transform(command.begin(), command.end(), command.begin(), pf);
			//SetcaseW
			args = w_trim(codeLine.substr(pos));
		}

		bool result = this->callCommand(command, args);

		// Error in processing, show error and die
		if(!result)
		{
			wstring message = L"Error";
			message.append(L"\n");
			message.append(L"Text: ");
			message.append(codeLine);
			message.append(L"\n");
			if(!errorstr.empty())
			{
				message.append(errorstr);
				message.append(L"\n");
			}
			MessageBox(hwmain, message.c_str(), PLUGIN_NAME L" error", MB_ICONERROR | MB_OK | MB_TOPMOST);
			errorstr = L"";
		}
	}
}

//modify script execution cursor
bool OllyLang::jumpToLine(int number) {
	script_pos = number-1;
	pgr_scriptpos = number;
	return true;
}

void OllyLang::DumpLabels()
{
	cerr << "_ LABELS _" << endl;
	map<wstring, int>::iterator iter;
	iter = labels.begin();

	pair<wstring, int> p;
	while(iter != labels.end())
	{
		p = *iter;

		cerr << "Name: " << w_wstrto(p.first) << ", ";
		cerr << "Row: " << p.second << endl;
		iter++;
	}
	cerr << endl;
}

void OllyLang::DumpBPJumps()
{
	cerr << "_ LABELS _" << endl;
	map<int, int>::iterator iter;
	iter = bpjumps.begin();

	pair<int, int> p;
	while(iter != bpjumps.end())
	{
		p = *iter;

		cerr << "Addr: " << hex << p.first << ", ";
		cerr << "Row: " << p.second << endl;
		iter++;
	}
	cerr << endl;
}

void OllyLang::DumpVars()
{
	cerr << "_ VARS _" << endl;
	map<wstring, var>::iterator iter;
	iter = variables.begin();

	pair<wstring, var> p;
	while(iter != variables.end())
	{
		p = *iter;

		cerr << "Name: " << w_wstrto(p.first) << ", ";
		cerr << "Value: " << hex << p.second.dw << endl;
		iter++;
	}
	cerr << endl;
}

void OllyLang::DumpScript()
{
	cerr << "_ SCRIPT _" << endl;
	vector<wstring>::iterator iter;
	iter = script.begin();

	while(iter != script.end())
	{
		cerr << "--> " << w_wstrto(*iter) << endl;
		iter++;
	}
	cerr << endl;
}

void OllyLang::DropVariable(wstring var)
{
	if (variables.find(var) != variables.end())
		variables.erase(variables.find(var));
}

//Add zero char before dw values, ex: 0DEADBEEF (to be assembled) usefull if first char is letter
wstring OllyLang::FormatAsmDwords(wstring asmLine)
{
		// Create command and arguments
		wstring command = asmLine;
		wstring arg, sSep, args = L"";
		size_t pos = asmLine.find_first_of(L" \t\r\n");
		DWORD nbArgs=0;
		if(pos != wstring::npos)
		{
			command = w_trim(asmLine.substr(0, pos));
			args = w_trim(asmLine.substr(pos));

		} else {
			//no args
			return asmLine;
		}

		command+=L" ";

		while ((pos = args.find_first_of(L"+,[")) != wstring::npos)
		{
			arg=w_trim(args.substr(0, pos));
			ForLastArg:
			if (sSep.empty()) {
				if (arg.substr(arg.size()-1,1) == L"]") {
					arg = arg.substr(0,arg.size()-1);
					if (is_hex(arg) && arg.size()>0) {
						if (arg.substr(0,1).find_first_of(L"abcdefABCDEF") != wstring::npos)
							arg=L"0"+arg;
					}
					arg = arg + L"]";
				}
			} else {
				if (is_hex(arg) && arg.size()>0) {
					if (arg.substr(0,1).find_first_of(L"abcdefABCDEF") != wstring::npos)
						arg=L"0"+arg;
				}
			}

//		if (nbArgs)	
			command.append(sSep);
			command.append(arg);

			nbArgs++;
			if (! args.empty()) {
				sSep=args.substr(pos,1);
				args.erase(0,pos+1);
			}
		}

		args=w_trim(args);
		if (! args.empty()) { 
			arg=args;
			args=L"";
			goto ForLastArg;
		}

		return w_trim(command);
}

DWORD OllyLang::AddProcessMemoryBloc(wstring data, int mode)
{
	HANDLE hDebugee = _process;
	DWORD pmem;

	// Allocate memory for data
	pmem = (DWORD) VirtualAllocEx(hDebugee, NULL, data.size(), MEM_COMMIT, mode);

	return pmem;
}

DWORD OllyLang::AddProcessMemoryBloc(int size, int mode)
{
	HANDLE hDebugee = _process;
	DWORD pmem;

	// Allocate memory for data
	pmem = (DWORD) VirtualAllocEx(hDebugee, NULL, size, MEM_COMMIT, mode);

	return pmem;
}

bool OllyLang::DelProcessMemoryBloc(DWORD address)
{
	HANDLE hDebugee = _process;

	t_memory* tmem = Findmemory(address);

	if (tmem!=NULL) {
		VirtualFreeEx(hDebugee, (void*) tmem->base, tmem->size, MEM_DECOMMIT);
		return true;
	}

	return false;
}

bool OllyLang::ExecuteASM(wstring command)
{
	// Old eip
	ulong eip;
	// For Assemble API
	uchar umodel[255] = {0};
	wchar_t error[255] = {0};
	wchar_t buffer[255] = {0};
	// Bytes assembled
	int len = 0, totallen = 0;
	bool res = true;
	// Temp storage
	wstring tmp;

	// Get process handle and save eip
	t_thread* thr = Findthread(Getcputhreadid());
	eip = thr->reg.ip;

	HANDLE hDebugee = _process;

	// Allocate memory for code
	DWORD pmemexec = (DWORD) VirtualAllocEx(hDebugee, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Assemble and write code to memory (everything between EXEC and ENDE)

	tmp = ResolveVarsForExec(command,true);
	wsprintf(buffer, tmp.c_str());
	len = Assemble(buffer, pmemexec + totallen, umodel, 0, 0, error);
	if (len < 0) {
		errorstr = tmp+L"\n"+error;
		return false;
	} else {
		WriteProcessMemory(hDebugee, (LPVOID)(pmemexec + totallen), umodel, len, 0);
		totallen += len;
	}

	// Assemble and write jump to original EIP
	wsprintf(buffer, L"JMP 0%lX", eip);
	len = Assemble(buffer, pmemexec + totallen, umodel, 0, 0, error);
	if (len < 0) {
		errorstr = error;
	} else {
		WriteProcessMemory(hDebugee, (LPVOID)(pmemexec + totallen), umodel, len, 0);
	}

	// Set new eip and run to the original one
	thr->reg.ip = pmemexec;
	thr->reg.status = RV_MODIFIED;
	thr->regvalid = 1;
	Redrawcpureg();
	//Go(Getcputhreadid(), eip, STEP_RUN, 0, 1);
	Broadcast(WM_USER_KEY, 0, 0);

	// Free memory block after next ollyloop
	t_dbgmemblock block={0};
	block.hmem = (void *) pmemexec;
	block.size = 0x1000;
	block.script_pos = script_pos;
	block.free_at_eip = eip;
	block.autoclean = true;

	regBlockToFree(block);
	require_addonaction = 1;
	require_ollyloop = 1;

	return true;
}


bool OllyLang::isCommand(wstring cmd)
{
	return (commands.find(cmd) != commands.end());
}

bool OllyLang::callCommand(wstring cmd, wstring args)
{
	if(commands.find(cmd) != commands.end())
	{
		// Command found, execute it
		PFCOMMAND func = commands[cmd];

		return (this->*func)(args);
	}
	return false;
}

void OllyLang::regBlockToFree(t_dbgmemblock &block)
{
	tMemBlocks.push_back(block);
}

void OllyLang::regBlockToFree(void * hMem, ulong size, bool autoclean)
{
	t_dbgmemblock block={0};
	block.hmem = hMem;
	block.size = size;	
	block.autoclean = autoclean; 
	block.script_pos = script_pos;
	block.restore_registers = 0;
	block.listmemory = 0;

	tMemBlocks.push_back(block);
}

bool OllyLang::unregMemBlock(void * hMem)
{
	vector<t_dbgmemblock>::iterator block = tMemBlocks.end();
	for (int b=tMemBlocks.size(); b>0; b--) {
		block--;		
		if (block->hmem == hMem) {
			tMemBlocks.erase(block);
			return true;
		}
	}
	return false;
}


bool OllyLang::freeMemBlocks()
{
	if (!tMemBlocks.empty()) {

		if (_process == NULL)
			return false;

		vector<t_dbgmemblock>::iterator block = tMemBlocks.end();
		while (tMemBlocks.size() > 0) {
			block--;
			if (block->autoclean)
				VirtualFreeEx(_process,block->hmem,block->size,MEM_DECOMMIT);
			tMemBlocks.pop_back();
		}

		tMemBlocks.clear();
		return true;
	}
	return false;
}

bool OllyLang::SaveRegisters(bool stackToo)
{

	t_thread* pt = Findthread(Getcputhreadid());			

	reg_backup.eax = pt->reg.r[REG_EAX];
	reg_backup.ebx = pt->reg.r[REG_EBX];
	reg_backup.ecx = pt->reg.r[REG_ECX];
	reg_backup.edx = pt->reg.r[REG_EDX];
	reg_backup.esi = pt->reg.r[REG_ESI];
	reg_backup.edi = pt->reg.r[REG_EDI];

	if (stackToo) {
		reg_backup.esp = pt->reg.r[REG_ESP];
		reg_backup.ebp = pt->reg.r[REG_EBP];
	}

	reg_backup.dwFlags = pt->reg.flags;

	reg_backup.eip = pt->reg.ip;

	reg_backup.threadid = pt->reg.threadid;
	reg_backup.loaded = script_pos || 1;

	return true;
}

bool OllyLang::RestoreRegisters(bool stackToo)
{
	if (!reg_backup.loaded)
		return false;

	t_thread* pt = Findthread(Getcputhreadid());			

	if (pt->reg.threadid != reg_backup.threadid)
		return false;

	pt->reg.r[REG_EAX] = reg_backup.eax;
	pt->reg.r[REG_EBX] = reg_backup.ebx;
	pt->reg.r[REG_ECX] = reg_backup.ecx;
	pt->reg.r[REG_EDX] = reg_backup.edx;
	pt->reg.r[REG_ESI] = reg_backup.esi;
	pt->reg.r[REG_EDI] = reg_backup.edi;

	if (stackToo) {
		pt->reg.r[REG_ESP] = reg_backup.esp;
		pt->reg.r[REG_EBP] = reg_backup.ebp;
	}	

	pt->reg.flags = reg_backup.dwFlags;

	pt->reg.status = RV_MODIFIED;
	pt->regvalid = 1;
	Redrawcpureg();

	return true;
}

bool OllyLang::AllocSwbpMem(uint tmpSizet)
{	
	if (tmpSizet==0) {
		FreeBpMem();
		return true;
	}

	if (softbp_t && tmpSizet < alloc_bp)
		return true;

	try
	{
		if (softbp_t)
			softbp_t = (t_bpoint*)realloc((void *)softbp_t, sizeof(t_bpoint*) * tmpSizet);
		else
			softbp_t = (t_bpoint*)malloc(sizeof(t_bpoint*) * tmpSizet);
		alloc_bp = tmpSizet;
	}
	catch( ... )
	{
		return false;
	}
	return true;
}

void OllyLang::FreeBpMem()
{
	if (softbp_t) {
		free((void *) softbp_t);
		softbp_t = NULL;
	}
	saved_bp = 0;
	alloc_bp = 0;
}

void OllyLang::addHistoryStep(int line)
{
	struct t_exec_history step = {0};

	step.line = line;
	step.time = GetTickCount();
	execHistory.push_back(step);
	execCursor++;
	if (execCursor > 1024) {
		//cleanup...
		for (int i=0; i<512; i++) {
			execHistory.erase(execHistory.begin());
		}
		execCursor = execHistory.size()-1;
	}
}

#include "var.cpp"

#include "OllyLangCommands.cpp"
