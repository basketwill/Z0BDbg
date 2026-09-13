#pragma once

#include "StdAfx.h"


typedef unsigned long DWORD;
typedef unsigned int uint;
typedef unsigned char BYTE;

enum {SS_NONE, SS_INITIALIZED, SS_LOADED, SS_RUNNING, SS_PAUSED};

using namespace std;

// Dialogs
INT_PTR CALLBACK InputDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

#include "Progress.h"
#include "LogWindows.h"

// This is the table for Script Execution
typedef struct t_dbgmemblock {

	void *	hmem;		 //Memory Adress
	ulong	size;		 //Block Size
	int		script_pos;	 //Registred at script pos
	bool	autoclean;	 //On script restart/change

	ulong	free_at_eip; //To free memory block used in ASM commands

	//Optional actions to do
	bool	restore_registers;
	bool	listmemory;

	//Delayed Result Origin
	bool	result_register;
	int		reg_to_return;

} t_dbgmemblock;

typedef struct t_export {

	ulong addr;
	char  label[TEXTLEN];

} t_export;

typedef struct t_exec_history {
	unsigned long	line;
	unsigned long	time;
} t_exec_history;

class OllyLang
{
public:

	//Window Objects
	t_table wndProg;
	vector<t_wndprog_data> tProgLines;
	uint pgr_scriptpos;
	uint pgr_scriptpos_paint;

	t_table wndLog;
	vector<t_wndlog_data> tLogLines;

	wstring scriptpath;
	wstring currentdir;

	//allocated memory blocks to free at end of script
	vector<t_dbgmemblock> tMemBlocks;

	//to know if dialog is opened, to destroy on reset
	HWND hwndinput;

	//last breakpoint reason
	ulong break_reason;
	ulong break_memaddr;

	// Constructor & destructor
	OllyLang();
	~OllyLang();

	// Public methods
//	int GetState();
	bool LoadScript(wstring fileName);
	bool SaveBreakPoints(wstring fileName);
	bool LoadBreakPoints(wstring fileName);

	bool Pause();
	bool Resume();
	bool Reset();
	bool Step(int forceStep);
	bool ProcessAddonAction();

	// Script Window
	int GetFirstCodeLine(int from);

	void menuListLabels(HMENU mLabels,int cmdIndex);
	void menuListVariables(HMENU mVars,int cmdIndex);

	bool editVariable(int nVar);
	bool followVariable(int nVar);
	void execCommand(void);

	bool jumpToLine(int number);

	int SearchInScript(wstring text, ulong fromPos);

	// "Events"
	bool OnBreakpoint(int reason, int details);
	bool OnException(DWORD ExceptionCode);

	// For ODBG_Plugincmd (external calls)
	bool isCommand(wstring cmd);
	bool callCommand(wstring cmd, wstring args);

	// Free Allocated Virtual Memory
	bool freeMemBlocks();
	void regBlockToFree(t_dbgmemblock &block);
	void regBlockToFree(void * hMem, ulong size, bool autoclean);
	bool unregMemBlock(void * hMem);

	// History
	void addHistoryStep(int line);

	// The script that is being executed
	vector<wstring> script;
	// Variables that exist
	map<wstring, var> variables;
	// Labels in script
	map<wstring, int> labels;
	// Breakpoint Auto Jumps
	map<int, int> bpjumps;
	// Call/Ret in script
	vector<ulong> calls;
	// IF/ELSE in script
	vector<wstring> conditions;

	bool showVarHistory;

	int script_state;
	bool require_ollyloop;
	bool require_addonaction;

	//hwnd to t_dump (OPENDUMP/BACKUP)
	map<HWND, t_dump*> dumpWindows;

	//left/right cursor to move like history
	vector<t_exec_history> execHistory;
	int execCursor;

private:

	typedef bool (OllyLang::*PFCOMMAND)(wstring);
	// Commands that can be executed
	map<wstring, PFCOMMAND> commands;
	// Possible register names
	set<wstring> reg_names;
	// Possible flag names
	set<wstring> flag_names;
	// Possible segment registers
	set<wstring> seg_names;

	bool bUnicode;

	union eflags
	{
		DWORD dwFlags;
		struct flagbits
		{
			unsigned CF : 1;
			unsigned dummy1 : 1;
			unsigned PF : 1;
			unsigned dummy2 : 1;
			unsigned AF : 1;
			unsigned dummy3 : 1;
			unsigned ZF : 1;
			unsigned SF : 1;
			unsigned TF : 1;
			unsigned IF : 1;
			unsigned DF : 1;
			unsigned OF : 1;
		} bitFlags;
	};

	bool enable_logging;
	uint script_pos;

	bool var_logging;
	bool sub_operand;

	int EOB_row;
	int EOE_row;

	bool bInternalBP;
	ulong nIgnoreNextValuesHist;

	wstring errorstr;

	DWORD tickcount;
	DWORD tickcounthi;
	ULONGLONG tickcount_startup;

	unsigned char * search_buffer;

	// Pseudo-flags to emulate CMP
	BYTE zf, cf;
	HWND hwmain;
	// Cursor for REF / (NEXT)REF function
	int adrREF; int curREF;

	// Commands
	bool DoADD(wstring args);
	bool DoAI(wstring args);
	bool DoALLOC(wstring args);
	bool DoANA(wstring args);
	bool DoAND(wstring args);
	bool DoAO(wstring args);
	bool DoASK(wstring args);
	bool DoASM(wstring args);
	bool DoASMTXT(wstring args);
	bool DoATOI(wstring args);
//	bool DoBACKUP(wstring args);
	bool DoBC(wstring args);
	bool DoBCA(wstring args);
	bool DoBD(wstring args);
	bool DoBDA(wstring args);
	bool DoBEGINSEARCH(wstring args);
	bool DoBP(wstring args);
//	bool DoBPCND(wstring args);
//	bool DoBPD(wstring args);
//	bool DoBPGOTO(wstring args);
//	bool DoBPHWCA(wstring args);
//	bool DoBPHWC(wstring args);
//	bool DoBPHWS(wstring args);
//	bool DoBPL(wstring args);
//	bool DoBPLCND(wstring args);
//	bool DoBPMC(wstring args);
//	bool DoBPRM(wstring args);
//	bool DoBPWM(wstring args);
//	bool DoBPX(wstring args);
//	bool DoBUF(wstring args);
//	bool DoCALL(wstring args);
//	bool DoCLOSE(wstring args);
//	bool DoCMP(wstring args);
//	bool DoCMT(wstring args);
//	bool DoCOB(wstring args);
//	bool DoCOE(wstring args);
//	bool DoCRET(wstring args);
//	bool DoDBH(wstring args);
//	bool DoDBS(wstring args);
//	bool DoDEC(wstring args);
//	bool DoDIV(wstring args);
//	bool DoDM(wstring args);
//	bool DoDMA(wstring args);
//	bool DoDPE(wstring args);
//	bool DoELSE(wstring args);
//	bool DoENDE(wstring args);
//	bool DoENDIF(wstring args);
	bool DoENDSEARCH(wstring args);
//	bool DoEOB(wstring args);
//	bool DoEOE(wstring args);
	bool DoERUN(wstring args);
	bool DoESTEP(wstring args);
	bool DoESTI(wstring args);
//	bool DoEVAL(wstring args);
//	bool DoEXEC(wstring args);
//	bool DoFILL(wstring args);
//	bool DoFIND(wstring args);
//	bool DoFINDCALLS(wstring args);
//	bool DoFINDCMD(wstring args);
//	bool DoFINDOP(wstring args);
//	bool DoFINDOPREV(wstring args);
//	bool DoFINDMEM(wstring args);
//	bool DoFREE(wstring args);
//	bool DoGAPI(wstring args);
//	bool DoGBPM(wstring args);
//	bool DoGBPR(wstring args);
//	bool DoGCI(wstring args);
//	bool DoGCMT(wstring args);
//	bool DoGFO(wstring args);
//	bool DoGLBL(wstring args);
//	bool DoGMA(wstring args);
//	bool DoGMEMI(wstring args);
//	bool DoGMEXP(wstring args);
//	bool DoGMI(wstring args);
//	bool DoGMIMP(wstring args);
//	bool DoGN(wstring args);
//	bool DoGO(wstring args);
//	bool DoGOPI(wstring args);
//	bool DoGPA(wstring args);
//	bool DoGPP(wstring args);
//	bool DoGPI(wstring args);
//	bool DoGREF(wstring args);
//	bool DoGRO(wstring args);
//	bool DoGSL(wstring args);
//	bool DoGSTR(wstring args);
//	bool DoGSTRW(wstring args);
//	bool DoHANDLE(wstring args);
//	bool DoHISTORY(wstring args);
//	bool DoElse(void);
//	bool DoIFA(wstring args);
//	bool DoIFAE(wstring args);
//	bool DoIFB(wstring args);
//	bool DoIFBE(wstring args);
//	bool DoIFEQ(wstring args);
//	bool DoIFNEQ(wstring args);
//	bool DoINC(wstring args);
	bool DoINIR(wstring args);
	bool DoINIW(wstring args);
	bool DoITOA(wstring args);
//	bool DoJA(wstring args);
//	bool DoJAE(wstring args);
//	bool DoJB(wstring args);
//	bool DoJBE(wstring args);
//	bool DoJE(wstring args);
//	bool DoJMP(wstring args);
//	bool DoJNE(wstring args);
//	bool DoKEY(wstring args);
//	bool DoLBL(wstring args);
//	bool DoLC(wstring args);
//	bool DoLCLR(wstring args);
//	bool DoLEN(wstring args);
//	bool DoLOADLIB(wstring args);
	bool DoLOG(wstring args);
	bool DoLOGBUF(wstring args);
	bool DoLM(wstring args);
	bool DoMEMCOPY(wstring args);
	bool DoMOV(wstring args);
	bool DoMSG(wstring args);
	bool DoMSGYN(wstring args);
	bool DoMUL(wstring args);
	bool DoNAMES(wstring args);
	bool DoNEG(wstring args);
	bool DoNOT(wstring args);
	bool DoOLLY(wstring args);
	bool DoOR(wstring args);
//	bool DoOPCODE(wstring args);
//	bool DoOPENDUMP(wstring args);
//	bool DoOPENTRACE(wstring args);
	bool DoPAUSE(wstring args);
	bool DoPOP(wstring args);
	bool DoPOPA(wstring args);
//	bool DoPREOP(wstring args);
	bool DoPUSH(wstring args);
	bool DoPUSHA(wstring args);
//	bool DoRBP(wstring args);
//	bool DoREADSTR(wstring args);
	bool DoREFRESH(wstring args);
//	bool DoREPL(wstring args);
//	bool DoRESET(wstring args);
//	bool DoREF(wstring args);
//	bool DoRET(wstring args);
//	bool DoREV(wstring args);
//	bool DoROL(wstring args);
//	bool DoROR(wstring args);
//	bool DoRTR(wstring args);
//	bool DoRTU(wstring args);
//	bool DoRUN(wstring args);
//	bool DoSBP(wstring args);
//	bool DoSCMP(wstring args);
//	bool DoSCMPI(wstring args);
//	bool DoSETOPTION(wstring args);
//	bool DoSHL(wstring args);
//	bool DoSHR(wstring args);
	bool DoSTI(wstring args);
	bool DoSTO(wstring args);
//	bool DoSTR(wstring args);
//	bool DoSUB(wstring args);
//	bool DoTC(wstring args);
//	bool DoTEST(wstring args);
//	bool DoTI(wstring args);
//	bool DoTICK(wstring args);
//	bool DoTICND(wstring args);
//	bool DoTO(wstring args);
//	bool DoTOCND(wstring args);
//	bool DoUNICODE(wstring args);
	bool DoVAR(wstring args);
	bool DoXOR(wstring args);
	bool DoXCHG(wstring args);
	bool DoWRT(wstring args);
	bool DoWRTA(wstring args);

	// Helper functions
	vector<wstring> GetScriptFromFile(wstring fileName);
	int InsertScript(vector<wstring> toInsert, int posInScript);
	int getStringOperatorPos(wstring &ops);
	int getDWOperatorPos(wstring &ops);
	int getFLTOperatorPos(wstring &ops);
	bool CreateOperands(wstring& args, wstring ops[], uint len, bool preferstr=false);
	bool CreateOp(wstring& args, wstring ops[], uint len, bool preferstr=false);
	bool GetBYTEOpValue(wstring op, BYTE &value);
	bool GetDWOpValue(wstring op, DWORD &value, DWORD default_val=0);
	bool GetAddrOpValue(wstring op, DWORD &value);
	bool GetFLTOpValue(wstring op, long double &value);
	bool GetSTROpValue(wstring op, wstring &value, int size=0);
	bool GetANYOpValue(wstring op, wstring &value, bool hex8forExec=false);
	void LogRegNr(wstring& name);
	int GetRegNr(wstring& name);
	int GetSegNr(wstring& name);
	bool is_register(wstring s);
	bool is_segment(wstring s);
	bool is_floatreg(wstring s);
	bool is_flag(wstring s);
	bool is_variable(wstring& s);

	bool ParseLabels();
	bool Process(wstring& codeLine);
	bool AddBPJump(int bpaddr,int labelpos);

	wstring ResolveVarsForExec(wstring in,bool hex8forExec);

	// Debug functions
	void DumpVars();
	void DumpLabels();
	void DumpBPJumps();
	void DumpScript();

	void DropVariable(wstring var);

	wstring FormatAsmDwords(wstring asmLine);

	DWORD AddProcessMemoryBloc(wstring data, int mode=PAGE_READWRITE);
	DWORD AddProcessMemoryBloc(int size, int mode=PAGE_READWRITE);
	bool  DelProcessMemoryBloc(DWORD address);

	bool ExecuteASM(wstring command);

	// Save / Restore Breakpoints
	t_bphard hwbp_t[4];
	t_sorted sortedsoftbp_t;
	t_bpoint* softbp_t;

	uint saved_bp;
	uint alloc_bp;
	bool AllocSwbpMem(uint tmpSizet);
	void FreeBpMem();

	// Save / Restore Registers
	struct t_reg_backup
	{
		int loaded;
		DWORD threadid;

		DWORD eax;
		DWORD ebx;
		DWORD ecx;
		DWORD edx;
		DWORD esi;
		DWORD edi;

		DWORD esp;
		DWORD ebp;

		DWORD dwFlags;

		DWORD eip;

	} reg_backup;

	bool SaveRegisters(bool stackToo);
	bool RestoreRegisters(bool stackToo);

	//cache for GMEXP
	vector<t_export> tExportsCache;
	ulong exportsCacheAddr;

	//cache for GMIMP
	vector<t_export> tImportsCache;
	ulong importsCacheAddr;

};
