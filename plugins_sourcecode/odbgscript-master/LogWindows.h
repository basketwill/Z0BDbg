#define LOG_MSG_LEN TEXTLEN

// This is the table for Script Execution
typedef struct t_wndlog_data {

	unsigned long	line;
	unsigned long	size;             // Size occupied by element in address space
	unsigned long	type;             // Type of data element, TY_xxx
	unsigned long	eip;
	wchar_t  message[LOG_MSG_LEN];

} t_logwnd_data; 

//LRESULT CALLBACK wndlog_winproc(HWND hw,UINT msg,WPARAM wp,LPARAM lp);
long wndlog_func(t_table *pt,HWND hw,UINT msg,WPARAM wp,LPARAM lp);

void initLogWindow();

DESTFUNC wndlog_dest_function;
SORTFUNC wndlog_sort_function;
DRAWFUNC wndlog_get_text;
TABFUNC  wndlog_func;

int add2log(wstring & command);
int add2log(wchar_t * command);

int add2logMasked(wchar_t* message,wchar_t* mask);

void clearLogLines();

int SearchInLog(wstring text,ulong fromPos);