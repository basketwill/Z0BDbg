DWORD strCurEIP; 
wchar_t  szFileName[MAX_PATH]={0},szFile[MAX_PATH]={0},szWorkPath[MAX_PATH]={0};
BOOL  FixSect = true;
wchar_t  buf[TEXTLEN];
#define PNAME   L"Scripted PE Dumper"

typedef struct {
	WORD  woNumOfSect;
	DWORD dwImageBase;
	DWORD dwSizeOfImage;
	DWORD dwAddrOfEP;
	DWORD dwBaseOfCode;
	DWORD dwBaseOfData;
} PEFILEINFO, *LPPEFILEINFO;

typedef struct {
	BYTE  byName[IMAGE_SIZEOF_SHORT_NAME];
	DWORD dwVSize;
	DWORD dwVOffset;
	DWORD dwRSize;
	DWORD dwROffset;
	DWORD dwCharacteristics;
} SECTIONINFO, *LPSECTIONINFO;

PEFILEINFO    PEFileInfo,PEFileInfoWrk;
SECTIONINFO   SectInfoWrk;
LPSECTIONINFO lpSectInfo = NULL;;
LPTSTR DbgePath;
LPSTR DbgeName;
LPSTR lpszSectName;