void mruAddFile(wstring szFilePath);
//int  mruGetMenu(char* buf);
int  mruGetCurrentMenu(wchar_t* buf);
int  mruGetCurrentMenu(HMENU mmru, int cmdIndex); // For Dynamic MRU List (Script Window Context Menu)
int  mruCmdMenu(HMENU mmru,int cmdindex);