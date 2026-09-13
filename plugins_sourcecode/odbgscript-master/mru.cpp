//NOTE : OllyDBG Main Menu is Static... so we need to store MRU for next OllyDbg start

void mruAddFile(wstring filePath) {
	
	wchar_t buf[4096] = {0};

	int n;
	wchar_t key[5];
	StrCpyW(key,L"NRU ");

	for(n=1; n<=9; n++) { 
		key[3]=n + 0x30; //ASCII n
		ZeroMemory(&buf, sizeof(buf));
		Getfromini(NULL,PLUGIN_NAME, key, L"%s", buf);
		if (wcscmp(buf,filePath.c_str())==0) {
			//Move File to first MRU
			key[3]='1';
			//Pluginreadstringfromini(h,key,buf,0);
			Getfromini(NULL,PLUGIN_NAME, key, L"%s", buf);
			//Pluginwritestringtoini(h,key,szFilePath);
			Writetoini(NULL,PLUGIN_NAME, key, L"%s", (wchar_t*) filePath.c_str() );
			key[3]=n + 0x30;
			//Pluginwritestringtoini(h,key,buf);
			Writetoini(NULL,PLUGIN_NAME, key, L"%s", buf);
			return;
		}
	}
	for(n=9; n>0; n--) {
		//Add File then Move others
		key[3]=n+0x30;
		ZeroMemory(&buf, sizeof(buf));
		//Pluginreadstringfromini(h,key,buf,0);
		Getfromini(NULL,PLUGIN_NAME, key, L"%s", buf);
		if (wcslen(buf)) {
			key[3]=n+1+0x30;
			//Pluginwritestringtoini(h,key,buf);
			Writetoini(NULL,PLUGIN_NAME, key, L"%s", buf);
		}
	}
	
	key[3]='1';
	//Pluginwritestringtoini(h, key, szFilePath);
	Writetoini(NULL,PLUGIN_NAME, key, L"%s", (wchar_t*) filePath.c_str() );

}

//ON MAIN MENU, ITS CALLED ONCE
/*
int  mruGetMenu(char* buf) {

	char buf2[4096] = {0};
	char key[5];
	char key2[5];
	int p=0;
	int c,v;
	string path;
	
	strcpy(key,"NRU ");
	strcpy(key2,"MRU ");

 	for(int n=1; n<=5; n++) {
		key[3]=n+0x30; //ASCII n
		key2[3]=key[3];

		ZeroMemory(&buf2, sizeof(buf2));
		Getfromini(NULL,PLUGIN_NAME, key, L"%s", buf2)
		Pluginwritestringtoini(0,key2, buf2);
		if (strlen(buf2)) {
			if (PathFileExists(buf2)) {
				buf[p]=0x32;   p++;
				buf[p]=key[3]; p++;
				buf[p]=0x20;   p++;
				
				path=buf2;
				c=path.rfind('\\') + 1;

				while ( (v = strchr(&buf2[c],',')-&buf2[c]) > 0) {
					buf2[c+v]='.';
				}
				while ( (v = strchr(&buf2[c],'{')-&buf2[c]) > 0) {
					buf2[c+v]='[';
				}
				while ( (v = strchr(&buf2[c],'}')-&buf2[c]) > 0) {
					buf2[c+v]=']';
				}

				strcpy(&buf[p],&buf2[c]); p+=strlen(&buf2[c]);
				buf[p]=',';p++; 
			}
		}
	}
	if (p>0) buf[--p]=0;

	return p;
}
*/

//ON DISASM WINDOW, ITS CALLED ON CONTEXT MENU
int mruGetCurrentMenu(wchar_t* buf) {

	wchar_t buf2[4096] = {0};
	wchar_t key[5];
	int p=0;
	int c,v;
	wstring path;

	wcscpy(key,L"NRU ");

 	for(int n=1; n<=9; n++) {
		key[3]=n+0x30; //ASCII n

		ZeroMemory(&buf2, sizeof(buf2));
		Getfromini(NULL,PLUGIN_NAME, key, L"%s", buf2);
		if (wcslen(buf2)) {
			if (PathFileExists(buf2)) {
				buf[p]=0x32;   p++;
				buf[p]=key[3]; p++;
				buf[p]=0x20;   p++;
				
				path=buf2;
				c=path.rfind('\\') + 1;

				while ( (v = wcschr(&buf2[c],',')-&buf2[c]) > 0) {
					buf2[c+v]='.';
				}
				while ( (v = wcschr(&buf2[c],'{')-&buf2[c]) > 0) {
					buf2[c+v]='[';
				}
				while ( (v = wcschr(&buf2[c],'}')-&buf2[c]) > 0) {
					buf2[c+v]=']';
				}

				StrCpyW(&buf[p],&buf2[c]); p+=wcslen(&buf2[c]);
				buf[p]=',';p++; 
			}
		}
	}
	if (p>0) buf[--p]=0;

	return p;

}

int mruGetCurrentMenu(HMENU mmru,int cmdIndex) {

	wchar_t buf2[4096] = {0};
	wchar_t key[5];	
	int c,v;
	wstring path;

	wcscpy(key,L"NRU ");

 	for(int n=1; n<=9; n++) {
		key[3]=n+0x30; //ASCII n

		ZeroMemory(&buf2, sizeof(buf2));
		Getfromini(NULL,PLUGIN_NAME, key, L"%s", buf2);
		if (wcslen(buf2)) {
			if (PathFileExists(buf2)) {
				path=buf2;
				c=path.rfind('\\') + 1;
				AppendMenu(mmru,MF_STRING,cmdIndex+n,&buf2[c]);
			}
		}
	}

	return 1;
}


int mruCmdMenu(HMENU mmru,int cmdIndex) {

	AppendMenu(mmru,MF_STRING,cmdIndex+1,L"ESP¶¨ÂÉ");
	return 1;
}




//MessageBox(hwmain,buf,"",MB_OK|MB_ICONEXCLAMATION|MB_TOPMOST);