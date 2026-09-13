#include "var.h"

var::var()
{
	vt = EMP;
	dw = 0;
	flt = 0;
	str = L"";
	size = 0;
	isbuf = false;
}

var::var(const var& rhs)
{
	vt = rhs.vt;
	dw = rhs.dw;
	flt = rhs.flt;
	str = rhs.str;
	size = rhs.size;
	isbuf = rhs.isbuf;
}

var::var(wstring& rhs)
{
	vt = STR;
	dw = 0;
	flt = 0;
	str  = rhs;
	wstring s=rhs;
	if (UnquoteString(s,'#','#')) {
		size = s.length()/2;
		int (*pf)(int) = toupper; 
		transform(str.begin(), str.end(), str.begin(), pf);
		isbuf = true;
	} else {
		size = rhs.length();
		isbuf = false;
	}
}

var::var(ulong rhs)
{
	vt = DW;
	dw = rhs;
	flt = 0;
	str = L"";
	size = sizeof(rhs);
	isbuf = false;
}

var::var(int rhs)
{
	vt = DW;
	dw = (ulong)rhs;
	flt = 0;
	str = L"";
	size = sizeof(rhs);
	isbuf = false;
}

var::var(long double rhs)
{
	vt = FLT;
	flt = rhs;
	dw = 0;
	str = L"";
	size = sizeof(rhs);
	isbuf = false;
}


var& var::operator=(const var& rhs)
{
	vt = rhs.vt;
	dw = rhs.dw;
	str = rhs.str;
	flt = rhs.flt;
	size = rhs.size;
	isbuf = rhs.isbuf;
	return *this;
}

var& var::operator=(const wstring& rhs)
{
	vt = STR;
	dw = 0;
	flt = 0;
	str = rhs;
	wstring s=rhs;
	if (UnquoteString(s,'#','#')) {
		size = s.length()/2;
		int (*pf)(int) = toupper; 
		transform(str.begin(), str.end(), str.begin(), pf);
		isbuf = true;
	} else {
		size = rhs.length();
		isbuf = false;
	}
	return *this;
}

var& var::operator=(const ulong& rhs)
{
	vt = DW;
	dw = rhs;
	flt = 0;
	str = L"";
	size = sizeof(rhs);
	isbuf = false;
	return *this;
}

var& var::operator=(const int& rhs)
{
	vt = DW;
	dw = (ulong)rhs;
	flt = 0;
	str = L"";
	size = sizeof(rhs);
	isbuf = false;
	return *this;
}

var& var::operator=(unsigned short& rhs)
{
	vt = DW;
	dw = rhs;
	flt = 0;
	str = L"";
	size = sizeof(rhs);
	isbuf = false;
	return *this;
}

var& var::operator=(unsigned char& rhs)
{
	vt = DW;
	dw = rhs;
	flt = 0;
	str = L"";
	size = sizeof(rhs);
	isbuf = false;
	return *this;
}

var& var::operator=(const long double& rhs)
{
	vt = FLT;
	dw = 0;
	flt = (long double)rhs;
	str = L"";
	size = sizeof(rhs);
	isbuf = false;
	return *this;
}

var& var::operator+=(const var& rhs)
{
	if(rhs.vt == DW)
		*this+=rhs.dw;
	else if(rhs.vt == FLT)
		*this+=rhs.flt;
	else if(rhs.vt == STR) {
		//operator+=(const wstring& rhs)
		*this+=rhs.str;
	}
	return *this;
}

var& var::operator+=(const wstring& rhs)
{
	wstring s;
	if(vt == STR) {
		wstring s=rhs;
		if (UnquoteString(s,'#','#')) {
			if (!isbuf) {
				//String + buf Hex Buffer to String ok
				size_t len=s.length()/2;
				wchar_t* buf = (wchar_t*)malloc(len*2+1);
				Str2Rgch(s,buf,len+1);
				s.assign(buf,len);
				str  += s;
				size += len;
				free(buf);
			} else { 
				// Buffer + Buffer
				str = L"#"+str.substr(1,str.length()-2)+s+L"#";
				size += s.length()/2;
			}
		} else {
			if (!isbuf) {
				//str + str
				str += rhs;
				size += rhs.length();
			} else {
				//buf + str
				wstring Hex;
				Str2Hex(s,Hex,s.length());
				str = L"#"+str.substr(1,str.length()-2)+Hex+L"#";
				size += s.length();
			}
		}

	} else if(vt == DW) {
		var v=(wstring)rhs;

		wchar_t dwbuf[12];
		if (v.isbuf) {
			//ulong + BUFFER >> CONCATE HEX
			s = strbuffhex();
			wsprintf(dwbuf, L"%08X",dw);
			*this = L"#"+((wstring)dwbuf)+s+L"#";
		} else {
			//ulong + STRING >> CONCATE _ultow+str
			s = _wcsupr(_ultow(dw, dwbuf, 16));
			*this = s+v.str;
		}
	}

	return *this;
}

var& var::operator+=(const ulong& rhs)
{
	if(vt == DW)
		dw += rhs;
	else if(vt == FLT)
		flt += rhs;
	else if(vt == STR) {
		wstring s;
		wchar_t dwbuf[12];
		if (isbuf) {
			//Concate Num ulong to a buffer (4 octets)
			s = strbuffhex();
			wsprintf(dwbuf, L"%08X",rev(rhs));
			*this = L"#" + s + dwbuf + L"#";
		} else {
			//Add Number to a String
			s = _wcsupr(_ultow(rhs, dwbuf, 16));
			str += s;
			size += s.length();
		}
	}
	return *this;
}

var& var::operator+=(const int& rhs)
{
	if(vt == DW)
		dw += (ulong)rhs;
	else if(vt == FLT)
		flt += rhs;
	else if(vt == STR)
		*this+=(ulong) rhs;

	return *this;
}

var& var::operator+=(const long double& rhs)
{
	if(vt == FLT)
		flt += (long double)rhs;
	return *this;
}

int var::compare(const var& rhs) const
{
	// less than zero this < rhs
	// zero this == rhs 
	// greater than zero this > rhs 
	if(vt != rhs.vt || vt == EMP || rhs.vt == EMP)
		return -2;
	
	if(vt == DW)
	{
		if(dw < rhs.dw) return -1;
		if(dw == rhs.dw) return 0;
		if(dw > rhs.dw) return 1;
	} 	
	else if(vt == FLT)
	{
		if(flt < rhs.flt) return -1;
		if(flt == rhs.flt) return 0;
		if(flt > rhs.flt) return 1;
	}
	else if(vt == STR) {
		if (isbuf == rhs.isbuf)
			return str.compare(rhs.str);
		else {
			wstring Hex;
			if (isbuf) {
				//Buffer / String
				wstring s=str;
				UnquoteString(s,'#','#');
				Str2Hex((wstring)rhs.str,Hex,rhs.size);
				return s.compare(Hex);
			} else { 
				//String / Buffer
				wstring s=rhs.str;
				UnquoteString(s,'#','#');
				Str2Hex((wstring)str,Hex,size);
				return Hex.compare(s);
			}
		}
	}
	return 0;
}

int var::compare(const wstring& rhs) const
{
	var tmp;
	tmp.vt = STR;
	tmp.str = rhs;
    return compare(tmp);
}

int var::compare(const ulong& rhs) const
{
	var tmp(rhs);
	return compare(tmp);
}

int var::compare(const int& rhs) const
{
	var tmp(rhs);
	return compare(tmp);
}

int var::compare(const long double& rhs) const
{
	var tmp(rhs);
	return compare(tmp);
}

wstring var::strclean(void) 
{
	return CleanString(strbuff());
}

wstring var::strbuffhex(void) 
{
	if (isbuf)
		//#001122# to "001122"
		return str.substr(1,str.length()-2);
	else {
		wstring s;
		Str2Hex(str,s,size);
		return s;
	}
}

wstring var::strbuff(void) 
{
	if (isbuf) {
		//#303132# to "012"
		wstring s=strbuffhex();
		wstring tmp=s.substr(0,size);
		Str2Rgch(s,(wchar_t*)tmp.c_str(),size);
		s=tmp;
		return s;
	} else
		return str;
}

void var::resize(ulong newsize)
{
	if (vt==DW){
		if (newsize==1) {
			dw&=0xFF;
		}
		else if (newsize==2) {
			dw&=0xFFFF;
		}
	} 
	else if (vt==STR){
		if (size > newsize) {
			if (isbuf) {
				*this = L"#"+strbuff().substr(0,newsize)+L"#";
			} else {
				*this = strbuff().substr(0,newsize);
			}
		}
	}
}