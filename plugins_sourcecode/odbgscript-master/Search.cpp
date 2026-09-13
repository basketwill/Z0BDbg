#include <math.h>

bool CompareChar(const wchar_t src, wchar_t* cmp)
{
	if(wcsstr(cmp, L"??")) // ??
		return true;

	if(wcsstr(cmp, L"?") == cmp) // ?6
	{
		wchar_t low = src % 0x10;
		wchar_t val = (wchar_t)wcstoul(cmp + 1, 0, 16);
		if(val == low)
			return true;
		return false;
	}
	else if(wcsstr(cmp, L"?") == cmp + 1) // 5?
	{
		cmp[1] = 0;
		wchar_t high = (src - src % 0x10) / 0x10;
		wchar_t val = (wchar_t)wcstoul(cmp, 0, 16);
		if(val == high)
			return true;
		return false;
	}
	else // 56
	{
		wchar_t high = (src - src % 0x10) / 0x10;
		wchar_t low = src % 0x10;
		wchar_t val2 = (wchar_t)wcstoul(cmp + 1, 0, 16);
		cmp[1] = 0;
		wchar_t val1 = (wchar_t)wcstoul(cmp, 0, 16);
		if(high == val1 && low == val2)
			return true;
		return false;
	}
}

int FindWithWildcards(const wchar_t* source, const wchar_t* findstring, size_t len)
{
	wchar_t cmp[3] = {0};
	int findlen = ceil(((double)wcslen(findstring) / 2));
	if(len < findlen)
		return -1;

	for(int i = 0; i < len; i++)
	{
		for(int j = 0; j < findlen; j++)
		{
			wcsncpy(cmp, findstring + j * 2, 2);
			if(!CompareChar(source[i+j], cmp))
				break;
			else if(j == (findlen - 1))
				return i;
		}
	}
	return -1;
}

wchar_t * HexString2BinArray(const wchar_t * s)
{
	wchar_t HexBuf[3];
	wchar_t * result=new wchar_t[(wcslen(s) /2)+1];
	result[0]=0;

	int i=0;
	while (wcslen(s))
	{
		wcsncpy(HexBuf,s,2);
		HexBuf[2]=0;
		result[i]=(wchar_t)wcstoul(HexBuf,0,16);
		i++;
		s+=2;
	}
	i++;

	return result;
}

wchar_t WildSymbolToChar(const wchar_t* x)
{
	wchar_t n;

	if (x[0]=='?')
		n=x[1];
	else
		n=x[0];

	if (n>='0' && n<='9')
		n-='0';
	else
	{
		if (n>='a' && n<='f')
			n-='a';
		else
		{
			if (n>='A' && n<='F')
				n-='A';
		}
	}
	if (x[1]=='?')
		n=n<<4;

	return n;
}
char HexString2BinChar(const wchar_t *s)
{
	wchar_t HexBuf[3];
	wcsncpy(HexBuf,s,2);
	HexBuf[2]=0;
	return (wchar_t)wcstoul(HexBuf,0,16);	
}

bool Replace(wchar_t * s, const wchar_t * searchstr, const wchar_t * replstring, size_t length)
{
	wchar_t * ps=s;
	bool WasReplaced=false;
	if (wcslen(searchstr)!=wcslen(replstring))
		throw(L"Search string and replace strings should be of equal length");

	if (wcslen(searchstr)%2)
		throw(L"Bad search string");

	if ((wcslen(searchstr)/2)>length)
		throw(L"The size of data is too small");

	size_t ReplaceLength=wcslen(replstring)/2;

	size_t offs=0;

	bool equal=true;
	unsigned i=0;
	unsigned j=0;

	//Wildcard Search
	while (i<wcslen(replstring))
	{
		if (wcsncmp(L"??",&searchstr[i],2)) // if searchstr[i] != "??"
		{
			if ((searchstr[i]=='?') || (searchstr[i+1]=='?'))
			{
				wchar_t mask=0;

				wchar_t maskbuf[3];

				if (searchstr[i]=='?')
				{
					maskbuf[0]=searchstr[i+1]; // "?5"
					maskbuf[1]=0;

					if (s[j]>0xF)
						equal=false;

					mask=0x0F;

				}
				else
				{
					maskbuf[0]=searchstr[i]; // "5?"
					maskbuf[1]='0';
					maskbuf[2]=0;
					mask=0xF0;
				}


				if ((wchar_t)(s[j]&mask)-(wchar_t)wcstoul(maskbuf,0,16))
					equal=false;

				if (!equal)
					break;
			}
			else
				if (HexString2BinChar(&searchstr[i])!=s[j])
				{
					equal=false;
					break;
				}

		}
		else
		{
			i+=2;
			i-=2;
		}
		i+=2;
		j++;

	}

	//Wildcard Replacment
	if (equal)
	{
		if (!wcsstr(replstring,L"?")) // no wildcards
		{
			wchar_t * replacestring;
			try
			{
				replacestring=HexString2BinArray(replstring);
			}
			catch (...)
			{
				throw(L"Bad replace string");
			}
			memcpy(s,replacestring,ReplaceLength);
			delete replacestring;
		}
		else //replace by wildcard
			for (i=0;i<ReplaceLength;i++)
			{
				if (wcsncmp(L"??",&replstring[i*2],2)) // if searchstr[i] != "??"
				{
					if ((replstring[i*2]=='?') || (replstring[i*2+1]=='?'))
					{

						if (replstring[i*2]=='?')	//?5
							ps[i]=(ps[i]& 0xF0) | WildSymbolToChar(&replstring[i*2]);
						else						//5?
							ps[i]=(ps[i]& 0x0F) | WildSymbolToChar(&replstring[i*2]);
					}
					else
						ps[i]=HexString2BinChar(&replstring[i*2]); //not wildcard replacement
				}
			}
			WasReplaced=true;
	}
	return WasReplaced;
}

wchar_t * Byte2Hex(wchar_t b)
{
	wchar_t * buf=new wchar_t[3];
	wsprintf(buf,L"%02X",(wchar_t)b);
	return buf;
}