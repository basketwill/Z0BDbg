#include "StdAfx.h"
#include <stdarg.h>

#ifdef _WIN64

static FARPROC Z0B_GetHostExport(const char *name) {
  HMODULE host = GetModuleHandleW(NULL);
  return host == NULL ? NULL : GetProcAddress(host, name);
}

template <typename T>
static T Z0B_HostApi(const char *name) {
  return reinterpret_cast<T>(Z0B_GetHostExport(name));
}

extern "C" void *__imp__hwollymain = NULL;
extern "C" void *__imp__hwclient = NULL;
extern "C" void *__imp__run = NULL;
extern "C" void *__imp__cpufeatures = NULL;
extern "C" void *__imp__hollyinst = NULL;
extern "C" void *__imp__process = NULL;
extern "C" void *__imp__bpoint = NULL;
extern "C" void *__imp__memory = NULL;
extern "C" void *__imp__ollydir = NULL;
extern "C" void *__imp__ollyfile = NULL;
extern "C" void *__imp__executable = NULL;

extern "C" void Z0B_InitializeHostImports(void) {
  __imp__hwollymain = Z0B_GetHostExport("_hwollymain");
  __imp__hwclient = Z0B_GetHostExport("_hwclient");
  __imp__run = Z0B_GetHostExport("_run");
  __imp__cpufeatures = Z0B_GetHostExport("_cpufeatures");
  __imp__hollyinst = Z0B_GetHostExport("_hollyinst");
  __imp__process = Z0B_GetHostExport("_process");
  __imp__bpoint = Z0B_GetHostExport("_bpoint");
  __imp__memory = Z0B_GetHostExport("_memory");
  __imp__ollydir = Z0B_GetHostExport("_ollydir");
  __imp__ollyfile = Z0B_GetHostExport("_ollyfile");
  __imp__executable = Z0B_GetHostExport("_executable");
}

static int Z0B_CountFormatArgs(const wchar_t *format) {
  int count = 0;
  if (format == NULL)
    return 0;
  for (const wchar_t *p = format; *p != L'\0'; ++p) {
    if (*p != L'%')
      continue;
    ++p;
    if (*p == L'%')
      continue;
    while (*p == L'-' || *p == L'+' || *p == L' ' || *p == L'#' || *p == L'0')
      ++p;
    while (*p >= L'0' && *p <= L'9')
      ++p;
    if (*p == L'.') {
      ++p;
      while (*p >= L'0' && *p <= L'9')
        ++p;
    }
    while (*p == L'h' || *p == L'l' || *p == L'L' || *p == L'I' || *p == L'w' || *p == L'z' || *p == L't')
      ++p;
    if (*p != L'\0')
      ++count;
    if (*p == L'\0')
      break;
  }
  return count;
}

typedef int (__cdecl *Z0B_Getfromini0)(wchar_t *, wchar_t *, wchar_t *, wchar_t *);
typedef int (__cdecl *Z0B_Getfromini1)(wchar_t *, wchar_t *, wchar_t *, wchar_t *, ULONG_PTR);
typedef int (__cdecl *Z0B_Writetoini0)(wchar_t *, wchar_t *, wchar_t *, wchar_t *);
typedef int (__cdecl *Z0B_Writetoini1)(wchar_t *, wchar_t *, wchar_t *, wchar_t *, ULONG_PTR);
typedef int (__cdecl *Z0B_StrcopyW)(wchar_t *, int, const wchar_t *);
typedef void (__cdecl *Z0B_Tempinfo0)(wchar_t *);
typedef void (__cdecl *Z0B_Tempinfo1)(wchar_t *, ULONG_PTR);
typedef void (__cdecl *Z0B_Addtolist0)(ulong, int, wchar_t *);
typedef void (__cdecl *Z0B_Addtolist1)(ulong, int, wchar_t *, ULONG_PTR);
typedef void (__cdecl *Z0B_Addtolist2)(ulong, int, wchar_t *, ULONG_PTR, ULONG_PTR);
typedef void (__cdecl *Z0B_Addtolist3)(ulong, int, wchar_t *, ULONG_PTR, ULONG_PTR, ULONG_PTR);

extern "C" int __cdecl Getfromini(wchar_t *file, wchar_t *section, wchar_t *key, wchar_t *format, ...) {
  const int argc = Z0B_CountFormatArgs(format);
  va_list args;
  va_start(args, format);
  ULONG_PTR a0 = argc > 0 ? va_arg(args, ULONG_PTR) : 0;
  va_end(args);
  if (argc > 0) {
    Z0B_Getfromini1 fn = Z0B_HostApi<Z0B_Getfromini1>("Getfromini");
    return fn == NULL ? 0 : fn(file, section, key, format, a0);
  }
  Z0B_Getfromini0 fn = Z0B_HostApi<Z0B_Getfromini0>("Getfromini");
  return fn == NULL ? 0 : fn(file, section, key, format);
}

extern "C" int __cdecl Writetoini(wchar_t *file, wchar_t *section, wchar_t *key, wchar_t *format, ...) {
  const int argc = Z0B_CountFormatArgs(format);
  va_list args;
  va_start(args, format);
  ULONG_PTR a0 = argc > 0 ? va_arg(args, ULONG_PTR) : 0;
  va_end(args);
  if (argc > 0) {
    Z0B_Writetoini1 fn = Z0B_HostApi<Z0B_Writetoini1>("Writetoini");
    return fn == NULL ? 0 : fn(file, section, key, format, a0);
  }
  Z0B_Writetoini0 fn = Z0B_HostApi<Z0B_Writetoini0>("Writetoini");
  return fn == NULL ? 0 : fn(file, section, key, format);
}

extern "C" int __cdecl StrcopyW(wchar_t *dest, int n, const wchar_t *src) {
  Z0B_StrcopyW fn = Z0B_HostApi<Z0B_StrcopyW>("StrcopyW");
  return fn == NULL ? 0 : fn(dest, n, src);
}

extern "C" void __cdecl Tempinfo(wchar_t *format, ...) {
  const int argc = Z0B_CountFormatArgs(format);
  va_list args;
  va_start(args, format);
  ULONG_PTR a0 = argc > 0 ? va_arg(args, ULONG_PTR) : 0;
  va_end(args);
  if (argc > 0) {
    Z0B_Tempinfo1 fn = Z0B_HostApi<Z0B_Tempinfo1>("Tempinfo");
    if (fn != NULL) fn(format, a0);
  }
  else {
    Z0B_Tempinfo0 fn = Z0B_HostApi<Z0B_Tempinfo0>("Tempinfo");
    if (fn != NULL) fn(format);
  }
}

extern "C" void __cdecl Addtolist(ulong addr, int color, wchar_t *format, ...) {
  const int argc = Z0B_CountFormatArgs(format);
  va_list args;
  va_start(args, format);
  ULONG_PTR a0 = argc > 0 ? va_arg(args, ULONG_PTR) : 0;
  ULONG_PTR a1 = argc > 1 ? va_arg(args, ULONG_PTR) : 0;
  ULONG_PTR a2 = argc > 2 ? va_arg(args, ULONG_PTR) : 0;
  va_end(args);
  if (argc > 2) {
    Z0B_Addtolist3 fn = Z0B_HostApi<Z0B_Addtolist3>("Addtolist");
    if (fn != NULL) fn(addr, color, format, a0, a1, a2);
  }
  else if (argc > 1) {
    Z0B_Addtolist2 fn = Z0B_HostApi<Z0B_Addtolist2>("Addtolist");
    if (fn != NULL) fn(addr, color, format, a0, a1);
  }
  else if (argc > 0) {
    Z0B_Addtolist1 fn = Z0B_HostApi<Z0B_Addtolist1>("Addtolist");
    if (fn != NULL) fn(addr, color, format, a0);
  }
  else {
    Z0B_Addtolist0 fn = Z0B_HostApi<Z0B_Addtolist0>("Addtolist");
    if (fn != NULL) fn(addr, color, format);
  }
}

#define Z0B_FORWARD(ret, name, args, params, fail) \
  extern "C" ret name args { \
    typedef ret (*PFN) args; \
    PFN fn = Z0B_HostApi<PFN>(#name); \
    if (fn == NULL) return fail; \
    return fn params; \
  }

#define Z0B_FORWARD_VOID(name, args, params) \
  extern "C" void name args { \
    typedef void (*PFN) args; \
    PFN fn = Z0B_HostApi<PFN>(#name); \
    if (fn != NULL) fn params; \
  }

#ifdef Tablefunction
#undef Tablefunction
#endif
#ifdef Painttable
#undef Painttable
#endif
#ifdef Findname
#undef Findname
#endif
#ifdef Insertname
#undef Insertname
#endif

Z0B_FORWARD(ulong, Readmemory, (void *buf, ulong addr, ulong size, int mode), (buf, addr, size, mode), 0)
Z0B_FORWARD(t_thread *, Findthread, (ulong threadid), (threadid), NULL)
Z0B_FORWARD(ulong, Getcputhreadid, (void), (), 0)
Z0B_FORWARD(int, Settableselection, (t_table *pt, int selected), (pt, selected), 0)
Z0B_FORWARD(t_table *, Getcpudisasmtable, (void), (), NULL)
Z0B_FORWARD(int, Createsorteddata, (t_sorted *sd, ulong itemsize, int nexp, SORTFUNC *sortfunc, DESTFUNC *destfunc, int mode), (sd, itemsize, nexp, sortfunc, destfunc, mode), 0)
Z0B_FORWARD_VOID(Suspendallthreads, (void), ())
Z0B_FORWARD_VOID(Resumeallthreads, (void), ())
Z0B_FORWARD(HWND, Activatetablewindow, (t_table *pt), (pt), NULL)
Z0B_FORWARD(HWND, Createtablewindow, (t_table *pt, int nrow, int ncolumn, HINSTANCE hi, wchar_t *icon, wchar_t *title), (pt, nrow, ncolumn, hi, icon, title), NULL)
Z0B_FORWARD(int, Tablefunction, (t_table *pt, HWND hw, UINT msg, WPARAM wp, LPARAM lp), (pt, hw, msg, wp, lp), 0)
Z0B_FORWARD_VOID(Painttable, (HWND hw, t_table *pt, DRAWFUNC *getline), (hw, pt, getline))
Z0B_FORWARD(int, Movetableselection, (t_table *pt, int n), (pt, n), 0)
Z0B_FORWARD_VOID(Delayedtableredraw, (t_table *pt), (pt))
Z0B_FORWARD(t_dump *, Getcpudisasmdump, (void), (), NULL)
Z0B_FORWARD(void *, Getsortedbyselection, (t_sorted *sd, int index), (sd, index), NULL)
Z0B_FORWARD(int, Getstring, (HWND hparent, wchar_t *title, wchar_t *s, int length, int savetype, int letter, int x, int y, int fi, int mode), (hparent, title, s, length, savetype, letter, x, y, fi, mode), 0)
Z0B_FORWARD(void *, Addsorteddata, (t_sorted *sd, void *item), (sd, item), NULL)
Z0B_FORWARD(int, Deletesorteddatarange, (t_sorted *sd, ulong addr0, ulong addr1), (sd, addr0, addr1), 0)
Z0B_FORWARD_VOID(Setcpu, (ulong threadid, ulong asmaddr, ulong dumpaddr, ulong selsize, ulong stackaddr, int mode), (threadid, asmaddr, dumpaddr, selsize, stackaddr, mode))
Z0B_FORWARD(int, Simpleaddress, (wchar_t *text, ulong addr, uchar *mask, int *select), (text, addr, mask, select), 0)
Z0B_FORWARD(HWND, Createdumpwindow, (wchar_t *title, ulong base, ulong size, wchar_t *path, ulong dumptype, ulong sel0, ulong sel1, wchar_t *strname), (title, base, size, path, dumptype, sel0, sel1, strname), NULL)
Z0B_FORWARD(t_memory *, Findmemory, (ulong addr), (addr), NULL)
Z0B_FORWARD(int, Broadcast, (UINT msg, WPARAM wp, LPARAM lp), (msg, wp, lp), 0)
Z0B_FORWARD_VOID(Redrawcpureg, (void), ())
Z0B_FORWARD(ulong, Assemble, (wchar_t *src, ulong ip, uchar *buf, ulong nbuf, int mode, wchar_t *errtxt), (src, ip, buf, nbuf, mode, errtxt), 0)
Z0B_FORWARD(int, Listmemory, (void), (), 0)
Z0B_FORWARD(ulong, Writememory, (const void *buf, ulong addr, ulong size, int mode), (buf, addr, size, mode), 0)
Z0B_FORWARD_VOID(Deletesorteddata, (t_sorted *sd, ulong addr, ulong subaddr), (sd, addr, subaddr))
Z0B_FORWARD_VOID(Updatetable, (t_table *pt, int force), (pt, force))
Z0B_FORWARD(void *, Getsortedbyindex, (t_sorted *sd, int index), (sd, index), NULL)
Z0B_FORWARD_VOID(Redrawcpudisasm, (void), ())
Z0B_FORWARD_VOID(Redrawdisassembler, (void), ())
Z0B_FORWARD(int, Decodeaddress, (ulong addr, ulong amod, int mode, wchar_t *symb, int nsymb, wchar_t *comment), (addr, amod, mode, symb, nsymb, comment), 0)
Z0B_FORWARD(t_module *, Findmodule, (ulong addr), (addr), NULL)
Z0B_FORWARD(int, FindnameW, (ulong addr, int type, wchar_t *name, int nname), (addr, type, name, nname), 0)
Z0B_FORWARD(int, InsertnameW, (ulong addr, int type, wchar_t *s), (addr, type, s), 0)
Z0B_FORWARD_VOID(Redrawlist, (void), ())
Z0B_FORWARD(int, Run, (t_status status, int pass), (status, pass), 0)

#endif
