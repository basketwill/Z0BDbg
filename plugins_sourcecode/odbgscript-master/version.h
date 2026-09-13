
//Change Here Plugin Version

#define VERSIONHI      2               // High plugin version
#define VERSIONLO      0               // Low plugin version
#define VERSIONST      1               // plugin state (1git 2beta 3official VC6 release 4hacked, 6:VC9 WDK, 9:VC9)


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define VERSIONSTR  TOSTRING(VERSIONHI) "." TOSTRING(VERSIONLO) "." TOSTRING(VERSIONST)

#define PLUGIN_NAME     L"ODbgScript"
#define PLUGIN_VERS     TOSTRING(VERSIONHI) "." TOSTRING(VERSIONLO) "." TOSTRING(VERSIONST)
#define PLUGIN_INIFILE  NULL

#ifdef _DEBUG
# define VERSDEBUG L"DEBUG "
#else
# define VERSDEBUG
#endif

#if _MSC_VER >= 1600
#  define VERSIONCOMPILED VERSDEBUG L"i686 VC2010 WDK7.1 CRT/STL60"
#elif _MSC_VER >= 1500
#  define VERSIONCOMPILED VERSDEBUG L"i686 VC2008 WDK7.1 CRT/STL60"
#elif _MSC_VER >= 1400
#  define VERSIONCOMPILED VERSDEBUG L"i686 VC2005 WDK7.1 CRT/STL60"
#elif _MSC_VER >= 1310
#  define VERSIONCOMPILED VERSDEBUG L"i686 VC2003 WDK7.1 CRT/STL60"
#elif _MSC_VER > 1300
#  define VERSIONCOMPILED VERSDEBUG L"i686 VC2002 WDK7.1 CRT/STL60"
#else
#  define VERSIONCOMPILED VERSDEBUG L"i686 VC6"
#endif
