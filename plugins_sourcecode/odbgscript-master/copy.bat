@echo off
zip -u -1 ..\backup.zip *.* doc\*.txt 2>NUL

REM COMMENT THIS LINE IF YOU ARE ON WIN x64
SET ProgramFiles(x86)=%ProgramFiles%

SET ODBG_PATH=%ProgramFiles(x86)%\_Dev\ODBG

del /f "%ODBG_PATH%\errorlog.txt"
copy /y Release\ODbgScript.dll "%ODBG_PATH%\plugins\" 1>NUL
copy /y Doc\ODbgScript.txt "%ODBG_PATH%\plugins\" 1>NUL

REM dont use pause (used in VC)
rem pause