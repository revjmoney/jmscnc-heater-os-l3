@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
cl /nologo /O2 /std:c11 /LD scrypt-harness.c /Fescrypt-harness.dll /link /OUT:scrypt-harness.dll
