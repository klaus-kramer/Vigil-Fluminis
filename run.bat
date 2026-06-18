@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set PATH=S:\prog\Qt\6.9.3\msvc2022_64\bin;%PATH%
start "" "S:\prog\projects\cpp\firewall\build\Release\Vigil_Fluminis.exe"
