@ECHO OFF

cl.exe /nologo /W0 dll.cpp /MT /link /DLL /OUT:dll.dll
del *.obj *.lib *.exp