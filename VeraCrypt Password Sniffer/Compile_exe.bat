@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp inject.cpp /link /OUT:inject.exe /SUBSYSTEM:WINDOWS
del *.obj *.lib *.exp