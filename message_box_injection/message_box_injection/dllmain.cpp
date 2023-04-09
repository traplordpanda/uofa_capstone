// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <detours.h>
#include <iostream>
#include <psapi.h>

#pragma comment(lib, "detours.lib")

// Export a dummy function to ensure the DLL can be loaded dynamically. Forces ordinal.
extern "C" __declspec(dllexport) void dummy(void) {
    return;
}

// Typedef for the original MessageBoxA function
typedef int (WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

// Pointer to the original MessageBoxA function
MESSAGEBOXA pMessageBoxA = MessageBoxA;

// Custom MessageBoxA function that logs the process ID and name
int MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    if (NULL != hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleFileNameEx(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
        }
    }

    std::wcout << "Message Box Hooked! PID: " << pid << "\nProcess Name: " << szProcessName << std::endl;
    return pMessageBoxA(hWnd, lpText, lpCaption, uType);
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Hook the MessageBoxA function upon DLL attach
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pMessageBoxA, MyMessageBoxA);
        DetourTransactionCommit();

        // Call the hooked MessageBoxA function
        MessageBoxA(NULL, "You have been hacked", "DEADBEEF FACEFEED", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        // Unhook the MessageBoxA function upon DLL detach
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)pMessageBoxA, MyMessageBoxA);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}
