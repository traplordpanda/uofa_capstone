export module detours_patch;

#include <Windows.h>
#include <detours.h>
#include <iostream>
#pragma comment(lib, "detours.lib") 

typedef int(WINAPI* MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
MessageBoxA_t TrueMessageBoxA = MessageBoxA;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "Process ID: " << GetCurrentProcessId() << std::endl;
    return TrueMessageBoxA(hWnd, lpText, lpCaption, uType);
}

export int detour_example()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueMessageBoxA, HookedMessageBoxA);
    DetourTransactionCommit();

    MessageBoxA(NULL, "Hello World!", "Detours Example", MB_OK);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueMessageBoxA, HookedMessageBoxA);
    DetourTransactionCommit();

    return 0;
}