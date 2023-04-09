module;

#include <Windows.h>
#include <iostream>
export module dll_injector;


export bool inject_dll(DWORD processID, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Error: Unable to open target process." << std::endl;
        return false;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, wcslen(dllPath) * sizeof(wchar_t) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pDllPath == NULL) {
        std::cerr << "Error: Unable to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath, wcslen(dllPath) * sizeof(wchar_t) + 1, NULL)) {
        std::cerr << "Error: Unable to write memory in target process." << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        std::cerr << "Error: Unable to find LoadLibraryW function." << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pDllPath, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Error: Unable to create remote thread in target process." << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}