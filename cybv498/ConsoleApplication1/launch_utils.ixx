export module launch_utils;

#include <Windows.h>
#include <iostream>

void print_error(std::string function) {
    DWORD errorCode = GetLastError();
    LPWSTR errorMessage = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&errorMessage,
        0,
        NULL);

    // Print the error message
    std::wcout << function.c_str() <<
        " ERROR CODE - " << errorCode
        << L": " << errorMessage << std::endl;
}

export bool launch_notepad(DWORD64 mitigationFlags)
{
    // Set up the STARTUPINFOW and PROCESS_INFORMATION structures
    STARTUPINFOEX si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    // Set up the attribute list
    SIZE_T size = 0;
    si.lpAttributeList = NULL;

    // Get the required size for the attribute list
    if (!InitializeProcThreadAttributeList(NULL, 1, 0, &size) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        print_error("Failed to get attribute list size");
        return false;
    }

    // Allocate memory for the attribute list
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    if (!si.lpAttributeList) {
        print_error("Failed to allocate attribute list");
        return false;
    }

    // Initialize the attribute list
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) {
        print_error("Failed to initialize attribute list 1");
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return false;
    }

    // Add the mitigation policy to the attribute list
    if (!UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        &mitigationFlags,
        sizeof(mitigationFlags),
        NULL,
        NULL)
        )
    {
        print_error("Failed to update attribute list");
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return false;
    }

    // The application path, for example, notepad.exe
    wchar_t application[] = L"C:\\Windows\\System32\\notepad.exe";

    // Create the process
    if (!CreateProcessW(
        NULL,
        application,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi)
        )
    {
        print_error("Failed to create process");
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return false;
    }
    std::cout << "We have launched notepad with Mitigation Flag!\n";
    std::cout << "the notepad pid is " << pi.dwProcessId << '\n';
    std::cout << "the parent process pid is " << GetCurrentProcessId() << '\n';

    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}
