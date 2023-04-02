export module msg_box_loader;

#include <Windows.h>
#include <iostream>

export bool launch_msgboxdll()
{
    HINSTANCE hinst_dll = LoadLibrary(TEXT("C:\\Users\\User\\source\\repos\\message_box_injection\\x64\\Debug\\message_box_injection.dll"));
    if (hinst_dll == NULL)
    {
        std::cout << "DLL could not be loaded. " << GetLastError() << std::endl;
        return false;
    }

    auto lpfn_pid= GetProcAddress(HMODULE(hinst_dll), "DllMain");
    if (lpfn_pid == NULL)
    {
        std::cout << "Could not locate the function." << std::endl;
        FreeLibrary(hinst_dll);
        return false;
    }


    FreeLibrary(hinst_dll);
    return true;
}
;