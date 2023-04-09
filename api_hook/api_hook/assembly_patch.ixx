// assembly_patch.ixx
module;

#include <Windows.h>
#include <iostream>

export module assembly_patch;

// Global variables for the MessageBoxA function's address and original bytes
FARPROC mbox_address = NULL;
SIZE_T szbytes = 0;
char mbox_original_bytes[6] = {};

// Hooked version of the MessageBoxA function
int __stdcall hook_message_box(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::cout << "function hooked\n";
    std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;

    // Restore the original MessageBoxA bytes
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)mbox_address, mbox_original_bytes, sizeof(mbox_original_bytes), &szbytes);

    // Call the original MessageBoxA function
    return MessageBoxA(NULL, lpText, lpCaption, uType);
}

// Function to patch the MessageBoxA function with our hook
export void patch_message_box() {
    // Load the User32 library and retrieve the MessageBoxA function address
    HINSTANCE library = LoadLibraryA("user32.dll");
    SIZE_T bytes_read = 0;
    mbox_address = GetProcAddress(library, "MessageBoxA");

    // Read the original MessageBoxA bytes and save them
    ReadProcessMemory(GetCurrentProcess(), mbox_address, mbox_original_bytes, 6, &bytes_read);

    // Create the patch for the MessageBoxA function
    void* hooked_message_box_address = &hook_message_box;
    char patch[6] = { 0 };
    memcpy_s(patch, 1, "\x68", 1); // Push instruction
    memcpy_s(patch + 1, 4, &hooked_message_box_address, 4); // Push the address of the hook_message_box function
    memcpy_s(patch + 5, 1, "\xC3", 1); // Ret instruction

    // Apply the patch to the MessageBoxA function
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)mbox_address, patch, sizeof(patch), &szbytes);
}
