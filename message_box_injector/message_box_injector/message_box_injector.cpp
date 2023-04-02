// message_box_injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <iostream>

import msg_box_loader;
import dll_injector;

int main()
{
	DWORD pid{ 0 };
	auto dllpath = L"C:\\Users\\User\\source\\repos\\message_box_injection\\x64\\Debug\\message_box_injection.dll";
	std::cout << "Enter the target process ID: ";
	std::cin >> pid;
	auto result = inject_dll(pid, dllpath);
	if (result) {
		std::cout << "\nDLL inject success";
		return 0;
	}
	std::cout << "\nDLL inject failed";
	return 1;
}