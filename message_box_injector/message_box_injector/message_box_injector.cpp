// message_box_injector.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <windows.h>
#include <string>
#include <iostream>
#include <string_view>

import detours_inject;

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		std::cerr << "Usage: " << argv[0] << " <target_executable_path>" << std::endl;
		return 1;
	}
	std::string_view exe_path { argv[1] };
	std::wstring wexe_path { exe_path.begin(), exe_path.end() };
	auto dllpath = "message_box_injection.dll";

	launch_proc_with_dll(wexe_path, dllpath);
	return 0;

}