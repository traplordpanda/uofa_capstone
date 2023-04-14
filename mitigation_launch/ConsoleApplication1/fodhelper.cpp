import launch_utils; 
import mitigations;

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string_view>

int main(int argc, char* argv[])
{
    DWORD64 mitigation_flags{ 0 };
    std::vector<std::string_view> arguments(argv+1, argv + argc);
    for ( const auto& arg: arguments ){
        if (auto mitigation = mitigation_map.find(arg);  mitigation == mitigation_map.end())
        {
            std::cout << "Mitigation " << arg << " not found\n";
            return 1;
        }
        else {
            mitigation_flags = mitigation->second | mitigation_flags;
        }
    }
    auto pl = launch_notepad(mitigation_flags);
}
