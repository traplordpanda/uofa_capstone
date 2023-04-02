#include <Windows.h>
#include <stdio.h>

void printMitigationFlags(PROCESS_INFORMATION pi) {
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy;
    DWORD dwSize;
    if (GetProcessMitigationPolicy(pi.hProcess, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy))) {
        printf("ASLR policy flags:\n");
        printf("  EnableBottomUpRandomization: %d\n", aslrPolicy.EnableBottomUpRandomization);
        printf("  EnableForceRelocateImages: %d\n", aslrPolicy.EnableForceRelocateImages);
        printf("  EnableHighEntropy: %d\n", aslrPolicy.EnableHighEntropy);
        printf("  DisallowStrippedImages: %d\n", aslrPolicy.DisallowStrippedImages);
    }
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY scdp;
    if (GetProcessMitigationPolicy(pi.hProcess, ProcessSystemCallDisablePolicy, &scdp, sizeof(scdp))) {
        printf("System call disable policy flags:\n");
        printf("  DisallowWin32kSystemCalls: %d\n", scdp.DisallowWin32kSystemCalls);
    }
}