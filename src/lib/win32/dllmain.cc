#include <windows.h>

__declspec(dllexport) BOOL WINAPI
DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpvReserved)
{
    hModule = hModule;
    lpvReserved = lpvReserved;
    
    switch (ul_reason_for_call) { 
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH: 
    case DLL_THREAD_DETACH: 
    case DLL_PROCESS_DETACH: 
    default:
        break;
    }
    return (TRUE);
}
