#pragma once

#include <Windows.h>
#include <TlHelp32.h>

using f_LoadLibraryA    = HINSTANCE (WINAPI*)(const char* lpLibFileName);
using f_GetProcAddress  = UINT_PTR  (WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL      (WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    HINSTANCE hMod;
};

void WINAPI ShellCode(MANUAL_MAPPING_DATA* mapping_data);
HANDLE ManualMap(HANDLE proc_handle, const char* dll_name);
