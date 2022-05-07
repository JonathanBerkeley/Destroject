#pragma once

/*
 * Manual map logic inspired by Broihon on behalf of GuidedHacking:
 * https://youtu.be/qzZTXcBu3cE
 */

#include <Windows.h>
#include <TlHelp32.h>


using LoadLibraryA_fn   = HINSTANCE (WINAPI*)(const char* lpLibFileName);
using GetProcAddress_fn = UINT_PTR  (WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using DllEntryPoint_fn  = BOOL      (WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);


/**
 * \brief Function pointers required for manual mapping
 */
struct MappingData {
    LoadLibraryA_fn     LoadLibraryA_ptr;
    GetProcAddress_fn   GetProcAddress_ptr;
    HINSTANCE           Module;
};

void WINAPI shell_code(MappingData* mapping_data);
HANDLE manual_map(HANDLE proc_handle, const char* dll_name);
