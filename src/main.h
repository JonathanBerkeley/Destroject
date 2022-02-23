#pragma once
#include <Windows.h>
#include <string>

bool is_proc_running(const wchar_t* proc_name);
DWORD get_proc_id(const wchar_t* proc_name);
HANDLE inject_into_proc(const std::string& dll_name, const int process_id);
HANDLE map_into_proc(const std::string& dll_name, const int process_id);
void sleep(long long milliseconds);
