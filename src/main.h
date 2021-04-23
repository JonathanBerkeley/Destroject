#pragma once
bool is_proc_running(const wchar_t* proc_name);
int get_proc_id(const wchar_t* proc_name);
void inject_into_proc(std::string dll_name, int& process_id);
void LogWrite(std::string text);

//From Il2CppInspector - http://www.djkaty.com - https://github.com/djkaty
const LPCWSTR LOG_FILE = L"destroy0m.log";