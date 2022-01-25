#pragma once
#include <Windows.h>
#include <string>

struct file_contents {
    std::string content;
    std::string error;
};

file_contents config_read();
void config_write(const std::string& content);
void log_write(std::string text);

//From Il2CppInspector - http://www.djkaty.com - https://github.com/djkaty
const LPCWSTR LOG_FILE = L"destroject.log";