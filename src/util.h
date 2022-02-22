#pragma once
#include <Windows.h>
#include <string>

struct file_contents {
    std::string target;
    std::string mode;
    std::string error;
};

file_contents config_read();
void config_write(const std::string& content);
void log_write(std::string text);
void sleep(long long milliseconds);

const LPCWSTR LOG_FILE = L"destroject.log";