#pragma once
#include <Windows.h>
#include <string>


/**
 * \brief Represents the contents and condition of a file
 */
struct FileContents {
    std::string target;
    std::string mode;
    std::string error;
};

FileContents config_read();
void config_write(const std::string& content);
void log_write(std::string text);
void sleep(long long milliseconds);
std::string str_to_lower(const std::string& str);

const LPCWSTR LOG_FILE = L"destroject.log";
