// ReSharper disable CppLocalVariableMayBeConst
#include <fstream>
#include <iostream>
#include <string>

#include "util.h"
#include "constants.h"
#include "main.h"

file_contents config_read() {
    if (std::ifstream in{ constants::CONFIG }; in) {
        return file_contents{
            .content = std::string{
                std::istreambuf_iterator{in},
                std::istreambuf_iterator<char>{}
            }
        };
    }
    return file_contents{ .error = "Couldn't find or open config!" };
}


void config_write(const std::string& content) {
    if (std::ofstream cfg { constants::CONFIG }; cfg) {
        cfg << content;
    }
}


// Helper function for writing a logfile to diagnose issues
void log_write(std::string text) {
    HANDLE file_handle = CreateFileW(
        LOG_FILE,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file_handle == INVALID_HANDLE_VALUE)
        MessageBoxW(nullptr, L"(destroject) Failed to open error log file", nullptr, 0);

    DWORD written;
    text += "\r\n";
    try {
        WriteFile(
            file_handle,
            text.c_str(),
            static_cast<int>(text.length()),
            &written,
            nullptr
        );
    }
    catch (const std::exception& ex) {
        const std::string exception_log = "Exception when trying to write previous entry to log file: " + std::string{ ex.what() };
        WriteFile(
            file_handle,
            exception_log.c_str(),
            static_cast<int>(exception_log.length()),
            &written,
            nullptr
        );
    }
    CloseHandle(file_handle);
}