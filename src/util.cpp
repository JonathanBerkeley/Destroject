// ReSharper disable CppLocalVariableMayBeConst
#include <fstream>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>

#include "util.h"
#include "constants.h"
#include "main.h"


/**
 * \brief Reads and parses config details
 * \return Structure containing string of contents or an error with error message
 */
file_contents config_read() {
    if (std::ifstream in{ constants::CONFIG }; in) {
        file_contents contents{};

        try {
            std::getline(in, contents.target);
            contents.target = contents.target.substr(
                contents.target.find(':') + 1u
            );

            std::getline(in, contents.mode);
            contents.mode = contents.mode.substr(
                contents.mode.find(':') + 1u
            );

            return contents;
        }
        catch (const std::out_of_range&) {
            contents.error = "(ERROR) Invalid config, delete it";
            return contents;
        }
    }
    return file_contents{ .error = "(ERROR) Couldn't find or open config!" };
}


/**
 * \brief Writes content to config
 * \param content String representation of content to be written to config
 */
void config_write(const std::string& content) {
    if (std::ofstream cfg { constants::CONFIG }; cfg) {
        cfg << content;
    }
}



/**
 * \brief Helper function for writing a logfile to diagnose issues
 * \param text Text to be logged
 */
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



/**
 * \brief Wrapper around std::this_thread::sleep_for() with long long to milliseconds conversion
 * \param milliseconds Milliseconds value of time to sleep for
 */
void sleep(const long long milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}



/**
 * \brief Helper function to set a string to lowercase
 * \param str String to be shifted to lowercase
 * \return New string that is lowercase
 */
std::string str_to_lower(const std::string& str) {
    std::string output;

    for (auto c : str)
        output += static_cast<char>(std::tolower(c));

    return output;
}
