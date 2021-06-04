#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <string>
#include <thread>
#include <chrono>
#include <sysinfoapi.h>
#include "main.h"
#include "constants.h"

int main() {
    // Get and format windows local time
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    std::string sessionDateTime = std::to_string(lt.wHour)
        + ":" + std::to_string(lt.wMinute)
        + ":" + std::to_string(lt.wSecond)
        + " " + std::to_string(lt.wDay)
        + "-" + std::to_string(lt.wMonth)
        + "-" + std::to_string(lt.wYear);

    log_write("\nNew session: (Injector version: " + VERSION + ") (Timestamp: " + sessionDateTime + ")\n");

    // Find DLLs in same path as executable
    std::vector<std::string> dll_options;
    for (const auto& entry : std::filesystem::directory_iterator(".")) {
        if (entry.path().extension().string() == ".dll") {
            dll_options.push_back(entry.path().string());
            log_write("(INFO) Preparing to load " + entry.path().string());
        }
    }

    if (dll_options.size() > 0) {
        log_write("(INFO) Waiting for " + TARGET);

        std::wstring qTarget = WTARGET + L".exe";
        const wchar_t* qualifiedTarget = qTarget.c_str();
        while (!is_proc_running(qualifiedTarget)) {
            sleep(200);
        }
        sleep(5000);

        int proc_id = get_proc_id(qualifiedTarget);
        log_write("(INFO) " + TARGET + " found with process id: " + std::to_string(proc_id));
        if (proc_id != 0) {
            for (std::string dll : dll_options) {
                HANDLE injected = inject_into_proc(std::filesystem::absolute(dll).string(), proc_id);
                sleep(2000);
                if (injected)
                    log_write("(SUCCESS) Injection of " + std::filesystem::absolute(dll).string() + " into " + std::to_string(proc_id) + " seems to have succeeded");
            }
        }
        else {
            log_write("(ERROR) Error getting " + TARGET + " process id (Exiting)");
            return 0;
        }
    }
    else {
        log_write("(ERROR) No DLL(s) found to inject (Exiting)");
        return 0;
    }
    return 0;
}

// Check if a given process is currently running
bool is_proc_running(const wchar_t* proc_name) {
    bool is_running = false;
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(proc_snap, &process_entry)) {
        while (Process32Next(proc_snap, &process_entry)) {
            if (!_wcsicmp(process_entry.szExeFile, proc_name)) {
                is_running = true;
            }
        }
    }

    CloseHandle(proc_snap);
    return is_running;
}

// Returns a process ID for given process name
int get_proc_id(const wchar_t* proc_name) {
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(proc_snap, &process_entry)) {
        while (Process32Next(proc_snap, &process_entry)) {
            if (!_wcsicmp(process_entry.szExeFile, proc_name)) {
                CloseHandle(proc_snap);
                return process_entry.th32ProcessID;
            }
        }
    }
    CloseHandle(proc_snap);
    return 0;
}


// Returns handle if successful, 0 otherwise
HANDLE inject_into_proc(std::string dll_name, int& process_id) {
    try {
        long dll_length = static_cast<long>(dll_name.length() + 1);
        HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
        if (proc_handle == NULL) {
            return 0;
        }
        LPVOID virt_alloc = VirtualAllocEx(proc_handle, NULL, dll_length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (virt_alloc == NULL) {
            return 0;
        }
        int write_dll_to_mem = WriteProcessMemory(proc_handle, virt_alloc, dll_name.c_str(), dll_length, 0);
        if (write_dll_to_mem == NULL) {
            return 0;
        }
        DWORD thread_id;
        LPTHREAD_START_ROUTINE load_lib;
        HMODULE load_lib_addr = LoadLibraryA("kernel32");
        if (load_lib_addr != 0)
            load_lib = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(load_lib_addr, "LoadLibraryA"));
        else
            return 0;

        HANDLE new_thread = CreateRemoteThread(proc_handle, NULL, 0, load_lib, virt_alloc, 0, &thread_id);
        if (!new_thread) {
            log_write("(ERROR) Unsuccessfully attempted to inject " + dll_name + " into " + std::to_string(process_id));
            log_write("(ERROR) Windows returned system error code 0x" + std::to_string(GetLastError()));
            return 0;
        }
        else {
            std::stringstream ss;
            ss << std::hex << new_thread;
            log_write("(INFO) Attempted to inject " + dll_name + " into " + std::to_string(process_id) + " handle: 0x" + ss.str());
            return new_thread;
        }

        return 0;
    }
    catch (std::exception ex) {
        log_write("(ERROR) " + std::string{ ex.what() });
        return 0;
    }

}


//Tidier thread sleep function
void sleep(long long milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}


// Helper function for writing a logfile to diagnose issues
void log_write(std::string toLog) {
    HANDLE fileHandle = CreateFileW(LOG_FILE, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
        MessageBoxW(0, L"(destroy0m) Failed to open error log file", 0, 0);

    DWORD written;
    toLog += "\r\n";
    try {
        WriteFile(fileHandle, toLog.c_str(), (DWORD)toLog.length(), &written, NULL);
    }
    catch (const std::exception& ex) {
        std::string exceptionLog = "Exception when trying to write previous entry to log file: " + std::string(ex.what());
        WriteFile(fileHandle, exceptionLog.c_str(), (DWORD)exceptionLog.length(), &written, NULL);
    }
    CloseHandle(fileHandle);
}