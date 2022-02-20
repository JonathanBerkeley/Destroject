// ReSharper disable CppLocalVariableMayBeConst
// ReSharper disable CppClangTidyConcurrencyMtUnsafe
// ReSharper disable CppRedundantCastExpression
// ReSharper disable CppClangTidyBugproneMisplacedWideningCast
// ReSharper disable CppClangTidyClangDiagnosticCastFunctionType
#define WIN32_LEAN_AND_MEAN

#include "main.h"

#include <chrono>
#include <filesystem>
#include <sstream>
#include <string>
#include <sysinfoapi.h>
#include <thread>
#include <TlHelp32.h>
#include <vector>
#include <Windows.h>

#include "constants.h"
#include "util.h"

int main(const int argc, const char* argv[]) {
    // Get and format windows local time
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    const std::string session_date_time = std::to_string(lt.wHour)
        + ":" + std::to_string(lt.wMinute)
        + ":" + std::to_string(lt.wSecond)
        + " " + std::to_string(lt.wDay)
        + "-" + std::to_string(lt.wMonth)
        + "-" + std::to_string(lt.wYear);

    log_write("\nNew session: (Injector version: " + constants::VERSION + ") (Timestamp: " + session_date_time + ")\n");

    std::string target;
    switch (argc) {
    case 1:
        // No argument given, check config file
        if (const auto& [content, error] { config_read() }; error.empty()) {
            target = content;
        }
        else {
            log_write("(ERROR) No config found, and no command-line arguments supplied \n"
                "(INFO) Run with arguments e.g:\n"
                "C:\\Users\\Me\\Desktop> " + constants::NAME + ".exe ProcessName\n");
            return 0;
        }
        break;
    case 2:
        // On argument supplied
        target = argv[1];
        config_write(target);
        break;
    default:
        return 0;
    }

    const auto w_target = std::wstring(target.begin(), target.end());

    // Find DLLs in same path as executable
    // When running in debug environment, you may need to put the DLL in the parent folder
    std::vector<std::string> dll_options;
    for (const auto& entry : std::filesystem::directory_iterator(".")) {
        if (entry.path().extension().string() == ".dll") {
            dll_options.push_back(entry.path().string());
            log_write("(INFO) Preparing to load " + entry.path().string());
        }
    }

    if (!dll_options.empty()) {
        log_write("(INFO) Waiting for " + target);

        const std::wstring q_target = w_target + L".exe";
        const wchar_t* qualified_target = q_target.c_str();
        while (!is_proc_running(qualified_target))
            sleep(200);

        sleep(5000);

        int proc_id = static_cast<int>(get_proc_id(qualified_target));
        log_write("(INFO) " + target + " found with process id: " + std::to_string(proc_id));
        if (proc_id != 0) {
            for (const std::string& dll : dll_options) {
                HANDLE injected = inject_into_proc(std::filesystem::absolute(dll).string(), proc_id);
                sleep(2000);
                if (injected) {
                    log_write("(SUCCESS) Injection of "
                        + std::filesystem::absolute(dll).string()
                        + " into " + std::to_string(proc_id)
                        + " seems to have succeeded"
                    );
                }
            }
        }
        else {
            log_write("(ERROR) Error getting " + target + " process id (Exiting)");
            return 0;
        }
    }
    else {
        log_write("(ERROR) No DLL(s) found to inject (Exiting)");
        return 0;
    }
}


// Check if a given process is currently running
bool is_proc_running(const wchar_t* proc_name) {
    bool is_running = false;
    PROCESSENTRY32 process_entry{};
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(proc_snap, &process_entry))
        while (Process32Next(proc_snap, &process_entry))
            if (!_wcsicmp(process_entry.szExeFile, proc_name))
                is_running = true;

    CloseHandle(proc_snap);
    return is_running;
}


// Returns a process ID for given process name
DWORD get_proc_id(const wchar_t* proc_name) {
    PROCESSENTRY32 process_entry{};
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
HANDLE inject_into_proc(const std::string& dll_name, const int process_id) {
    try {
        const long dll_length = static_cast<long>(dll_name.length() + 1);
        HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
        if (proc_handle == nullptr)
            return nullptr;

        LPVOID virt_alloc = VirtualAllocEx(
            proc_handle,
            nullptr,
            dll_length,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );

        if (virt_alloc == nullptr)
            return nullptr;

        if (const int write_dll_to_mem = WriteProcessMemory(
            proc_handle,
            virt_alloc,
            dll_name.c_str(),
            dll_length,
            nullptr
        ); write_dll_to_mem == NULL)
            return nullptr;

        DWORD thread_id;
        LPTHREAD_START_ROUTINE load_lib;
        if (const HMODULE load_lib_addr = LoadLibraryA("kernel32"); load_lib_addr != nullptr)
            load_lib = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(load_lib_addr, "LoadLibraryA"));  
        else
            return nullptr;

        HANDLE new_thread = CreateRemoteThread(
            proc_handle,
            nullptr,
            0,
            load_lib,
            virt_alloc,
            0,
            &thread_id
        );

        if (!new_thread) {
            log_write("(ERROR) Unsuccessfully attempted to inject " + dll_name + " into " + std::to_string(process_id));
            log_write("(ERROR) Windows returned system error code 0x" + std::to_string(GetLastError()));
            return nullptr;
        }

        std::stringstream ss;
        ss << std::hex << new_thread;
        log_write("(INFO) Attempted to inject " + dll_name + " into " + std::to_string(process_id) + " handle: 0x" + ss.str());
        return new_thread;
    }
    catch (const std::exception& ex) {
        log_write("(ERROR) " + std::string{ ex.what() });
        return nullptr;
    }

}


// Tidier thread sleep function
void sleep(const long long milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}