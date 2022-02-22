// ReSharper disable CppClangTidyPerformanceNoIntToPtr
// ReSharper disable CppClangTidyClangDiagnosticMicrosoftCast
#include <fstream>
#include <string>

#include "manual_map.h"
#include "util.h"


HANDLE manual_map(HANDLE proc_handle, const char* dll_name) {
    IMAGE_NT_HEADERS* old_nt_header = nullptr;
    BYTE* pTargetBase = nullptr;

    DWORD dwCheck = 0;
    if (!GetFileAttributesA(dll_name)) {
        log_write("(ERROR_MM) File doesn't exist");
        return nullptr;
    }

    std::ifstream file(dll_name, std::ios::binary | std::ios::ate);
    if (file.fail()) {
        log_write("(ERROR_MM) Opening file failed: " + std::to_string(static_cast<DWORD>(file.rdstate())));
        return nullptr;
    }

    const auto file_size = file.tellg();
    if (file_size < 0x1000) {
        log_write("(ERROR_MM) File-size invalid");
        file.close();
        return nullptr;
    }

    const auto src_data = std::make_unique<BYTE[]>(file_size);
    if (!src_data) {
        log_write("(ERROR_MM) Memory allocating failed");
        file.close();
        return nullptr;
    }

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(src_data.get()), file_size);
    file.close();

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(src_data.get())->e_magic != 0x5A4D) {
        log_write("(ERROR_MM) Wrong file type");
        return nullptr;
    }

    old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(src_data.get() + reinterpret_cast<IMAGE_DOS_HEADER*>(src_data.get())->e_lfanew);
    const IMAGE_OPTIONAL_HEADER* old_opt_header = &old_nt_header->OptionalHeader;
    const IMAGE_FILE_HEADER* old_file_header = &old_nt_header->FileHeader;

#ifdef _WIN64
    if (old_file_header->Machine != IMAGE_FILE_MACHINE_AMD64) {
        log_write("(ERROR_MM) Unsupported platform");
        return nullptr;
    }
#else
    if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
        log_write("(ERROR_MM) Unsupported platform");
        return nullptr;
    }
#endif

    pTargetBase = static_cast<BYTE*>(VirtualAllocEx(proc_handle, reinterpret_cast<void*>(old_opt_header->ImageBase), old_opt_header->SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!pTargetBase) {
        pTargetBase = static_cast<BYTE*>(VirtualAllocEx(proc_handle, nullptr, old_opt_header->SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (!pTargetBase) {
            log_write("(ERROR_MM) Memory allocation failed: " + std::to_string(GetLastError()));
            return nullptr;
        }
    }

    MANUAL_MAPPING_DATA data{};
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

    auto* pSectionHeader = IMAGE_FIRST_SECTION(old_nt_header);
    for (UINT i = 0; i != old_file_header->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(proc_handle, pTargetBase + pSectionHeader->VirtualAddress,
                src_data.get() + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
                log_write("(ERROR_MM) Could not map sections: " + std::to_string(GetLastError()));
                VirtualFreeEx(proc_handle, pTargetBase, 0, MEM_RELEASE);
                return nullptr;
            }
        }
    }
    memcpy(src_data.get(), &data, sizeof(data));
    WriteProcessMemory(proc_handle, pTargetBase, src_data.get(), 0x1000, nullptr);

    void* alloc_memory = VirtualAllocEx(proc_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!alloc_memory) {
        log_write("(ERROR_MM) Shell-code memory allocation failed: " + std::to_string(GetLastError()));
        VirtualFreeEx(proc_handle, pTargetBase, 0, MEM_RELEASE);
        return nullptr;
    }

    WriteProcessMemory(proc_handle, alloc_memory, shell_code, 0x1000, nullptr);

    HANDLE new_thread = CreateRemoteThread(
        proc_handle,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(alloc_memory),
        pTargetBase,
        0,
        nullptr
    );
    if (!new_thread) {
        log_write("(ERROR_MM) CreateRemoteThread failed:  " + std::to_string(GetLastError()));
        VirtualFreeEx(proc_handle, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(proc_handle, alloc_memory, 0, MEM_RELEASE);
        return nullptr;
    }

    HINSTANCE hCheck = nullptr;
    while (!hCheck) {
        MANUAL_MAPPING_DATA data_checked{};
        ReadProcessMemory(proc_handle, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.hMod;
        Sleep(10);
    }

    VirtualFreeEx(proc_handle, alloc_memory, 0, MEM_RELEASE);

    return new_thread;
}

#define RELOC_FLAG32(RelInfo)(((RelInfo) >> 0x0C == IMAGE_REL_BASED_HIGHLOW))
#define RELOC_FLAG64(RelInfo)(((RelInfo) >> 0x0C == IMAGE_REL_BASED_DIR64))
#ifdef  _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif //  _WIN64


void WINAPI shell_code(MANUAL_MAPPING_DATA* mapping_data) {
    // todo: Add more checks to members (mapping_data->)
    if (!mapping_data)
        return;

    const auto base = reinterpret_cast<BYTE*>(mapping_data);
    const auto* optional_headers = 
        &reinterpret_cast<IMAGE_NT_HEADERS*>(
            base + reinterpret_cast<IMAGE_DOS_HEADER*>(mapping_data)->e_lfanew
        )->OptionalHeader;

    const auto load_library_a = mapping_data->pLoadLibraryA;
    const auto get_proc_address = mapping_data->pGetProcAddress;
    const auto dll_main = reinterpret_cast<f_DLL_ENTRY_POINT>(base + optional_headers->AddressOfEntryPoint);

    if (BYTE* location_delta = base - optional_headers->ImageBase) {
        // Check if can relocate data
        if (!optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            return;

        auto* base_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            base + optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        );
        while (base_relocation->VirtualAddress) {
            const UINT entry_count = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            auto relative_info = reinterpret_cast<WORD*>(base_relocation + 1);
            for (UINT i = 0; i != entry_count; ++i, ++relative_info) {
                if (RELOC_FLAG(*relative_info)) {
                    const auto patch = reinterpret_cast<UINT_PTR*>(base + base_relocation->VirtualAddress + ((*relative_info) & 0xFFF));
                    *patch += reinterpret_cast<UINT_PTR>(location_delta);
                }
            }
            base_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<BYTE*>(base_relocation) + base_relocation->SizeOfBlock);
        }
    }

    if (optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            base + optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );

        while (import_descriptor->Name) {
            const char* szMod = reinterpret_cast<char*>(base + import_descriptor->Name);
            HINSTANCE dll = load_library_a(szMod);
            auto pThunkRef = reinterpret_cast<ULONG_PTR*>(base + import_descriptor->OriginalFirstThunk);
            auto* pFuncRef = reinterpret_cast<ULONG_PTR*>(base + import_descriptor->FirstThunk);

            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = get_proc_address(dll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                }
                else {
                    const auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + *pThunkRef);
                    *pFuncRef = get_proc_address(dll, import_by_name->Name);
                }
            }
            ++import_descriptor;
        }
    }

    if (optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        const auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
            base + optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
        );

        for (auto* tls_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks); tls_callback && *tls_callback; ++tls_callback)
            (*tls_callback)(base, DLL_PROCESS_ATTACH, nullptr);
    }
    dll_main(base, DLL_PROCESS_ATTACH, nullptr);
    mapping_data->hMod = reinterpret_cast<HINSTANCE>(base);
}
