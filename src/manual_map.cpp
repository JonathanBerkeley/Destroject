
// ReSharper disable CppClangTidyPerformanceNoIntToPtr
// ReSharper disable CppClangTidyClangDiagnosticMicrosoftCast
// ReSharper disable CppClangTidyClangDiagnosticUnusedMacros

#include <fstream>
#include <string>

#include "manual_map.h"
#include "util.h"


// Parse details of supplied .DLL
std::unique_ptr<BYTE[]> parse_dll(const char* dll_name) {
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
        return nullptr;
    }

    auto src_data = std::make_unique<BYTE[]>(static_cast<size_t>(file_size));
    if (!src_data) {
        log_write("(ERROR_MM) Memory allocating failed");
        return nullptr;
    }

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(src_data.get()), file_size);
    return src_data;
}


/**
 * \brief Maps dll into memory manually
 * \param proc_handle Handle to process
 * \param dll_name Exact name of the DLL
 * \return A handle to execution thread created if succeeds
 */
HANDLE manual_map(HANDLE proc_handle, const char* dll_name) {

    const auto src_data = parse_dll(dll_name);

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(src_data.get())->e_magic != 0x5A4D) {
        log_write("(ERROR_MM) Wrong file type");
        return nullptr;
    }

    auto old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(
        src_data.get() + reinterpret_cast<IMAGE_DOS_HEADER*>(src_data.get())->e_lfanew);

    const IMAGE_OPTIONAL_HEADER* old_opt_header = &old_nt_header->OptionalHeader;
    const IMAGE_FILE_HEADER* old_file_header = &old_nt_header->FileHeader;

#ifdef _WIN64
    if (old_file_header->Machine != IMAGE_FILE_MACHINE_AMD64) {
        log_write("(ERROR_MM) Unsupported platform");
        return nullptr;
    }
#else
    if (old_file_header->Machine != IMAGE_FILE_MACHINE_I386) {
        log_write("(ERROR_MM) Unsupported platform");
        return nullptr;
    }
#endif

    auto target_base = static_cast<BYTE*>(
        VirtualAllocEx(
            proc_handle,
            reinterpret_cast<void*>(old_opt_header->ImageBase),
            old_opt_header->SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        ));

    if (!target_base) {
        target_base = static_cast<BYTE*>(VirtualAllocEx(proc_handle, nullptr, old_opt_header->SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (!target_base) {
            log_write("(ERROR_MM) Memory allocation failed: " + std::to_string(GetLastError()));
            return nullptr;
        }
    }

    MappingData mapping_data{};
    mapping_data.LoadLibraryA_ptr = LoadLibraryA;
    mapping_data.GetProcAddress_ptr = reinterpret_cast<GetProcAddress_fn>(GetProcAddress);  // NOLINT(clang-diagnostic-cast-function-type)

    auto* section_header = IMAGE_FIRST_SECTION(old_nt_header);
    for (UINT i = 0; i != old_file_header->NumberOfSections; ++i, ++section_header) {
        if (section_header->SizeOfRawData) {
            if (!WriteProcessMemory(proc_handle, target_base + section_header->VirtualAddress,
                src_data.get() + section_header->PointerToRawData, section_header->SizeOfRawData, nullptr)) {
                log_write("(ERROR_MM) Could not map sections: " + std::to_string(GetLastError()));
                VirtualFreeEx(proc_handle, target_base, 0, MEM_RELEASE);
                return nullptr;
            }
        }
    }
    memcpy(src_data.get(), &mapping_data, sizeof(mapping_data));
    WriteProcessMemory(proc_handle, target_base, src_data.get(), 0x1000, nullptr);

    void* alloc_memory = VirtualAllocEx(
        proc_handle,
        nullptr,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!alloc_memory) {
        log_write("(ERROR_MM) Shell-code memory allocation failed: " + std::to_string(GetLastError()));
        VirtualFreeEx(proc_handle, target_base, 0, MEM_RELEASE);
        return nullptr;
    }

    WriteProcessMemory(proc_handle, alloc_memory, shell_code, 0x1000, nullptr);

    HANDLE new_thread = CreateRemoteThread(
        proc_handle,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(alloc_memory),
        target_base,
        0,
        nullptr
    );

    // If CreateRemoteThread causes the process to crash, this won't know
    if (!new_thread) {
        log_write("(ERROR_MM) CreateRemoteThread failed:  " + std::to_string(GetLastError()));
        VirtualFreeEx(proc_handle, target_base, 0, MEM_RELEASE);
        VirtualFreeEx(proc_handle, alloc_memory, 0, MEM_RELEASE);
        return nullptr;
    }

    HINSTANCE hCheck = nullptr;
    while (!hCheck) {

        // Prevent infinite loop on target process death
        DWORD exit_code{};
        if (GetExitCodeProcess(proc_handle, &exit_code); exit_code != STILL_ACTIVE) {
            log_write("(ERROR_MM) Target process died while attempting to manual map to it");
            return nullptr;
        }

        MappingData data_checked{};
        ReadProcessMemory(proc_handle, target_base, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.Module;
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

void WINAPI shell_code(MappingData* mapping_data) {

    if (!mapping_data)
        return;

    const auto base = reinterpret_cast<BYTE*>(mapping_data);

    auto* e_lfanew = base + reinterpret_cast<IMAGE_DOS_HEADER*>(mapping_data)->e_lfanew;
    const auto* optional_headers = &reinterpret_cast<IMAGE_NT_HEADERS*>(e_lfanew)->OptionalHeader;

    const auto load_library_a = mapping_data->LoadLibraryA_ptr;
    const auto get_proc_address = mapping_data->GetProcAddress_ptr;
    const auto dll_main = reinterpret_cast<DllEntryPoint_fn>(base + optional_headers->AddressOfEntryPoint);

    if (BYTE* location_delta = base - optional_headers->ImageBase) {

        // Check if possible to relocate data
        if (!optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            return;

        const auto base_reloc_vaddr = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        auto* base_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + base_reloc_vaddr);

        while (base_relocation->VirtualAddress) {

            const UINT entry_count = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto relative_info = reinterpret_cast<WORD*>(base_relocation + 1);

            for (UINT i = 0u; i != entry_count; ++i, ++relative_info) {

                if (RELOC_FLAG(*relative_info)) {
                    const auto reloc_addr = base + base_relocation->VirtualAddress + (*relative_info & 0xFFF);
                    const auto patch = reinterpret_cast<UINT_PTR*>(reloc_addr);

                    *patch += reinterpret_cast<UINT_PTR>(location_delta);
                }

            }
            base_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<BYTE*>(base_relocation) + base_relocation->SizeOfBlock);
        }
    }

    // Check for import directory
    if (const auto [VirtualAddress, Size]
        = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        Size) {

        auto* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + VirtualAddress);

        while (import_descriptor->Name) {

            const char* sz_mod = reinterpret_cast<char*>(base + import_descriptor->Name);

            // ReSharper disable once CppLocalVariableMayBeConst
            HINSTANCE dll = load_library_a(sz_mod);

            auto thunk_ref = reinterpret_cast<ULONG_PTR*>(base + import_descriptor->OriginalFirstThunk);
            auto* func_ref = reinterpret_cast<ULONG_PTR*>(base + import_descriptor->FirstThunk);

            if (!thunk_ref)
                thunk_ref = func_ref;

            for (; *thunk_ref; ++thunk_ref, ++func_ref) {
                if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref)) {
                    *func_ref = get_proc_address(dll, reinterpret_cast<char*>(*thunk_ref & 0xFFFF));
                }
                else {
                    const auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + *thunk_ref);
                    *func_ref = get_proc_address(dll, import_by_name->Name);
                }
            }
            ++import_descriptor;
        }
    }

    // Check for thread local storage
    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory
    if (const auto [VirtualAddress, Size]
        = optional_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        Size) {

        const auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + VirtualAddress);

        for (auto* tls_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks); tls_callback && *tls_callback; ++tls_callback)
            (*tls_callback)(base, DLL_PROCESS_ATTACH, nullptr);

    }
    dll_main(base, DLL_PROCESS_ATTACH, nullptr);
    mapping_data->Module = reinterpret_cast<HINSTANCE>(base);
}
