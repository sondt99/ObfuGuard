#include "pdbparser.h"
#include "../constants.h"

#include <Windows.h>
#define _NO_CVCONST_H
#include <dbghelp.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_set>

#pragma comment(lib, "dbghelp.lib")

namespace {

// Prefer sibling .pdb next to the EXE; reject UNC / parent-relative paths for embedded CV strings.
bool is_safe_local_pdb_path(const std::filesystem::path& p) {
    const auto s = p.wstring();
    if (s.size() >= 2 && s[0] == L'\\' && s[1] == L'\\')
        return false; // UNC
    if (s.find(L"..") != std::wstring::npos)
        return false;
    return true;
}

std::string load_sibling_pdb(const std::string& exe_path) {
    auto fallback = std::filesystem::path(exe_path).replace_extension(".pdb");
    if (!std::filesystem::exists(fallback)) {
        throw std::runtime_error("PDB not found (sibling): " + fallback.string());
    }
    return fallback.string();
}

} // namespace

pdbparser::pdbparser(pe64* pe_image) {
    HANDLE process_handle = GetCurrentProcess();

    if (!SymInitialize(process_handle, nullptr, FALSE)) {
        throw std::runtime_error("Failed to initialize symbol handler (SymInitialize).");
    }

    std::string exe_path = pe_image->get_path();
    auto dbg_dir_va = pe_image->get_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;

    auto try_load = [&](const std::string& pdb_path) {
        auto file_size64 = std::filesystem::file_size(pdb_path);
        if (file_size64 == 0 || file_size64 > (4ull * 1024 * 1024 * 1024)) {
            throw std::runtime_error("PDB file size is invalid: " + pdb_path);
        }
        auto file_size = static_cast<DWORD>(file_size64);
        this->module_base = reinterpret_cast<uint8_t*>(
            SymLoadModuleEx(process_handle, nullptr, pdb_path.c_str(), nullptr,
                ObfuGuard::SYM_LOAD_BASE_ADDRESS, file_size, nullptr, 0)
            );
        if (!this->module_base) {
            throw std::runtime_error("Failed to load PDB module with SymLoadModuleEx: " + pdb_path);
        }
    };

    try {
        if (!dbg_dir_va) {
            try_load(load_sibling_pdb(exe_path));
            return;
        }

        auto buffer_size = pe_image->get_buffer()->size();
        const auto raw_size = pe_image->get_buffer_not_relocated()->size();
        auto dbg_dir_size = pe_image->get_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

        if (dbg_dir_size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
            static_cast<size_t>(dbg_dir_va) + sizeof(IMAGE_DEBUG_DIRECTORY) > buffer_size) {
            // Malformed directory — try sibling PDB before failing
            try_load(load_sibling_pdb(exe_path));
            return;
        }

        auto max_entries = dbg_dir_size / sizeof(IMAGE_DEBUG_DIRECTORY);
        bool tried_cv = false;

        for (DWORD entry_idx = 0; entry_idx < max_entries; ++entry_idx) {
            const size_t entry_off = static_cast<size_t>(dbg_dir_va) +
                static_cast<size_t>(entry_idx) * sizeof(IMAGE_DEBUG_DIRECTORY);
            if (entry_off + sizeof(IMAGE_DEBUG_DIRECTORY) > buffer_size)
                break;

            auto* dbg_dir_ptr = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
                pe_image->get_buffer()->data() + entry_off);

            if (dbg_dir_ptr->SizeOfData == 0)
                continue;
            if (dbg_dir_ptr->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
                continue;

            tried_cv = true;

            // Widened arithmetic to avoid DWORD wrap
            const size_t raw_off = static_cast<size_t>(dbg_dir_ptr->PointerToRawData);
            const size_t raw_len = static_cast<size_t>(dbg_dir_ptr->SizeOfData);
            if (raw_off > raw_size || raw_len > raw_size - raw_off)
                continue;

            // Minimum CodeView header: signature + GUID + age + at least 1 path byte
            if (raw_len < sizeof(ULONG) + sizeof(GUID) + sizeof(ULONG) + 1)
                continue;

            auto* raw = pe_image->get_buffer_not_relocated()->data() + raw_off;
            // PdbFileName starts after CvSignature(4) + GUID(16) + Age(4) = 24
            constexpr size_t kPathOffset = 24;
            if (raw_len <= kPathOffset)
                continue;

            const size_t path_max = raw_len - kPathOffset;
            const char* path_ptr = reinterpret_cast<const char*>(raw + kPathOffset);
            size_t path_len = 0;
            while (path_len < path_max && path_ptr[path_len] != '\0')
                ++path_len;
            if (path_len == 0 || path_len >= path_max) {
                // Not NUL-terminated within SizeOfData
                continue;
            }

            std::string embedded_pdb(path_ptr, path_len);
            std::filesystem::path embedded_path(embedded_pdb);

            std::string resolved;
            if (is_safe_local_pdb_path(embedded_path) && std::filesystem::exists(embedded_path)) {
                resolved = embedded_path.string();
            } else {
                // Sibling-only fallback (do not follow arbitrary remote/parent paths)
                resolved = load_sibling_pdb(exe_path);
            }

            try_load(resolved);
            return;
        }

        // No usable CodeView entry — sibling fallback (parity with no-debug-dir case)
        if (!tried_cv || true) {
            try_load(load_sibling_pdb(exe_path));
            return;
        }
    }
    catch (const std::exception&) {
        SymCleanup(process_handle);
        throw;
    }
}

pdbparser::~pdbparser() {
    if (this->module_base) {
        SymUnloadModule64(GetCurrentProcess(), reinterpret_cast<DWORD64>(this->module_base));
        this->module_base = nullptr;
    }
    SymCleanup(GetCurrentProcess());
}

std::vector<pdbparser::sym_func> pdbparser::parse_functions() {
    struct symbol_collector {
        DWORD64 base_address;
        std::vector<sym_func>* function_list;
        std::unordered_set<uint32_t>* seen_offsets;
        int id_counter;
    };

    symbol_collector collector_ctx;
    collector_ctx.base_address = reinterpret_cast<DWORD64>(this->module_base);
    std::vector<sym_func> collected_functions;
    std::unordered_set<uint32_t> seen_offsets;
    collector_ctx.function_list = &collected_functions;
    collector_ctx.seen_offsets = &seen_offsets;
    collector_ctx.id_counter = 0;

    auto callback = [](PSYMBOL_INFO sym_info, ULONG /*size*/, PVOID user_data) -> BOOL {
        if (sym_info->Tag != SymTagFunction)
            return TRUE;

        auto* ctx = static_cast<symbol_collector*>(user_data);
        sym_func fn_data{};
        fn_data.offset = 0;

        // Section-relative / address-offset as used by FunctionDiscovery (.text + offset)
        if (!SymGetTypeInfo(GetCurrentProcess(), ctx->base_address, sym_info->Index, TI_GET_OFFSET, &fn_data.offset)) {
            SymGetTypeInfo(GetCurrentProcess(), ctx->base_address, sym_info->Index, TI_GET_ADDRESSOFFSET, &fn_data.offset);
        }

        if (!ctx->seen_offsets->insert(fn_data.offset).second) {
            return TRUE;
        }

        fn_data.id = ctx->id_counter++;
        fn_data.name = sym_info->Name;
        fn_data.size = static_cast<uint32_t>(sym_info->Size);
        // Cap absurd sizes from malicious/corrupt PDBs
        if (fn_data.size > ObfuGuard::MAX_FUNC_SCAN_SIZE * 4)
            fn_data.size = ObfuGuard::MAX_FUNC_SCAN_SIZE * 4;
        ctx->function_list->push_back(fn_data);

        return TRUE;
        };

    if (!SymEnumSymbols(GetCurrentProcess(), collector_ctx.base_address, nullptr,
        reinterpret_cast<PSYM_ENUMERATESYMBOLS_CALLBACK>(callback), &collector_ctx)) {
        throw std::runtime_error("Failed to enumerate symbols from PDB.");
    }

    return collected_functions;
}
