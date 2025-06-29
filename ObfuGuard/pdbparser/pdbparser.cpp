#include "pdbparser.h"

#include <Windows.h>
#define _NO_CVCONST_H
#include <dbghelp.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")

pdbparser::pdbparser(pe64* pe_image) {
    HANDLE process_handle = GetCurrentProcess();

    if (!SymInitialize(process_handle, nullptr, FALSE)) {
        throw std::runtime_error("Failed to initialize symbol handler (SymInitialize).");
    }

    std::string exe_path = pe_image->get_path();
    auto dbg_dir_va = pe_image->get_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;

    std::string resolved_pdb_path;

    if (!dbg_dir_va) {
        auto fallback_pdb_path = std::filesystem::path(exe_path).replace_extension(".pdb");
        if (!std::filesystem::exists(fallback_pdb_path)) {
            throw std::runtime_error("PDB not found (fallback mode): " + fallback_pdb_path.string());
        }
        resolved_pdb_path = fallback_pdb_path.string();
    }

    auto dbg_dir_ptr = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
        pe_image->get_buffer()->data() + dbg_dir_va
        );

    while (dbg_dir_ptr->SizeOfData) {
        if (dbg_dir_ptr->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
            ++dbg_dir_ptr;
            continue;
        }

        auto cv_info = reinterpret_cast<codeviewInfo_t*>(
            pe_image->get_buffer_not_relocated()->data() + dbg_dir_ptr->PointerToRawData
            );

        std::string embedded_pdb = cv_info->PdbFileName;
        std::filesystem::path embedded_path(embedded_pdb);

        if (!std::filesystem::exists(embedded_path)) {
            auto fallback_pdb = std::filesystem::path(exe_path).replace_extension(".pdb");
            if (!std::filesystem::exists(fallback_pdb)) {
                throw std::runtime_error("PDB file missing. Attempted: " + fallback_pdb.string());
            }
            embedded_pdb = fallback_pdb.string();
        }

        auto file_size = static_cast<DWORD>(std::filesystem::file_size(embedded_pdb));
        this->module_base = reinterpret_cast<uint8_t*>(
            SymLoadModuleEx(process_handle, nullptr, embedded_pdb.c_str(), nullptr, 0x10000000, file_size, nullptr, 0)
            );

        if (!this->module_base) {
            throw std::runtime_error("Failed to load PDB module with SymLoadModuleEx.");
        }

        return;
    }

    throw std::runtime_error("No valid debug directory entry found.");
}

pdbparser::~pdbparser() {
    SymCleanup(GetCurrentProcess());
}

std::vector<pdbparser::sym_func> pdbparser::parse_functions() {
    struct symbol_collector {
        DWORD64 base_address;
        std::vector<sym_func>* function_list;
    };

    symbol_collector collector_ctx;
    collector_ctx.base_address = reinterpret_cast<DWORD64>(this->module_base);
    std::vector<sym_func> collected_functions;

    collector_ctx.function_list = &collected_functions;
    static int symbol_id_counter = 0;

    auto callback = [](PSYMBOL_INFO sym_info, ULONG /*size*/, PVOID user_data) -> BOOL {
        if (sym_info->Tag != SymTagFunction)
            return TRUE;

        auto* ctx = static_cast<symbol_collector*>(user_data);
        sym_func fn_data{};
        fn_data.offset = 0;

        if (!SymGetTypeInfo(GetCurrentProcess(), ctx->base_address, sym_info->Index, TI_GET_OFFSET, &fn_data.offset)) {
            SymGetTypeInfo(GetCurrentProcess(), ctx->base_address, sym_info->Index, TI_GET_ADDRESSOFFSET, &fn_data.offset);
        }

        auto exists = std::any_of(ctx->function_list->begin(), ctx->function_list->end(),
            [&](const sym_func& existing) {
                return existing.offset == fn_data.offset;
            });

        if (!exists) {
            fn_data.id = symbol_id_counter++;
            fn_data.name = sym_info->Name;
            fn_data.size = sym_info->Size;
            ctx->function_list->push_back(fn_data);
        }

        return TRUE;
        };

    if (!SymEnumSymbols(GetCurrentProcess(), collector_ctx.base_address, nullptr,
        (PSYM_ENUMERATESYMBOLS_CALLBACK)callback, &collector_ctx)) {
        throw std::runtime_error("Failed to enumerate symbols from PDB.");
    }

    return collected_functions;
}
