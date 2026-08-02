#include "function_discovery.h"
#include <stdexcept>
#include <iostream>

namespace ObfuGuard {

FunctionDiscovery::FunctionDiscovery(const std::string& pe_path) {
    pe_ = std::make_unique<pe64>(pe_path);

    PIMAGE_NT_HEADERS nt = pe_->get_nt();
    if (!nt) {
        throw std::runtime_error("Failed to get NT headers from: " + pe_path);
    }
    image_base_ = nt->OptionalHeader.ImageBase;

    PIMAGE_SECTION_HEADER text_section = pe_->get_section(".text");
    if (text_section) {
        text_section_rva_ = text_section->VirtualAddress;
    } else {
        std::cerr << "Warning: .text section not found in " << pe_path << std::endl;
    }

    pdb_ = std::make_unique<pdbparser>(pe_.get());
    auto sym_functions = pdb_->parse_functions();

    functions_.reserve(sym_functions.size());
    for (const auto& sf : sym_functions) {
        FunctionInfo info;
        info.name = sf.name;
        info.pdb_offset = sf.offset;
        info.size = sf.size;
        info.rva = text_section_rva_ + sf.offset;
        functions_.push_back(info);
    }
}

const std::vector<FunctionInfo>& FunctionDiscovery::get_functions() const {
    return functions_;
}

uint32_t FunctionDiscovery::get_text_section_rva() const {
    return text_section_rva_;
}

uint64_t FunctionDiscovery::get_image_base() const {
    return image_base_;
}

} // namespace ObfuGuard
