#pragma once
#include "function_info.h"
#include "../pe/pe.h"
#include "../pdbparser/pdbparser.h"
#include <vector>
#include <string>
#include <memory>

namespace ObfuGuard {

class FunctionDiscovery {
public:
    explicit FunctionDiscovery(const std::string& pe_path);

    [[nodiscard]] const std::vector<FunctionInfo>& get_functions() const;
    [[nodiscard]] uint32_t get_text_section_rva() const;
    [[nodiscard]] uint64_t get_image_base() const;

private:
    std::unique_ptr<pe64> pe_;
    std::unique_ptr<pdbparser> pdb_;
    std::vector<FunctionInfo> functions_;
    uint32_t text_section_rva_ = 0;
    uint64_t image_base_ = 0;
};

} // namespace ObfuGuard
