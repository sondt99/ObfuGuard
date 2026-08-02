#pragma once
#include "function_info.h"
#include <vector>
#include <string>

namespace ObfuGuard {

std::vector<FunctionInfo> filter_functions(
    const std::vector<FunctionInfo>& all_functions,
    const std::string& binary_path,
    uint32_t min_size = 5
);

void sort_functions_by_size_desc(std::vector<FunctionInfo>& functions);

bool is_function_blacklisted(const std::string& func_name);
bool is_function_blacklisted_by_binary_size(const std::string& func_name, const std::string& binary_path);

bool select_functions_interactive(
    const std::vector<FunctionInfo>& all_functions,
    std::vector<uint32_t>& out_rvas,
    std::vector<std::string>& out_names
);

} // namespace ObfuGuard
