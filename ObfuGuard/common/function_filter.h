#pragma once
#include "function_info.h"
#include <vector>
#include <string>

namespace ObfuGuard {

// Optional: load additional blacklist names from a text file.
// Format: one name per line; '#' comments and blank lines ignored.
// Safe to call multiple times; names are merged into the runtime set.
bool load_blacklist_file(const std::string& path);

// Try common locations for blacklist_default.txt (CWD, next to binary path).
// Falls back to built-in defaults if no file is found.
void ensure_blacklist_loaded(const std::string& binary_path = "");

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
