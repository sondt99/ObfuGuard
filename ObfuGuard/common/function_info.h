#pragma once
#include <string>
#include <cstdint>
#include <vector>

namespace ObfuGuard {

struct FunctionInfo {
    std::string name;
    uint32_t pdb_offset;
    uint32_t rva;
    uint32_t size;
};

} // namespace ObfuGuard
