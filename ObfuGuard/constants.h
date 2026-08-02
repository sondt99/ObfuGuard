#pragma once
#include <cstdint>

namespace ObfuGuard {

    // PE format constants
    constexpr uint32_t PE_FILE_ALIGNMENT = 0x200;
    constexpr uint32_t PE_SECTION_ALIGNMENT = 0x1000;
    constexpr uint32_t PE_MAX_SECTIONS = 96;
    constexpr uint32_t PE_SECTION_SAFETY_MARGIN = 10;
    constexpr uint32_t PE_RESERVED_SYSTEM_SECTIONS = 5;
    constexpr uint32_t PE_HEADER_SIZE = 0x1000;
    constexpr uint32_t MAX_PE_IMAGE_SIZE = 512 * 1024 * 1024;

    // CFF obfuscation constants
    constexpr uint32_t CFF_SECTION_SIZE = 10'000'000;
    constexpr const char* CFF_SECTION_NAME = ".0Cff";
    constexpr const char* CFF_DEV_SECTION_NAME = ".0Dev";

    // Junk code injection constants
    constexpr uint32_t MAX_JUNK_ITERATIONS = 500;
    constexpr uint32_t MIN_TRAMPOLINE_PATCH_SIZE = 5;
    constexpr uint32_t MAX_TRAMPOLINE_PATCH_SIZE = 0x1000;
    constexpr uint32_t MAX_FUNC_SCAN_SIZE = 8192;
    constexpr uint32_t DEFAULT_SECTION_SIZE = 0x1000;
    constexpr uint32_t LARGE_BINARY_SIZE_THRESHOLD = 350 * 1024;
    constexpr uint32_t MIN_FUNCTION_SIZE = 5;

    // PDB constants
    constexpr uint64_t SYM_LOAD_BASE_ADDRESS = 0x10000000;

    // Instruction format buffer
    constexpr size_t INSTRUCTION_FORMAT_BUFFER_SIZE = 256;

}
