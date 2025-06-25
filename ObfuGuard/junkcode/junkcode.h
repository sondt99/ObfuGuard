#pragma once

#ifndef JUNKCODE_H
#define JUNKCODE_H

#include <vector>
#include <string>
#include <memory>
#include <set>
#include <cstdint>

// Khai báo trước
namespace LIEF {
    namespace PE {
        class Binary;
        class Section;
    }
}

// Thêm namespace FuncToRVA forward declaration
namespace FuncToRVA {
    struct FunctionInfo;
}

class TrampolineInjector {
private:
    std::unique_ptr<LIEF::PE::Binary> binary_ptr;
    LIEF::PE::Binary* binary;
    uint64_t image_base;
    bool is_64_bit;

    void print_bytes(const std::string& prefix, const std::vector<uint8_t>& bytes);

    bool get_and_relocate_original_function_code(
        uint64_t original_func_va,
        uint64_t new_func_base_va,
        std::vector<uint8_t>& relocated_code_buffer,
        size_t& determined_original_function_size
    );

    bool create_new_section(const std::string& section_name, uint32_t initial_size = 0x1000);
    bool create_trampoline(uint64_t original_func_va, uint64_t new_func_va, size_t original_size);

    std::string get_random_junk_instruction();
    void fill_remaining_space_with_nops(uint64_t address, size_t size);
    std::string generate_unique_section_name(const std::string& function_name, int index);

public:
    TrampolineInjector();
    ~TrampolineInjector();

    bool load_pe(const std::string& pe_path);
    bool inject_function_trampoline(uint32_t function_rva);
    bool save_pe(const std::string& output_path);

    bool inject_multiple_function_trampolines(const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names);

    uint32_t get_current_section_count() const;
    uint32_t calculate_max_injectable_functions() const;
    bool check_section_limit_before_injection(uint32_t planned_injections) const;

    bool inject_multiple_function_trampolines_with_limit(
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        uint32_t& actual_injected_count
    );

    bool get_is_64_bit() const { return is_64_bit; }
    uint64_t get_image_base() const { return image_base; }

    // Static methods
    static bool inject_trampoline_to_function(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        uint32_t function_rva,
        bool force_64_bit = false
    );

    static bool inject_trampoline_to_multiple_functions(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        bool force_64_bit = false
    );

    static bool inject_trampoline_to_multiple_functions_smart(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        uint32_t& actual_injected_count,
        bool force_64_bit = false
    );
};

// ============ THÊM MỚI: JunkCodeManager ============
class JunkCodeManager {
public:
    // Main interface methods
    static int run_auto_injection_mode(const std::string& input_pe_path,
        const std::string& output_pe_path,
        bool is_64_bit);

    static int run_manual_injection_mode(const std::string& input_pe_path,
        const std::string& output_pe_path,
        bool is_64_bit);

private:
    // Utility methods moved from main.cpp
    static bool filter_functions_by_size(const std::string& input_pe_path,
        const std::vector<uint32_t>& input_rvas,
        const std::vector<std::string>& input_names,
        std::vector<uint32_t>& filtered_rvas,
        std::vector<std::string>& filtered_names,
        uint32_t min_size = 5);

    static bool get_multiple_rvas_interactive(const std::string& input_pe_path,
        std::vector<uint32_t>& rvas_out,
        std::vector<std::string>& names_out);

    static void sort_functions_by_size_desc(std::vector<uint32_t>& function_rvas,
        std::vector<std::string>& function_names,
        const std::vector<FuncToRVA::FunctionInfo>& all_functions);

    static bool is_function_blacklisted(const std::string& func_name);

    // ========== THÊM MỚI: Binary size checking methods ==========
    static bool is_binary_large(const std::string& binary_path);
    static bool is_large_binary_function_dangerous(const std::string& func_name, const std::string& binary_path);
    static bool is_function_blacklisted_by_binary_size(const std::string& func_name, const std::string& binary_path);

    // Constants moved from main.cpp
    static const std::set<std::string> DANGEROUS_FUNCTION_NAMES;
    static const std::vector<std::string> DANGEROUS_PREFIXES;

    // ========== THAY ĐỔI: Constants cho binary size checking ==========
    static const uint32_t LARGE_BINARY_SIZE_THRESHOLD; // Thay đổi từ LARGE_FUNCTION_SIZE_THRESHOLD
    static const std::set<std::string> DANGEROUS_FUNCTION_NAMES_BIG_BINARY; // Thay đổi từ DANGEROUS_FUNCTION_NAMES_BIG_SIZE
};

#endif // JUNKCODE_H