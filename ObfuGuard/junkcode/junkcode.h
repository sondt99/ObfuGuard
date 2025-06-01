#pragma once

#include <vector>
#include <string>
#include <memory>

// Forward declarations để tránh include các thư viện nặng trong header
namespace LIEF {
    namespace PE {
        class Binary;
        class Section;
    }
}

class TrampolineInjector {
private:
    std::unique_ptr<LIEF::PE::Binary> binary_ptr;
    LIEF::PE::Binary* binary;
    uint64_t image_base;
    bool is_64_bit;

    // Helper functions
    void print_bytes(const std::string& prefix, const std::vector<uint8_t>& bytes);

    bool get_and_relocate_original_function_code(
        uint64_t original_func_va,
        uint64_t new_func_base_va,
        std::vector<uint8_t>& relocated_code_buffer,
        size_t& determined_original_function_size
    );

    bool create_new_section(const std::string& section_name, uint32_t initial_size = 0x1000);
    bool create_trampoline(uint64_t original_func_va, uint64_t new_func_va, size_t original_size);

    // New helper functions for junk code generation
    std::string get_random_junk_instruction();
    void fill_remaining_space_with_nops(uint64_t address, size_t size);

    // Helper để tạo tên section unique
    std::string generate_unique_section_name(const std::string& function_name, int index);

public:
    TrampolineInjector();
    ~TrampolineInjector();

    // Main interface functions
    bool load_pe(const std::string& pe_path);
    bool inject_function_trampoline(uint32_t function_rva);
    bool save_pe(const std::string& output_path);

    // Hàm để xử lý nhiều hàm cùng lúc
    bool inject_multiple_function_trampolines(const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names);

    // NEW: Section limit checking functions
    uint32_t get_current_section_count() const;
    uint32_t calculate_max_injectable_functions() const;
    bool check_section_limit_before_injection(uint32_t planned_injections) const;

    // NEW: Smart injection with automatic limiting
    bool inject_multiple_function_trampolines_with_limit(
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        uint32_t& actual_injected_count
    );

    // Getters
    bool get_is_64_bit() const { return is_64_bit; }
    uint64_t get_image_base() const { return image_base; }

    // Static utility function (original)
    static bool inject_trampoline_to_function(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        uint32_t function_rva,
        bool force_64_bit = false
    );

    // Static utility function cho nhiều hàm
    static bool inject_trampoline_to_multiple_functions(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        bool force_64_bit = false
    );

    // NEW: Static utility function với auto-limiting
    static bool inject_trampoline_to_multiple_functions_smart(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        uint32_t& actual_injected_count,
        bool force_64_bit = false
    );
};