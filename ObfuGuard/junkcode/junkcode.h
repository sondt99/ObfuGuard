#pragma once

#include <vector>
#include <string>
#include <memory>

// Khai báo trước
namespace LIEF {
    namespace PE {
        class Binary;
        class Section;
    }
}

class TrampolineInjector {
private:
    std::unique_ptr<LIEF::PE::Binary> binary_ptr; // Con trỏ smart sở hữu đối tượng Binary của LIEF
    LIEF::PE::Binary* binary; // Con trỏ raw dùng nội bộ để truy cập nhanh
    uint64_t image_base; // Địa chỉ cơ sở của file PE
    bool is_64_bit;

    // In chuỗi byte (dùng để debug)
    void print_bytes(const std::string& prefix, const std::vector<uint8_t>& bytes);
    
    // Lấy mã gốc của hàm và relocate sang địa chỉ mới
    bool get_and_relocate_original_function_code(
        uint64_t original_func_va,
        uint64_t new_func_base_va,
        std::vector<uint8_t>& relocated_code_buffer,
        size_t& determined_original_function_size
    );

    // Tạo section mới trong PE file
    bool create_new_section(const std::string& section_name, uint32_t initial_size = 0x1000);
    // Tạo JMP từ hàm gốc sang mã relocated
    bool create_trampoline(uint64_t original_func_va, uint64_t new_func_va, size_t original_size);

    // Sinh lệnh junk (ASM không có tác dụng thực sự) để gây nhiễu người phân tích
    std::string get_random_junk_instruction();
    void fill_remaining_space_with_nops(uint64_t address, size_t size); // Chèn NOP để điền phần còn lại chưa sử dụng

    // Tạo tên section hợp lệ, ngắn gọn và unique theo tên hàm
    std::string generate_unique_section_name(const std::string& function_name, int index);

public:
    TrampolineInjector(); // Hàm khởi tạo
    ~TrampolineInjector(); // Hàm hủy

    bool load_pe(const std::string& pe_path);
    bool inject_function_trampoline(uint32_t function_rva); // Inject trampoline vào một hàm (theo RVA)
    bool save_pe(const std::string& output_path);

    // Inject nhiều hàm cùng lúc
    bool inject_multiple_function_trampolines(const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names);

    // Lấy số section hiện có trong PE, tính số lượng max và kiểm tra xem có thể chèn thêm được bao nhiêu nữa
    uint32_t get_current_section_count() const;
    uint32_t calculate_max_injectable_functions() const;
    bool check_section_limit_before_injection(uint32_t planned_injections) const;

    // Inject nhiều hàm, nhưng giới hạn tự động nếu gần đạt giới hạn PE section
    bool inject_multiple_function_trampolines_with_limit(
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        uint32_t& actual_injected_count
    );

    bool get_is_64_bit() const { return is_64_bit; }
    uint64_t get_image_base() const { return image_base; } // Lấy image base của PE file

    // Inject vào một hàm (single)
    static bool inject_trampoline_to_function(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        uint32_t function_rva,
        bool force_64_bit = false
    );

    // Inject nhiều hàm (không giới hạn section)
    static bool inject_trampoline_to_multiple_functions(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        bool force_64_bit = false
    );

    // Inject nhiều hàm có auto-limiting dựa theo số section tối đa
    static bool inject_trampoline_to_multiple_functions_smart(
        const std::string& input_pe_path,
        const std::string& output_pe_path,
        const std::vector<uint32_t>& function_rvas,
        const std::vector<std::string>& function_names,
        uint32_t& actual_injected_count,
        bool force_64_bit = false
    );
};