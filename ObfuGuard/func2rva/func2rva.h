#pragma once

#include <string>
#include <vector>
#include <cstdint> // For uint32_t, uint64_t
#include <memory>  // For std::unique_ptr
#include "../pe/pe.h" // Include the header file where pe64 is defined
#include "../pdbparser/pdbparser.h"

namespace FuncToRVA {

    // Thông tin về một hàm được phân giải
    struct FunctionInfo {
        std::string name;       // Tên hàm
        uint32_t rva;           // RVA đã tính toán (ví dụ: text_section_rva + pdb_offset)
        uint32_t pdb_offset;    // Offset gốc từ PDB
        uint32_t size;          // Kích thước hàm từ PDB
    };

    // Lớp để phân giải RVA của hàm từ tệp PE và PDB
    class RVAResolver {
    public:
        // Constructor, nhận đường dẫn đến tệp PE
        RVAResolver(const std::string& pe_path);
        // Destructor
        ~RVAResolver();

        // Khởi tạo: tải tệp PE và phân tích PDB.
        // Trả về true nếu thành công, false nếu thất bại.
        bool initialize();

        // Trả về danh sách các hàm đã phân giải (tên, RVA, offset PDB, kích thước).
        // Chỉ gọi sau khi initialize() thành công.
        const std::vector<FunctionInfo>& get_functions_info() const;

        // Hiển thị danh sách các hàm và cho phép người dùng chọn một hàm.
        // Trả về true và gán RVA của hàm được chọn vào out_rva nếu thành công.
        // Chỉ gọi sau khi initialize() thành công.
        bool select_function_rva_interactive(uint32_t& out_rva);

        // HÀM MỚI: Hiển thị danh sách các hàm và cho phép người dùng chọn nhiều hàm.
        // Trả về true và gán danh sách RVA và tên hàm được chọn nếu thành công.
        // Chỉ gọi sau khi initialize() thành công.
        bool select_multiple_functions_rva_interactive(std::vector<uint32_t>& out_rvas, std::vector<std::string>& out_names);

    private:
        std::string pe_path_str_;                       // Đường dẫn đến tệp PE
        std::unique_ptr<pe64> pe_file_handle_;          // Con trỏ thông minh đến đối tượng pe64
        std::unique_ptr<pdbparser> pdb_parser_handle_;  // Con trỏ thông minh đến đối tượng pdbparser
        std::vector<FunctionInfo> resolved_functions_list_; // Danh sách các hàm đã phân giải
        bool is_initialized_ = false;                   // Trạng thái khởi tạo
        uint64_t image_base_ = 0;                       // ImageBase của tệp PE
        uint32_t text_section_rva_ = 0;                 // RVA của section .text
        bool has_text_section_for_reference_ = false;   // Cờ cho biết có section .text hay không

        // Hàm nội bộ để tải PE và phân tích PDB
        bool load_pe_and_parse_pdb();
    };

    // Hàm tiện ích độc lập để đơn giản hóa việc sử dụng trong main.cpp
    // Hiển thị danh sách hàm từ tệp PE và cho phép người dùng chọn một hàm, trả về RVA của hàm đó.
    // Trả về true nếu thành công, false nếu thất bại hoặc người dùng hủy bỏ.
    bool get_rva_by_interactive_selection(const std::string& pe_file_path, uint32_t& selected_rva);

    // HÀM MỚI: Hàm tiện ích để chọn nhiều hàm cùng lúc
    // Hiển thị danh sách hàm từ tệp PE và cho phép người dùng chọn nhiều hàm, trả về danh sách RVA và tên.
    // Trả về true nếu thành công, false nếu thất bại hoặc người dùng hủy bỏ.
    bool get_multiple_rvas_by_interactive_selection(const std::string& pe_file_path,
        std::vector<uint32_t>& selected_rvas,
        std::vector<std::string>& selected_names);

} // namespace FuncToRVA