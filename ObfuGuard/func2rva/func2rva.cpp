#include "func2rva.h" 
#include "../pe/pe.h" 
#include "../pdbparser/pdbparser.h" 

#include <iostream>
#include <iomanip>   
#include <stdexcept> 
#include <limits>    
#include <sstream> 
#include <algorithm>
#include <vector>    
#include <memory>    


namespace FuncToRVA { // Namespace cho phân giải hàm thành RVAs

    RVAResolver::RVAResolver(const std::string& pe_path) // Hàm khởi tạo lớp RVAResolver, nhận vào đường dẫn tới file PE (EXE/DLL)
        : pe_path_str_(pe_path),
        is_initialized_(false),
        image_base_(0),
        text_section_rva_(0),
        has_text_section_for_reference_(false) {
    }

    RVAResolver::~RVAResolver() {} // Hàm hủy của lớp RVAResolver, mặc định không cần xử lý gì thêm

    bool RVAResolver::initialize() { // Hàm khởi tạo phân giải RVA. Nếu đã khởi tạo trước đó thì bỏ qua.
        if (is_initialized_) {
            return true; 
        }
        is_initialized_ = load_pe_and_parse_pdb();
        return is_initialized_;
    }

    bool RVAResolver::load_pe_and_parse_pdb() { // Trích xuất hàm từ pe và pdb, tính toán RVA dựa trên offset
        try {   
            pe_file_handle_ = std::make_unique<pe64>(pe_path_str_);

			PIMAGE_NT_HEADERS nt_headers = pe_file_handle_->get_nt(); // Lấy NT Headers từ PE
            if (!nt_headers) {
                std::cerr << "Error: Could not get NT Headers from PE file: " << pe_path_str_ << std::endl;
                return false;
            }
            image_base_ = nt_headers->OptionalHeader.ImageBase;

			PIMAGE_SECTION_HEADER text_section = pe_file_handle_->get_section(".text"); // lấy .text section
            if (text_section) {
                text_section_rva_ = text_section->VirtualAddress;
                has_text_section_for_reference_ = true;
            }
            else {
                std::cerr << "Warning: Could not find '.text' section in file " << pe_path_str_
                    << ". RVA calculations may be affected." << std::endl;
                // Dựa trên func2rva.cpp, giả định rằng offset từ PDB được cộng thêm vào địa chỉ RVA của đoạn .text
            }

            pdb_parser_handle_ = std::make_unique<pdbparser>(pe_file_handle_.get());
            std::vector<pdbparser::sym_func> functions_from_pdb = pdb_parser_handle_->parse_functions();

            if (functions_from_pdb.empty()) {
                std::cout << "Info: No functions found or parsed from PDB for file "
                    << pe_path_str_ << std::endl;
             
            }

            resolved_functions_list_.clear();
            for (const auto& pdb_func : functions_from_pdb) {
                FunctionInfo info;
                info.name = pdb_func.name;
                info.pdb_offset = pdb_func.offset; 
                info.size = pdb_func.size;        

                if (has_text_section_for_reference_) {
                    info.rva = text_section_rva_ + pdb_func.offset;
                }
                else {
         
                    std::cerr << "Warning: Cannot compute RVA for function '" << info.name
                        << "' because '.text' section was not found." << std::endl;
                    info.rva = 0; 
                }
                resolved_functions_list_.push_back(info);
            }
            return true; 
        }
        catch (const std::exception& e) {
            std::cerr << "Error during RVAResolver initialization: " << e.what() << std::endl;
            return false; 
        }
    }

	// Trả về danh sách các hàm đã phân giải. Nếu chưa khởi tạo, trả về danh sách rỗng và thông báo lỗi.
    const std::vector<FunctionInfo>& RVAResolver::get_functions_info() const {
        if (!is_initialized_) {
            static std::vector<FunctionInfo> empty_list; 
            std::cerr << "Error: RVAResolver has not been initialized. Please call initialize() first." << std::endl;
            return empty_list;
        }
        return resolved_functions_list_;
    }

	// Hiển thị danh sách các hàm, cho người dùng chọn một hàm để lấy RVA
    bool RVAResolver::select_function_rva_interactive(uint32_t& out_rva) {
        if (!is_initialized_) {
            std::cerr << "Error: RVAResolver has not been initialized. Please call initialize() first." << std::endl;
            return false;
        }

        if (resolved_functions_list_.empty()) {
            std::cout << "Info: No functions from PDB available to select." << std::endl;
            return false;
        }

        std::cout << "\nAvailable functions from PDB for file: " << pe_path_str_ << std::endl;
        std::cout << "PE ImageBase: 0x" << std::hex << image_base_ << std::dec << std::endl;
        if (has_text_section_for_reference_) {
            std::cout << "Using PDB offsets relative to '.text' section (RVA: 0x"
                << std::hex << text_section_rva_ << std::dec << ")" << std::endl;
        }
        else {
            std::cout << "Warning: '.text' section not found. Displayed RVAs may be PDB offsets or 0 if unable to compute." << std::endl;
        }
        std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
        std::cout << std::setw(7) << "No." << " | "
            << std::setw(12) << "RVA (Hex)" << " | "
            << std::setw(12) << "Offset (Hex)" << " | "
            << std::setw(10) << "Size" << " | "
            << "Function Name" << std::endl;
        std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;

        for (size_t i = 0; i < resolved_functions_list_.size(); ++i) {
            const auto& func_info = resolved_functions_list_[i];
            std::cout << std::setw(7) << std::left << i + 1 << " | "
                << "0x" << std::hex << std::setw(10) << std::left << func_info.rva
                << " | "
                << "0x" << std::hex << std::setw(10) << std::left << func_info.pdb_offset
                << " | "
                << std::dec << std::setw(10) << std::left << func_info.size
                << " | "
                << func_info.name << std::endl;
        }
        std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;

        int choice = 0;
        while (true) {
            std::cout << "Select function by No. (enter 0 to cancel): ";
            std::cin >> choice;

            if (std::cin.fail()) {
                std::cin.clear(); 
                std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n'); 
                std::cout << "Invalid input. Please enter a number." << std::endl;
                continue;
            }
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

            if (choice == 0) {
                std::cout << "Selection cancelled." << std::endl;
                return false; 
            }
            if (choice > 0 && static_cast<size_t>(choice) <= resolved_functions_list_.size()) {
                out_rva = resolved_functions_list_[choice - 1].rva;
               
                if (out_rva == 0 && !has_text_section_for_reference_ && resolved_functions_list_[choice - 1].pdb_offset != 0) {
                    std::cout << "Warning: Selected function has RVA 0, possibly because '.text' section was not found. Be cautious." << std::endl;
                }
                std::cout << "Selected: " << resolved_functions_list_[choice - 1].name
                    << " (RVA: 0x" << std::hex << out_rva << std::dec << ")" << std::endl;
                return true; 
            }
            else {
                std::cout << "Invalid No. Please try again." << std::endl;
            }
        }
    }

    // Hàm tiện ích cho phép chọn một hàm từ PE và gọi nội bộ RVAResolver thực hiện chọn hàm
    bool get_rva_by_interactive_selection(const std::string& pe_file_path, uint32_t& selected_rva) {
        RVAResolver resolver(pe_file_path);
        if (!resolver.initialize()) {
            // Error messages already printed by resolver.initialize() or resolver.load_pe_and_parse_pdb()
            return false;
        }
        return resolver.select_function_rva_interactive(selected_rva);
    }

    // Cho phép chọn nhiều hàm từ list
    bool RVAResolver::select_multiple_functions_rva_interactive(std::vector<uint32_t>& out_rvas, std::vector<std::string>& out_names) {
        if (!is_initialized_) {
            std::cerr << "Error: RVAResolver has not been initialized. Please call initialize() first." << std::endl;
            return false;
        }

        if (resolved_functions_list_.empty()) {
            std::cout << "Info: No functions from PDB available to select." << std::endl;
            return false;
        }

        std::cout << "\nAvailable functions from PDB for file: " << pe_path_str_ << std::endl;
        std::cout << "PE ImageBase: 0x" << std::hex << image_base_ << std::dec << std::endl;
        if (has_text_section_for_reference_) {
            std::cout << "Using PDB offsets relative to '.text' section (RVA: 0x"
                << std::hex << text_section_rva_ << std::dec << ")" << std::endl;
        }
        else {
            std::cout << "Warning: '.text' section not found. Displayed RVAs may be PDB offsets or 0 if unable to compute." << std::endl;
        }
        std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
        std::cout << std::setw(7) << "No." << " | "
            << std::setw(12) << "RVA (Hex)" << " | "
            << std::setw(12) << "Offset (Hex)" << " | "
            << std::setw(10) << "Size" << " | "
            << "Function Name" << std::endl;
        std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;

        for (size_t i = 0; i < resolved_functions_list_.size(); ++i) {
            const auto& func_info = resolved_functions_list_[i];
            std::cout << std::setw(7) << std::left << i + 1 << " | "
                << "0x" << std::hex << std::setw(10) << std::left << func_info.rva
                << " | "
                << "0x" << std::hex << std::setw(10) << std::left << func_info.pdb_offset
                << " | "
                << std::dec << std::setw(10) << std::left << func_info.size
                << " | "
                << func_info.name << std::endl;
        }
        std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;

        std::string input_str;
        while (true) {
            std::cout << "Select functions by No. (comma-separated, e.g., '1,3,5' or enter 0 to cancel): ";
            std::getline(std::cin, input_str);

            if (input_str.empty()) {
                std::cout << "Invalid input. Please enter numbers separated by commas." << std::endl;
                continue;
            }

            if (input_str == "0") {
                std::cout << "Selection cancelled." << std::endl;
                return false;
            }

            // Parse comma-separated input
            std::vector<int> choices;
            std::stringstream ss(input_str);
            std::string token;
            bool valid_input = true;

            while (std::getline(ss, token, ',')) {
                // Trim whitespace
                token.erase(0, token.find_first_not_of(" \t"));
                token.erase(token.find_last_not_of(" \t") + 1);

                try {
                    int choice = std::stoi(token);
                    if (choice <= 0 || static_cast<size_t>(choice) > resolved_functions_list_.size()) {
                        std::cout << "Invalid No. " << choice << ". Please enter numbers between 1 and "
                            << resolved_functions_list_.size() << "." << std::endl;
                        valid_input = false;
                        break;
                    }
                    choices.push_back(choice);
                }
                catch (const std::exception&) {
                    std::cout << "Invalid input format: '" << token << "'. Please enter valid numbers." << std::endl;
                    valid_input = false;
                    break;
                }
            }

            if (!valid_input) {
                continue;
            }

            if (choices.empty()) {
                std::cout << "No valid selections. Please try again." << std::endl;
                continue;
            }

            // Remove duplicates
            std::sort(choices.begin(), choices.end());
            choices.erase(std::unique(choices.begin(), choices.end()), choices.end());

            // Validate all choices and collect results
            out_rvas.clear();
            out_names.clear();

            std::cout << "\nSelected functions:" << std::endl;
            for (int choice : choices) {
                const auto& func_info = resolved_functions_list_[choice - 1];
                out_rvas.push_back(func_info.rva);
                out_names.push_back(func_info.name);

                // Check if RVA is 0 due to missing .text section
                if (func_info.rva == 0 && !has_text_section_for_reference_ && func_info.pdb_offset != 0) {
                    std::cout << "Warning: Function '" << func_info.name
                        << "' has RVA 0, possibly because '.text' section was not found. Be cautious." << std::endl;
                }

                std::cout << "  " << choice << ". " << func_info.name
                    << " (RVA: 0x" << std::hex << func_info.rva << std::dec << ")" << std::endl;
            }

            std::cout << "Total selected: " << choices.size() << " function(s)" << std::endl;
            return true;
        }
    }

    // Hàm tiện ích chọn nhiều hàm --> danh sách RVA và tên hàm
    bool get_multiple_rvas_by_interactive_selection(const std::string& pe_file_path,
        std::vector<uint32_t>& selected_rvas,
        std::vector<std::string>& selected_names) {
        RVAResolver resolver(pe_file_path);
        if (!resolver.initialize()) {
            // Error messages already printed by resolver.initialize() or resolver.load_pe_and_parse_pdb()
            return false;
        }
        return resolver.select_multiple_functions_rva_interactive(selected_rvas, selected_names);
    }

} // namespace FuncToRVA
