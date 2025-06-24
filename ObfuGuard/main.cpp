#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <limits>
#include <iomanip>
#include <ctime>
#include <stdexcept>
#include <fstream>

#define NOMINMAX
#include <windows.h>

#include "pe/pe.h"
#include "pdbparser/pdbparser.h"
#include "obfuscatecff/obfuscatecff.h"
#include "junkcode/junkcode.h"
#include "func2rva/func2rva.h"

void print_banner() {
    std::cout << "========================================\n";
    std::cout << "         ObfuGuard Tool - sondt         \n";
    std::cout << "========================================\n\n";
}

void print_menu() {
    std::cout << "Select obfuscation mode:\n  1. Control Flow Flattening\n  2. Insert Junk Code - Trampoline\n  0. Exit\n";
    std::cout << "Enter your choice (0-2): ";
}

// Lấy tệp đầu vào và kiểm tra tính hợp lệ
bool get_file_input(const std::string& prompt, std::string& file_path) {
    std::cout << prompt;
    std::getline(std::cin, file_path);

    if (!file_path.empty() && file_path.front() == '"' && file_path.back() == '"') {
        file_path = file_path.substr(1, file_path.length() - 2);
    }
    if (!std::filesystem::exists(file_path)) {
        std::cerr << "Error: File '" << file_path << "' does not exist!\n";
        return false;
    }
    if (!std::filesystem::is_regular_file(file_path)) {
        std::cerr << "Error: Path '" << file_path << "' is not a regular file!\n";
        return false;
    }
    return true;
}

// Tự động phát hiện kiến trúc tệp PE
bool DetectPEArchitecture(const std::string& filePath, bool& is64Bit) {
    std::ifstream peFile(filePath, std::ios::binary);
    if (!peFile.is_open()) {
        std::cerr << "Error [DetectPE]: Could not open file: " << filePath << std::endl;
        return false;
    }

    // Đọc DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (!peFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER))) {
        std::cerr << "Error [DetectPE]: Could not read DOS header from: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    // Kiểm tra chữ ký DOS (MZ)
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) { // 0x5A4D (MZ)
        std::cerr << "Error [DetectPE]: Not a valid PE file (Missing MZ signature): " << filePath << std::endl;
        peFile.close();
        return false;
    }

    // Kiểm tra e_lfanew để đảm bảo nó là hợp lệ
    if (dosHeader.e_lfanew == 0 || static_cast<long>(dosHeader.e_lfanew) < 0) {
        std::cerr << "Error [DetectPE]: Invalid PE header offset (e_lfanew is " << dosHeader.e_lfanew << ") in: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    // Đến vị trí của PE header
    peFile.seekg(dosHeader.e_lfanew, std::ios::beg);
    if (peFile.fail()) {
        std::cerr << "Error [DetectPE]: Failed to seek to PE header (e_lfanew: 0x"
            << std::hex << dosHeader.e_lfanew << std::dec << ") in: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    // Đọc PE signature
    DWORD signature;
    if (!peFile.read(reinterpret_cast<char*>(&signature), sizeof(DWORD))) {
        std::cerr << "Error [DetectPE]: Could not read PE signature from: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    // Kiểm tra chữ ký PE (PE00)
    if (signature != IMAGE_NT_SIGNATURE) { // 0x00004550 (PE00)
        std::cerr << "Error [DetectPE]: Not a valid PE file (Missing PE signature 'PE00'): " << filePath << std::endl;
        peFile.close();
        return false;
    }

    // Đọc File header
    IMAGE_FILE_HEADER fileHeader;
    if (!peFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(IMAGE_FILE_HEADER))) {
        std::cerr << "Error [DetectPE]: Could not read File header from: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    WORD magic;
    // Đến Optional header
    if (!peFile.read(reinterpret_cast<char*>(&magic), sizeof(WORD))) { // Đọc Magic number
        std::cerr << "Error [DetectPE]: Could not read Magic number from OptionalHeader in: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    peFile.close();

    // Kiểm tra Magic number để xác định kiến trúc
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) { // 0x10b
        is64Bit = false; // 32-bit
        return true;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) { // 0x20b
        is64Bit = true; // 64-bit
        return true;
    }
    else {
        std::cerr << "Error [DetectPE]: Unknown PE Magic number (0x" << std::hex << magic << std::dec << ") in: " << filePath << std::endl;
        return false;
    }
}

// Hàm lấy và kiểm tra file PE
bool get_valid_pe_file_path(const std::string& prompt, std::string& path, bool& is_64_bit) {
    if (!get_file_input(prompt, path)) return false;
    if (!DetectPEArchitecture(path, is_64_bit)) {
        std::cerr << "Failed to determine PE architecture for " << path << ".\n";
        return false;
    }
    return true;
}

// Hàm tạo output file path
std::string build_output_path(const std::string& input_path, const std::string& suffix) {
    std::filesystem::path p(input_path);
    std::string stem = p.stem().string();
    std::string extension = p.extension().string();
    return (p.has_parent_path() ?
        (p.parent_path() / (stem + suffix + extension)) :
        std::filesystem::path(stem + suffix + extension)).lexically_normal().string();
}

// Hàm in thời gian thực thi
void print_execution_time(clock_t begin_time, const std::string& mode_name) {
    std::cout << mode_name << " completed in "
        << static_cast<float>(clock() - begin_time) / CLOCKS_PER_SEC
        << " seconds." << std::endl;
}

// Hàm chính cho chế độ làm rối mã điều khiển luồng (CFF - Control Flow Flattening)
int mode_control_flow_flattening() {
    std::cout << "\n=== Control Flow Flattening Mode ===\n";
    std::string binary_path;
    bool is_64_bit;

    if (!get_valid_pe_file_path("Enter PE file path for CFF: ", binary_path, is_64_bit) || !is_64_bit) {
        if (!is_64_bit) {
            std::cerr << "Error: Control Flow Flattening only supports 64-bit PE files.\n";
        }
        return 1;
    }

    std::cout << "Control Flow Flattening Mode: Detected 64-bit PE" << std::endl;

    const clock_t begin_time = clock(); // Bắt đầu tính thời gian thực hiện

    try {
        pe64 pe(binary_path);

        pdbparser pdb(&pe);
        // Đẩy PDB từ tệp PE
        auto functions = pdb.parse_functions();
        if (functions.empty()) {
            std::cout << "Warning: No functions found through PDB. Obfuscation might not be effective or possible." << std::endl;
        }
        else {
            std::cout << "Successfully analyzed all functions." << std::endl;
        }

        std::cout << "Creating new section .0Cff" << std::endl; // Tạo section mới cho mã đã làm rối
        auto new_section = pe.create_section(".0Cff", 10000000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);

        obfuscatecff obf(&pe); // Tạo đối tượng obfuscatecff với tệp PE
        obf.create_functions(functions); // Tạo các hàm bổ sung từ PDB đã phân tích

        std::cout << "Running Control Flow Flattening Mode" << std::endl;
        obf.run(new_section, true); // Chạy làm rối mã điều khiển luồng (CFF) với section mới và tạo hàm bổ sung

        // Lưu tệp PE đã làm rối
        std::string output_filename_str = build_output_path(binary_path, ".cff");

        std::cout << "\nSuccessfully control-flow-flattened " << functions.size() << " selected function(s)." << std::endl;
        std::cout << "Output saved to: " << output_filename_str << std::endl;
        pe.save_to_disk(output_filename_str, new_section, obf.get_added_size());
    }
    catch (const std::runtime_error& e) {
        std::cerr << "Runtime error during CFF obfuscation: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred during CFF obfuscation: " << e.what() << std::endl;
        return 1;
    }

    print_execution_time(begin_time, "Control Flow Flattening mode");
    return 0;
}

// Hàm chính cho chế độ chèn mã rối (Junk Code) với Trampoline
int mode_trampoline_junkcode() {
    std::cout << "\n=== Junk Code Injection with Trampoline Mode ===\n";
    std::string input_pe_path;
    bool is_64_bit;

    if (!get_valid_pe_file_path("Enter input PE file path: ", input_pe_path, is_64_bit)) {
        return 1;
    }

    std::cout << "Junk Code Injection Mode: Detected: " << (is_64_bit ? "64-bit" : "32-bit") << " PE file\n";

    std::string output_pe_path = build_output_path(input_pe_path, ".junk");

    // Lựa chọn chế độ tự động hay thủ công
    std::string mode_choice;
    std::cout << "\nSelect injection mode:\n  1. Auto-inject functions\n  2. Manually choose multiple functions\nEnter your choice (1 or 2): ";
    std::getline(std::cin, mode_choice);

    const clock_t begin_time = clock();

    int result;
    if (mode_choice == "1") {
        result = JunkCodeManager::run_auto_injection_mode(input_pe_path, output_pe_path, is_64_bit);
    }
    else if (mode_choice == "2") {
        result = JunkCodeManager::run_manual_injection_mode(input_pe_path, output_pe_path, is_64_bit);
    }
    else {
        std::cerr << "Invalid mode selected.\n";
        return 1;
    }

    if (result == 0) {
        std::cout << "Output saved to: " << output_pe_path << std::endl;
        print_execution_time(begin_time, "Junk Code Injection mode");
    }

    return result;
}

int main() {
    srand(static_cast<unsigned int>(time(nullptr)));
    print_banner();
    print_menu();

    std::string choice_str;
    std::getline(std::cin, choice_str);
    int choice = (choice_str.size() == 1 && std::isdigit(choice_str[0])) ? choice_str[0] - '0' : -1;

    switch (choice) {
    case 1:
        return mode_control_flow_flattening();
    case 2:
        return mode_trampoline_junkcode();
    case 0:
        std::cout << "Exiting ObfuGuard by sondt. Goodbye!\n";
        return 0;
    default:
        std::cerr << "Error: Invalid choice. Please enter a number from the menu.\n";
        return 1;
    }
}