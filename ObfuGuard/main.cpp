#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <limits>
#include <iomanip>
#include <chrono>
#include <stdexcept>
#include <fstream>

#include <windows.h>

#include "pe/pe.h"
#include "pdbparser/pdbparser.h"
#include "obfuscatecff/obfuscatecff.h"
#include "junkcode/junkcode.h"
#include "func2rva/func2rva.h"
#include "constants.h"

void print_banner() {
    std::cout << "========================================\n";
    std::cout << "         ObfuGuard Tool - sondt         \n";
    std::cout << "========================================\n\n";
}

void print_menu() {
    std::cout << "Select obfuscation mode:\n  1. Control Flow Flattening\n  2. Insert Junk Code - Trampoline\n  0. Exit\n";
    std::cout << "Enter your choice (0-2): ";
}

[[nodiscard]] bool get_file_input(const std::string& prompt, std::string& file_path) {
    std::cout << prompt;
    if (!std::getline(std::cin, file_path)) {
        std::cerr << "Error: Failed to read input.\n";
        return false;
    }

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

[[nodiscard]] bool detect_pe_architecture(const std::string& file_path, bool& is_64_bit) {
    std::ifstream pe_file(file_path, std::ios::binary);
    if (!pe_file.is_open()) {
        std::cerr << "Error [DetectPE]: Could not open file: " << file_path << std::endl;
        return false;
    }

    IMAGE_DOS_HEADER dos_header;
    if (!pe_file.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER))) {
        std::cerr << "Error [DetectPE]: Could not read DOS header from: " << file_path << std::endl;
        return false;
    }

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Error [DetectPE]: Not a valid PE file (Missing MZ signature): " << file_path << std::endl;
        return false;
    }

    if (dos_header.e_lfanew == 0 || static_cast<long>(dos_header.e_lfanew) < 0) {
        std::cerr << "Error [DetectPE]: Invalid PE header offset (e_lfanew is " << dos_header.e_lfanew << ") in: " << file_path << std::endl;
        return false;
    }

    pe_file.seekg(dos_header.e_lfanew, std::ios::beg);
    if (pe_file.fail()) {
        std::cerr << "Error [DetectPE]: Failed to seek to PE header in: " << file_path << std::endl;
        return false;
    }

    DWORD signature;
    if (!pe_file.read(reinterpret_cast<char*>(&signature), sizeof(DWORD))) {
        std::cerr << "Error [DetectPE]: Could not read PE signature from: " << file_path << std::endl;
        return false;
    }

    if (signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Error [DetectPE]: Not a valid PE file (Missing PE signature 'PE00'): " << file_path << std::endl;
        return false;
    }

    IMAGE_FILE_HEADER file_header;
    if (!pe_file.read(reinterpret_cast<char*>(&file_header), sizeof(IMAGE_FILE_HEADER))) {
        std::cerr << "Error [DetectPE]: Could not read File header from: " << file_path << std::endl;
        return false;
    }

    WORD magic;
    if (!pe_file.read(reinterpret_cast<char*>(&magic), sizeof(WORD))) {
        std::cerr << "Error [DetectPE]: Could not read Magic number from OptionalHeader in: " << file_path << std::endl;
        return false;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        is_64_bit = false;
        return true;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is_64_bit = true;
        return true;
    }
    else {
        std::cerr << "Error [DetectPE]: Unknown PE Magic number (0x" << std::hex << magic << std::dec << ") in: " << file_path << std::endl;
        return false;
    }
}

[[nodiscard]] bool get_valid_pe_file_path(const std::string& prompt, std::string& path, bool& is_64_bit) {
    if (!get_file_input(prompt, path)) return false;
    if (!detect_pe_architecture(path, is_64_bit)) {
        std::cerr << "Failed to determine PE architecture for " << path << ".\n";
        return false;
    }
    return true;
}

std::string build_output_path(const std::string& input_path, const std::string& suffix) {
    std::filesystem::path p(input_path);
    std::string stem = p.stem().string();
    std::string extension = p.extension().string();
    return (p.has_parent_path() ?
        (p.parent_path() / (stem + suffix + extension)) :
        std::filesystem::path(stem + suffix + extension)).lexically_normal().string();
}

void print_elapsed_time(std::chrono::steady_clock::time_point start_time, const std::string& mode_name) {
    auto elapsed = std::chrono::duration<float>(std::chrono::steady_clock::now() - start_time).count();
    std::cout << mode_name << " completed in " << elapsed << " seconds." << std::endl;
}

int mode_control_flow_flattening() {
    std::cout << "\n=== Control Flow Flattening Mode ===\n";
    std::string binary_path;
    bool is_64_bit = false;

    if (!get_valid_pe_file_path("Enter PE file path for CFF: ", binary_path, is_64_bit)) {
        return 1;
    }
    if (!is_64_bit) {
        std::cerr << "Error: Control Flow Flattening only supports 64-bit PE files.\n";
        return 1;
    }

    std::cout << "Control Flow Flattening Mode: Detected 64-bit PE" << std::endl;

    auto start_time = std::chrono::steady_clock::now();

    try {
        pe64 pe(binary_path);

        pdbparser pdb(&pe);
        auto functions = pdb.parse_functions();
        if (functions.empty()) {
            std::cout << "Warning: No functions found through PDB. Obfuscation might not be effective or possible." << std::endl;
        }
        else {
            std::cout << "Successfully analyzed all functions." << std::endl;
        }

        std::cout << "Creating new section " << ObfuGuard::CFF_SECTION_NAME << std::endl;
        auto new_section = pe.create_section(ObfuGuard::CFF_SECTION_NAME, ObfuGuard::CFF_SECTION_SIZE, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);

        obfuscatecff obf(&pe);
        obf.create_functions(functions);

        std::cout << "Running Control Flow Flattening Mode" << std::endl;
        obf.run(new_section, true);

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

    print_elapsed_time(start_time, "Control Flow Flattening mode");
    return 0;
}

int mode_trampoline_junkcode() {
    std::cout << "\n=== Junk Code Injection with Trampoline Mode ===\n";
    std::string input_pe_path;
    bool is_64_bit = false;

    if (!get_valid_pe_file_path("Enter input PE file path: ", input_pe_path, is_64_bit)) {
        return 1;
    }

    std::cout << "Junk Code Injection Mode: Detected: " << (is_64_bit ? "64-bit" : "32-bit") << " PE file\n";

    std::string output_pe_path = build_output_path(input_pe_path, ".junk");

    std::string mode_choice;
    std::cout << "\nSelect injection mode:\n  1. Auto-inject functions\n  2. Manually choose multiple functions\nEnter your choice (1 or 2): ";
    if (!std::getline(std::cin, mode_choice)) {
        std::cerr << "Error: Failed to read input.\n";
        return 1;
    }

    auto start_time = std::chrono::steady_clock::now();

    try {
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
            print_elapsed_time(start_time, "Junk Code Injection mode");
        }

        return result;
    }
    catch (const std::runtime_error& e) {
        std::cerr << "Runtime error during Junk Code injection: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred during Junk Code injection: " << e.what() << std::endl;
        return 1;
    }
}

int main() {
    print_banner();
    print_menu();

    std::string choice_str;
    if (!std::getline(std::cin, choice_str)) {
        std::cerr << "Error: Failed to read input.\n";
        return 1;
    }
    int choice = (choice_str.size() == 1 && std::isdigit(static_cast<unsigned char>(choice_str[0]))) ? choice_str[0] - '0' : -1;

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
