#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <algorithm> // For std::transform
#include <limits>    // For std::numeric_limits
#include <iomanip>   // For std::hex, std::dec
#include <ctime>     // For clock, time, srand
#include <stdexcept> // For std::runtime_error, etc.
#include <fstream>   // For reading files
#define NOMINMAX
#include <windows.h>
#include <sstream>  // Cần cho stringstream
#include <set>

// Import necessary headers for PE manipulation and obfuscation
#include "pe/pe.h"
#include "pdbparser/pdbparser.h"
#include "obfuscator/obfuscator.h"
#include "junkcode/junkcode.h"
#include "func2rva/func2rva.h"


const std::set<std::string> DANGEROUS_FUNCTION_NAMES = {
    "mainCRTStartup","atexit",
    "__scrt_initialize_onexit_tables",
    "__scrt_dllmain_before_initialize",
    "_initterm",
    "_initterm_e",
    "__C_specific_handler",
    "_chkstk",
    "__security_check_cookie",
    "__GSHandlerCheck",
    "__isa_available_init",
    "pre_c_initialization","DebuggerRuntime",
	"pre_cpp_initialization","operator new","operator delete","failwithmessage",
};

const std::vector<std::string> DANGEROUS_PREFIXES = {
    "??_",
};


bool is_function_blacklisted(const std::string& func_name) {
    // C++ mangled names
    if (func_name.find_first_of("`_") != std::string::npos) {
        return true;
    }
	// start with underscore
    if (func_name.rfind('_', 0) == 0) {
        return true;
    }

	// check for dangerous function names
    if (DANGEROUS_FUNCTION_NAMES.count(func_name)) {
        return true;
    }

	// check for dangerous prefixes
    for (const auto& prefix : DANGEROUS_PREFIXES) {
        if (func_name.rfind(prefix, 0) == 0) {
            return true;
        }
    }

    return false;
}

// print banner
void print_banner() {
    std::cout << "========================================\n";
    std::cout << "         ObfuGuard Tool - BKSEC         \n";
    std::cout << "========================================\n\n";
}

void print_menu() {
    std::cout << "Select obfuscation mode:\n";
    std::cout << "  1. Control Flow Flattening\n";
    std::cout << "  2. Insert Junk Code - Trampoline\n";
    std::cout << "  0. Exit\n";
    std::cout << "Enter your choice (0-2): ";
}

// input file path and check if it exists
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

// Helper function to sort functions by size (descending order)
void sort_functions_by_size_desc(std::vector<uint32_t>& function_rvas,
    std::vector<std::string>& function_names,
    const std::vector<FuncToRVA::FunctionInfo>& all_functions) {
    // Create index pairs for sorting
    std::vector<std::pair<size_t, uint32_t>> index_size_pairs;

    for (size_t i = 0; i < function_rvas.size(); ++i) {
        uint32_t rva = function_rvas[i];

        // Find the size for this RVA
        auto it = std::find_if(all_functions.begin(), all_functions.end(),
            [rva](const FuncToRVA::FunctionInfo& func) { return func.rva == rva; });

        if (it != all_functions.end()) {
            index_size_pairs.push_back({ i, it->size });
        }
        else {
            index_size_pairs.push_back({ i, 0 }); // Unknown size, put at end
        }
    }

    // Sort by size (descending)
    std::sort(index_size_pairs.begin(), index_size_pairs.end(),
        [](const std::pair<size_t, uint32_t>& a, const std::pair<size_t, uint32_t>& b) {
            return a.second > b.second; // Descending order
        });

    // Reorder the arrays based on sorted indices
    std::vector<uint32_t> sorted_rvas;
    std::vector<std::string> sorted_names;

    for (const auto& pair : index_size_pairs) {
        sorted_rvas.push_back(function_rvas[pair.first]);
        sorted_names.push_back(function_names[pair.first]);
    }

    function_rvas = std::move(sorted_rvas);
    function_names = std::move(sorted_names);
}

bool get_multiple_rvas_interactive(const std::string& input_pe_path,
    std::vector<uint32_t>& rvas_out,
    std::vector<std::string>& names_out) {
    std::cout << "Attempting to select multiple function RVAs from: " << input_pe_path << std::endl;
    if (FuncToRVA::get_multiple_rvas_by_interactive_selection(input_pe_path, rvas_out, names_out)) {
        std::cout << "Selected " << rvas_out.size() << " function(s):" << std::endl;
        for (size_t i = 0; i < rvas_out.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << names_out[i]
                << " (RVA: 0x" << std::hex << rvas_out[i] << std::dec << ")" << std::endl;
        }
        return true;
    }
    else {
        std::cout << "Selection via PDB failed, was canceled by user, PDB not found, or PDB unparsable." << std::endl;
        std::cout << "Please enter RVAs manually or ensure a valid PDB is accessible.\n" << std::endl;

        // Manual input cho nhiều RVA
        std::string input_str;
        std::cout << "Type RVAs of functions (comma-separated, e.g., 1A2B0,1C3D0): ";
        std::getline(std::cin, input_str);

        if (input_str.empty()) {
            std::cerr << "Error: No RVAs provided." << std::endl;
            return false;
        }

        // Parse comma-separated RVAs
        std::stringstream ss(input_str);
        std::string token;
        rvas_out.clear();
        names_out.clear();

        while (std::getline(ss, token, ',')) {
            // Trim whitespace
            token.erase(0, token.find_first_not_of(" \t"));
            token.erase(token.find_last_not_of(" \t") + 1);

            try {
                std::string temp_token = token;

                if (temp_token.rfind("0x", 0) == 0 || temp_token.rfind("0X", 0) == 0) {
                    temp_token = temp_token.substr(2);
                }

                if (temp_token.empty()) {
                    std::cerr << "Error: Invalid RVA format '" << token << "'." << std::endl;
                    continue;
                }

                uint32_t rva = static_cast<uint32_t>(std::stoul(temp_token, nullptr, 16));
                rvas_out.push_back(rva);
                names_out.push_back("Manual_RVA_0x" + temp_token);

                std::cout << "Added RVA: 0x" << std::hex << rva << std::dec << std::endl;
            }
            catch (const std::exception& e) {
                std::cerr << "Error parsing RVA '" << token << "': " << e.what() << std::endl;
            }
        }

        if (rvas_out.empty()) {
            std::cerr << "Error: No valid RVAs were parsed." << std::endl;
            return false;
        }

        std::cout << "Using " << rvas_out.size() << " manually provided RVA(s)." << std::endl;
        return true;
    }
}

bool get_rva_interactive(const std::string& input_pe_path, uint32_t& rva_out) {
    std::string input_str;
    while (true) {
        input_str = "";

        std::cout << "Attempting to select function RVA: " << input_pe_path << std::endl;
        if (FuncToRVA::get_rva_by_interactive_selection(input_pe_path, rva_out)) {
            std::cout << "Selected RVA: 0x" << std::hex << rva_out << std::dec << std::endl;
            return true;
        }
        else {
            std::cout << "Selection via PDB failed, was canceled by user, PDB not found, or PDB unparsable." << std::endl;
            std::cout << "Please enter the RVA manually or ensure a valid PDB is accessible.\n" << std::endl;
            std::cout << "Type rva of function:";
            std::getline(std::cin, input_str);

            try {
                size_t parsed_chars = 0;
                std::string temp_input_str = input_str;

                if (temp_input_str.rfind("0x", 0) == 0 || temp_input_str.rfind("0X", 0) == 0) {
                    temp_input_str = temp_input_str.substr(2);
                }

                if (temp_input_str.empty() && (input_str.rfind("0x", 0) == 0 || input_str.rfind("0X", 0) == 0)) {
                    std::cerr << "Error: RVA format '" << input_str << "' is invalid. Expecting hex digits after '0x'." << std::endl;
                    continue;
                }
                if (temp_input_str.empty() && input_str.empty()) {
                    std::cerr << "Error: RVA input cannot be empty." << std::endl;
                    continue;
                }

                rva_out = static_cast<uint32_t>(std::stoul(temp_input_str, &parsed_chars, 16));

                if (parsed_chars == temp_input_str.length() && !temp_input_str.empty()) {
                    std::cout << "Using provided RVA: 0x" << std::hex << rva_out << std::dec << std::endl;
                    return true;
                }
                else if (!temp_input_str.empty()) {
                    std::cerr << "Error: RVA format '" << input_str << "' contains invalid characters after hexadecimal number." << std::endl;
                }
                else {
                    std::cerr << "Error: RVA format '" << input_str << "' is invalid. Expecting hex format (e.g., 1A2B0) or \"select\"." << std::endl;
                }
            }
            catch (const std::invalid_argument&) {
                std::cerr << "Error: RVA value '" << input_str << "' is not a valid hexadecimal number." << std::endl;
            }
            catch (const std::out_of_range&) {
                std::cerr << "Error: Provided RVA '" << input_str << "' is out of range for a 32-bit unsigned integer." << std::endl;
            }
            std::cout << std::endl;
        }
    }
}

// function to detect PE architecture
// returns true if successful, false if not
// is64Bit is set to true if the PE file is 64-bit, false if it is 32-bit
bool DetectPEArchitecture(const std::string& filePath, bool& is64Bit) {
    std::ifstream peFile(filePath, std::ios::binary);
    if (!peFile.is_open()) {
        std::cerr << "Error [DetectPE]: Could not open file: " << filePath << std::endl;
        return false;
    }

    IMAGE_DOS_HEADER dosHeader;
    if (!peFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER))) {
        std::cerr << "Error [DetectPE]: Could not read DOS header from: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) { // 0x5A4D (MZ)
        std::cerr << "Error [DetectPE]: Not a valid PE file (Missing MZ signature): " << filePath << std::endl;
        peFile.close();
        return false;
    }

    // Additional check for e_lfanew to ensure it is a valid offset
    // or a non-negative value
    if (dosHeader.e_lfanew == 0 || static_cast<long>(dosHeader.e_lfanew) < 0) {
        std::cerr << "Error [DetectPE]: Invalid PE header offset (e_lfanew is " << dosHeader.e_lfanew << ") in: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    peFile.seekg(dosHeader.e_lfanew, std::ios::beg);
    if (peFile.fail()) { // check if seek was successful
        std::cerr << "Error [DetectPE]: Failed to seek to PE header (e_lfanew: 0x"
            << std::hex << dosHeader.e_lfanew << std::dec << ") in: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    DWORD signature;
    if (!peFile.read(reinterpret_cast<char*>(&signature), sizeof(DWORD))) {
        std::cerr << "Error [DetectPE]: Could not read PE signature from: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    if (signature != IMAGE_NT_SIGNATURE) { // 0x00004550 (PE00)
        std::cerr << "Error [DetectPE]: Not a valid PE file (Missing PE signature 'PE00'): " << filePath << std::endl;
        peFile.close();
        return false;
    }

    IMAGE_FILE_HEADER fileHeader;
    if (!peFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(IMAGE_FILE_HEADER))) {
        std::cerr << "Error [DetectPE]: Could not read File header from: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    WORD magic;
    if (!peFile.read(reinterpret_cast<char*>(&magic), sizeof(WORD))) { // read Magic number
        std::cerr << "Error [DetectPE]: Could not read Magic number from OptionalHeader in: " << filePath << std::endl;
        peFile.close();
        return false;
    }

    peFile.close(); // close the file after reading

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

// mode functions
int mode_control_flow_flattening() {
    std::cout << "\n=== Original Obfuscation (Control Flow Flattening) Mode ===\n";
    std::string binary_path;

    if (!get_file_input("Enter PE file path for CFF: ", binary_path)) {
        return 1;
    }

    const clock_t begin_time = clock();
    try {
        // check if the file is a valid PE file and determine its architecture
        bool is_input_64_bit_cff;
        if (!DetectPEArchitecture(binary_path, is_input_64_bit_cff)) {
            std::cerr << "Control Flow Flattening Mode: Failed to determine PE architecture for " << binary_path << ". Aborting." << std::endl;
            return 1;
        }
        if (!is_input_64_bit_cff) { // suppose pe64 is only for 64-bit files
            std::cerr << "Control Flow Flattening Mode: Input file " << binary_path << " is 32-bit. This mode currently expects a 64-bit PE file. Aborting." << std::endl;
            return 1;
        }
        std::cout << "Control Flow Flattening Mode: Detected 64-bit PE file: " << std::endl;

        pe64 pe(binary_path);

        std::cout << "Parsing PDB information..." << std::endl;
        pdbparser pdb(&pe);
        auto functions = pdb.parse_functions();
        if (functions.empty()) {
            std::cout << "Warning: No functions found through PDB. Obfuscation might not be effective or possible." << std::endl;
        }
        else {
            std::cout << "Successfully analyzed " << functions.size() << " function(s)." << std::endl;
        }

        std::cout << "Creating new section for obfuscated code..." << std::endl;
        auto new_section = pe.create_section(".0Dev", 10000000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);

        obfuscator obf(&pe);
        obf.create_functions(functions);

        std::cout << "Running CFF obfuscation..." << std::endl;
        obf.run(new_section, true);

        std::filesystem::path p(binary_path);
        std::string stem = p.stem().string();
        std::string extension = p.extension().string();
        std::string output_filename_str;
        if (p.has_parent_path()) {
            output_filename_str = (p.parent_path() / (stem + ".cff" + extension)).lexically_normal().string();
        }
        else {
            output_filename_str = (std::filesystem::path(stem + ".cff" + extension)).lexically_normal().string();
        }

        std::cout << "Saving obfuscated PE to: " << output_filename_str << std::endl;
        pe.save_to_disk(output_filename_str, new_section, obf.get_added_size());

        std::cout << "Control Flow Flattening Obfuscation completed successfully!" << std::endl;
    }
    catch (const std::runtime_error& e) {
        std::cerr << "Runtime error during CFF obfuscation: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred during CFF obfuscation: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Control Flow Flattening mode completed in " << static_cast<float>(clock() - begin_time) / CLOCKS_PER_SEC << " seconds." << std::endl;
    return 0;
}

int mode_trampoline_junkcode() {
    std::cout << "\n=== Insert Trampoline with Junk Code Mode ===\n";
    std::string input_pe_path;
    std::string output_pe_path_str;
    bool is_64_bit;

    if (!get_file_input("Enter input PE file path: ", input_pe_path)) {
        return 1;
    }

    if (!DetectPEArchitecture(input_pe_path, is_64_bit)) {
        std::cerr << "Failed to determine PE architecture for " << input_pe_path << ". Aborting trampoline mode.\n";
        return 1;
    }
    std::cout << "Junk Code Injection Mode: Detected: " << (is_64_bit ? "64-bit" : "32-bit") << " PE file\n";

    std::filesystem::path p_input(input_pe_path);
    std::string stem = p_input.stem().string();
    std::string extension = p_input.extension().string();
    output_pe_path_str = (p_input.has_parent_path() ?
        (p_input.parent_path() / (stem + ".junk" + extension)) :
        std::filesystem::path(stem + ".junk" + extension)).lexically_normal().string();

    std::cout << "Output file will be saved as: " << output_pe_path_str << std::endl;

    std::string mode_choice;
    std::cout << "\nSelect injection mode:\n";
    std::cout << "  1. Auto-inject functions\n";
    std::cout << "  2. Manually choose multiple functions\n";
    std::cout << "Enter your choice (1 or 2): ";
    std::getline(std::cin, mode_choice);

    const clock_t begin_time = clock();

    try {
        if (mode_choice == "1") {
            // NEW: Enhanced auto-injection with smart limiting
            FuncToRVA::RVAResolver resolver(input_pe_path);
            if (!resolver.initialize()) {
                std::cerr << "Error: Could not initialize PDB resolver.\n";
                return 1;
            }

            const auto& all_functions = resolver.get_functions_info();
            std::vector<uint32_t> function_rvas;
            std::vector<std::string> function_names;

            // Filter functions with size > 15 and sort by size (descending)
            std::vector<std::pair<uint32_t, std::string>> size_sorted_functions;
            int skipped_count = 0; // Đếm số hàm đã bỏ qua

            for (const auto& func_info : all_functions) {
                if (is_function_blacklisted(func_info.name)) {
                    skipped_count++;
                    continue; // Bỏ qua và đi đến hàm tiếp theo
                }
				std::cout << "PASS " << func_info.name << std::endl;

                if (func_info.size > 15) { // Only consider functions larger than 15 bytes
                    size_sorted_functions.push_back({ func_info.size, func_info.name });
                }
            }

            if (skipped_count > 0) {
                std::cout << "Info: Skipped " << skipped_count << " blacklisted/dangerous functions." << std::endl;
            }


            // Sort by size (descending) - largest functions first
            std::sort(size_sorted_functions.begin(), size_sorted_functions.end(),
                [](const std::pair<uint32_t, std::string>& a, const std::pair<uint32_t, std::string>& b) {
                    return a.first > b.first; // Descending order by size
                });

            // Extract RVAs and names in sorted order
            for (const auto& size_name_pair : size_sorted_functions) {
                const std::string& func_name = size_name_pair.second;

                // Find the function info to get RVA
                auto it = std::find_if(all_functions.begin(), all_functions.end(),
                    [&func_name](const FuncToRVA::FunctionInfo& func) {
                        return func.name == func_name;
                    });

                if (it != all_functions.end()) {
                    function_rvas.push_back(it->rva);
                    function_names.push_back(it->name);
                }
            }

            if (function_rvas.empty()) {
                std::cerr << "No functions > 15 bytes found.\n";
                return 1;
            }

            // std::cout << "\nFound " << function_rvas.size() << " functions > 15 bytes (sorted by size, largest first):" << std::endl;
            for (size_t i = 0; i < std::min(static_cast<size_t>(10), function_rvas.size()); ++i) {
                // Find size for display
                auto it = std::find_if(all_functions.begin(), all_functions.end(),
                    [&function_rvas, i](const FuncToRVA::FunctionInfo& func) {
                        return func.rva == function_rvas[i];
                    });
                uint32_t size = (it != all_functions.end()) ? it->size : 0;

                /*std::cout << "  " << (i + 1) << ". " << function_names[i]
                    << " (RVA: 0x" << std::hex << function_rvas[i]
                    << ", Size: " << std::dec << size << " bytes)" << std::endl;*/
            }
            /*if (function_rvas.size() > 10) {
                std::cout << "  ... and " << (function_rvas.size() - 10) << " more functions" << std::endl;
            }*/

            // Use smart injection with automatic limiting
            uint32_t actual_injected_count = 0;
            bool result = TrampolineInjector::inject_trampoline_to_multiple_functions_smart(
                input_pe_path,
                output_pe_path_str,
                function_rvas,
                function_names,
                actual_injected_count,
                is_64_bit
            );

            if (!result) {
                std::cerr << "Smart Auto-injection failed!\n";
                return 1;
            }

            std::cout << "\nSuccessfully injected trampolines into " << actual_injected_count
                << " function(s) out of " << function_rvas.size() << " candidates." << std::endl;
        }
        else if (mode_choice == "2") {
            std::vector<uint32_t> function_rvas;
            std::vector<std::string> function_names;

            if (!get_multiple_rvas_interactive(input_pe_path, function_rvas, function_names)) {
                return 1;
            }

            // Check if we can proceed with the selected functions
            TrampolineInjector temp_injector;
            if (!temp_injector.load_pe(input_pe_path)) {
                std::cerr << "Error: Could not load PE for section analysis.\n";
                return 1;
            }

            if (!temp_injector.check_section_limit_before_injection(static_cast<uint32_t>(function_rvas.size()))) {
                std::cout << "\nWarning: Selected functions exceed safe section limit." << std::endl;
                std::cout << "Would you like to proceed with automatic limiting? (y/n): ";
                std::string proceed_choice;
                std::getline(std::cin, proceed_choice);

                if (proceed_choice != "y" && proceed_choice != "Y") {
                    std::cout << "Operation cancelled by user." << std::endl;
                    return 1;
                }

                // Use smart injection
                uint32_t actual_injected_count = 0;
                bool result = TrampolineInjector::inject_trampoline_to_multiple_functions_smart(
                    input_pe_path,
                    output_pe_path_str,
                    function_rvas,
                    function_names,
                    actual_injected_count,
                    is_64_bit
                );

                if (!result) {
                    std::cerr << "Smart Manual Injection failed!\n";
                    return 1;
                }

                std::cout << "\nSuccessfully injected trampolines into " << actual_injected_count
                    << " function(s) out of " << function_rvas.size() << " selected." << std::endl;
            }
            else {
                // Normal injection - within limits
                bool result = TrampolineInjector::inject_trampoline_to_multiple_functions(
                    input_pe_path,
                    output_pe_path_str,
                    function_rvas,
                    function_names,
                    is_64_bit
                );

                if (!result) {
                    std::cerr << "Manual Functions Injection failed!\n";
                    return 1;
                }

                std::cout << "\nSuccessfully injected trampolines into all " << function_rvas.size()
                    << " selected function(s)." << std::endl;
            }
        }
        else {
            std::cerr << "Invalid mode selected.\n";
            return 1;
        }

        std::cout << "\nJunk Code Injection completed successfully!\n";
        std::cout << "Output saved to: " << output_pe_path_str << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Completed in " << static_cast<float>(clock() - begin_time) / CLOCKS_PER_SEC << " seconds.\n";
    return 0;
}

int main() {
    srand(static_cast<unsigned int>(time(NULL)));

    print_banner();

    std::string choice_str;
    int choice_num = -1;

    print_menu();
    std::getline(std::cin, choice_str);

    try {
        if (choice_str.length() == 1 && std::isdigit(choice_str[0])) {
            choice_num = std::stoi(choice_str);
        }
        else {
            choice_num = -1;
        }
    }
    catch (...) {
        choice_num = -1;
    }

    if (choice_num == 1) {
        mode_control_flow_flattening();
    }
    else if (choice_num == 2) {
        mode_trampoline_junkcode();
    }
    else if (choice_num == 0) {
        std::cout << "Exiting ObfuGuard by BKSEC. Goodbye!\n";
    }
    else {
        std::cerr << "Error: Invalid choice. Please enter a number from the menu.\n";
    }

    return 0;
}