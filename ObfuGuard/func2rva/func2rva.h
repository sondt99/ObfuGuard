#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include "../pe/pe.h"
#include "../pdbparser/pdbparser.h"

namespace FuncToRVA {

    // Information about a resolved function
    struct FunctionInfo {
        std::string name;       // Function name
        uint32_t rva;           // Calculated RVA (e.g., text_section_rva + pdb_offset)
        uint32_t pdb_offset;    // Original offset from PDB
        uint32_t size;          // Function size from PDB
    };

    // Class to resolve function RVA from PE file and PDB
    class RVAResolver {
    public:
        // Constructor, takes path to PE file
        RVAResolver(const std::string& pe_path);
        // Destructor
        ~RVAResolver();

        // Initialize: load PE file and parse PDB. Returns true on success, false on failure.
        bool initialize();

        // Returns list of resolved functions (name, RVA, PDB offset, size). Only call after successful initialize().
        const std::vector<FunctionInfo>& get_functions_info() const;

        // Display list of functions and allow user to select one function.
        bool select_function_rva_interactive(uint32_t& out_rva);

        // Display list of functions and allow user to select multiple functions.
        bool select_multiple_functions_rva_interactive(std::vector<uint32_t>& out_rvas, std::vector<std::string>& out_names);

    private:
        std::string pe_path_str_;                       
        std::unique_ptr<pe64> pe_file_handle_;          
        std::unique_ptr<pdbparser> pdb_parser_handle_;  
        std::vector<FunctionInfo> resolved_functions_list_; // List of resolved functions
        bool is_initialized_ = false;                   // Initialization state
        uint64_t image_base_ = 0;                       // PE ImageBase
        uint32_t text_section_rva_ = 0;                 // RVA of .text section
        bool has_text_section_for_reference_ = false;   // Flag indicating if .text section exists

        bool load_pe_and_parse_pdb();
    };

    // Display function list from PE file and allow user to select one function, returns RVA of that function.
    bool get_rva_by_interactive_selection(const std::string& pe_file_path, uint32_t& selected_rva);

    // Display function list from PE file and allow user to select multiple functions, returns list of RVAs and names.
    bool get_multiple_rvas_by_interactive_selection(const std::string& pe_file_path, std::vector<uint32_t>& selected_rvas, std::vector<std::string>& selected_names);
} // namespace FuncToRVA