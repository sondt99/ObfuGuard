#pragma once
#include "../pe/pe.h"
#include "Zydis/Zydis.h"
#include "../pdbparser/pdbparser.h"

#include <map>
#include <string>
#include <unordered_map>
#include <asmjit/asmjit.h>
class obfuscatecff {
private:
    pe64* pe;
    static ZydisFormatter formatter;
    static ZydisDecoder decoder;
    struct func_id_instr_id {
        int func_id;
        int inst_index;
    };
    // map tracking runtime address -> instruction
    std::map<uint64_t, func_id_instr_id> runtime_addr_track;

    int instruction_id = 0;
    int function_iterator = 0;

    static std::unordered_map<ZydisRegister_, asmjit::x86::Gp> lookupmap;

    // generate code using asmjit
    asmjit::JitRuntime rt;
    asmjit::CodeHolder code;
    asmjit::x86::Assembler assm;

    std::vector<function_t> functions;

    uint32_t total_size_used;

    bool find_inst_at_dst(uint64_t dst, instruction_t** instptr, function_t** funcptr);

    void remove_jumptables();

    bool analyze_functions();

    void relocate(PIMAGE_SECTION_HEADER new_section);

    bool find_instruction_by_id(int funcid, int instid, instruction_t* inst) const;

    bool fix_relative_jmps(function_t* func, int depth = 0);

    bool convert_relative_jmps();

    bool apply_relocations(PIMAGE_SECTION_HEADER new_section);

    void compile(PIMAGE_SECTION_HEADER new_section);

    // Reverse translate generated machine code to instruction_t for further processing
    std::vector<instruction_t> instructions_from_jit(uint8_t* code, uint32_t size);

    // Apply control flow flattening technique to a function
    bool apply_control_flow_flattening(std::vector<obfuscatecff::function_t>::iterator& func_iter);

#ifdef _MSC_VER
    __declspec(safebuffers)
#endif
    int custom_main(int argc, char* argv[]);

public:
    obfuscatecff(pe64* pe);

    void create_functions(const std::vector<pdbparser::sym_func>& functions);

    void run(PIMAGE_SECTION_HEADER new_section, bool obfuscate_entry_point);

    uint32_t get_added_size() const;

    struct instruction_t {
        int inst_id;
        int func_id;
        bool is_first_instruction;
        std::vector<uint8_t> raw_bytes;
        uint64_t runtime_address;
        uint64_t relocated_address;
        ZydisDisassembledInstruction zyinstr;
        bool has_relative;
        bool isjmpcall;

        struct {
            int target_inst_id;
            int target_func_id;
            uint32_t offset;
            uint32_t size;
        } relative;

        uint64_t location_of_data;

        instruction_t()
            : inst_id(0),
            func_id(0),
            is_first_instruction(false),
            runtime_address(0),
            relocated_address(0),
            has_relative(false),
            isjmpcall(false),
            location_of_data(0),
            relative{ 0, 0, 0, 0 },
            zyinstr{} {
        }

        void load_relative_info(); // Get relative jump information from Zydis instruction
        void load(int funcid, const std::vector<uint8_t>& raw_data); // Load from raw bytes
        void load(int funcid, ZydisDisassembledInstruction zyinstruction, uint64_t runtime_address);
        void reload();
        void print();
    };

    struct function_t {
        int func_id;
        std::string name;
        std::vector<instruction_t> instructions;
        std::map<int, uint64_t> inst_id_index;
        uint32_t offset;
        uint32_t size;

        function_t(int func_id, const std::string& name, uint32_t offset, uint32_t size)
            : func_id(func_id), name(name), offset(offset), size(size) {
        };

        bool cff_flattening = true;
        bool has_jumptables = false;
    };
};