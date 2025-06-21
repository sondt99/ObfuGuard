#include "junkcode.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

// Constructor/Destructor
TrampolineInjector::TrampolineInjector() : binary(nullptr), image_base(0), is_64_bit(false) {
    // Initialize random seed for junk code generation
    srand(static_cast<unsigned int>(time(nullptr)));
}

TrampolineInjector::~TrampolineInjector() {
    //binary_ptr auto clean
}

// Helper function to print byte vectors for debugging
void TrampolineInjector::print_bytes(const std::string& prefix, const std::vector<uint8_t>& bytes) {
    std::cout << prefix;
    std::cout << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        std::cout << std::setw(2) << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

bool TrampolineInjector::load_pe(const std::string& pe_path) {
    binary_ptr = LIEF::PE::Parser::parse(pe_path);
    if (!binary_ptr) {
        std::cerr << "Error: Could not parse PE file '" << pe_path << "'." << std::endl;
        return false;
    }

    binary = binary_ptr.get();
    image_base = binary->imagebase();

    // Detect if 64-bit
    is_64_bit = (binary->header().machine() == LIEF::PE::Header::MACHINE_TYPES::AMD64);

    /*std::cout << "Loaded PE: " << pe_path << std::endl;
    std::cout << "Image Base: 0x" << std::hex << image_base << std::endl;
    std::cout << "Architecture: " << (is_64_bit ? "64-bit" : "32-bit") << std::dec << std::endl;*/

    return true;
}

// NEW: Get current section count
uint32_t TrampolineInjector::get_current_section_count() const {
    if (!binary) {
        return 0;
    }
    return static_cast<uint32_t>(binary->sections().size());
}

// NEW: Calculate maximum injectable functions based on PE section limits
uint32_t TrampolineInjector::calculate_max_injectable_functions() const {
    if (!binary) {
        return 0;
    }

    const uint32_t PE_MAX_SECTIONS = 96;        // Theoretical PE limit
    const uint32_t SAFETY_MARGIN = 10;         // Safety margin for stability
    const uint32_t RESERVED_FOR_SYSTEM = 5;    // Reserve some sections for system use

    uint32_t current_sections = get_current_section_count();
    uint32_t max_usable_sections = PE_MAX_SECTIONS - SAFETY_MARGIN - RESERVED_FOR_SYSTEM;

    if (current_sections >= max_usable_sections) {
        return 0; // Already at or over limit
    }

    return max_usable_sections - current_sections;
}

// NEW: Check if we can safely inject the planned number of functions
bool TrampolineInjector::check_section_limit_before_injection(uint32_t planned_injections) const {
    uint32_t max_injectable = calculate_max_injectable_functions();

    std::cout << "Section Analysis:" << std::endl;
    std::cout << "  Current sections: " << get_current_section_count() << std::endl;
    std::cout << "  Injectable functions: " << max_injectable << std::endl;

    if (planned_injections > max_injectable) {
        // std::cout << "  Status: EXCEEDS LIMIT - Will auto-limit to " << max_injectable << " functions" << std::endl;
        return false;
    }
    else {
        // std::cout << "  Status: WITHIN LIMIT - Safe to proceed" << std::endl;
        return true;
    }
}

bool TrampolineInjector::get_and_relocate_original_function_code(
    uint64_t original_func_va,
    uint64_t new_func_base_va,
    std::vector<uint8_t>& relocated_code_buffer,
    size_t& determined_original_function_size)
{
    relocated_code_buffer.clear();
    determined_original_function_size = 0;

    const LIEF::PE::Section* original_section = nullptr;

    /*std::cout << "Info: Searching for section containing VA 0x" << std::hex << original_func_va << std::dec << std::endl;*/
    for (const LIEF::PE::Section& sec : binary->sections()) {
        uint64_t sec_va_start = image_base + sec.virtual_address();
        uint64_t sec_va_end = sec_va_start + sec.virtual_size();
        if (original_func_va >= sec_va_start && original_func_va < sec_va_end) {
            original_section = &sec;
            break;
        }
    }

    if (!original_section) {
        std::cerr << "Error: Could not find section containing original function VA: 0x" << std::hex << original_func_va << std::endl;
        return false;
    }
    /*std::cout << "Found section '" << original_section->name() << "' for VA 0x" << std::hex << original_func_va << std::dec << std::endl;*/

    uint64_t section_base_va = image_base + original_section->virtual_address();
    uint64_t offset_in_section = original_func_va - section_base_va;

    uint64_t max_read_size = 0;
    uint64_t section_content_limit = original_section->size();
    if (section_content_limit > offset_in_section) {
        max_read_size = section_content_limit - offset_in_section;
    }
    else {
        std::cerr << "Error: Offset in section (0x" << std::hex << offset_in_section
            << ") is greater than or equal to section's raw data size (0x" << section_content_limit
            << ") for VA 0x" << original_func_va << std::endl;
        return false;
    }

    if (max_read_size == 0) {
        std::cerr << "Error: Max read size is 0 for VA 0x" << std::hex << original_func_va << " in section " << original_section->name() << std::endl;
        return false;
    }

    LIEF::span<const uint8_t> function_raw_bytes_span = binary->get_content_from_virtual_address(original_func_va, static_cast<uint32_t>(max_read_size));
    if (function_raw_bytes_span.empty()) {
        std::cerr << "Error: Could not read content from original function VA: 0x" << std::hex << original_func_va << std::endl;
        return false;
    }

    csh cs_handle;
    cs_mode capstone_mode = is_64_bit ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, capstone_mode, &cs_handle) != CS_ERR_OK) {
        std::cerr << "Error: Failed to initialize Capstone." << std::endl;
        return false;
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn;
    size_t count = 0;
    size_t current_copied_offset = 0;
    bool ret_found = false;
    const size_t MAX_FUNC_SCAN_SIZE = 8192;
    const uint8_t* code_ptr = function_raw_bytes_span.data();
    size_t code_available_size = function_raw_bytes_span.size();

    while (current_copied_offset < code_available_size && relocated_code_buffer.size() < MAX_FUNC_SCAN_SIZE) {
        count = cs_disasm(cs_handle, code_ptr + current_copied_offset, code_available_size - current_copied_offset, original_func_va + current_copied_offset, 1, &insn);
        if (count > 0) {
            std::vector<uint8_t> instr_bytes(insn[0].bytes, insn[0].bytes + insn[0].size);

            // Handle CALL and JMP relocation
            if (insn[0].id == X86_INS_CALL || insn[0].id == X86_INS_JMP) {
                if (insn[0].detail->x86.op_count == 1) {
                    const cs_x86_op* op = &(insn[0].detail->x86.operands[0]);

                    if (op->type == X86_OP_IMM) {
                        if (insn[0].bytes[0] == 0xE8 || insn[0].bytes[0] == 0xE9) { // CALL rel32 or JMP rel32
                            int32_t original_relative_offset;
                            memcpy(&original_relative_offset, &insn[0].bytes[1], sizeof(int32_t));

                            uint64_t old_instr_va = insn[0].address;
                            uint64_t old_target_va = old_instr_va + insn[0].size + original_relative_offset;
                            uint64_t new_instr_va = new_func_base_va + current_copied_offset;

                            int64_t new_relative_offset_64 = static_cast<int64_t>(old_target_va) - static_cast<int64_t>(new_instr_va + insn[0].size);

                            if (new_relative_offset_64 >= INT32_MIN && new_relative_offset_64 <= INT32_MAX) {
                                int32_t new_relative_offset = static_cast<int32_t>(new_relative_offset_64);
                                memcpy(instr_bytes.data() + 1, &new_relative_offset, sizeof(int32_t));

                                /*std::cout << "Relocated " << (insn[0].bytes[0] == 0xE8 ? "CALL" : "JMP")
                                    << " at old VA 0x" << std::hex << old_instr_va
                                    << " to new VA 0x" << new_instr_va
                                    << ". Target VA: 0x" << old_target_va
                                    << ", New rel offset: 0x" << new_relative_offset << std::dec << std::endl;*/
                            }
                            else {
                                std::cout << "";
                                /*std::cerr << "Error: Cannot relocate " << (insn[0].bytes[0] == 0xE8 ? "CALL" : "JMP")
                                    << " at VA 0x" << std::hex << old_instr_va
                                    << " - target too far (offset: 0x" << new_relative_offset_64 << ")" << std::dec << std::endl;*/
                            }
                        }
                        else if (insn[0].bytes[0] == 0xFF) {
                            std::cout << "";
                            /*std::cout << "Warning: Indirect CALL/JMP at VA 0x" << std::hex << insn[0].address
                                << " - may need manual verification" << std::dec << std::endl;*/
                        }
                    }
                    else if (op->type == X86_OP_MEM && is_64_bit) {
                        if (op->mem.base == X86_REG_RIP) {
                            int32_t original_disp = op->mem.disp;
                            uint64_t old_instr_va = insn[0].address;
                            uint64_t old_target_data_va = old_instr_va + insn[0].size + original_disp;
                            uint64_t new_instr_va = new_func_base_va + current_copied_offset;
                            int32_t new_disp = static_cast<int32_t>(old_target_data_va - (new_instr_va + insn[0].size));

                            if (insn[0].detail->x86.encoding.disp_offset > 0 && insn[0].detail->x86.encoding.disp_size == sizeof(int32_t)) {
                                memcpy(instr_bytes.data() + insn[0].detail->x86.encoding.disp_offset, &new_disp, sizeof(int32_t));
                                /*std::cout << "Relocated RIP-relative " << (insn[0].id == X86_INS_CALL ? "CALL" : "JMP")
                                    << " at old VA 0x" << std::hex << old_instr_va
                                    << ". Target data VA: 0x" << old_target_data_va
                                    << ", New disp: 0x" << new_disp << std::dec << std::endl;*/
                            }
                        }
                    }
                }
            }
            // Handle other RIP-relative operands
            else if (is_64_bit) {
                for (uint8_t i = 0; i < insn[0].detail->x86.op_count; ++i) {
                    const cs_x86_op* op = &(insn[0].detail->x86.operands[i]);
                    if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
                        int32_t original_disp = op->mem.disp;
                        uint64_t old_instr_va = insn[0].address;
                        uint64_t old_target_data_va = old_instr_va + insn[0].size + original_disp;
                        uint64_t new_instr_va = new_func_base_va + current_copied_offset;
                        int32_t new_disp = static_cast<int32_t>(old_target_data_va - (new_instr_va + insn[0].size));

                        if (insn[0].detail->x86.encoding.disp_offset > 0 && insn[0].detail->x86.encoding.disp_size > 0) {
                            if ((insn[0].detail->x86.encoding.disp_offset + insn[0].detail->x86.encoding.disp_size) <= instr_bytes.size()) {
                                if (insn[0].detail->x86.encoding.disp_size == sizeof(int32_t)) {
                                    memcpy(instr_bytes.data() + insn[0].detail->x86.encoding.disp_offset, &new_disp, sizeof(int32_t));
                                    /*std::cout << "Relocated RIP-relative operand in instruction at old VA 0x" << std::hex << old_instr_va
                                        << " (Opcode: " << insn[0].mnemonic << " " << insn[0].op_str << ")"
                                        << ". Target data VA: 0x" << old_target_data_va
                                        << ", New disp: 0x" << new_disp << std::dec << std::endl;*/
                                }
                            }
                        }
                    }
                }
            }

            relocated_code_buffer.insert(relocated_code_buffer.end(), instr_bytes.begin(), instr_bytes.end());
            current_copied_offset += insn[0].size;

            if (insn[0].id == X86_INS_RET) {
                ret_found = true;
                cs_free(insn, count);
                break;
            }

            cs_free(insn, count);
        }
        else {
            std::cerr << "Warning: Capstone disassembly failed at VA 0x" << std::hex << (original_func_va + current_copied_offset)
                << ". Error: " << cs_strerror(cs_errno(cs_handle)) << std::endl;
            break;
        }
    }

    cs_close(&cs_handle);

    if (relocated_code_buffer.empty()) {
        std::cerr << "Error: Could not disassemble any instruction from original function." << std::endl;
        return false;
    }

    if (!ret_found) {
        std::cout << "Warning: No RET instruction found within scan limit. Appending RET (0xC3)." << std::endl;
        relocated_code_buffer.push_back(0xC3);
    }

    determined_original_function_size = current_copied_offset;
    return true;
}

bool TrampolineInjector::create_new_section(const std::string& section_name, uint32_t initial_size) {
    LIEF::PE::Section new_section_obj(section_name);
    new_section_obj.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
    new_section_obj.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);
    new_section_obj.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::CNT_CODE);

    new_section_obj.virtual_size(initial_size);
    new_section_obj.size(0);

    LIEF::PE::Section* new_section_ptr = binary->add_section(new_section_obj);
    return (new_section_ptr != nullptr);
}

// Enhanced junk instruction generator with more sophisticated patterns
std::string TrampolineInjector::get_random_junk_instruction() {
    std::vector<std::string> junk_instructions;

    if (is_64_bit) {
        junk_instructions = {
            // Basic no-op equivalents
            "mov rax, rax",
            "mov rbx, rbx",
            "mov rcx, rcx",
            "mov rdx, rdx",

            // Math pairs that cancel each other out (add/sub sequences)
            "add r8, 0x10; sub r8, 0x10",
            "add r9, 0x20; sub r9, 0x20",
            "add r10, 0x30; sub r10, 0x30",
            "add r11, 0x40; sub r11, 0x40",
            "add r12, 0x50; sub r12, 0x50",
            "add r13, 0x60; sub r13, 0x60",
            "add r14, 0x70; sub r14, 0x70",
            "add r15, 0x80; sub r15, 0x80",

            // Reverse order (sub then add)
            "sub r8, 0x15; add r8, 0x15",
            "sub r9, 0x25; add r9, 0x25",
            "sub r10, 0x35; add r10, 0x35",
            "sub r11, 0x45; add r11, 0x45",

            // More complex math sequences
            "add r8, 0x100; sub r8, 0x80; sub r8, 0x80",
            "sub r9, 0x200; add r9, 0x100; add r9, 0x100",
            "add r10, 0x50; add r10, 0x50; sub r10, 0xA0",

            // XOR patterns that cancel out
            "xor r8, 0x1234; xor r8, 0x1234",
            "xor r9, 0x5678; xor r9, 0x5678",
            "xor r10, 0x9ABC; xor r10, 0x9ABC",
            "xor r11, 0xDEF0; xor r11, 0xDEF0",

            // Shift operations that cancel
            "shl r8, 2; shr r8, 2",
            "shl r9, 3; shr r9, 3",
            "shr r10, 1; shl r10, 1",
            "shr r11, 2; shl r11, 2",

            // Cross-register stack operations (more confusing)
            "push r8; push r9; pop r9; pop r8",

            // Bit operations that don't change values
            "or r8, 0",
            "and r8, -1",
            "or r9, 0",
            "and r9, -1",
            "or r10, 0",
            "and r10, -1",

            // ROL/ROR operations that cancel out
            "rol r8, 1; ror r8, 1",
            "rol r9, 2; ror r9, 2",
            "ror r10, 3; rol r10, 3",
            "ror r11, 4; rol r11, 4",

            // INC/DEC pairs
            "inc r8; dec r8",
            "inc r9; dec r9",
            "dec r10; inc r10",
            "dec r11; inc r11",

            // Multiple operations that result in no change
            "mov r8, r9; mov r9, r8; mov r8, r9; mov r9, r8",
            "add r8, 1; add r8, 1; sub r8, 2",
            "sub r9, 5; add r9, 3; add r9, 2",

        };
    }
    else {
        junk_instructions = {
            // 32-bit equivalents with similar patterns
            "mov eax, eax",
            "mov ebx, ebx",
            "mov ecx, ecx",
            "mov edx, edx",
            "mov esi, esi",
            "mov edi, edi",

            // Math pairs for 32-bit
            "add esi, 0x10; sub esi, 0x10",
            "add edi, 0x20; sub edi, 0x20",
            "sub esi, 0x15; add esi, 0x15",
            "sub edi, 0x25; add edi, 0x25",

            // XOR patterns
            "xor esi, 0x1234; xor esi, 0x1234",
            "xor edi, 0x5678; xor edi, 0x5678",

            // Stack operations
            "push esi; pop esi",
            "push edi; pop edi",
            "push eax; push ebx; pop ebx; pop eax",

            // Other operations
            "test esi, esi",
            "test edi, edi",
            "cmp esi, esi",
            "cmp edi, edi",
            "lea esi, [esi]",
            "lea edi, [edi]",
            "inc esi; dec esi",
            "inc edi; dec edi",
            "rol esi, 1; ror esi, 1",
            "rol edi, 2; ror edi, 2"
        };
    }

    return junk_instructions[rand() % junk_instructions.size()];
}

// Helper function to fill remaining space with appropriate NOPs
void TrampolineInjector::fill_remaining_space_with_nops(uint64_t address, size_t size) {
    while (size > 0) {
        if (size >= 9) {
            // 9-byte NOP: 66 0F 1F 84 00 00 00 00 00
            std::vector<uint8_t> nop_9 = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
            binary->patch_address(address, nop_9);
            address += 9;
            size -= 9;
        }
        else if (size >= 8) {
            // 8-byte NOP: 0F 1F 84 00 00 00 00 00
            std::vector<uint8_t> nop_8 = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
            binary->patch_address(address, nop_8);
            address += 8;
            size -= 8;
        }
        else if (size >= 7) {
            // 7-byte NOP: 0F 1F 80 00 00 00 00
            std::vector<uint8_t> nop_7 = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
            binary->patch_address(address, nop_7);
            address += 7;
            size -= 7;
        }
        else if (size >= 6) {
            // 6-byte NOP: 66 0F 1F 44 00 00
            std::vector<uint8_t> nop_6 = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
            binary->patch_address(address, nop_6);
            address += 6;
            size -= 6;
        }
        else if (size >= 5) {
            // 5-byte NOP: 0F 1F 44 00 00
            std::vector<uint8_t> nop_5 = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
            binary->patch_address(address, nop_5);
            address += 5;
            size -= 5;
        }
        else if (size >= 4) {
            // 4-byte NOP: 0F 1F 40 00
            std::vector<uint8_t> nop_4 = { 0x0F, 0x1F, 0x40, 0x00 };
            binary->patch_address(address, nop_4);
            address += 4;
            size -= 4;
        }
        else if (size >= 3) {
            // 3-byte NOP: 0F 1F 00
            std::vector<uint8_t> nop_3 = { 0x0F, 0x1F, 0x00 };
            binary->patch_address(address, nop_3);
            address += 3;
            size -= 3;
        }
        else if (size >= 2) {
            // 2-byte NOP: 66 90
            std::vector<uint8_t> nop_2 = { 0x66, 0x90 };
            binary->patch_address(address, nop_2);
            address += 2;
            size -= 2;
        }
        else {
            // 1-byte NOP: 90
            std::vector<uint8_t> nop_1 = { 0x90 };
            binary->patch_address(address, nop_1);
            address += 1;
            size -= 1;
        }
    }
}

bool TrampolineInjector::create_trampoline(uint64_t original_func_va, uint64_t new_func_va, size_t original_size) {
    ks_engine* ks;
    ks_err ks_e;
    ks_mode keystone_mode = is_64_bit ? KS_MODE_64 : KS_MODE_32;
    ks_e = ks_open(KS_ARCH_X86, keystone_mode, &ks);
    if (ks_e != KS_ERR_OK) {
        std::cerr << "Error: Failed to initialize Keystone: " << ks_strerror(ks_e) << std::endl;
        return false;
    }

    // Calculate position for JMP first
    size_t min_junk_before = std::min((size_t)3, original_size / 3);
    size_t max_junk_before = (original_size > 5 + 1) ? (original_size - 5 - 1) : min_junk_before; // 5 bytes for JMP

    if (max_junk_before < min_junk_before) {
        max_junk_before = min_junk_before;
    }

    size_t junk_before_size = min_junk_before;
    if (max_junk_before > min_junk_before) {
        junk_before_size = min_junk_before + (rand() % (max_junk_before - min_junk_before + 1));
    }

    // JMP will be placed at this VA
    uint64_t jmp_va = original_func_va + junk_before_size;

    // Calculate relative offset for JMP instruction
    // JMP instruction: E9 [4-byte relative offset]
    // Target = JMP_VA + 5 + relative_offset
    // So: relative_offset = Target - (JMP_VA + 5)
    int64_t relative_offset_64 = static_cast<int64_t>(new_func_va) - static_cast<int64_t>(jmp_va + 5);

    /*std::cout << "JMP calculation:" << std::endl;
    std::cout << "  JMP VA: 0x" << std::hex << jmp_va << std::endl;
    std::cout << "  Target VA: 0x" << new_func_va << std::endl;
    std::cout << "  Relative offset: 0x" << relative_offset_64 << std::dec << std::endl;*/

    if (relative_offset_64 < INT32_MIN || relative_offset_64 > INT32_MAX) {
        std::cerr << "Error: JMP target too far, cannot use relative JMP (offset: 0x"
            << std::hex << relative_offset_64 << ")" << std::dec << std::endl;
        ks_close(ks);
        return false;
    }

    int32_t relative_offset = static_cast<int32_t>(relative_offset_64);

    // Create JMP instruction manually
    std::vector<uint8_t> jmp_bytes(5);
    jmp_bytes[0] = 0xE9; // JMP rel32 opcode
    memcpy(jmp_bytes.data() + 1, &relative_offset, sizeof(int32_t));

    // print_bytes("Manual JMP instruction: ", jmp_bytes);

    try {
        size_t jmp_size = 5; // E9 + 4 bytes
        size_t junk_after_size = original_size - junk_before_size - jmp_size;

        /*std::cout << "Trampoline layout: " << junk_before_size << " bytes junk -> "
            << jmp_size << " bytes JMP -> " << junk_after_size << " bytes junk" << std::endl;*/

        uint64_t current_address = original_func_va;

        // Phase 1: Patch junk code before JMP
        size_t remaining_before = junk_before_size;
        /*std::cout << "Phase 1: Adding " << remaining_before << " bytes of junk before JMP..." << std::endl;*/

        while (remaining_before > 0) {
            std::string junk_asm = get_random_junk_instruction();
            unsigned char* junk_encode = nullptr;
            size_t junk_asm_size = 0;
            size_t junk_count = 0;

            if (ks_asm(ks, junk_asm.c_str(), current_address, &junk_encode, &junk_asm_size, &junk_count) == KS_ERR_OK && junk_count > 0) {
                if (junk_asm_size <= remaining_before) {
                    std::vector<uint8_t> junk_bytes(junk_encode, junk_encode + junk_asm_size);
                    binary->patch_address(current_address, junk_bytes);

                    /*std::cout << "  Added junk: " << junk_asm
                        << " (" << junk_asm_size << " bytes) at VA 0x"
                        << std::hex << current_address << std::dec << std::endl;*/

                    current_address += junk_asm_size;
                    remaining_before -= junk_asm_size;
                    ks_free(junk_encode);
                }
                else {
                    ks_free(junk_encode);
                    fill_remaining_space_with_nops(current_address, remaining_before);
                    current_address += remaining_before;
                    remaining_before = 0;
                }
            }
            else {
                fill_remaining_space_with_nops(current_address, remaining_before);
                current_address += remaining_before;
                remaining_before = 0;
            }
        }

        // Phase 2: Patch the JMP instruction
        /*std::cout << "Phase 2: Patching JMP at VA 0x" << std::hex << current_address
            << " -> target 0x" << new_func_va << std::dec << std::endl;*/

        binary->patch_address(current_address, jmp_bytes);
        current_address += jmp_size;

        // Phase 3: Patch junk code after JMP
        size_t remaining_after = junk_after_size;
        /*std::cout << "Phase 3: Adding " << remaining_after << " bytes of junk after JMP..." << std::endl;*/

        while (remaining_after > 0) {
            std::string junk_asm = get_random_junk_instruction();
            unsigned char* junk_encode = nullptr;
            size_t junk_asm_size = 0;
            size_t junk_count = 0;

            if (ks_asm(ks, junk_asm.c_str(), current_address, &junk_encode, &junk_asm_size, &junk_count) == KS_ERR_OK && junk_count > 0) {
                if (junk_asm_size <= remaining_after) {
                    std::vector<uint8_t> junk_bytes(junk_encode, junk_encode + junk_asm_size);
                    binary->patch_address(current_address, junk_bytes);

                    /*std::cout << "  Added junk: " << junk_asm
                        << " (" << junk_asm_size << " bytes) at VA 0x"
                        << std::hex << current_address << std::dec << std::endl;*/

                    current_address += junk_asm_size;
                    remaining_after -= junk_asm_size;
                    ks_free(junk_encode);
                }
                else {
                    ks_free(junk_encode);
                    fill_remaining_space_with_nops(current_address, remaining_after);
                    remaining_after = 0;
                }
            }
            else {
                fill_remaining_space_with_nops(current_address, remaining_after);
                remaining_after = 0;
            }
        }

        /*std::cout << "Completed advanced trampoline with embedded JMP" << std::endl;*/
        ks_close(ks);
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "LIEF Error patching trampoline: " << e.what() << std::endl;
        ks_close(ks);
        return false;
    }
}

bool TrampolineInjector::inject_function_trampoline(uint32_t function_rva) {
    uint64_t original_function_va = image_base + function_rva;

    /*std::cout << "Step 1: Creating new section '.injcod'..." << std::endl;*/
    if (!create_new_section(".injcod", 0x1000)) {
        std::cerr << "Error: Could not create new section." << std::endl;
        return false;
    }

    /*std::cout << "Step 2: Copying and relocating original function..." << std::endl;*/
    std::vector<uint8_t> relocated_code_bytes;
    size_t original_function_processed_size = 0;

    // First, get the relocated code before building
    if (!get_and_relocate_original_function_code(original_function_va, 0, relocated_code_bytes, original_function_processed_size)) {
        std::cerr << "Error processing original function code." << std::endl;
        return false;
    }

    if (relocated_code_bytes.empty()) {
        std::cerr << "Error: Relocated code is empty." << std::endl;
        return false;
    }

    // Find the new section
    LIEF::PE::Section* new_section_ptr = nullptr;
    for (LIEF::PE::Section& sec : binary->sections()) {
        if (sec.name() == ".injcod") {
            new_section_ptr = &sec;
            break;
        }
    }

    if (!new_section_ptr) {
        std::cerr << "Error: Could not find the created section." << std::endl;
        return false;
    }

    // Update section content first
    uint32_t file_alignment = binary->optional_header().file_alignment();
    if (file_alignment == 0) file_alignment = 0x200;

    uint32_t section_alignment = binary->optional_header().section_alignment();
    if (section_alignment == 0) section_alignment = 0x1000;

    size_t final_raw_size = ((relocated_code_bytes.size() + file_alignment - 1) / file_alignment) * file_alignment;
    size_t final_virtual_size = ((relocated_code_bytes.size() + section_alignment - 1) / section_alignment) * section_alignment;
    final_virtual_size = std::max(final_virtual_size, static_cast<size_t>(0x1000));
    final_virtual_size = std::max(final_virtual_size, final_raw_size);

    new_section_ptr->size(static_cast<uint32_t>(final_raw_size));
    new_section_ptr->virtual_size(static_cast<uint32_t>(final_virtual_size));
    new_section_ptr->content(relocated_code_bytes);

    // Build to finalize layout
    LIEF::PE::Builder temp_builder(*binary);
    temp_builder.build_imports(false);
    temp_builder.patch_imports(false);
    try {
        temp_builder.build();
    }
    catch (const std::exception& e) {
        std::cerr << "LIEF Error during layout build: " << e.what() << std::endl;
        return false;
    }

    // Get final section address after build
    uint64_t new_function_base_va = image_base + new_section_ptr->virtual_address();
    std::cout << "New section '.injcod' VA: 0x" << std::hex << new_function_base_va << std::dec << std::endl;

    // Now relocate the code with correct target address
    relocated_code_bytes.clear();
    if (!get_and_relocate_original_function_code(original_function_va, new_function_base_va, relocated_code_bytes, original_function_processed_size)) {
        std::cerr << "Error processing original function code with correct VA." << std::endl;
        return false;
    }

    // Update section content with properly relocated code
    new_section_ptr->content(relocated_code_bytes);
    print_bytes("Relocated code (" + std::to_string(relocated_code_bytes.size()) + " bytes): ", relocated_code_bytes);

    /*std::cout << "Step 3: Creating trampoline JMP..." << std::endl;*/
    if (!create_trampoline(original_function_va, new_function_base_va, original_function_processed_size)) {
        std::cerr << "Error creating trampoline." << std::endl;
        return false;
    }

    return true;
}

// Helper để tạo tên section unique
std::string TrampolineInjector::generate_unique_section_name(const std::string& function_name, int index) {
    std::string clean_name = function_name;

    // Loại bỏ các ký tự không hợp lệ cho section name
    std::replace_if(clean_name.begin(), clean_name.end(),
        [](char c) { return !std::isalnum(c); }, '_');

    // Giới hạn độ dài tên (PE section name tối đa 8 ký tự)
    if (clean_name.length() > 4) {
        clean_name = clean_name.substr(0, 4);
    }

    // Tạo tên section với index
    std::string section_name = "." + clean_name + std::to_string(index);

    // Đảm bảo không vượt quá 8 ký tự
    if (section_name.length() > 8) {
        section_name = ".jk" + std::to_string(index);
    }

    return section_name;
}

// Hàm xử lý nhiều hàm cùng lúc
bool TrampolineInjector::inject_multiple_function_trampolines(const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names) {
    if (function_rvas.empty()) {
        std::cerr << "Error: No functions provided for injection." << std::endl;
        return false;
    }

    if (function_rvas.size() != function_names.size()) {
        std::cerr << "Error: Mismatch between function RVAs and names count." << std::endl;
        return false;
    }

    std::cout << "Processing " << function_rvas.size() << " function(s) for trampoline injection..." << std::endl;

    for (size_t i = 0; i < function_rvas.size(); ++i) {
        uint32_t function_rva = function_rvas[i];
        const std::string& function_name = function_names[i];

        /*std::cout << "\n--- Processing function " << (i + 1) << "/" << function_rvas.size()
            << ": " << function_name << " (RVA: 0x" << std::hex << function_rva << std::dec << ") ---" << std::endl;*/

        uint64_t original_function_va = image_base + function_rva;

        // Tạo tên section unique cho hàm này
        std::string section_name = generate_unique_section_name(function_name, static_cast<int>(i + 1));
        /*std::cout << "Creating section: " << section_name << std::endl;*/

        // Tạo section mới cho hàm này
        if (!create_new_section(section_name, 0x1000)) {
            std::cerr << "Error: Could not create section " << section_name << " for function " << function_name << std::endl;
            return false;
        }

        // Copy và relocate code của hàm gốc
        std::vector<uint8_t> relocated_code_bytes;
        size_t original_function_processed_size = 0;

        // Lấy relocated code trước khi build
        if (!get_and_relocate_original_function_code(original_function_va, 0, relocated_code_bytes, original_function_processed_size)) {
            std::cerr << "Error processing original function code for " << function_name << std::endl;
            return false;
        }

        if (relocated_code_bytes.empty()) {
            std::cerr << "Error: Relocated code is empty for function " << function_name << std::endl;
            return false;
        }

        // Tìm section vừa tạo
        LIEF::PE::Section* new_section_ptr = nullptr;
        for (LIEF::PE::Section& sec : binary->sections()) {
            if (sec.name() == section_name) {
                new_section_ptr = &sec;
                break;
            }
        }

        if (!new_section_ptr) {
            std::cerr << "Error: Could not find created section " << section_name << std::endl;
            return false;
        }

        // Cập nhật section content
        uint32_t file_alignment = binary->optional_header().file_alignment();
        if (file_alignment == 0) file_alignment = 0x200;

        uint32_t section_alignment = binary->optional_header().section_alignment();
        if (section_alignment == 0) section_alignment = 0x1000;

        size_t final_raw_size = ((relocated_code_bytes.size() + file_alignment - 1) / file_alignment) * file_alignment;
        size_t final_virtual_size = ((relocated_code_bytes.size() + section_alignment - 1) / section_alignment) * section_alignment;
        final_virtual_size = std::max(final_virtual_size, static_cast<size_t>(0x1000));
        final_virtual_size = std::max(final_virtual_size, final_raw_size);

        new_section_ptr->size(static_cast<uint32_t>(final_raw_size));
        new_section_ptr->virtual_size(static_cast<uint32_t>(final_virtual_size));
        new_section_ptr->content(relocated_code_bytes);

        // Build để finalize layout
        LIEF::PE::Builder temp_builder(*binary);
        temp_builder.build_imports(false);
        temp_builder.patch_imports(false);
        try {
            temp_builder.build();
        }
        catch (const std::exception& e) {
            std::cerr << "LIEF Error during layout build for " << function_name << ": " << e.what() << std::endl;
            return false;
        }

        // Lấy địa chỉ VA của section sau khi build
        uint64_t new_function_base_va = image_base + new_section_ptr->virtual_address();
        // std::cout << "Section " << section_name << " VA: 0x" << std::hex << new_function_base_va << std::dec << std::endl;

        // Relocate lại code với địa chỉ VA chính xác
        relocated_code_bytes.clear();
        if (!get_and_relocate_original_function_code(original_function_va, new_function_base_va, relocated_code_bytes, original_function_processed_size)) {
            std::cerr << "Error processing original function code with correct VA for " << function_name << std::endl;
            return false;
        }

        // Cập nhật section content với code đã relocate đúng
        new_section_ptr->content(relocated_code_bytes);
        // std::cout << "Relocated " << relocated_code_bytes.size() << " bytes for function " << function_name << std::endl;

        // Tạo trampoline JMP
        if (!create_trampoline(original_function_va, new_function_base_va, original_function_processed_size)) {
            std::cerr << "Error creating trampoline for function " << function_name << std::endl;
            return false;
        }

        // std::cout << "Successfully processed function: " << function_name << std::endl;
    }

    std::cout << "\nCompleted processing all " << function_rvas.size() << " function(s)." << std::endl;
    return true;
}

// NEW: Smart injection with automatic limiting
bool TrampolineInjector::inject_multiple_function_trampolines_with_limit(
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    uint32_t& actual_injected_count)
{
    actual_injected_count = 0;

    if (function_rvas.empty()) {
        std::cerr << "Error: No functions provided for injection." << std::endl;
        return false;
    }

    if (function_rvas.size() != function_names.size()) {
        std::cerr << "Error: Mismatch between function RVAs and names count." << std::endl;
        return false;
    }

    // Check section limits
    uint32_t max_injectable = calculate_max_injectable_functions();
    uint32_t planned_injections = static_cast<uint32_t>(function_rvas.size());

    // Show section analysis
    check_section_limit_before_injection(planned_injections);

    if (max_injectable == 0) {
        std::cerr << "Error: Cannot inject any functions - section limit reached." << std::endl;
        return false;
    }

    // Limit the number of functions to inject
    uint32_t functions_to_inject = std::min(planned_injections, max_injectable);

    std::cout << "Proceeding with injection of " << functions_to_inject << " function(s) out of "
        << planned_injections << " requested." << std::endl;

    // Create limited vectors
    std::vector<uint32_t> limited_rvas(function_rvas.begin(), function_rvas.begin() + functions_to_inject);
    std::vector<std::string> limited_names(function_names.begin(), function_names.begin() + functions_to_inject);

    // Perform injection with limited set
    bool result = inject_multiple_function_trampolines(limited_rvas, limited_names);

    return result;
}

// Static utility function cho nhiều hàm
bool TrampolineInjector::inject_trampoline_to_multiple_functions(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    bool force_64_bit)
{
    TrampolineInjector injector;

    if (!injector.load_pe(input_pe_path)) {
        return false;
    }

    if (!injector.inject_multiple_function_trampolines(function_rvas, function_names)) {
        return false;
    }

    return injector.save_pe(output_pe_path);
}

// NEW: Static utility function với auto-limiting
bool TrampolineInjector::inject_trampoline_to_multiple_functions_smart(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    uint32_t& actual_injected_count,
    bool force_64_bit)
{
    TrampolineInjector injector;

    if (!injector.load_pe(input_pe_path)) {
        return false;
    }

    if (!injector.inject_multiple_function_trampolines_with_limit(function_rvas, function_names, actual_injected_count)) {
        return false;
    }

    return injector.save_pe(output_pe_path);
}

bool TrampolineInjector::save_pe(const std::string& output_path) {
    /*std::cout << "Building and writing modified PE..." << std::endl;*/
    LIEF::PE::Builder builder(*binary);

    try {
        builder.build();
        builder.write(output_path);
        /*std::cout << "Successfully wrote modified PE to: " << output_path << std::endl;*/
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "LIEF Error during final build/write: " << e.what() << std::endl;
        return false;
    }
}

// Static utility function
bool TrampolineInjector::inject_trampoline_to_function(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    uint32_t function_rva,
    bool force_64_bit)
{
    TrampolineInjector injector;

    if (!injector.load_pe(input_pe_path)) {
        return false;
    }

    if (!injector.inject_function_trampoline(function_rva)) {
        return false;
    }

    return injector.save_pe(output_pe_path);
}