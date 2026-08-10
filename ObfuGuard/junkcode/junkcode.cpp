#include "junkcode.h"
#include "../constants.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <sstream>
#include <set>
#include <filesystem>

#include <LIEF/LIEF.hpp>
#include <keystone/keystone.h>

#include "../common/function_info.h"
#include "../common/function_filter.h"

// Constructor/Destructor
TrampolineInjector::TrampolineInjector() : image_base(0), is_64_bit(false), rng_(std::random_device{}()) {
}

TrampolineInjector::~TrampolineInjector() {
    close_disasm_engines();
}

bool TrampolineInjector::ensure_disasm_engines() {
    if (!cs_ready_) {
        cs_mode mode = is_64_bit ? CS_MODE_64 : CS_MODE_32;
        if (cs_open(CS_ARCH_X86, mode, &cs_handle_) != CS_ERR_OK) {
            std::cerr << "Error: Failed to initialize Capstone." << std::endl;
            return false;
        }
        cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);
        cs_ready_ = true;
    }
    if (!ks_engine_) {
        ks_mode mode = is_64_bit ? KS_MODE_64 : KS_MODE_32;
        if (ks_open(KS_ARCH_X86, mode, &ks_engine_) != KS_ERR_OK) {
            std::cerr << "Error: Failed to initialize Keystone." << std::endl;
            return false;
        }
    }
    return true;
}

void TrampolineInjector::close_disasm_engines() {
    if (cs_ready_) {
        cs_close(&cs_handle_);
        cs_handle_ = 0;
        cs_ready_ = false;
    }
    if (ks_engine_) {
        ks_close(ks_engine_);
        ks_engine_ = nullptr;
    }
}

void TrampolineInjector::compute_section_sizes(size_t content_size, uint32_t& out_raw, uint32_t& out_virtual) const {
    uint32_t file_alignment = binary_ptr->optional_header().file_alignment();
    if (file_alignment == 0) file_alignment = ObfuGuard::PE_FILE_ALIGNMENT;
    uint32_t section_alignment = binary_ptr->optional_header().section_alignment();
    if (section_alignment == 0) section_alignment = ObfuGuard::PE_SECTION_ALIGNMENT;

    out_raw = static_cast<uint32_t>(((content_size + file_alignment - 1) / file_alignment) * file_alignment);
    size_t virt = ((content_size + section_alignment - 1) / section_alignment) * section_alignment;
    virt = std::max(virt, static_cast<size_t>(ObfuGuard::DEFAULT_SECTION_SIZE));
    virt = std::max(virt, static_cast<size_t>(out_raw));
    out_virtual = static_cast<uint32_t>(virt);
}

// Print byte array for debugging
void TrampolineInjector::print_bytes(const std::string& prefix, const std::vector<uint8_t>& bytes) {
    std::cout << prefix;
    std::cout << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        std::cout << std::setw(2) << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

// Load PE file
bool TrampolineInjector::load_pe(const std::string& pe_path) {
    binary_ptr = LIEF::PE::Parser::parse(pe_path);
    if (!binary_ptr) {
        std::cerr << "Error: Could not parse PE file '" << pe_path << "'." << std::endl;
        return false;
    }

    image_base = binary_ptr->imagebase();

    is_64_bit = (binary_ptr->header().machine() == LIEF::PE::Header::MACHINE_TYPES::AMD64);

    return true;
}

// Get current number of sections in PE
uint32_t TrampolineInjector::get_current_section_count() const {
    if (!binary_ptr) {
        return 0;
    }
    return static_cast<uint32_t>(binary_ptr->sections().size());
}

// Calculate maximum number of functions that can be injected based on section limit
uint32_t TrampolineInjector::calculate_max_injectable_functions() const {
    if (!binary_ptr) {
        return 0;
    }

    uint32_t current_sections = get_current_section_count();
    uint32_t max_usable_sections = ObfuGuard::PE_MAX_SECTIONS - ObfuGuard::PE_SECTION_SAFETY_MARGIN - ObfuGuard::PE_RESERVED_SYSTEM_SECTIONS;

    if (current_sections >= max_usable_sections) {
        return 0; // Cannot inject any more functions if limit is reached
    }

    return max_usable_sections - current_sections;
}

// Check how many functions can be injected without exceeding the limit
bool TrampolineInjector::check_section_limit_before_injection(uint32_t planned_injections) const {
    uint32_t max_injectable = calculate_max_injectable_functions();

    std::cout << "Section Analysis:  Current sections: " << get_current_section_count() << "  Injectable functions: " << max_injectable << std::endl;
    std::cout << "Junk Code Injection with Trampoline Mode" << std::endl;

    if (planned_injections > max_injectable) {
        // std::cout << "  Status: EXCEEDS LIMIT - Will auto-limit to " << max_injectable << " functions" << std::endl;
        return false;
    }
    else {
        // std::cout << "  Status: WITHIN LIMIT - Safe to proceed" << std::endl;
        return true;
    }
}

// Get original function code and relocate to new position.
// When known_function_size > 0 (from PDB), copy the full span instead of stopping at the first RET.
bool TrampolineInjector::get_and_relocate_original_function_code(
    uint64_t original_func_va,
    uint64_t new_func_base_va,
    std::vector<uint8_t>& relocated_code_buffer,
    size_t& determined_original_function_size,
    size_t known_function_size)
{
    relocated_code_buffer.clear();
    determined_original_function_size = 0;

    const LIEF::PE::Section* original_section = nullptr;

    // Check if the VA address is valid
    /*std::cout << "Info: Searching for section containing VA 0x" << std::hex << original_func_va << std::dec << std::endl;*/
    for (const LIEF::PE::Section& sec : binary_ptr->sections()) {
        uint64_t sec_va_start = image_base + sec.virtual_address();
        uint64_t sec_va_end = sec_va_start + sec.virtual_size();
        if (original_func_va >= sec_va_start && original_func_va < sec_va_end) {
            original_section = &sec;
            break;
        }
    }

    // If section containing the VA address is not found, report error
    if (!original_section) {
        std::cerr << "Error: Could not find section containing original function VA: 0x" << std::hex << original_func_va << std::endl;
        return false;
    }
    /*std::cout << "Found section '" << original_section->name() << "' for VA 0x" << std::hex << original_func_va << std::dec << std::endl;*/


    uint64_t section_base_va = image_base + original_section->virtual_address(); // Calculate starting VA address of section
    uint64_t offset_in_section = original_func_va - section_base_va; // Calculate function offset within section

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

    // Check if maximum read size is valid
    if (max_read_size == 0) {
        std::cerr << "Error: Max read size is 0 for VA 0x" << std::hex << original_func_va << " in section " << original_section->name() << std::endl;
        return false;
    }

    // Read raw bytes from original function's virtual address in PE file
    LIEF::span<const uint8_t> function_raw_bytes_span = binary_ptr->get_content_from_virtual_address(original_func_va, static_cast<uint32_t>(max_read_size));
    if (function_raw_bytes_span.empty()) {
        std::cerr << "Error: Could not read content from original function VA: 0x" << std::hex << original_func_va << std::endl;
        return false;
    }

    if (!ensure_disasm_engines()) {
        return false;
    }

    cs_insn* insn;
    size_t count = 0;
    size_t current_copied_offset = 0;
    bool ret_found = false;
    const bool use_pdb_size = known_function_size > 0;
    const uint8_t* code_ptr = function_raw_bytes_span.data();
    size_t code_available_size = function_raw_bytes_span.size();

    // Prefer PDB size when available; always cap with MAX_FUNC_SCAN_SIZE for safety
    size_t scan_limit = code_available_size;
    if (use_pdb_size) {
        scan_limit = (std::min)(scan_limit, known_function_size);
    }
    scan_limit = (std::min)(scan_limit, static_cast<size_t>(ObfuGuard::MAX_FUNC_SCAN_SIZE));

    // Pre-size buffer to reduce reallocations during instruction appends
    relocated_code_buffer.reserve(scan_limit + 16);

    // Disassemble within the scan limit (PDB size or first-RET fallback)
    while (current_copied_offset < scan_limit && relocated_code_buffer.size() < ObfuGuard::MAX_FUNC_SCAN_SIZE) {
        count = cs_disasm(cs_handle_, code_ptr + current_copied_offset, scan_limit - current_copied_offset, original_func_va + current_copied_offset, 1, &insn);
        if (count > 0) {
            // Do not start an instruction that would exceed the PDB-known span
            if (use_pdb_size && current_copied_offset + insn[0].size > scan_limit) {
                cs_free(insn, count);
                break;
            }
            std::vector<uint8_t> instr_bytes(insn[0].bytes, insn[0].bytes + insn[0].size);

            // Process CALL and JMP instructions
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
                            }
                            else {
                                // Fail closed: do not keep a stale relative after the move
                                std::cerr << "Error: Cannot relocate " << (insn[0].bytes[0] == 0xE8 ? "CALL" : "JMP")
                                    << " at VA 0x" << std::hex << old_instr_va
                                    << " — relative offset 0x" << new_relative_offset_64
                                    << " exceeds INT32 range." << std::dec << std::endl;
                                cs_free(insn, count);
                                return false;
                            }
                        }
                        else if (insn[0].bytes[0] == 0xFF) {
                            // Indirect CALL/JMP -- no relocation needed
                        }
                    }
                    else if (op->type == X86_OP_MEM && is_64_bit) {
                        if (op->mem.base == X86_REG_RIP) {
                            int32_t original_disp = op->mem.disp;
                            uint64_t old_instr_va = insn[0].address;
                            uint64_t old_target_data_va = old_instr_va + insn[0].size + original_disp;
                            uint64_t new_instr_va = new_func_base_va + current_copied_offset;
                            int64_t new_disp64 = static_cast<int64_t>(old_target_data_va) -
                                static_cast<int64_t>(new_instr_va + insn[0].size);
                            if (new_disp64 < INT32_MIN || new_disp64 > INT32_MAX) {
                                std::cerr << "Error: RIP-relative CALL/JMP displacement out of range at VA 0x"
                                    << std::hex << old_instr_va << std::dec << std::endl;
                                cs_free(insn, count);
                                return false;
                            }
                            int32_t new_disp = static_cast<int32_t>(new_disp64);

                            if (insn[0].detail->x86.encoding.disp_offset > 0 && insn[0].detail->x86.encoding.disp_size == sizeof(int32_t)) {
                                memcpy(instr_bytes.data() + insn[0].detail->x86.encoding.disp_offset, &new_disp, sizeof(int32_t));
                            }
                        }
                    }
                }
            }

            // Process RIP-relative operands in other instructions
            else if (is_64_bit) {
                for (uint8_t i = 0; i < insn[0].detail->x86.op_count; ++i) {
                    const cs_x86_op* op = &(insn[0].detail->x86.operands[i]);
                    if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
                        int32_t original_disp = op->mem.disp;
                        uint64_t old_instr_va = insn[0].address;
                        uint64_t old_target_data_va = old_instr_va + insn[0].size + original_disp;
                        uint64_t new_instr_va = new_func_base_va + current_copied_offset;
                        int64_t new_disp64 = static_cast<int64_t>(old_target_data_va) -
                            static_cast<int64_t>(new_instr_va + insn[0].size);
                        if (new_disp64 < INT32_MIN || new_disp64 > INT32_MAX) {
                            std::cerr << "Error: RIP-relative operand displacement out of range at VA 0x"
                                << std::hex << old_instr_va << std::dec << std::endl;
                            cs_free(insn, count);
                            return false;
                        }
                        int32_t new_disp = static_cast<int32_t>(new_disp64);

                        if (insn[0].detail->x86.encoding.disp_offset > 0 && insn[0].detail->x86.encoding.disp_size > 0) {
                            if ((insn[0].detail->x86.encoding.disp_offset + insn[0].detail->x86.encoding.disp_size) <= instr_bytes.size()) {
                                if (insn[0].detail->x86.encoding.disp_size == sizeof(int32_t)) {
                                    memcpy(instr_bytes.data() + insn[0].detail->x86.encoding.disp_offset, &new_disp, sizeof(int32_t));
                                }
                            }
                        }
                    }
                }
            }

            // Add processed instruction to buffer
            relocated_code_buffer.insert(relocated_code_buffer.end(), instr_bytes.begin(), instr_bytes.end());
            current_copied_offset += insn[0].size;

            if (insn[0].id == X86_INS_RET) {
                ret_found = true;
                // With PDB size, continue past early RETs so the full function body is relocated
                if (!use_pdb_size) {
                    cs_free(insn, count);
                    break;
                }
            }

            cs_free(insn, count); // Free memory of processed instruction
        }
        else {
            std::cerr << "Warning: Capstone disassembly failed at VA 0x" << std::hex << (original_func_va + current_copied_offset)
                << ". Error: " << cs_strerror(cs_errno(cs_handle_)) << std::endl;
            break;
        }
    }

    // Check if any code was relocated
    if (relocated_code_buffer.empty()) {
        std::cerr << "Error: Could not disassemble any instruction from original function." << std::endl;
        return false;
    }

    // Only append a synthetic RET when size was unknown and no RET was found
    if (!use_pdb_size && !ret_found) {
        std::cout << "Warning: No RET instruction found within scan limit. Appending RET (0xC3)." << std::endl;
        relocated_code_buffer.push_back(0xC3);
    }

    // Refuse partial copies when PDB size was authoritative
    if (use_pdb_size) {
        if (known_function_size > ObfuGuard::MAX_FUNC_SCAN_SIZE) {
            std::cerr << "Error: Function size " << known_function_size
                << " exceeds MAX_FUNC_SCAN_SIZE (" << ObfuGuard::MAX_FUNC_SCAN_SIZE
                << "); refusing partial inject." << std::endl;
            return false;
        }
        if (current_copied_offset < known_function_size &&
            current_copied_offset + 16 < known_function_size) {
            // Allow tiny trailing pad for undecodable alignment bytes, else fail
            std::cerr << "Error: Only relocated " << current_copied_offset
                << " of " << known_function_size
                << " PDB-reported bytes; refusing partial function body." << std::endl;
            return false;
        }
        determined_original_function_size = known_function_size;
    } else {
        determined_original_function_size = current_copied_offset;
    }
    return true;
}

// Create new section with name and initial size
bool TrampolineInjector::create_new_section(const std::string& section_name, uint32_t initial_size) {
    LIEF::PE::Section new_section_obj(section_name);
    new_section_obj.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
    new_section_obj.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);
    new_section_obj.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::CNT_CODE);

    new_section_obj.virtual_size(initial_size);
    new_section_obj.size(0);

    LIEF::PE::Section* new_section_ptr = binary_ptr->add_section(new_section_obj);
    return (new_section_ptr != nullptr);
}

// Create ASM instruction sequence that doesn't affect logic (junk) to insert into code
std::string TrampolineInjector::get_random_junk_instruction() {
    // Prefer flag-neutral / volatile-only idioms for live trampoline entry
    static const std::vector<std::string> junk_64bit = {
        "mov rax, rax",
        "mov rcx, rcx",
        "mov rdx, rdx",
        "mov r8, r8",
        "mov r9, r9",
        "mov r10, r10",
        "mov r11, r11",
        "lea rax, [rax]",
        "lea rcx, [rcx]",
        "lea rdx, [rdx]",
        "nop",
        "xchg rax, rax",

        // Self-canceling pairs on volatile regs only (r8–r11)
        "add r8, 0x10; sub r8, 0x10",
        "add r9, 0x20; sub r9, 0x20",
        "add r10, 0x30; sub r10, 0x30",
        "add r11, 0x40; sub r11, 0x40",

        // Reversed
        "sub r8, 0x15; add r8, 0x15",
        "sub r9, 0x25; add r9, 0x25",
        "sub r10, 0x35; add r10, 0x35",
        "sub r11, 0x45; add r11, 0x45",

        // More complex math sequences
        "add r8, 0x100; sub r8, 0x80; sub r8, 0x80",
        "sub r9, 0x200; add r9, 0x100; add r9, 0x100",
        "add r10, 0x50; add r10, 0x50; sub r10, 0xA0",

        // Simple XOR patterns
        "xor r8, 0x1234; xor r8, 0x1234",
        "xor r9, 0x5678; xor r9, 0x5678",
        "xor r10, 0x9ABC; xor r10, 0x9ABC",
        "xor r11, 0xDEF0; xor r11, 0xDEF0",

        // Bit rotation pairs (safe -- rotate is fully reversible)
        "rol r8, 3; ror r8, 3",
        "ror r9, 5; rol r9, 5",
        "rol r10, 7; ror r10, 7",
        "ror r11, 4; rol r11, 4",

        // Cross-register stack
        "push r8; push r9; pop r9; pop r8",

        // Bitwise operations that don't change value
        "or r8, 0",
        "and r8, -1",
        "or r9, 0",
        "and r9, -1",
        "or r10, 0",
        "and r10, -1",

        // rol/ror operations that don't change value
        "rol r8, 1; ror r8, 1",
        "rol r9, 2; ror r9, 2",
        "ror r10, 3; rol r10, 3",
        "ror r11, 6; rol r11, 6",

        // INC/DEC pairs
        "inc r8; dec r8",
        "inc r9; dec r9",
        "dec r10; inc r10",
        "dec r11; inc r11",

        // Multiple operations that don't change value
        "push r8; pop r8; push r9; pop r9",
        "add r8, 1; add r8, 1; sub r8, 2",
        "sub r9, 5; add r9, 3; add r9, 2",
    };

    static const std::vector<std::string> junk_32bit = {
        "mov eax, eax",
        "mov ebx, ebx",
        "mov ecx, ecx",
        "mov edx, edx",
        "mov esi, esi",
        "mov edi, edi",

        "add esi, 0x10; sub esi, 0x10",
        "add edi, 0x20; sub edi, 0x20",
        "sub esi, 0x15; add esi, 0x15",
        "sub edi, 0x25; add edi, 0x25",

        "xor esi, 0x1234; xor esi, 0x1234",
        "xor edi, 0x5678; xor edi, 0x5678",

        "push esi; pop esi",
        "push edi; pop edi",
        "push eax; push ebx; pop ebx; pop eax",

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

    const auto& pool = is_64_bit ? junk_64bit : junk_32bit;
    return pool[std::uniform_int_distribution<size_t>(0, pool.size() - 1)(rng_)];
}

// Fill remaining memory space with NOPs (no-operation)
void TrampolineInjector::fill_remaining_space_with_nops(uint64_t address, size_t size) {
    while (size > 0) {
        if (size >= 9) {
            // 9-byte NOP: 66 0F 1F 84 00 00 00 00 00
            std::vector<uint8_t> nop_9 = { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
            binary_ptr->patch_address(address, nop_9);
            address += 9;
            size -= 9;
        }
        else if (size >= 8) {
            // 8-byte NOP: 0F 1F 84 00 00 00 00 00
            std::vector<uint8_t> nop_8 = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
            binary_ptr->patch_address(address, nop_8);
            address += 8;
            size -= 8;
        }
        else if (size >= 7) {
            // 7-byte NOP: 0F 1F 80 00 00 00 00
            std::vector<uint8_t> nop_7 = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
            binary_ptr->patch_address(address, nop_7);
            address += 7;
            size -= 7;
        }
        else if (size >= 6) {
            // 6-byte NOP: 66 0F 1F 44 00 00
            std::vector<uint8_t> nop_6 = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
            binary_ptr->patch_address(address, nop_6);
            address += 6;
            size -= 6;
        }
        else if (size >= 5) {
            // 5-byte NOP: 0F 1F 44 00 00
            std::vector<uint8_t> nop_5 = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
            binary_ptr->patch_address(address, nop_5);
            address += 5;
            size -= 5;
        }
        else if (size >= 4) {
            // 4-byte NOP: 0F 1F 40 00
            std::vector<uint8_t> nop_4 = { 0x0F, 0x1F, 0x40, 0x00 };
            binary_ptr->patch_address(address, nop_4);
            address += 4;
            size -= 4;
        }
        else if (size >= 3) {
            // 3-byte NOP: 0F 1F 00
            std::vector<uint8_t> nop_3 = { 0x0F, 0x1F, 0x00 };
            binary_ptr->patch_address(address, nop_3);
            address += 3;
            size -= 3;
        }
        else if (size >= 2) {
            // 2-byte NOP: 66 90
            std::vector<uint8_t> nop_2 = { 0x66, 0x90 };
            binary_ptr->patch_address(address, nop_2);
            address += 2;
            size -= 2;
        }
        else {
            // 1-byte NOP: 90
            std::vector<uint8_t> nop_1 = { 0x90 };
            binary_ptr->patch_address(address, nop_1);
            address += 1;
            size -= 1;
        }
    }
}

// Patch a region with random junk instructions, returns bytes written
size_t TrampolineInjector::patch_junk_region(ks_engine* ks, uint64_t start_address, size_t region_size, const LIEF::PE::Section& section) {
    uint64_t current_address = start_address;
    size_t remaining = region_size;
    size_t iteration_count = 0;

    uint64_t section_start_va = image_base + section.virtual_address();
    uint64_t section_end_va = section_start_va + section.virtual_size();

    while (remaining > 0 && iteration_count < ObfuGuard::MAX_JUNK_ITERATIONS) {
        iteration_count++;

        std::string junk_asm = get_random_junk_instruction();
        unsigned char* junk_encode = nullptr;
        size_t junk_asm_size = 0;
        size_t junk_count = 0;

        if (ks_asm(ks, junk_asm.c_str(), current_address, &junk_encode, &junk_asm_size, &junk_count) == KS_ERR_OK && junk_count > 0) {
            if (junk_asm_size <= remaining) {
                // Check bounds before patching
                uint64_t patch_end = current_address + junk_asm_size;

                if (patch_end > section_end_va) {
                    std::cerr << "Error: Junk patch would exceed section bounds. Stopping." << std::endl;
                    ks_free(junk_encode);
                    break;
                }

                std::vector<uint8_t> junk_bytes(junk_encode, junk_encode + junk_asm_size);
                binary_ptr->patch_address(current_address, junk_bytes);

                current_address += junk_asm_size;
                remaining -= junk_asm_size;
                ks_free(junk_encode);
            }
            else {
                ks_free(junk_encode);
                fill_remaining_space_with_nops(current_address, remaining);
                current_address += remaining;
                remaining = 0;
            }
        }
        else {
            fill_remaining_space_with_nops(current_address, remaining);
            current_address += remaining;
            remaining = 0;
        }
    }

    if (iteration_count >= ObfuGuard::MAX_JUNK_ITERATIONS && remaining > 0) {
        std::cerr << "Warning: Maximum junk iterations reached. Filling remaining space with NOPs." << std::endl;
        fill_remaining_space_with_nops(current_address, remaining);
        current_address += remaining;
    }

    return current_address - start_address;
}

// Create a JMP from original address to relocated code, insert junk to hide
bool TrampolineInjector::create_trampoline(uint64_t original_func_va, uint64_t new_func_va, size_t original_size) {
    if (!ensure_disasm_engines() || !ks_engine_) {
        return false;
    }
    ks_engine* ks = ks_engine_;

    // CHECK BOUNDS BEFORE STARTING
    const LIEF::PE::Section* original_section = nullptr;

    try {
        // 1. Find section containing original function by looping through sections
        for (const LIEF::PE::Section& sec : binary_ptr->sections()) {
            uint64_t sec_va_start = image_base + sec.virtual_address();
            uint64_t sec_va_end = sec_va_start + sec.virtual_size();
            if (original_func_va >= sec_va_start && original_func_va < sec_va_end) {
                original_section = &sec;
                break;
            }
        }

        if (!original_section) {
            std::cerr << "Error: Can't find section containing VA: 0x" << std::hex << original_func_va << std::dec << std::endl;
            return false;
        }

        // 2. Check section bounds
        uint64_t section_start_va = image_base + original_section->virtual_address();
        uint64_t section_end_va = section_start_va + original_section->virtual_size();

        if (original_func_va + original_size > section_end_va) {
            std::cerr << "Error: The patch value (" << original_size << " bytes @0x" << std::hex
                << original_func_va << ") is out of bounds of the section (limit: 0x"
                << section_end_va << ")" << std::dec << std::endl;
            return false;
        }

        // 3. Check minimum required size
        if (original_size < ObfuGuard::MIN_TRAMPOLINE_PATCH_SIZE) {
            std::cerr << "Error: Original function size (" << original_size
                << " bytes) is too small for trampoline injection (minimum: "
                << ObfuGuard::MIN_TRAMPOLINE_PATCH_SIZE << " bytes)" << std::endl;
            return false;
        }

        // 4. Check reasonable size (avoid overly large patches)
        if (original_size > ObfuGuard::MAX_TRAMPOLINE_PATCH_SIZE) {
            std::cerr << "Warning: Original function size (" << original_size
                << " bytes) is very large. Limiting to " << ObfuGuard::MAX_TRAMPOLINE_PATCH_SIZE << " bytes." << std::endl;
            original_size = ObfuGuard::MAX_TRAMPOLINE_PATCH_SIZE;
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error during bounds checking: " << e.what() << std::endl;
        return false;
    }

    // JMP first (no live junk before trampoline) — flag-safe function entry
    // Remaining bytes after the 5-byte JMP are filled with dead junk / NOPs
    const size_t junk_before_size = 0;

    // JMP instruction will be placed at this VA
    uint64_t jmp_va = original_func_va + junk_before_size;

    // Calculate relative offset for JMP instruction
    // JMP: E9 [4-byte relative offset]
    // Target = JMP_VA + 5 + relative_offset --> relative_offset = Target - (JMP_VA + 5)
    int64_t relative_offset_64 = static_cast<int64_t>(new_func_va) - static_cast<int64_t>(jmp_va + 5);

    /*std::cout << "JMP calculation:" << std::endl;
    std::cout << "  JMP VA: 0x" << std::hex << jmp_va << std::endl;
    std::cout << "  Target VA: 0x" << new_func_va << std::endl;
    std::cout << "  Relative offset: 0x" << relative_offset_64 << std::dec << std::endl;*/

    if (relative_offset_64 < INT32_MIN || relative_offset_64 > INT32_MAX) {
        std::cerr << "Error: JMP target too far, cannot use relative JMP (offset: 0x"
            << std::hex << relative_offset_64 << ")" << std::dec << std::endl;
        return false;
    }

    int32_t relative_offset = static_cast<int32_t>(relative_offset_64);

    // Create JMP instruction manually
    std::vector<uint8_t> jmp_bytes(5);
    jmp_bytes[0] = 0xE9; // JMP rel32 opcode
    memcpy(jmp_bytes.data() + 1, &relative_offset, sizeof(int32_t));

    try {
        size_t jmp_size = 5; // E9 + 4 bytes
        size_t junk_after_size = original_size - junk_before_size - jmp_size;

        uint64_t current_address = original_func_va;

        // Patch junk code before JMP instruction
        current_address += patch_junk_region(ks, current_address, junk_before_size, *original_section);

        // CHECK BOUNDS FOR JMP
        uint64_t jmp_patch_end = current_address + jmp_size;
        uint64_t section_start_va = image_base + original_section->virtual_address();
        uint64_t section_end_va = section_start_va + original_section->virtual_size();

        if (jmp_patch_end > section_end_va) {
            std::cerr << "Error: JMP patch would exceed section bounds." << std::endl;
            return false;
        }

        binary_ptr->patch_address(current_address, jmp_bytes);
        current_address += jmp_size;

        // Patch junk code after JMP instruction (dead code, never executed)
        patch_junk_region(ks, current_address, junk_after_size, *original_section);
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "LIEF Error patching trampoline: " << e.what() << std::endl;
        return false;
    }
}

// Inject a function: relocate original code, create new section, insert trampoline
bool TrampolineInjector::inject_function_trampoline(uint32_t function_rva, uint32_t function_size) {
    std::vector<uint32_t> rvas = { function_rva };
    std::vector<std::string> names = { "func" };
    std::vector<uint32_t> sizes = { function_size };
    return inject_multiple_function_trampolines(rvas, names, sizes);
}

// Generate unique section names based on function name and index
std::string TrampolineInjector::generate_unique_section_name(const std::string& function_name, int index) {
    std::string clean_name = function_name;

    // Remove invalid characters for section name
    std::replace_if(clean_name.begin(), clean_name.end(),
        [](char c) { return !std::isalnum(c); }, '_');

    // Limit name length (PE section name maximum 8 characters)
    if (clean_name.length() > 4) {
        clean_name = clean_name.substr(0, 4);
    }

    // Create section name with index
    std::string section_name = "." + clean_name + std::to_string(index);

    // Ensure section name does not exceed 8 characters (PE limit)
    if (section_name.length() > 8) {
        section_name = ".jk" + std::to_string(index);
    }

    return section_name;
}

// Inject multiple functions with a single LIEF layout build (major speedup vs per-function rebuild)
bool TrampolineInjector::inject_multiple_function_trampolines(const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    const std::vector<uint32_t>& function_sizes) {
    if (function_rvas.empty()) {
        std::cerr << "Error: No functions provided for injection." << std::endl;
        return false;
    }

    if (function_rvas.size() != function_names.size()) {
        std::cerr << "Error: Mismatch between function RVAs and names count." << std::endl;
        return false;
    }

    if (!function_sizes.empty() && function_sizes.size() != function_rvas.size()) {
        std::cerr << "Error: Mismatch between function RVAs and sizes count." << std::endl;
        return false;
    }

    if (!ensure_disasm_engines()) {
        return false;
    }

    struct PendingInject {
        uint32_t rva = 0;
        std::string name;
        size_t known_size = 0;
        std::string section_name;
        size_t original_processed_size = 0;
        std::vector<uint8_t> code_bytes;
    };

    std::vector<PendingInject> pending;
    pending.reserve(function_rvas.size());

    // Phase 1: disassemble/relocate with provisional VA (0) and create all sections
    for (size_t i = 0; i < function_rvas.size(); ++i) {
        PendingInject item;
        item.rva = function_rvas[i];
        item.name = function_names[i];
        item.known_size = function_sizes.empty() ? 0 : function_sizes[i];
        item.section_name = generate_unique_section_name(item.name, static_cast<int>(i + 1));

        uint64_t original_function_va = image_base + item.rva;
        if (!get_and_relocate_original_function_code(original_function_va, 0, item.code_bytes,
                item.original_processed_size, item.known_size)) {
            std::cerr << "Error processing original function code for " << item.name << std::endl;
            return false;
        }
        if (item.code_bytes.empty()) {
            std::cerr << "Error: Relocated code is empty for function " << item.name << std::endl;
            return false;
        }

        if (!create_new_section(item.section_name, ObfuGuard::DEFAULT_SECTION_SIZE)) {
            std::cerr << "Error: Could not create section " << item.section_name
                << " for function " << item.name << std::endl;
            return false;
        }

        LIEF::PE::Section* new_section_ptr = nullptr;
        for (LIEF::PE::Section& sec : binary_ptr->sections()) {
            if (sec.name() == item.section_name) {
                new_section_ptr = &sec;
                break;
            }
        }
        if (!new_section_ptr) {
            std::cerr << "Error: Could not find created section " << item.section_name << std::endl;
            return false;
        }

        uint32_t raw_size = 0, virt_size = 0;
        compute_section_sizes(item.code_bytes.size(), raw_size, virt_size);
        new_section_ptr->size(raw_size);
        new_section_ptr->virtual_size(virt_size);
        new_section_ptr->content(item.code_bytes);

        pending.push_back(std::move(item));
    }

    // Phase 2: one layout build for all new sections (assigns final VAs)
    {
        LIEF::PE::Builder layout_builder(*binary_ptr);
        layout_builder.build_imports(false);
        layout_builder.patch_imports(false);
        try {
            layout_builder.build();
        }
        catch (const std::exception& e) {
            std::cerr << "LIEF Error during batch layout build: " << e.what() << std::endl;
            return false;
        }
    }

    std::cout << "Batch-injected layout for " << pending.size() << " function(s); applying relocations..." << std::endl;

    // Phase 3: re-relocate with real VAs, update section content, install trampolines
    for (auto& item : pending) {
        LIEF::PE::Section* new_section_ptr = nullptr;
        for (LIEF::PE::Section& sec : binary_ptr->sections()) {
            if (sec.name() == item.section_name) {
                new_section_ptr = &sec;
                break;
            }
        }
        if (!new_section_ptr) {
            std::cerr << "Error: Lost section " << item.section_name << " after layout build." << std::endl;
            return false;
        }

        uint64_t original_function_va = image_base + item.rva;
        uint64_t new_function_base_va = image_base + new_section_ptr->virtual_address();

        item.code_bytes.clear();
        if (!get_and_relocate_original_function_code(original_function_va, new_function_base_va,
                item.code_bytes, item.original_processed_size, item.known_size)) {
            std::cerr << "Error re-relocating function " << item.name << std::endl;
            return false;
        }

        new_section_ptr->content(item.code_bytes);

        if (verbose_) {
            print_bytes("Relocated " + item.name + " (" + std::to_string(item.code_bytes.size()) + " bytes): ",
                item.code_bytes);
        } else {
            std::cout << "  " << item.name << " -> " << item.section_name
                << " @ 0x" << std::hex << new_function_base_va << std::dec
                << " (" << item.code_bytes.size() << " bytes)" << std::endl;
        }

        if (!create_trampoline(original_function_va, new_function_base_va, item.original_processed_size)) {
            std::cerr << "Error creating trampoline for function " << item.name << std::endl;
            return false;
        }
    }

    return true;
}

// Inject multiple functions intelligently with quantity limit
bool TrampolineInjector::inject_multiple_function_trampolines_with_limit(
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    uint32_t& actual_injected_count,
    const std::vector<uint32_t>& function_sizes)
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

    if (!function_sizes.empty() && function_sizes.size() != function_rvas.size()) {
        std::cerr << "Error: Mismatch between function RVAs and sizes count." << std::endl;
        return false;
    }

    // Check number of limited functions that can be injected
    uint32_t max_injectable = calculate_max_injectable_functions();
    uint32_t planned_injections = static_cast<uint32_t>(function_rvas.size());

    // Show analysis of number of functions to be injected
    check_section_limit_before_injection(planned_injections);

    if (max_injectable == 0) {
        std::cerr << "Error: Cannot inject any functions - section limit reached." << std::endl;
        return false;
    }

    // Limit number of functions to inject
    uint32_t functions_to_inject = std::min(planned_injections, max_injectable);
    if (functions_to_inject < planned_injections) {
        std::cout << "Note: Auto-limiting inject count from " << planned_injections
            << " to " << functions_to_inject << " due to PE section budget.\n";
    }

    /*std::cout << "Proceeding with injection of " << functions_to_inject << " function(s) out of "
        << planned_injections << " requested." << std::endl;*/

        // Create limited vector
    std::vector<uint32_t> limited_rvas(function_rvas.begin(), function_rvas.begin() + functions_to_inject);
    std::vector<std::string> limited_names(function_names.begin(), function_names.begin() + functions_to_inject);
    std::vector<uint32_t> limited_sizes;
    if (!function_sizes.empty()) {
        limited_sizes.assign(function_sizes.begin(), function_sizes.begin() + functions_to_inject);
    }

    // Perform injection of qualified functions
    bool result = inject_multiple_function_trampolines(limited_rvas, limited_names, limited_sizes);

    if (result) {
        actual_injected_count = functions_to_inject;
    }

    return result;
}

// Static function: inject multiple functions without limit
bool TrampolineInjector::inject_trampoline_to_multiple_functions(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    const std::vector<uint32_t>& function_sizes)
{
    TrampolineInjector injector;

    if (!injector.load_pe(input_pe_path)) {
        return false;
    }

    if (!injector.inject_multiple_function_trampolines(function_rvas, function_names, function_sizes)) {
        return false;
    }

    return injector.save_pe(output_pe_path);
}

// ============ IMPLEMENTATION OF JunkCodeManager ============
// Filtering/blacklist logic lives in ObfuGuard::function_filter (single source of truth).

// Implement automatic code injection mode
int JunkCodeManager::run_auto_injection_mode(const std::string& input_pe_path,
    const std::string& output_pe_path,
    bool is_64_bit,
    const std::vector<ObfuGuard::FunctionInfo>& discovered_functions) {
    std::cout << "Running auto-injection mode..." << std::endl;

    try {
        // Filter functions: remove blacklisted and those with size < 6 (i.e. size > 5)
        std::vector<ObfuGuard::FunctionInfo> filtered = ObfuGuard::filter_functions(
            discovered_functions, input_pe_path, ObfuGuard::MIN_FUNCTION_SIZE);

        // Sort by size descending
        ObfuGuard::sort_functions_by_size_desc(filtered);

        // Extract RVAs, names, and PDB sizes into parallel vectors
        std::vector<uint32_t> function_rvas;
        std::vector<std::string> function_names;
        std::vector<uint32_t> function_sizes;
        function_rvas.reserve(filtered.size());
        function_names.reserve(filtered.size());
        function_sizes.reserve(filtered.size());

        for (const auto& func : filtered) {
            function_rvas.push_back(func.rva);
            function_names.push_back(func.name);
            function_sizes.push_back(func.size);
        }

        if (function_rvas.empty()) {
            std::cerr << "No functions with size >= " << ObfuGuard::MIN_FUNCTION_SIZE
                << " bytes found after filtering.\n";
            return 1;
        }

        std::cout << "After filtering: " << function_rvas.size() << " function(s) eligible for injection." << std::endl;

        // Smart injection with automatic function limit
        uint32_t actual_injected_count = 0;
        bool result = TrampolineInjector::inject_trampoline_to_multiple_functions_smart(
            input_pe_path, output_pe_path, function_rvas, function_names,
            actual_injected_count, function_sizes);

        if (!result) {
            std::cerr << "Smart Auto-injection failed!\n";
            return 1;
        }

        std::cout << "\nSuccessfully injected trampolines into " << actual_injected_count << " function(s)" << std::endl;
        return 0;

    }
    catch (const std::exception& e) {
        std::cerr << "Error in auto injection mode: " << e.what() << std::endl;
        return 1;
    }
}

// Implement manual injection mode
int JunkCodeManager::run_manual_injection_mode(const std::string& input_pe_path,
    const std::string& output_pe_path,
    bool is_64_bit,
    const std::vector<ObfuGuard::FunctionInfo>& discovered_functions) {
    std::cout << "Running manual injection mode..." << std::endl;

    try {
        // Filter first so the interactive list only shows injectable functions
        std::vector<ObfuGuard::FunctionInfo> eligible = ObfuGuard::filter_functions(
            discovered_functions, input_pe_path, ObfuGuard::MIN_FUNCTION_SIZE);
        if (eligible.empty()) {
            std::cerr << "Error: No eligible functions remain after filtering.\n";
            return 1;
        }

        std::vector<uint32_t> function_rvas;
        std::vector<std::string> function_names;

        if (!ObfuGuard::select_functions_interactive(eligible, function_rvas, function_names)) {
            return 1;
        }

        std::vector<ObfuGuard::FunctionInfo> filtered;
        for (size_t i = 0; i < function_rvas.size(); ++i) {
            uint32_t rva = function_rvas[i];
            auto it = std::find_if(eligible.begin(), eligible.end(),
                [rva](const ObfuGuard::FunctionInfo& f) { return f.rva == rva; });
            if (it != eligible.end()) {
                filtered.push_back(*it);
            }
        }

        // Extract RVAs, names, and PDB sizes from filtered list
        function_rvas.clear();
        function_names.clear();
        std::vector<uint32_t> function_sizes;
        for (const auto& func : filtered) {
            function_rvas.push_back(func.rva);
            function_names.push_back(func.name);
            function_sizes.push_back(func.size);
        }

        if (function_rvas.empty()) {
            std::cerr << "Error: No functions remain after filtering.\n";
            return 1;
        }

        std::cout << "Proceeding with " << function_rvas.size() << " function(s) that meet size requirements." << std::endl;

        // Use smart injection which handles section limits internally
        uint32_t actual_injected_count = 0;
        bool result = TrampolineInjector::inject_trampoline_to_multiple_functions_smart(
            input_pe_path, output_pe_path, function_rvas, function_names,
            actual_injected_count, function_sizes);

        if (!result) {
            std::cerr << "Manual Injection failed!\n";
            return 1;
        }

        std::cout << "\nSuccessfully injected trampolines into " << actual_injected_count
            << " function(s) out of " << function_rvas.size() << " selected." << std::endl;

        return 0;

    }
    catch (const std::exception& e) {
        std::cerr << "Error in manual injection mode: " << e.what() << std::endl;
        return 1;
    }
}

// Static function: inject multiple functions with section limit checking
bool TrampolineInjector::inject_trampoline_to_multiple_functions_smart(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    uint32_t& actual_injected_count,
    const std::vector<uint32_t>& function_sizes)
{
    TrampolineInjector injector;

    if (!injector.load_pe(input_pe_path)) {
        return false;
    }

    if (!injector.inject_multiple_function_trampolines_with_limit(function_rvas, function_names, actual_injected_count, function_sizes)) {
        return false;
    }

    return injector.save_pe(output_pe_path);
}

bool TrampolineInjector::save_pe(const std::string& output_path) {
    /*std::cout << "Building and writing modified PE..." << std::endl;*/
    LIEF::PE::Builder builder(*binary_ptr);

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

// Static function: inject a single function
bool TrampolineInjector::inject_trampoline_to_function(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    uint32_t function_rva,
    uint32_t function_size)
{
    TrampolineInjector injector;

    if (!injector.load_pe(input_pe_path)) {
        return false;
    }

    if (!injector.inject_function_trampoline(function_rva, function_size)) {
        return false;
    }

    return injector.save_pe(output_pe_path);
}