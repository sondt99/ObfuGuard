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
#include <sstream>
#include <set>
#define NOMINMAX
#include <filesystem>

#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "../func2rva/func2rva.h"

// Hàm khởi tạo/Hàm huỷ
TrampolineInjector::TrampolineInjector() : binary(nullptr), image_base(0), is_64_bit(false) {
    // thiết lập biến ban đầu và seed cho random
    srand(static_cast<unsigned int>(time(nullptr)));
}

TrampolineInjector::~TrampolineInjector() {
    // binary_ptr clean
}

// In ra mảng byte để debug
void TrampolineInjector::print_bytes(const std::string& prefix, const std::vector<uint8_t>& bytes) {
    std::cout << prefix;
    std::cout << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        std::cout << std::setw(2) << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

// Nạp file PE
bool TrampolineInjector::load_pe(const std::string& pe_path) {
    binary_ptr = LIEF::PE::Parser::parse(pe_path);
    if (!binary_ptr) {
        std::cerr << "Error: Could not parse PE file '" << pe_path << "'." << std::endl;
        return false;
    }

    binary = binary_ptr.get();
    image_base = binary->imagebase();

    is_64_bit = (binary->header().machine() == LIEF::PE::Header::MACHINE_TYPES::AMD64);

    return true;
}

// Lấy số lượng section hiện tại có trong PE
uint32_t TrampolineInjector::get_current_section_count() const {
    if (!binary) {
        return 0;
    }
    return static_cast<uint32_t>(binary->sections().size());
}

// Tính toán số hàm tối đa có thể chèn thêm dựa vào giới hạn section
uint32_t TrampolineInjector::calculate_max_injectable_functions() const {
    if (!binary) {
        return 0;
    }

    const uint32_t PE_MAX_SECTIONS = 96;
    const uint32_t SAFETY_MARGIN = 10;
    const uint32_t RESERVED_FOR_SYSTEM = 5;

    uint32_t current_sections = get_current_section_count();
    uint32_t max_usable_sections = PE_MAX_SECTIONS - SAFETY_MARGIN - RESERVED_FOR_SYSTEM;

    if (current_sections >= max_usable_sections) {
        return 0; // Không thể chèn thêm hàm nào nếu đã đạt giới hạn
    }

    return max_usable_sections - current_sections;
}

// Kiểm tra xem có thể chèn thêm bao nhiêu hàm mà không vượt quá giới hạn
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

// Lấy mã gốc của hàm và di chuyển đến vị trí mới
bool TrampolineInjector::get_and_relocate_original_function_code(
    uint64_t original_func_va,
    uint64_t new_func_base_va,
    std::vector<uint8_t>& relocated_code_buffer,
    size_t& determined_original_function_size)
{
    relocated_code_buffer.clear();
    determined_original_function_size = 0;

    const LIEF::PE::Section* original_section = nullptr;

    // Kiểm tra xem địa chỉ VA có hợp lệ không
    /*std::cout << "Info: Searching for section containing VA 0x" << std::hex << original_func_va << std::dec << std::endl;*/
    for (const LIEF::PE::Section& sec : binary->sections()) {
        uint64_t sec_va_start = image_base + sec.virtual_address();
        uint64_t sec_va_end = sec_va_start + sec.virtual_size();
        if (original_func_va >= sec_va_start && original_func_va < sec_va_end) {
            original_section = &sec;
            break;
        }
    }

    // Nếu không tìm thấy section chứa địa chỉ VA, báo lỗi
    if (!original_section) {
        std::cerr << "Error: Could not find section containing original function VA: 0x" << std::hex << original_func_va << std::endl;
        return false;
    }
    /*std::cout << "Found section '" << original_section->name() << "' for VA 0x" << std::hex << original_func_va << std::dec << std::endl;*/


    uint64_t section_base_va = image_base + original_section->virtual_address(); // Tính toán địa chỉ VA bắt đầu của section
    uint64_t offset_in_section = original_func_va - section_base_va; // Tính toán offset của hàm trong section

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

    // Kiểm tra xem kích thước đọc tối đa có hợp lệ không
    if (max_read_size == 0) {
        std::cerr << "Error: Max read size is 0 for VA 0x" << std::hex << original_func_va << " in section " << original_section->name() << std::endl;
        return false;
    }

    // Đọc bytes thô từ địa chỉ ảo của hàm gốc trong file PE
    LIEF::span<const uint8_t> function_raw_bytes_span = binary->get_content_from_virtual_address(original_func_va, static_cast<uint32_t>(max_read_size));
    if (function_raw_bytes_span.empty()) {
        std::cerr << "Error: Could not read content from original function VA: 0x" << std::hex << original_func_va << std::endl;
        return false;
    }

    csh cs_handle; // Xử lý capstone

    cs_mode capstone_mode = is_64_bit ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, capstone_mode, &cs_handle) != CS_ERR_OK) {
        std::cerr << "Error: Failed to initialize Capstone." << std::endl;
        return false;
    }
    // Bật chế độ chi tiết để lấy thông tin về các toán hạng
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn;
    size_t count = 0;
    size_t current_copied_offset = 0;
    bool ret_found = false;
    const size_t MAX_FUNC_SCAN_SIZE = 8192;
    const uint8_t* code_ptr = function_raw_bytes_span.data();
    size_t code_available_size = function_raw_bytes_span.size();


    // Giới hạn kích thước quét mã để tránh tràn bộ nhớ
    while (current_copied_offset < code_available_size && relocated_code_buffer.size() < MAX_FUNC_SCAN_SIZE) {
        count = cs_disasm(cs_handle, code_ptr + current_copied_offset, code_available_size - current_copied_offset, original_func_va + current_copied_offset, 1, &insn);
        if (count > 0) {
            std::vector<uint8_t> instr_bytes(insn[0].bytes, insn[0].bytes + insn[0].size);

            // xử lý các lệnh CALL và JMP
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

            // Xử lý các toán hạng RIP-relative trong các lệnh khác
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

            // Thêm mã lệnh đã xử lý vào bộ đệm
            relocated_code_buffer.insert(relocated_code_buffer.end(), instr_bytes.begin(), instr_bytes.end());
            current_copied_offset += insn[0].size;

            if (insn[0].id == X86_INS_RET) {
                ret_found = true;
                cs_free(insn, count);
                break;
            }

            cs_free(insn, count); // Giải phóng bộ nhớ của lệnh đã xử lý
        }
        else {
            std::cerr << "Warning: Capstone disassembly failed at VA 0x" << std::hex << (original_func_va + current_copied_offset)
                << ". Error: " << cs_strerror(cs_errno(cs_handle)) << std::endl;
            break;
        }
    }

    cs_close(&cs_handle); // Đóng Capstone engine

    // Kiểm tra xem có mã nào được di chuyển không
    if (relocated_code_buffer.empty()) {
        std::cerr << "Error: Could not disassemble any instruction from original function." << std::endl;
        return false;
    }

    // In ra mã đã di chuyển để debug
    if (!ret_found) {
        std::cout << "Warning: No RET instruction found within scan limit. Appending RET (0xC3)." << std::endl;
        relocated_code_buffer.push_back(0xC3);
    }

    // In ra mã đã di chuyển
    determined_original_function_size = current_copied_offset;
    return true;
}

// Tạo section mới với tên và kích thước khởi tạo
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

// Tạo 1 chuỗi lệnh ASM không ảnh hưởng logic (junk) để chèn vào code
std::string TrampolineInjector::get_random_junk_instruction() {
    std::vector<std::string> junk_instructions;

    if (is_64_bit) {
        junk_instructions = {
            // tương đương no-op cơ bản
            "mov rax, rax",
            "mov rbx, rbx",
            "mov rcx, rcx",
            "mov rdx, rdx",

            // các cặp toán tự triệt tiêu
            "add r8, 0x10; sub r8, 0x10",
            "add r9, 0x20; sub r9, 0x20",
            "add r10, 0x30; sub r10, 0x30",
            "add r11, 0x40; sub r11, 0x40",
            "add r12, 0x50; sub r12, 0x50",
            "add r13, 0x60; sub r13, 0x60",
            "add r14, 0x70; sub r14, 0x70",
            "add r15, 0x80; sub r15, 0x80",

            // Đảo ngược
            "sub r8, 0x15; add r8, 0x15",
            "sub r9, 0x25; add r9, 0x25",
            "sub r10, 0x35; add r10, 0x35",
            "sub r11, 0x45; add r11, 0x45",

            // các chuỗi toán học phức tạp hơn
            "add r8, 0x100; sub r8, 0x80; sub r8, 0x80",
            "sub r9, 0x200; add r9, 0x100; add r9, 0x100",
            "add r10, 0x50; add r10, 0x50; sub r10, 0xA0",

            // các mẫu XOR đơn giản
            "xor r8, 0x1234; xor r8, 0x1234",
            "xor r9, 0x5678; xor r9, 0x5678",
            "xor r10, 0x9ABC; xor r10, 0x9ABC",
            "xor r11, 0xDEF0; xor r11, 0xDEF0",

            // các hoạt động stack đơn giản
            "shl r8, 2; shr r8, 2",
            "shl r9, 3; shr r9, 3",
            "shr r10, 1; shl r10, 1",
            "shr r11, 2; shl r11, 2",

            // Cross-register stack
            "push r8; push r9; pop r9; pop r8",

            // các phép toán bit không thay đổi giá trị
            "or r8, 0",
            "and r8, -1",
            "or r9, 0",
            "and r9, -1",
            "or r10, 0",
            "and r10, -1",

            // các phép rol/ror không thay đổi giá trị
            "rol r8, 1; ror r8, 1",
            "rol r9, 2; ror r9, 2",
            "ror r10, 3; rol r10, 3",
            "ror r11, 4; rol r11, 4",

            // cặp INC/DEC
            "inc r8; dec r8",
            "inc r9; dec r9",
            "dec r10; inc r10",
            "dec r11; inc r11",

            // Nhiều thao tác không thay đổi giá trị
            "mov r8, r9; mov r9, r8; mov r8, r9; mov r9, r8",
            "add r8, 1; add r8, 1; sub r8, 2",
            "sub r9, 5; add r9, 3; add r9, 2",

        };
    }
    else {
        junk_instructions = {
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
    }

    return junk_instructions[rand() % junk_instructions.size()];
}

// Điền các NOP (không làm gì cả) vào vùng nhớ còn trống
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

// Tạo một JMP từ địa chỉ gốc tới mã relocated, chèn junk để che giấu
bool TrampolineInjector::create_trampoline(uint64_t original_func_va, uint64_t new_func_va, size_t original_size) {
    ks_engine* ks;
    ks_err ks_e;
    ks_mode keystone_mode = is_64_bit ? KS_MODE_64 : KS_MODE_32;
    ks_e = ks_open(KS_ARCH_X86, keystone_mode, &ks);
    if (ks_e != KS_ERR_OK) {
        std::cerr << "Error: Failed to initialize Keystone: " << ks_strerror(ks_e) << std::endl;
        return false;
    }

    // KIỂM TRA BOUNDS TRƯỚC KHI BẮT ĐẦU
    const LIEF::PE::Section* original_section = nullptr;

    try {
        // 1. Tìm section chứa original function bằng cách loop qua sections
        for (const LIEF::PE::Section& sec : binary->sections()) {
            uint64_t sec_va_start = image_base + sec.virtual_address();
            uint64_t sec_va_end = sec_va_start + sec.virtual_size();
            if (original_func_va >= sec_va_start && original_func_va < sec_va_end) {
                original_section = &sec;
                break;
            }
        }

        if (!original_section) {
            std::cerr << "Error: Can't find section containing VA: 0x" << std::hex << original_func_va << std::dec << std::endl;
            ks_close(ks);
            return false;
        }

        // 2. Kiểm tra bounds của section
        uint64_t section_start_va = image_base + original_section->virtual_address();
        uint64_t section_end_va = section_start_va + original_section->virtual_size();

        if (original_func_va + original_size > section_end_va) {
            std::cerr << "Error: The patch value (" << original_size << " bytes @0x" << std::hex
                << original_func_va << ") is out of bounds of the section (limit: 0x"
                << section_end_va << ")" << std::dec << std::endl;
            ks_close(ks);
            return false;
        }

        // 3. Kiểm tra kích thước tối thiểu cần thiết
        const size_t MIN_PATCH_SIZE = 5; // Đảm bảo xử lý tối thiểu 5 bytes
        if (original_size < MIN_PATCH_SIZE) {
            std::cerr << "Error: Original function size (" << original_size
                << " bytes) is too small for trampoline injection (minimum: "
                << MIN_PATCH_SIZE << " bytes)" << std::endl;
            ks_close(ks);
            return false;
        }

        // 4. Kiểm tra kích thước hợp lý (tránh patch quá lớn)
        const size_t MAX_PATCH_SIZE = 0x1000; // 4KB max
        if (original_size > MAX_PATCH_SIZE) {
            std::cerr << "Warning: Original function size (" << original_size
                << " bytes) is very large. Limiting to " << MAX_PATCH_SIZE << " bytes." << std::endl;
            original_size = MAX_PATCH_SIZE;
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error during bounds checking: " << e.what() << std::endl;
        ks_close(ks);
        return false;
    }

    // tính vị trí và kích thước của junk code trước khi chèn JMP
    size_t min_junk_before = std::min((size_t)3, original_size / 3);
    size_t max_junk_before = (original_size > 5 + 1) ? (original_size - 5 - 1) : min_junk_before; // 5 bytes for JMP

    if (max_junk_before < min_junk_before) {
        max_junk_before = min_junk_before;
    }

    size_t junk_before_size = min_junk_before;
    if (max_junk_before > min_junk_before) {
        junk_before_size = min_junk_before + (rand() % (max_junk_before - min_junk_before + 1));
    }

    // lệnh jmp sẽ được đặt tại VA này
    uint64_t jmp_va = original_func_va + junk_before_size;

    // Tính toán độ lệch tương đối cho lệnh JMP
    // JMP: E9 [4-byte offset tương đối]
    // Target = JMP_VA + 5 + relative_offset --> relative_offset = Target - (JMP_VA + 5)
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

    // tạo lệnh JMP thủ công
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

        // patch mã rác (junk) trước lệnh JMP với giới hạn iteration
        size_t remaining_before = junk_before_size;
        size_t junk_iteration_count = 0;
        const size_t MAX_JUNK_ITERATIONS = 500; // Giới hạn iteration để tránh vô tận

        /*std::cout << "Phase 1: Adding " << remaining_before << " bytes of junk before JMP..." << std::endl;*/

        while (remaining_before > 0 && junk_iteration_count < MAX_JUNK_ITERATIONS) {
            junk_iteration_count++;

            std::string junk_asm = get_random_junk_instruction();
            unsigned char* junk_encode = nullptr;
            size_t junk_asm_size = 0;
            size_t junk_count = 0;

            if (ks_asm(ks, junk_asm.c_str(), current_address, &junk_encode, &junk_asm_size, &junk_count) == KS_ERR_OK && junk_count > 0) {
                if (junk_asm_size <= remaining_before) {
                    // KIỂM TRA BOUNDS TRƯỚC KHI PATCH
                    uint64_t patch_end = current_address + junk_asm_size;
                    uint64_t section_start_va = image_base + original_section->virtual_address();
                    uint64_t section_end_va = section_start_va + original_section->virtual_size();

                    if (patch_end > section_end_va) {
                        std::cerr << "Error: Junk patch would exceed section bounds. Stopping." << std::endl;
                        ks_free(junk_encode);
                        break;
                    }

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

        // Kiểm tra nếu vượt quá iteration limit
        if (junk_iteration_count >= MAX_JUNK_ITERATIONS) {
            std::cerr << "Warning: Maximum junk iterations reached. Filling remaining space with NOPs." << std::endl;
            fill_remaining_space_with_nops(current_address, remaining_before);
            current_address += remaining_before;
        }

        // patch lệnh jmp tại địa chỉ hiện tại
        /*std::cout << "Phase 2: Patching JMP at VA 0x" << std::hex << current_address
            << " -> target 0x" << new_func_va << std::dec << std::endl;*/

            // KIỂM TRA BOUNDS CHO JMP
        uint64_t jmp_patch_end = current_address + jmp_size;
        uint64_t section_start_va = image_base + original_section->virtual_address();
        uint64_t section_end_va = section_start_va + original_section->virtual_size();

        if (jmp_patch_end > section_end_va) {
            std::cerr << "Error: JMP patch would exceed section bounds." << std::endl;
            ks_close(ks);
            return false;
        }

        binary->patch_address(current_address, jmp_bytes);
        current_address += jmp_size;

        // patch junkcode sau lệnh JMP với giới hạn iteration
        size_t remaining_after = junk_after_size;
        junk_iteration_count = 0; // Reset counter

        /*std::cout << "Phase 3: Adding " << remaining_after << " bytes of junk after JMP..." << std::endl;*/

        // nếu không có junk sau lệnh JMP, điền bằng NOPs
        while (remaining_after > 0 && junk_iteration_count < MAX_JUNK_ITERATIONS) {
            junk_iteration_count++;

            std::string junk_asm = get_random_junk_instruction();
            unsigned char* junk_encode = nullptr;
            size_t junk_asm_size = 0;
            size_t junk_count = 0;

            if (ks_asm(ks, junk_asm.c_str(), current_address, &junk_encode, &junk_asm_size, &junk_count) == KS_ERR_OK && junk_count > 0) {
                if (junk_asm_size <= remaining_after) {
                    // KIỂM TRA BOUNDS TRƯỚC KHI PATCH
                    uint64_t patch_end = current_address + junk_asm_size;
                    uint64_t section_start_va = image_base + original_section->virtual_address();
                    uint64_t section_end_va = section_start_va + original_section->virtual_size();

                    if (patch_end > section_end_va) {
                        std::cerr << "Error: Final junk patch would exceed section bounds. Stopping." << std::endl;
                        ks_free(junk_encode);
                        break;
                    }

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

        // Kiểm tra nếu vượt quá iteration limit
        if (junk_iteration_count >= MAX_JUNK_ITERATIONS) {
            std::cerr << "Warning: Maximum final junk iterations reached. Filling remaining space with NOPs." << std::endl;
            fill_remaining_space_with_nops(current_address, remaining_after);
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

// Inject một hàm: relocate mã gốc, tạo section mới, chèn trampoline
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

    // đầu tiên lấy mã relocated trước khi build
    if (!get_and_relocate_original_function_code(original_function_va, 0, relocated_code_bytes, original_function_processed_size)) {
        std::cerr << "Error processing original function code." << std::endl;
        return false;
    }

    if (relocated_code_bytes.empty()) {
        std::cerr << "Error: Relocated code is empty." << std::endl;
        return false;
    }

    // tìm section mới đã tạo
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

    // cập nhật nội dung section mới trước
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

    // xây d dựng lại layout của binary
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

    // nhận địa chỉ vùng cuối cùng sau khi build
    uint64_t new_function_base_va = image_base + new_section_ptr->virtual_address();
    std::cout << "New section '.injcod' VA: 0x" << std::hex << new_function_base_va << std::dec << std::endl;

    // di ch chuyển mã gốc sang địa chỉ mới chính xác
    relocated_code_bytes.clear();
    if (!get_and_relocate_original_function_code(original_function_va, new_function_base_va, relocated_code_bytes, original_function_processed_size)) {
        std::cerr << "Error processing original function code with correct VA." << std::endl;
        return false;
    }

    // cập nhật nội dung section mới với mã đã relocate
    new_section_ptr->content(relocated_code_bytes);
    print_bytes("Relocated code (" + std::to_string(relocated_code_bytes.size()) + " bytes): ", relocated_code_bytes);

    /*std::cout << "Step 3: Creating trampoline JMP..." << std::endl;*/
    if (!create_trampoline(original_function_va, new_function_base_va, original_function_processed_size)) {
        std::cerr << "Error creating trampoline." << std::endl;
        return false;
    }

    return true;
}

// Tạo các tên section duy nhất dựa trên tên hàm và chỉ mục
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

    /*std::cout << "Processing " << function_rvas.size() << " function(s) for trampoline injection..." << std::endl;*/

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

        // Cập nhật nội dung section
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

        // dựng finalize layout
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

        // Di chuyển lại code với địa chỉ VA chính xác
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

    /*std::cout << "\nCompleted processing all " << function_rvas.size() << " function(s)." << std::endl;*/
    return true;
}

// Chèn thông minh nhiều hàm với giới hạn số lượng
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

    // kiểm tra số lượng hàm giới hạn được chèn
    uint32_t max_injectable = calculate_max_injectable_functions();
    uint32_t planned_injections = static_cast<uint32_t>(function_rvas.size());

    // show phân tích số lượng hàm sẽ chèn
    check_section_limit_before_injection(planned_injections);

    if (max_injectable == 0) {
        std::cerr << "Error: Cannot inject any functions - section limit reached." << std::endl;
        return false;
    }

    // Giới hạn số lượng hàm sẽ chèn
    uint32_t functions_to_inject = std::min(planned_injections, max_injectable);

    /*std::cout << "Proceeding with injection of " << functions_to_inject << " function(s) out of "
        << planned_injections << " requested." << std::endl;*/

        // tạo vector giới hạn
    std::vector<uint32_t> limited_rvas(function_rvas.begin(), function_rvas.begin() + functions_to_inject);
    std::vector<std::string> limited_names(function_names.begin(), function_names.begin() + functions_to_inject);

    // thưc hiện chèn các hàm đạt điều kiện
    bool result = inject_multiple_function_trampolines(limited_rvas, limited_names);

    if (result) {
        actual_injected_count = functions_to_inject;
    }

    return result;
}

// Hàm static: inject nhiều hàm không giới hạn
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

// ============ IMPLEMENTATION CỦA JunkCodeManager ============
const uint32_t JunkCodeManager::LARGE_BINARY_SIZE_THRESHOLD = 350 * 1024;

// các hàm nguy hiểm và tiền tố nguy hiểm
const std::set<std::string> JunkCodeManager::DANGEROUS_FUNCTION_NAMES = {
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
    "exit", "fget", "fwrite", "memcpy", "memmove", "memset", "malloc", "free",
    "fread", "fclose", "fopen", "fprintf", "printf", "sprintf", "snprintf",
    "strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp", "strncmp",
    "fgetc", "fgets", "fputc", "fputs", "vfprintf", "vprintf", "vsprintf", "fgetpos", "fsetpos", "fegetenv"
    "srand", "rand", "time", "localtime", "gmtime", "asctime", "ctime",
    "clock", "ceil", "wcsnlen", "strpbrk", "GetLocaleNameFromLanguage", "strcspn", "memcmp", "qsort",
};

const std::set<std::string> JunkCodeManager::DANGEROUS_FUNCTION_NAMES_BIG_BINARY = {
    "DetectPEArchitecture", "main", "pe64::pe64", "pdbparser::pdbparser", "obfuscatecff::obfuscatecff", "obfuscatecff::run", "obfuscatecff::compile", "obfuscatecff::~obfuscatecff", "TrampolineInjector::TrampolineInjector", "TrampolineInjector::~TrampolineInjector", "FuncToRVA::RVAResolver::initialize", "FuncToRVA::RVAResolver::RVAResolver", "FuncToRVA::RVAResolver::~RVAResolver",
    "terminate", "raise", "raise$fin$0", "std::setw", "ceilf", "InternalCompareStringA", "InternalGetLocaleInfoA",
    "std::filesystem::exists", "std::filesystem::path::path", "std::filesystem::path::operator/=", "std::filesystem::path::string", "std::filesystem::operator/", "std::vector<unsigned char,std::allocator<unsigned char> >::vector<unsigned char,std::allocator<unsigned char> >", "std::vector<unsigned char,std::allocator<unsigned char> >::resize", "std::vector<unsigned int,std::allocator<unsigned int> >::operator=", "std::exception::exception", "std::exception::what",
    "strrchr", "srand", "CountryEnumProc","LangCountryEnumProc", "LangCountryEnumProcEx","strnlen", "strrchr", "strtol","strtoul","wcschr","wcscmp","wcsncmp","wcspbrk","isdigit","islower","isupper",
    "GetLcidFromLanguage","GetLcidFromLangCountry","TranslateName", "TranslateName","TestDefaultLanguage","setSBCS",
    "setSBUpLow","setvbuf","getSystemCP","ExFilterRethrow","ExFilterRethrowFH4","fallbackMethod","fallbackMethod","FH4::HandlerMap4::HandlerMap4","FH4::HandlerMap4::DecompHandler",
    "FH4::TryBlockMap4::TryBlockMap4","FH4::TryBlockMap4::setBuffer","FH4::UWMap4::ReadEntry","FH4::UWMap4::getStateFromIterators","FH4::UWMap4::getStartStop","IsInExceptionSpec",
};



bool JunkCodeManager::is_large_binary_function_dangerous(const std::string& func_name, const std::string& binary_path) {
    // Chỉ kiểm tra khi binary lớn hơn threshold
    if (!is_binary_large(binary_path)) {
        return false;
    }

    // Kiểm tra xem tên hàm có nằm trong danh sách các hàm nguy hiểm với binary lớn
    return DANGEROUS_FUNCTION_NAMES_BIG_BINARY.count(func_name) > 0;
}

const std::vector<std::string> JunkCodeManager::DANGEROUS_PREFIXES = {
    "??_",
};

// Kiểm tra kích thước binary và trả về true nếu binary lớn hơn threshold
bool JunkCodeManager::is_binary_large(const std::string& binary_path) {
    try {
        std::filesystem::path file_path(binary_path);
        if (!std::filesystem::exists(file_path)) {
            std::cerr << "Error: Binary file does not exist: " << binary_path << std::endl;
            return false;
        }

        std::uintmax_t file_size = std::filesystem::file_size(file_path);

        /*std::cout << "Binary size: " << (file_size / 1024) << " KB (Threshold: "
            << (LARGE_BINARY_SIZE_THRESHOLD / 1024) << " KB)" << std::endl;*/

        return file_size > LARGE_BINARY_SIZE_THRESHOLD;
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error checking binary size: " << e.what() << std::endl;
        return false;
    }


}
// Kiểm tra xem tên hàm có bị blacklist hay không
bool JunkCodeManager::is_function_blacklisted(const std::string& func_name) {
    // Các hàm có ký tự đặc biệt như "_" hoặc "`" thường là các hàm nội bộ hoặc không mong muốn
    if (func_name.find_first_of("`_") != std::string::npos) {
        return true;
    }
    // bắt đầu bằng dấu gạch dưới
    if (func_name.rfind('_', 0) == 0) {
        return true;
    }

    // Kiểm tra xem tên hàm có nằm trong danh sách các hàm nguy hiểm hay không
    if (DANGEROUS_FUNCTION_NAMES.count(func_name)) {
        return true;
    }

    // Kiểm tra xem tên hàm có bắt đầu bằng các tiền tố nguy hiểm hay không
    for (const auto& prefix : DANGEROUS_PREFIXES) {
        if (func_name.rfind(prefix, 0) == 0) {
            return true;
        }
    }

    return false;
}

bool JunkCodeManager::is_function_blacklisted_by_binary_size(const std::string& func_name, const std::string& binary_path) {
    // Kiểm tra blacklist thông thường trước
    if (is_function_blacklisted(func_name)) {
        return true;
    }

    // Kiểm tra blacklist dựa trên kích thước binary
    if (is_large_binary_function_dangerous(func_name, binary_path)) {
        return true;
    }

    return false;
}

// sắp xếp các hàm theo kích thước giảm dần
void JunkCodeManager::sort_functions_by_size_desc(std::vector<uint32_t>& function_rvas,
    std::vector<std::string>& function_names,
    const std::vector<FuncToRVA::FunctionInfo>& all_functions) {

    // Tạo một vector để lưu trữ cặp chỉ mục và kích thước
    std::vector<std::pair<size_t, uint32_t>> index_size_pairs;

    for (size_t i = 0; i < function_rvas.size(); ++i) {
        uint32_t rva = function_rvas[i];

        // Tìm kích thước của hàm dựa trên RVA
        auto it = std::find_if(all_functions.begin(), all_functions.end(),
            [rva](const FuncToRVA::FunctionInfo& func) { return func.rva == rva; });

        if (it != all_functions.end()) {
            index_size_pairs.push_back({ i, it->size });
        }
        else {
            index_size_pairs.push_back({ i, 0 }); // Nếu không tìm thấy, đặt kích thước là 0
        }
    }

    // sắp xếp các cặp chỉ mục và kích thước theo kích thước giảm dần
    std::sort(index_size_pairs.begin(), index_size_pairs.end(),
        [](const std::pair<size_t, uint32_t>& a, const std::pair<size_t, uint32_t>& b) {
            return a.second > b.second; // Giảm dần theo kích thước
        });

    // sắp xếp lại các mảng dựa trên chỉ mục đã sắp xếp
    std::vector<uint32_t> sorted_rvas;
    std::vector<std::string> sorted_names;

    for (const auto& pair : index_size_pairs) {
        sorted_rvas.push_back(function_rvas[pair.first]);
        sorted_names.push_back(function_names[pair.first]);
    }

    function_rvas = std::move(sorted_rvas);
    function_names = std::move(sorted_names);
}

// Lấy nhiều RVAs tương tác từ người dùng
bool JunkCodeManager::get_multiple_rvas_interactive(const std::string& input_pe_path,
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
        std::cout << "Please enter RVAs manually or ensure a valid PDB is accessible.\n" << std::endl;

        // Nhập thủ công cho nhiều RVAs
        std::string input_str;
        std::cout << "Type RVAs of functions (comma-separated, e.g., 1A2B0,1C3D0): ";
        std::getline(std::cin, input_str);

        if (input_str.empty()) {
            std::cerr << "Error: No RVAs provided." << std::endl;
            return false;
        }

        // Lấy các thứ tự tương ứng với các RVA
        std::stringstream ss(input_str);
        std::string token;
        rvas_out.clear();
        names_out.clear();

        while (std::getline(ss, token, ',')) {
            // tách khoảng trắng
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

// Lọc các hàm theo kích thước tối thiểu
bool JunkCodeManager::filter_functions_by_size(const std::string& input_pe_path,
    const std::vector<uint32_t>& input_rvas,
    const std::vector<std::string>& input_names,
    std::vector<uint32_t>& filtered_rvas,
    std::vector<std::string>& filtered_names,
    uint32_t min_size) {

    filtered_rvas.clear();
    filtered_names.clear();

    try {
        // Khởi tạo RVAResolver để lấy thông tin size
        FuncToRVA::RVAResolver resolver(input_pe_path);
        if (!resolver.initialize()) {
            std::cerr << "Error: Could not initialize PDB resolver for size filtering.\n";
            return false;
        }

        const auto& all_functions = resolver.get_functions_info();
        std::vector<std::string> excluded_functions;
        std::vector<uint32_t> excluded_sizes;
        std::vector<std::string> excluded_by_binary_size_blacklist;

        for (size_t i = 0; i < input_rvas.size(); ++i) {
            uint32_t rva = input_rvas[i];
            const std::string& name = input_names[i];

            // Tìm thông tin size từ all_functions
            auto it = std::find_if(all_functions.begin(), all_functions.end(),
                [rva](const FuncToRVA::FunctionInfo& func) { return func.rva == rva; });

            if (it != all_functions.end()) {
                if (is_function_blacklisted_by_binary_size(it->name, input_pe_path)) {
                    excluded_functions.push_back(name);
                    excluded_sizes.push_back(it->size);

                    if (is_large_binary_function_dangerous(it->name, input_pe_path)) {
                        excluded_by_binary_size_blacklist.push_back(name);
                    }
                    continue;
                }

                if (it->size >= min_size) {
                    filtered_rvas.push_back(rva);
                    filtered_names.push_back(name);
                }
                else {
                    excluded_functions.push_back(name);
                    excluded_sizes.push_back(it->size);
                }
            }
            else {
                // Không tìm thấy trong PDB, có thể là manual RVA
                std::cout << "Warning: Could not find size info for " << name << " (RVA: 0x"
                    << std::hex << rva << std::dec << "). Adding to filtered list." << std::endl;
                filtered_rvas.push_back(rva);
                filtered_names.push_back(name);
            }
        }

        // Hiển thị kết quả lọc
        if (!excluded_functions.empty()) {
            std::cout << "\n=== Size Filtering Results ===" << std::endl;
            std::cout << "Excluded " << excluded_functions.size() << " function(s):" << std::endl;
            for (size_t i = 0; i < excluded_functions.size(); ++i) {
                std::string reason = "size < " + std::to_string(min_size) + " bytes";

                // ========== THAY ĐỔI: Hiển thị lý do loại trừ dựa trên binary size ==========
                if (std::find(excluded_by_binary_size_blacklist.begin(), excluded_by_binary_size_blacklist.end(),
                    excluded_functions[i]) != excluded_by_binary_size_blacklist.end()) {
                    reason = "large binary blacklist (binary > " + std::to_string(LARGE_BINARY_SIZE_THRESHOLD / 1024) + "KB)";
                }

                std::cout << "  - " << excluded_functions[i] << " (" << reason << ")" << std::endl;
            }
            std::cout << std::endl;
        }

        if (filtered_rvas.empty()) {
            std::cout << "Warning: No functions remain after size filtering (min size: " << min_size << " bytes)." << std::endl;
            return false;
        }

        std::cout << "After filtering: " << filtered_rvas.size() << " function(s) with size >= " << min_size << " bytes" << std::endl;
        return true;

    }
    catch (const std::exception& e) {
        std::cerr << "Error during size filtering: " << e.what() << std::endl;
        return false;
    }
}

// Triển khai chế độ tự động chèn mã
int JunkCodeManager::run_auto_injection_mode(const std::string& input_pe_path,
    const std::string& output_pe_path,
    bool is_64_bit) {
    std::cout << "Running auto-injection mode..." << std::endl;

    try {
        FuncToRVA::RVAResolver resolver(input_pe_path);
        if (!resolver.initialize()) {
            std::cerr << "Error: Could not initialize PDB resolver.\n";
            return 1;
        }

        const auto& all_functions = resolver.get_functions_info();
        std::vector<uint32_t> function_rvas;
        std::vector<std::string> function_names;

        // Lọc các hàm có kích thước lớn hơn 5 bytes và không bị blacklist
        std::vector<std::pair<uint32_t, std::string>> size_sorted_functions;
        int skipped_count = 0;
        int skipped_by_binary_size_blacklist = 0;

        // Kiểm tra xem binary có lớn hơn threshold không
        bool is_large_binary = is_binary_large(input_pe_path);

        for (const auto& func_info : all_functions) {
            if (is_function_blacklisted_by_binary_size(func_info.name, input_pe_path)) {
                skipped_count++;

                // Kiểm tra xem có bị skip do binary size-based blacklist không
                if (is_large_binary_function_dangerous(func_info.name, input_pe_path)) {
                    skipped_by_binary_size_blacklist++;
                    /*std::cout << "Skipped large binary function: " << func_info.name
                        << " (binary size > " << (LARGE_BINARY_SIZE_THRESHOLD / 1024) << "KB)" << std::endl;*/
                }
                continue;
            }

            if (func_info.size > 5) { // Chỉ lấy các hàm có kích thước lớn hơn 5 bytes
                size_sorted_functions.push_back({ func_info.size, func_info.name });
                // std::cout << func_info.name << std::endl;
            }
        }

        // Sắp xếp các hàm theo kích thước giảm dần
        std::sort(size_sorted_functions.begin(), size_sorted_functions.end(),
            [](const std::pair<uint32_t, std::string>& a, const std::pair<uint32_t, std::string>& b) {
                return a.first > b.first; // Giảm dần theo kích thước
            });

        // Phân tách các hàm đã sắp xếp thành danh sách các RVA và tên hàm
        for (const auto& size_name_pair : size_sorted_functions) {
            const std::string& func_name = size_name_pair.second;

            // Tìm kiếm thông tin hàm để lấy RVA    
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
            std::cerr << "No functions > 5 bytes found.\n";
            return 1;
        }

        std::cout << "\nSkipped " << skipped_by_binary_size_blacklist
            << " functions due to large binary blacklist." << std::endl;

        // Chèn thông minh với tự động giới hạn các hàm
        uint32_t actual_injected_count = 0;
        bool result = TrampolineInjector::inject_trampoline_to_multiple_functions_smart(
            input_pe_path, output_pe_path, function_rvas, function_names,
            actual_injected_count, is_64_bit);

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

// Triển khai chế độ chèn thủ công 
int JunkCodeManager::run_manual_injection_mode(const std::string& input_pe_path,
    const std::string& output_pe_path,
    bool is_64_bit) {
    std::cout << "Running manual injection mode..." << std::endl;

    try {
        std::vector<uint32_t> function_rvas;
        std::vector<std::string> function_names;

        if (!get_multiple_rvas_interactive(input_pe_path, function_rvas, function_names)) {
            return 1;
        }

        // Lọc size cho manual mode
        std::vector<uint32_t> filtered_rvas;
        std::vector<std::string> filtered_names;

        if (!filter_functions_by_size(input_pe_path, function_rvas, function_names,
            filtered_rvas, filtered_names, 5)) {
            std::cerr << "Error: Size filtering failed or no functions remain after filtering.\n";
            return 1;
        }

        // Sử dụng filtered list thay vì original list
        function_rvas = std::move(filtered_rvas);
        function_names = std::move(filtered_names);

        if (function_rvas.empty()) {
            std::cerr << "Error: No functions remain after size filtering.\n";
            return 1;
        }

        std::cout << "Proceeding with " << function_rvas.size() << " function(s) that meet size requirements." << std::endl;

        // Kiểm tra giới hạn section
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

            // Chèn tự động với giới hạn
            uint32_t actual_injected_count = 0;
            bool result = TrampolineInjector::inject_trampoline_to_multiple_functions_smart(
                input_pe_path, output_pe_path, function_rvas, function_names,
                actual_injected_count, is_64_bit);

            if (!result) {
                std::cerr << "Smart Manual Injection failed!\n";
                return 1;
            }

            std::cout << "\nSuccessfully injected trampolines into " << actual_injected_count
                << " function(s) out of " << function_rvas.size() << " selected." << std::endl;
        }
        else {
            // Chèn thường - giới hạn chấp nhận được
            bool result = TrampolineInjector::inject_trampoline_to_multiple_functions(
                input_pe_path, output_pe_path, function_rvas, function_names, is_64_bit);

            if (!result) {
                std::cerr << "Manual Functions Injection failed!\n";
                return 1;
            }

            std::cout << "\nSuccessfully injected trampolines into all " << function_rvas.size()
                << " selected function(s)." << std::endl;
        }

        return 0;

    }
    catch (const std::exception& e) {
        std::cerr << "Error in manual injection mode: " << e.what() << std::endl;
        return 1;
    }
}

// Hàm static: inject nhiều hàm có kiểm tra giới hạn section
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

// Hàm static: inject một hàm đơn
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