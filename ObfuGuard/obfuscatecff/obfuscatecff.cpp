#include "obfuscatecff.h"
#include <iostream>
#include <bit>
#include <unordered_set>
#include <unordered_map>

#define REG_PAIR(zreg, areg) { ZYDIS_REGISTER_##zreg, x86::areg }

ZydisFormatter formatter;
ZydisDecoder decoder;

int obfuscatecff::instruction_id = 0;
int obfuscatecff::function_iterator = 0;

// Hàm xoay phải 32 bit
__forceinline int _strcmp(const char* s1, const char* s2)
{
	while (*s1 && (*s1 == *s2))
	{
		s1++;
		s2++;
	}
	return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

// Hàm khởi tạo obfuscatecff với đối tượng pe64
obfuscatecff::obfuscatecff(pe64* pe) {
	this->pe = pe;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
		throw std::runtime_error("failed to init decoder");
	if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
		throw std::runtime_error("failed to init formatter");
}

// Khởi tạo danh sách các hàm theo cấu trúc function_t từ pdbparser
void obfuscatecff::create_functions(std::vector<pdbparser::sym_func>functions) {

	auto text_section = this->pe->get_section(".text"); // tìm section .text trong tệp PE

	if (!text_section)
		throw std::runtime_error("couldn't find .text section");

	std::vector<uint32_t>visited_rvas; // danh sách các rva đã được phân tích

	// khởi tạo các hàm trong tệp PE từ pdbparser
	for (auto function : functions) {
		if (function.obfuscate == false) // nếu hàm không được đánh dấu để obfuscate thì bỏ qua
			continue;
		if (std::find(visited_rvas.begin(), visited_rvas.end(), function.offset) != visited_rvas.end()) // nếu rva đã được phân tích thì bỏ qua
			continue;
		if (function.size < 5) // kích thước hàm quá nhỏ thì bỏ qua
			continue;

		ZydisDisassembledInstruction zyinstruction{};

		// tính toán địa chỉ của hàm trong bộ nhớ
		auto address_to_analyze = this->pe->get_buffer()->data() + text_section->VirtualAddress + function.offset;
		uint32_t offset = 0;

		function_t new_function(function_iterator++, function.name, function.offset, function.size); // khởi tạo một đối tượng function_t mới với các thông tin từ pdbparser

		new_function.ctfflattening = function.ctfflattening; // nếu hàm được đánh dấu để flattening thì đánh dấu trong đối tượng function_t

		std::vector <uint64_t> runtime_addresses; // danh sách các địa chỉ runtime của các câu lệnh trong hàm

		while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)(address_to_analyze + offset), (const void*)(address_to_analyze + offset), function.size - offset, &zyinstruction))) { // phân tích từng câu lệnh trong hàm

			instruction_t new_instruction{};
			new_instruction.runtime_address = (uint64_t)address_to_analyze + offset;
			new_instruction.load(function_iterator, zyinstruction, new_instruction.runtime_address);
			if (offset == 0)
				new_instruction.is_first_instruction = true;
			new_function.instructions.push_back(new_instruction);
			offset += new_instruction.zyinstr.info.length;

			uint64_t inst_index = new_function.instructions.size() - 1;
			this->runtime_addr_track[new_instruction.runtime_address].inst_index = inst_index;
			runtime_addresses.push_back(new_instruction.runtime_address);

			new_function.inst_id_index[new_instruction.inst_id] = inst_index;
		}

		visited_rvas.push_back(function.offset); // đánh dấu rva đã được phân tích
		this->functions.push_back(new_function); // thêm hàm mới vào danh sách các hàm

		for (auto runtime_address = runtime_addresses.begin(); runtime_address != runtime_addresses.end(); ++runtime_address) {
			this->runtime_addr_track[*runtime_address].func_id = new_function.func_id;
		}
	}

}

// Dùng safebuffers để đảm bảo an toàn bộ đệm khi nhảy vào entrypoint đã vá lại
__declspec(safebuffers) int obfuscatecff::custom_main(int argc, char* argv[]) {
	// Lấy địa chỉ PEB thông qua GS register
	uint64_t peb_address = __readgsqword(0x60);

	// Lấy base address của tiến trình từ PEB
	uint64_t module_base = *(uint64_t*)(peb_address + 0x10);

	// Lấy con trỏ đến NT Headers
	auto dos_header = (PIMAGE_DOS_HEADER)module_base;
	auto nt_headers = (PIMAGE_NT_HEADERS)(module_base + dos_header->e_lfanew);

	// Tìm section có tên ".0Dev"
	PIMAGE_SECTION_HEADER target_section = nullptr;
	auto section_headers = IMAGE_FIRST_SECTION(nt_headers);

	const char target_name[] = ".0Dev";

	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
		if (strncmp((char*)section_headers[i].Name, target_name, sizeof(section_headers[i].Name)) == 0) {
			target_section = &section_headers[i];
			break;
		}
	}

	if (!target_section) {
		return -1; // Không tìm thấy section
	}

	// Lấy entrypoint đã bị mã hóa từ section ".0Dev"
	uint32_t encoded_entry = *(uint32_t*)(module_base + target_section->VirtualAddress);

	// Giải mã entrypoint
	encoded_entry ^= nt_headers->OptionalHeader.SizeOfStackCommit;
	encoded_entry = _rotr(encoded_entry, nt_headers->FileHeader.TimeDateStamp);

	// Gọi hàm main thực sự tại địa chỉ đã giải mã
	using MainFunc = int(*)(int, char**);
	MainFunc real_main = reinterpret_cast<MainFunc>(module_base + encoded_entry);
	return real_main(argc, argv);
}


// Tìm instruction tại địa chỉ runtime cụ thể
bool obfuscatecff::find_inst_at_dst(uint64_t target_addr, instruction_t** out_instruction, function_t** out_function) {
	// Kiểm tra xem địa chỉ có nằm trong bản ghi runtime không
	auto it = runtime_addr_track.find(target_addr);
	if (it == runtime_addr_track.end()) {
		return false;
	}

	const auto& track_info = it->second;
	*out_function = &functions[track_info.func_id];

	// Nếu hàm có sử dụng jump tables thì bỏ qua
	if ((*out_function)->has_jumptables) {
		return false;
	}

	// Trả về con trỏ đến instruction tương ứng
	*out_instruction = &(*out_function)->instructions[track_info.inst_index];
	return true;
}

// Đánh dấu các hàm có sử dụng jump table để loại trừ khỏi xử lý sau này
void obfuscatecff::remove_jumptables() {
	for (auto& func : functions) {
		for (auto& instr : func.instructions) {
			// Kiểm tra xem instruction có tham chiếu tương đối 32-bit, không phải jump/call
			if (instr.has_relative && !instr.isjmpcall && instr.relative.size == 32) {

				// Tính địa chỉ thực mà instruction này tham chiếu đến
				int32_t rel_offset = *(int32_t*)(&instr.raw_bytes[instr.relative.offset]);
				uint64_t resolved_address = instr.runtime_address + rel_offset + instr.zyinstr.info.length;

				// Nếu địa chỉ trỏ về đầu file buffer, đánh dấu hàm này có jumptable
				if (resolved_address == (uint64_t)this->pe->get_buffer()->data()) {
					func.has_jumptables = true;
					break; // Không cần kiểm tra thêm instruction nào trong hàm này
				}
			}
		}
	}
}

// phân tích các hàm phù hợp để obfuscate và phân tích các câu lệnh liên quan đến địa chỉ tương đối của hàm
bool obfuscatecff::analyze_functions() {

	this->remove_jumptables();

	for (auto func = functions.begin(); func != functions.end(); func++) {
		if (!func->has_jumptables) {
			for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

				if (instruction->has_relative) {

					if (instruction->isjmpcall) {

						uint64_t absolute_address = 0;

						if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction->zyinstr.info, &instruction->zyinstr.operands[0], instruction->runtime_address, (ZyanU64*)&absolute_address)))
							return false;

						obfuscatecff::instruction_t* instptr;
						obfuscatecff::function_t* funcptr;

						if (!this->find_inst_at_dst(absolute_address, &instptr, &funcptr)) {
							instruction->relative.target_inst_id = -1;
							continue;
						}

						instruction->relative.target_inst_id = instptr->inst_id;
						instruction->relative.target_func_id = funcptr->func_id;
					}
					else {

						uint64_t original_data = instruction->runtime_address + instruction->zyinstr.info.length;

						switch (instruction->relative.size) {
						case 8:
							original_data += *(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						case 16:
							original_data += *(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						case 32:
							original_data += *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						}
						instruction->location_of_data = original_data;
					}
				}
			}
		}
	}

	return true;
}

// relocate đoạn mã trong section
void obfuscatecff::relocate(PIMAGE_SECTION_HEADER new_section) {
	auto base = pe->get_buffer()->data() + 0x1000;
	int used_memory = 0;
	for (auto func = functions.begin(); func != functions.end(); ++func) { // lặp qua từng hàm trong danh sách
		if (func->has_jumptables)
			continue;
		uint32_t dst = new_section->VirtualAddress + used_memory; // tính toán địa chỉ đích của hàm trong bộ nhớ mới
		int instr_ctr = 0;
		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); ++instruction) {
			// cập nhật địa chỉ relocated_address của câu lệnh
			instruction->relocated_address = (uint64_t)base + dst + instr_ctr;
			instr_ctr += instruction->zyinstr.info.length;
		}
		used_memory += instr_ctr;
	}
	this->total_size_used = used_memory + 0x1000;
}

// tìm câu lệnh dựa trên id lệnh và id hàm
bool obfuscatecff::find_instruction_by_id(int funcid, int instid, instruction_t* inst) {

	auto func = std::find_if(this->functions.begin(), this->functions.end(), [&](const obfuscatecff::function_t& func) {
		return func.func_id == funcid;
		});
	if (func == this->functions.end())
		return false;
	auto it = std::find_if(func->instructions.begin(), func->instructions.end(), [&](const obfuscatecff::instruction_t& inst) {
		return inst.inst_id == instid;
		});

	if (it != func->instructions.end())
	{
		*inst = *it;
		return true;
	}
	return false;
}

//chuyển đổi các lệnh nhảy sang dạng 16 bit
uint16_t rel8_to16(ZydisMnemonic mnemonic) {
	static const std::unordered_map<ZydisMnemonic, uint16_t> jump_map = {
		{ZYDIS_MNEMONIC_JNBE, 0x870F},
		{ZYDIS_MNEMONIC_JB,   0x820F},
		{ZYDIS_MNEMONIC_JBE,  0x860F},
		{ZYDIS_MNEMONIC_JL,   0x8C0F},
		{ZYDIS_MNEMONIC_JLE,  0x8E0F},
		{ZYDIS_MNEMONIC_JNB,  0x830F},
		{ZYDIS_MNEMONIC_JNL,  0x8D0F},
		{ZYDIS_MNEMONIC_JNLE, 0x8F0F},
		{ZYDIS_MNEMONIC_JNO,  0x810F},
		{ZYDIS_MNEMONIC_JNP,  0x8B0F},
		{ZYDIS_MNEMONIC_JNS,  0x890F},
		{ZYDIS_MNEMONIC_JNZ,  0x850F},
		{ZYDIS_MNEMONIC_JO,   0x800F},
		{ZYDIS_MNEMONIC_JP,   0x8A0F},
		{ZYDIS_MNEMONIC_JS,   0x880F},
		{ZYDIS_MNEMONIC_JZ,   0x840F},
		{ZYDIS_MNEMONIC_JMP,  0xE990}
	};
	auto it = jump_map.find(mnemonic);
	return (it != jump_map.end()) ? it->second : 0;
}

// sửa các lệnh nhảy theo địa chỉ tương đối
bool obfuscatecff::fix_relative_jmps(function_t* func) {

	for (auto instruction_iter = func->instructions.begin(); instruction_iter != func->instructions.end(); instruction_iter++) {

		if (instruction_iter->isjmpcall && instruction_iter->relative.target_inst_id != -1) {

			instruction_t inst{};

			if (!this->find_instruction_by_id(instruction_iter->relative.target_func_id, instruction_iter->relative.target_inst_id, &inst)) {
				return false;
			}


			switch (instruction_iter->relative.size) {
			case 8: {
				signed int distance = inst.relocated_address - instruction_iter->relocated_address - instruction_iter->zyinstr.info.length;
				if (distance > 127 || distance < -128) {

					if (instruction_iter->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JMP) {


						instruction_iter->raw_bytes.resize(5);
						*(uint8_t*)(instruction_iter->raw_bytes.data()) = 0xE9;
						*(int32_t*)(&instruction_iter->raw_bytes.data()[1]) = (int32_t)(inst.relocated_address - instruction_iter->relocated_address - instruction_iter->zyinstr.info.length);

						instruction_iter->reload();

						for (auto instruction_iter2 = instruction_iter; instruction_iter2 != func->instructions.end(); instruction_iter2++) {
							instruction_iter2->relocated_address += 3;
						}

						return this->fix_relative_jmps(func);

					}
					else {

						uint16_t new_opcode = rel8_to16(instruction_iter->zyinstr.info.mnemonic);
						instruction_iter->raw_bytes.resize(6);
						*(uint16_t*)(instruction_iter->raw_bytes.data()) = new_opcode;
						*(int32_t*)(&instruction_iter->raw_bytes.data()[2]) = (int32_t)(inst.relocated_address - instruction_iter->relocated_address - instruction_iter->zyinstr.info.length);

						instruction_iter->reload();

						for (auto instruction2 = instruction_iter; instruction2 != func->instructions.end(); ++instruction2) {
							instruction2->relocated_address += 4;
						}

						return this->fix_relative_jmps(func);
					}

				}
				break;
			}

			case 16: {
				signed int distance = inst.relocated_address - instruction_iter->relocated_address - instruction_iter->zyinstr.info.length;
				if (distance > 32767 || distance < -32768)
				{

					return false;
				}
				break;
			}
			case 32: {
				signed int distance = inst.relocated_address - instruction_iter->relocated_address - instruction_iter->zyinstr.info.length;
				if (distance > 2147483647 || distance < -2147483648)
				{

					return false;
				}
				break;
			}
			default:
			{
				return false;
			}
			}
		}
	}
	return true;
}

// áp dụng fix relative jmp cho tất cả các hàm không có jumptable
bool obfuscatecff::convert_relative_jmps() {
	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		if (!this->fix_relative_jmps(&(*func)))
			return false;
	}
	return true;
}

// Thực hiện relocate, cập nhật lại các operand tương đối 
bool obfuscatecff::apply_relocations(PIMAGE_SECTION_HEADER new_section) {

	this->relocate(new_section);

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		for (auto instruction_ptr = func->instructions.begin(); instruction_ptr != func->instructions.end(); ++instruction_ptr) {

			if (instruction_ptr->has_relative) {

				if (instruction_ptr->isjmpcall) {

					if (instruction_ptr->relative.target_inst_id == -1) {

						switch (instruction_ptr->relative.size) {
						case 8: {
							uint64_t dst = instruction_ptr->runtime_address + *(int8_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) + instruction_ptr->zyinstr.info.length;
							*(int8_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int8_t)(dst - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
							break;
						}
						case 16: {
							uint64_t dst = instruction_ptr->runtime_address + *(int16_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) + instruction_ptr->zyinstr.info.length;
							*(int16_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int16_t)(dst - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
							break;
						}
						case 32: {
							uint64_t dst = instruction_ptr->runtime_address + *(int32_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) + instruction_ptr->zyinstr.info.length;
							*(int32_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int32_t)(dst - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
							break;
						}
						default:
							return false;
						}

						memcpy((void*)instruction_ptr->relocated_address, instruction_ptr->raw_bytes.data(), instruction_ptr->zyinstr.info.length);
					}
					else {

						instruction_t inst;
						if (!this->find_instruction_by_id(instruction_ptr->relative.target_func_id, instruction_ptr->relative.target_inst_id, &inst)) {
							return false;
						}

						switch (instruction_ptr->relative.size) {
						case 8: {
							*(int8_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int8_t)(inst.relocated_address - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
							break;
						}
						case 16:
							*(int16_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int16_t)(inst.relocated_address - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
							break;
						case 32: {
							if (inst.is_first_instruction)
								*(int32_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int32_t)(inst.runtime_address - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
							else
								*(int32_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int32_t)(inst.relocated_address - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
							break;
						}
						default:
							return false;
						}

						memcpy((void*)instruction_ptr->relocated_address, instruction_ptr->raw_bytes.data(), instruction_ptr->zyinstr.info.length);
					}

				}
				else {

					uint64_t dst = instruction_ptr->location_of_data;
					switch (instruction_ptr->relative.size) {
					case 8: {
						*(int8_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int8_t)(dst - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
						break;
					}
					case 16: {
						*(int16_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int16_t)(dst - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
						break;
					}
					case 32: {
						*(int32_t*)(&instruction_ptr->raw_bytes.data()[instruction_ptr->relative.offset]) = (int32_t)(dst - instruction_ptr->relocated_address - instruction_ptr->zyinstr.info.length);
						break;
					}
					default:
						return false;
					}

					memcpy((void*)instruction_ptr->relocated_address, instruction_ptr->raw_bytes.data(), instruction_ptr->zyinstr.info.length);
				}

			}
			else {
				memcpy((void*)instruction_ptr->relocated_address, instruction_ptr->raw_bytes.data(), instruction_ptr->zyinstr.info.length);
			}

		}
	}

	return true;
}

// biên dịch lại tệp nhị phân
void obfuscatecff::compile(PIMAGE_SECTION_HEADER new_section) {

	const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(this->pe->get_nt());
	for (auto i = 0; i < this->pe->get_nt()->FileHeader.NumberOfSections; ++i) {
		current_image_section[i].PointerToRawData = current_image_section[i].VirtualAddress;
	}

	auto text_section = this->pe->get_section(".text");
	auto base = this->pe->get_buffer()->data();

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		auto first_instruction = func->instructions.begin();

		const uint8_t jmp_shell[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

		if (func->offset != -1) {
			uint32_t src = text_section->VirtualAddress + func->offset;
			uint32_t dst = first_instruction->relocated_address - (uint64_t)pe->get_buffer()->data();


			*(int32_t*)&jmp_shell[1] = (signed int)(dst - src - sizeof(jmp_shell));

			for (int i = 0; i < func->size - 5; i++) {
				*(uint8_t*)((uint64_t)base + src + 5 + i) = rand() % 255 + 1;
			}

			memcpy((void*)(base + src), jmp_shell, sizeof(jmp_shell));
		}
	}

}

void obfuscatecff::run(PIMAGE_SECTION_HEADER new_section, bool obfuscate_entry_point) { // luồng xử lý làm rối mã trên Control Flow Flattening (CFF)

	if (!this->analyze_functions())
		throw std::runtime_error("Error when analyzing function");

	*(uint32_t*)(pe->get_buffer()->data() + new_section->VirtualAddress) = _rotl(pe->get_nt()->OptionalHeader.AddressOfEntryPoint, pe->get_nt()->FileHeader.TimeDateStamp) ^ pe->get_nt()->OptionalHeader.SizeOfStackCommit;

	code.init(rt.environment());
	code.attach(&this->assm);

	for (auto func = functions.begin(); func != functions.end(); func++) {
		if (func->has_jumptables)
			continue;

		if (func->ctfflattening)
			this->apply_control_flow_flattening(func);
	}

	this->relocate(new_section);

	if (!this->convert_relative_jmps())
		throw std::runtime_error("couldn't convert relative jmps");

	if (!this->apply_relocations(new_section))
		throw std::runtime_error("couldn't apply relocs");

	this->compile(new_section);

}

uint32_t obfuscatecff::get_added_size() { // tổng bộ nhớ đã obfu
	return this->total_size_used;
}

std::vector<obfuscatecff::instruction_t>obfuscatecff::instructions_from_jit(uint8_t* code, uint32_t size) { // dịch các câu lệnh hợp ngữ từ biên dịch just-in-time (jit)

	std::vector<instruction_t>instr;

	uint32_t offset = 0;
	ZydisDisassembledInstruction zyinstruction{};
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)(code + offset), (const void*)(code + offset), size - offset, &zyinstruction))) {

		instruction_t new_instruction{};
		new_instruction.load(-1, zyinstruction, (uint64_t)(code + offset));
		instr.push_back(new_instruction);
		offset += new_instruction.zyinstr.info.length;
	}

	return instr;
}

bool is_jmpcall(const ZydisDecodedInstruction& instr) { // kiểm tra xem câu lệnh có phải là jump/call hay không
	static const std::unordered_set<ZydisMnemonic> jmpcall_mnemonics = {
		ZYDIS_MNEMONIC_JNBE, ZYDIS_MNEMONIC_JB,    ZYDIS_MNEMONIC_JBE,
		ZYDIS_MNEMONIC_JCXZ, ZYDIS_MNEMONIC_JECXZ, ZYDIS_MNEMONIC_JKNZD,
		ZYDIS_MNEMONIC_JKZD, ZYDIS_MNEMONIC_JL,    ZYDIS_MNEMONIC_JLE,
		ZYDIS_MNEMONIC_JNB,  ZYDIS_MNEMONIC_JNL,   ZYDIS_MNEMONIC_JNLE,
		ZYDIS_MNEMONIC_JNO,  ZYDIS_MNEMONIC_JNP,   ZYDIS_MNEMONIC_JNS,
		ZYDIS_MNEMONIC_JNZ,  ZYDIS_MNEMONIC_JO,    ZYDIS_MNEMONIC_JP,
		ZYDIS_MNEMONIC_JRCXZ,ZYDIS_MNEMONIC_JS,    ZYDIS_MNEMONIC_JZ,
		ZYDIS_MNEMONIC_JMP,  ZYDIS_MNEMONIC_CALL
	};

	return jmpcall_mnemonics.contains(instr.mnemonic);
}

void obfuscatecff::instruction_t::load_relative_info() { // lấy thông tin về các giá trị tham chiếu tương đối

	if (!(this->zyinstr.info.attributes & ZYDIS_ATTRIB_IS_RELATIVE))
	{
		this->relative.offset = 0; this->relative.size = 0; this->has_relative = false;
		return;
	}

	this->has_relative = true;
	this->isjmpcall = is_jmpcall(this->zyinstr.info);

	ZydisInstructionSegments segs;
	ZydisGetInstructionSegments(&this->zyinstr.info, &segs);
	for (uint8_t idx = 0; idx < this->zyinstr.info.operand_count; ++idx)
	{
		auto& op = this->zyinstr.operands[idx];


		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			if (op.imm.is_relative)
			{
				for (uint8_t segIdx = 0; segIdx < segs.count; ++segIdx)
				{
					auto seg = segs.segments[segIdx];

					if (seg.type == ZYDIS_INSTR_SEGMENT_IMMEDIATE)
					{
						this->relative.offset = this->zyinstr.info.raw.imm->offset;
						this->relative.size = this->zyinstr.info.raw.imm->size;
						break;
					}
				}
			}
		}
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			if (op.mem.base == ZYDIS_REGISTER_RIP)
			{
				for (uint8_t segIdx = 0; segIdx < segs.count; ++segIdx)
				{
					auto seg = segs.segments[segIdx];

					if (seg.type == ZYDIS_INSTR_SEGMENT_DISPLACEMENT)
					{
						this->relative.offset = this->zyinstr.info.raw.disp.offset;
						this->relative.size = this->zyinstr.info.raw.disp.size;
						break;
					}
				}
			}
		}
	}
}


void obfuscatecff::instruction_t::load(int funcid, std::vector<uint8_t>raw_data) { // nạp câu lệnh từ raw_data và funcid
	this->inst_id = instruction_id++;
	ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)raw_data.data(), (const void*)(raw_data.data()), raw_data.size(), &this->zyinstr);
	this->func_id = funcid;
	this->raw_bytes = raw_data;
	this->load_relative_info();
}

void obfuscatecff::instruction_t::load(int funcid, ZydisDisassembledInstruction zyinstruction, uint64_t runtime_address) { // nạp câu lệnh từ zydis disassembled instruction và địa chỉ runtime
	this->inst_id = instruction_id++;
	this->zyinstr = zyinstruction;
	this->func_id = funcid;
	this->raw_bytes.resize(this->zyinstr.info.length); memcpy(this->raw_bytes.data(), (void*)runtime_address, this->zyinstr.info.length);
	this->load_relative_info();
}

void obfuscatecff::instruction_t::reload() { // nạp lại câu lệnh từ raw_bytes, dùng khi sửa đổi raw_bytes
	ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)this->raw_bytes.data(), (const void*)this->raw_bytes.data(), this->raw_bytes.size(), &this->zyinstr);
	this->load_relative_info();
}

void obfuscatecff::instruction_t::print() { // in ra thông tin của câu lệnh
	char buffer[256];
	ZydisFormatterFormatInstruction(&formatter, &this->zyinstr.info, this->zyinstr.operands, this->zyinstr.info.operand_count,
		buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
	puts(buffer);
}

// map giữa các register và mnemonic tương ứng tring zydis
// map giữa các register và mnemonic tương ứng tring zydis
std::unordered_map<ZydisRegister_, x86::Gp> obfuscatecff::lookupmap = {
	// 8-bit
	REG_PAIR(AL, al), REG_PAIR(CL, cl), REG_PAIR(DL, dl), REG_PAIR(BL, bl),
	REG_PAIR(AH, ah), REG_PAIR(CH, ch), REG_PAIR(DH, dh), REG_PAIR(BH, bh),
	REG_PAIR(SPL, spl), REG_PAIR(BPL, bpl), REG_PAIR(SIL, sil), REG_PAIR(DIL, dil),
	REG_PAIR(R8B, r8b), REG_PAIR(R9B, r9b), REG_PAIR(R10B, r10b), REG_PAIR(R11B, r11b),
	REG_PAIR(R12B, r12b), REG_PAIR(R13B, r13b), REG_PAIR(R14B, r14b), REG_PAIR(R15B, r15b),

	// 16-bit
	REG_PAIR(AX, ax), REG_PAIR(CX, cx), REG_PAIR(DX, dx), REG_PAIR(BX, bx),
	REG_PAIR(SP, sp), REG_PAIR(BP, bp), REG_PAIR(SI, si), REG_PAIR(DI, di),
	REG_PAIR(R8W, r8w), REG_PAIR(R9W, r9w), REG_PAIR(R10W, r10w), REG_PAIR(R11W, r11w),
	REG_PAIR(R12W, r12w), REG_PAIR(R13W, r13w), REG_PAIR(R14W, r14w), REG_PAIR(R15W, r15w),

	// 32-bit
	REG_PAIR(EAX, eax), REG_PAIR(ECX, ecx), REG_PAIR(EDX, edx), REG_PAIR(EBX, ebx),
	REG_PAIR(ESP, esp), REG_PAIR(EBP, ebp), REG_PAIR(ESI, esi), REG_PAIR(EDI, edi),
	REG_PAIR(R8D, r8d), REG_PAIR(R9D, r9d), REG_PAIR(R10D, r10d), REG_PAIR(R11D, r11d),
	REG_PAIR(R12D, r12d), REG_PAIR(R13D, r13d), REG_PAIR(R14D, r14d), REG_PAIR(R15D, r15d),

	// 64-bit
	REG_PAIR(RAX, rax), REG_PAIR(RCX, rcx), REG_PAIR(RDX, rdx), REG_PAIR(RBX, rbx),
	REG_PAIR(RSP, rsp), REG_PAIR(RBP, rbp), REG_PAIR(RSI, rsi), REG_PAIR(RDI, rdi),
	REG_PAIR(R8, r8), REG_PAIR(R9, r9), REG_PAIR(R10, r10), REG_PAIR(R11, r11),
	REG_PAIR(R12, r12), REG_PAIR(R13, r13), REG_PAIR(R14, r14), REG_PAIR(R15, r15)
};

#undef REG_PAIR