#include "../obfuscator/obfuscator.h"

#include <random>


//detect các lệnh nhảy có điều kiện
bool is_jmp_conditional(ZydisDecodedInstruction instr) {
	switch (instr.mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JKNZD:
	case ZYDIS_MNEMONIC_JKZD:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
		return true;
	default:
		return false;
	}
	return false;
}


// áp dụng thuật toán làm phẳng luồng
bool obfuscator::apply_control_flow_flattening(std::vector<obfuscator::function_t>::iterator& func) {

	struct block_t {
		int block_id;
		std::vector < obfuscator::instruction_t>instructions;

		int next_block;
		int dst_block = -1;

	};

	std::vector<block_t>blocks;
	std::vector<int>block_starts;
	block_t block;
	int block_iterator = 0;

	
	// thực hiện khởi tạo vector block_start

	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

		if (is_jmp_conditional(instruction->zyinstr.info) || (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JMP && instruction->zyinstr.info.raw.imm->size == 8)) {

			if (instruction->relative.target_func_id == func->func_id) {
				block_starts.push_back(instruction->relative.target_inst_id);
			}
		}
	}

	
	// detect các block trong hàm
	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

		block.instructions.push_back(*instruction);
		auto next_instruction = instruction + 1;

		if (next_instruction != func->instructions.end()) {

			if (std::find(block_starts.begin(), block_starts.end(), next_instruction->inst_id) != block_starts.end()) {
				block.block_id = block_iterator++;
				blocks.push_back(block);
				block.instructions.clear();
				continue;
			}
		}
		else {
			block.block_id = block_iterator++;
			blocks.push_back(block);
			block.instructions.clear();
			continue;
		}

		if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_RET || (instruction->isjmpcall && instruction->zyinstr.info.mnemonic != ZYDIS_MNEMONIC_CALL))
		{
			block.block_id = block_iterator++;
			blocks.push_back(block);
			block.instructions.clear();
		}
	}

	// xây dựng liên kết giữa các block
	for (auto curr_block = blocks.begin(); curr_block != blocks.end(); curr_block++) {

		auto last_instruction = curr_block->instructions.end() - 1;
		curr_block->next_block = curr_block->block_id + 1;


		if (last_instruction->isjmpcall && is_jmp_conditional(last_instruction->zyinstr.info)) {
			for (auto curr_block2 = blocks.begin(); curr_block2 != blocks.end(); curr_block2++) {

				auto first_instruction = curr_block2->instructions.begin();
				if (first_instruction->inst_id == last_instruction->relative.target_inst_id) {
					curr_block->dst_block = curr_block2->block_id;
					break;
				}
			}
		}
	}

	int first_inst_id = func->instructions.begin()->inst_id;
	int new_id = this->instruction_id++;
	func->instructions.begin()->inst_id = new_id;
	func->instructions.begin()->is_first_instruction = false;

	// đảo vị trí các block trong vector một cách ngẫu nhiên
	auto rng = std::default_random_engine{};
	std::shuffle(blocks.begin(), blocks.end(), rng);

	

	// thực hiện tái cấu trúc luồng với bộ điều phối thông qua so sánh với biến trạng thái rax

	instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });
	push_rax.inst_id = first_inst_id;
	push_rax.is_first_instruction = false;
	auto it = func->instructions.insert(func->instructions.begin(), push_rax);
	instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });
	it = func->instructions.insert(it + 1, push_f);
	instruction_t mov_eax_0{}; mov_eax_0.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
	it = func->instructions.insert(it + 1, mov_eax_0);

	for (auto current_block = blocks.begin(); current_block != blocks.end(); current_block++) {

		instruction_t cmp_eax{}; cmp_eax.load(func->func_id, { 0x3D, 0x00, 0x00,0x00,0x00 });
		*(uint32_t*)&cmp_eax.raw_bytes.data()[1] = current_block->block_id;

		instruction_t jne{}; jne.load(func->func_id, { 0x75, 0x08 });

		instruction_t pop_f{}; pop_f.load(func->func_id, { 0x66, 0x9D });

		instruction_t pop_rax{}; pop_rax.load(func->func_id, { 0x58 });

		instruction_t jmp{}; jmp.load(func->func_id, { 0xE9,0x00,0x00,0x00,0x00 });
		jmp.relative.target_inst_id = current_block->block_id == 0 ? new_id : current_block->instructions.begin()->inst_id;
		jmp.relative.target_func_id = func->func_id;

		it = func->instructions.insert(it + 1, { cmp_eax , jne, pop_f, pop_rax, jmp });
		it = it + 4;
	}

	

	for (auto inst = func->instructions.begin(); inst != it + 1; inst++) {

		if (inst->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JNZ) {
			auto dst = inst + 4;

			inst->relative.target_func_id = func->func_id;
			inst->relative.target_inst_id = dst->inst_id;
		}
	}


	// cấu hình lại các block để nó trở lại bộ điều phối sau khi thực hiện xong
	for (auto current_block = blocks.begin(); current_block != blocks.end() - 1; current_block++) {

		auto last_instruction = std::find_if(func->instructions.begin(), func->instructions.end(), [&](obfuscator::instruction_t it) {
			return it.inst_id == (current_block->instructions.end() - 1)->inst_id;
			});

		auto next_block = std::find_if(blocks.begin(), blocks.end(), [&](const block_t block) {return block.block_id == current_block->next_block; });
		if (next_block == blocks.end()) continue;

		if (is_jmp_conditional(last_instruction->zyinstr.info) && current_block->dst_block != -1) {

			auto dst_block = std::find_if(blocks.begin(), blocks.end(), [&](const block_t block) {return block.block_id == current_block->dst_block; });

			{
				instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

				instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

				instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
				*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = next_block->block_id;

				instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
				jmp.relative.target_func_id = func->func_id;
				jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

				last_instruction = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
				last_instruction = last_instruction + 3;
			}

			{

				instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

				instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

				instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
				*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = dst_block->block_id;

				instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
				jmp.relative.target_func_id = func->func_id;
				jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

				last_instruction = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
				last_instruction = last_instruction + 3;
			}

			
			last_instruction = last_instruction - 8;
			last_instruction->relative.target_inst_id = (last_instruction + 5)->inst_id;

		}
		else {

			instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

			instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

			instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
			*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = next_block->block_id;

			instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
			jmp.relative.target_func_id = func->func_id;
			jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

			auto it = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
			it = it + 3;
		}
	}

	return true;
}
