#include "../obfuscatecff/obfuscatecff.h"
#include <random>
#include <vector>

//detect các lệnh nhảy có điều kiện
bool is_jmp_conditional(const ZydisDecodedInstruction& instr) {
	return instr.meta.category == ZYDIS_CATEGORY_COND_BR;
}

// áp dụng thuật toán làm phẳng luồng
bool obfuscatecff::apply_control_flow_flattening(std::vector<obfuscatecff::function_t>::iterator& func) {

	struct basic_block {
		int block_id;
		std::vector < obfuscatecff::instruction_t>instructions;

		int next_block;
		int dst_block = -1;
	};

	std::vector<basic_block>blocks;
	std::vector<int>block_starts;
	basic_block block;
	int block_iterator = 0;

	// Thu thập các điểm bắt đầu basic-block nội tại hàm
	for (const auto& inst : func->instructions)
	{
		// Chỉ quan tâm tới những nhảy có đích vẫn nằm trong cùng hàm
		if (inst.relative.target_func_id != func->func_id)
			continue;

		const auto& meta = inst.zyinstr.info;

		const bool condJump = is_jmp_conditional(meta);
		const bool shortJmp = (meta.mnemonic == ZYDIS_MNEMONIC_JMP) &&
			meta.raw.imm &&              // bảo đảm tồn tại immediate
			meta.raw.imm->size == 8;     // JMP ngắn 8-bit

		if (condJump || shortJmp)
			block_starts.emplace_back(inst.relative.target_inst_id);
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

	// Xây dựng liên kết giữa các block
	for (auto& block : blocks) {
		// Mặc định block kế tiếp là block có ID + 1
		block.next_block = block.block_id + 1;

		auto& last_inst = block.instructions.back();

		// Xử lý lệnh nhảy có điều kiện
		if (last_inst.isjmpcall && is_jmp_conditional(last_inst.zyinstr.info)) {

			// Tìm block đích của lệnh nhảy
			auto target_block = std::find_if(blocks.begin(), blocks.end(),
				[&](const auto& blk) {
					return blk.instructions.front().inst_id == last_inst.relative.target_inst_id;
				});

			if (target_block != blocks.end()) {
				block.dst_block = target_block->block_id;
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

	// Cấu hình lại các lệnh nhảy có điều kiện JNZ trong bộ điều phối
	auto configure_dispatcher_jumps = [&](auto dispatcher_end_iterator) {
		constexpr int DISPATCHER_BLOCK_SIZE = 4; // Kích thước mỗi khối so sánh trong dispatcher

		for (auto inst_iter = func->instructions.begin(); inst_iter <= dispatcher_end_iterator; ++inst_iter) {

			// Kiểm tra xem có phải lệnh JNZ (Jump if Not Zero) không
			if (inst_iter->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JNZ) {

				// Tính toán vị trí đích nhảy (bỏ qua khối dispatcher hiện tại)
				auto jump_target_iter = inst_iter + DISPATCHER_BLOCK_SIZE;

				// Đảm bảo không vượt quá phạm vi hợp lệ
				if (jump_target_iter <= dispatcher_end_iterator) {
					inst_iter->relative.target_func_id = func->func_id;
					inst_iter->relative.target_inst_id = jump_target_iter->inst_id;
				}
			}
		}
		};

	// Gọi hàm cấu hình với iterator kết thúc dispatcher
	configure_dispatcher_jumps(it);

	// Hàm hỗ trợ tạo chuỗi lệnh chuyển về bộ điều phối
	auto create_dispatcher_transition = [&](int target_block_id) -> std::vector<instruction_t> {
		std::vector<instruction_t> transition_sequence;

		// Lưu trạng thái thanh ghi
		instruction_t preserve_rax{};
		preserve_rax.load(func->func_id, { 0x50 }); // push rax - đẩy rax vào stack

		instruction_t preserve_flags{};
		preserve_flags.load(func->func_id, { 0x66, 0x9C }); // pushf - đẩy flags vào stack

		// Nạp ID của block đích vào thanh ghi EAX
		instruction_t load_state{};
		load_state.load(func->func_id, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // mov eax, imm32
		*(uint32_t*)(&load_state.raw_bytes.data()[1]) = target_block_id;

		// Nhảy trở lại bộ điều phối
		instruction_t return_to_dispatcher{};
		return_to_dispatcher.load(func->func_id, { 0xE9, 0x00, 0x00, 0x00, 0x00 }); // jmp rel32
		return_to_dispatcher.relative.target_func_id = func->func_id;
		return_to_dispatcher.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

		transition_sequence = { preserve_rax, preserve_flags, load_state, return_to_dispatcher };
		return transition_sequence;
		};

	// Cấu hình lại các block để trở về bộ điều phối sau khi thực hiện xong
	for (auto block_iter = blocks.begin(); block_iter != blocks.end() - 1; block_iter++) {

		// Tìm lệnh cuối cùng của block hiện tại
		auto last_inst = std::find_if(func->instructions.begin(), func->instructions.end(),
			[&](const obfuscatecff::instruction_t& inst) {
				return inst.inst_id == (block_iter->instructions.end() - 1)->inst_id;
			});

		// Tìm block kế tiếp trong chuỗi thực thi
		auto next_block_iter = std::find_if(blocks.begin(), blocks.end(),
			[&](const basic_block& blk) { return blk.block_id == block_iter->next_block; });

		if (next_block_iter == blocks.end()) continue;

		// Xử lý các lệnh nhảy có điều kiện với 2 đích
		if (is_jmp_conditional(last_inst->zyinstr.info) && block_iter->dst_block != -1) {

			auto dst_block_iter = std::find_if(blocks.begin(), blocks.end(),
				[&](const basic_block& blk) { return blk.block_id == block_iter->dst_block; });

			// Tạo chuyển tiếp cho đường đi fall-through (không nhảy)
			auto fallthrough_transition = create_dispatcher_transition(next_block_iter->block_id);
			last_inst = func->instructions.insert(last_inst + 1,
				fallthrough_transition.begin(), fallthrough_transition.end());
			last_inst += fallthrough_transition.size() - 1;

			// Tạo chuyển tiếp cho đường đi branch target (có nhảy)
			auto branch_transition = create_dispatcher_transition(dst_block_iter->block_id);
			last_inst = func->instructions.insert(last_inst + 1,
				branch_transition.begin(), branch_transition.end());
			last_inst += branch_transition.size() - 1;

			// Điều chỉnh lệnh nhảy có điều kiện để nhảy đến branch transition
			auto conditional_inst = last_inst - (fallthrough_transition.size() + branch_transition.size());
			conditional_inst->relative.target_inst_id = (last_inst - branch_transition.size() + 1)->inst_id;
		}
		else {
			// Xử lý luồng không điều kiện - chỉ cần 1 chuyển tiếp
			auto transition_sequence = create_dispatcher_transition(next_block_iter->block_id);
			auto insertion_point = func->instructions.insert(last_inst + 1,
				transition_sequence.begin(), transition_sequence.end());
			insertion_point += transition_sequence.size() - 1;
		}
	}
	return true;
}
