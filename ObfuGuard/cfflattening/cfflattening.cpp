#include "cfflattening.h"
#include <algorithm>
#include <cstdint>
#include <random>
#include <vector>

namespace x86_opcodes {
    const std::vector<uint8_t> PUSH_RAX = { 0x50 };
    const std::vector<uint8_t> POP_RAX = { 0x58 };
    // Full RFLAGS push/pop for long mode (not 16-bit operand-size forms)
    const std::vector<uint8_t> PUSHF = { 0x9C };
    const std::vector<uint8_t> POPF = { 0x9D };
    const std::vector<uint8_t> MOV_EAX_IMM32 = { 0xB8, 0x00, 0x00, 0x00, 0x00 };
    const std::vector<uint8_t> CMP_EAX_IMM32 = { 0x3D, 0x00, 0x00, 0x00, 0x00 };
    const std::vector<uint8_t> JNE_REL8 = { 0x75, 0x08 };
    const std::vector<uint8_t> JMP_REL32 = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
}

//detect conditional jump instructions
bool is_jmp_conditional(const ZydisDecodedInstruction& instr) {
	return instr.meta.category == ZYDIS_CATEGORY_COND_BR;
}

static bool is_unconditional_jmp(const ZydisDecodedInstruction& instr) {
	return instr.mnemonic == ZYDIS_MNEMONIC_JMP;
}

// apply control flow flattening algorithm
bool obfuscatecff::apply_control_flow_flattening(std::vector<obfuscatecff::function_t>::iterator& func) {

	if (func->instructions.empty())
		return false;

	struct basic_block {
		int block_id;
		std::vector<obfuscatecff::instruction_t> instructions;
		int next_block;
		int dst_block;

		basic_block()
			: block_id(-1)
			, next_block(-1)
			, dst_block(-1)
		{
		}
	};

	std::vector<basic_block> blocks;
	std::vector<int> block_starts;
	basic_block block;
	int block_iterator = 0;

	// Collect basic block start points: any intra-function branch target
	for (const auto& inst : func->instructions)
	{
		if (inst.relative.target_func_id != func->func_id)
			continue;
		if (!inst.isjmpcall)
			continue;
		if (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_CALL)
			continue;

		// Conditional or unconditional JMP with a resolved target
		if (inst.relative.target_inst_id != -1)
			block_starts.emplace_back(inst.relative.target_inst_id);
	}

	// detect blocks within the function
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

		if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_RET ||
			(instruction->isjmpcall && instruction->zyinstr.info.mnemonic != ZYDIS_MNEMONIC_CALL))
		{
			block.block_id = block_iterator++;
			blocks.push_back(block);
			block.instructions.clear();
		}
	}

	if (blocks.empty())
		return false;

	// Build connections between blocks
	const int max_block_id = block_iterator - 1;
	for (auto& blk : blocks) {
		// Default fall-through to next sequential block id (if any)
		blk.next_block = (blk.block_id < max_block_id) ? (blk.block_id + 1) : -1;

		if (blk.instructions.empty())
			continue;

		auto& last_inst = blk.instructions.back();

		// Conditional or unconditional JMP with resolved target → dst_block
		if (last_inst.isjmpcall &&
			last_inst.zyinstr.info.mnemonic != ZYDIS_MNEMONIC_CALL &&
			last_inst.relative.target_inst_id != -1) {

			auto target_block = std::find_if(blocks.begin(), blocks.end(),
				[&](const auto& b) {
					return !b.instructions.empty() &&
						b.instructions.front().inst_id == last_inst.relative.target_inst_id;
				});

			if (target_block != blocks.end()) {
				blk.dst_block = target_block->block_id;
			}

			// Unconditional JMP has no fall-through
			if (is_unconditional_jmp(last_inst.zyinstr.info)) {
				blk.next_block = -1;
			}
		}

		// RET has no fall-through / dispatcher successor
		if (last_inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_RET) {
			blk.next_block = -1;
			blk.dst_block = -1;
		}
	}

	int first_inst_id = func->instructions.begin()->inst_id;
	int new_id = this->instruction_id++;
	func->instructions.begin()->inst_id = new_id;
	func->instructions.begin()->is_first_instruction = false;

	// Shuffle only the dispatcher compare order — not which blocks get transitions
	auto rng = std::default_random_engine{ std::random_device{}() };
	std::shuffle(blocks.begin(), blocks.end(), rng);

	// Dispatcher prologue
	instruction_t push_rax{}; push_rax.load(func->func_id, x86_opcodes::PUSH_RAX);
	push_rax.inst_id = first_inst_id;
	push_rax.is_first_instruction = true;
	auto it = func->instructions.insert(func->instructions.begin(), push_rax);
	instruction_t push_f{}; push_f.load(func->func_id, x86_opcodes::PUSHF);
	it = func->instructions.insert(it + 1, push_f);
	instruction_t mov_eax_0{}; mov_eax_0.load(func->func_id, x86_opcodes::MOV_EAX_IMM32);
	it = func->instructions.insert(it + 1, mov_eax_0);

	for (auto current_block = blocks.begin(); current_block != blocks.end(); current_block++) {

		instruction_t cmp_eax{}; cmp_eax.load(func->func_id, x86_opcodes::CMP_EAX_IMM32);
		*reinterpret_cast<uint32_t*>(&cmp_eax.raw_bytes.data()[1]) = static_cast<uint32_t>(current_block->block_id);

		instruction_t jne{}; jne.load(func->func_id, x86_opcodes::JNE_REL8);

		instruction_t pop_f{}; pop_f.load(func->func_id, x86_opcodes::POPF);

		instruction_t pop_rax{}; pop_rax.load(func->func_id, x86_opcodes::POP_RAX);

		instruction_t jmp{}; jmp.load(func->func_id, x86_opcodes::JMP_REL32);
		jmp.relative.target_inst_id = current_block->block_id == 0
			? new_id
			: current_block->instructions.begin()->inst_id;
		jmp.relative.target_func_id = func->func_id;

		it = func->instructions.insert(it + 1, { cmp_eax , jne, pop_f, pop_rax, jmp });
		it = it + 4;
	}

	auto configure_dispatcher_jumps = [&](auto dispatcher_end_iterator) {
		constexpr int DISPATCHER_BLOCK_SIZE = 4;

		for (auto inst_iter = func->instructions.begin(); inst_iter <= dispatcher_end_iterator; ++inst_iter) {
			if (inst_iter->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JNZ) {
				auto jump_target_iter = inst_iter + DISPATCHER_BLOCK_SIZE;
				if (jump_target_iter <= dispatcher_end_iterator) {
					inst_iter->relative.target_func_id = func->func_id;
					inst_iter->relative.target_inst_id = jump_target_iter->inst_id;
				}
			}
		}
	};

	configure_dispatcher_jumps(it);

	auto create_dispatcher_transition = [&](int target_block_id) -> std::vector<instruction_t> {
		std::vector<instruction_t> transition_sequence;

		instruction_t preserve_rax{};
		preserve_rax.load(func->func_id, x86_opcodes::PUSH_RAX);

		instruction_t preserve_flags{};
		preserve_flags.load(func->func_id, x86_opcodes::PUSHF);

		instruction_t load_state{};
		load_state.load(func->func_id, x86_opcodes::MOV_EAX_IMM32);
		*reinterpret_cast<uint32_t*>(&load_state.raw_bytes.data()[1]) = static_cast<uint32_t>(target_block_id);

		instruction_t return_to_dispatcher{};
		return_to_dispatcher.load(func->func_id, x86_opcodes::JMP_REL32);
		return_to_dispatcher.relative.target_func_id = func->func_id;
		return_to_dispatcher.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

		transition_sequence = { preserve_rax, preserve_flags, load_state, return_to_dispatcher };
		return transition_sequence;
	};

	// Reconfigure EVERY block that needs a dispatcher successor (not "all but last shuffled")
	for (auto block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {

		if (block_iter->instructions.empty())
			continue;

		// RET terminal: leave as-is
		const auto& last_orig = block_iter->instructions.back();
		if (last_orig.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_RET)
			continue;

		// No successors → nothing to rewrite
		if (block_iter->next_block < 0 && block_iter->dst_block < 0)
			continue;

		auto last_inst = std::find_if(func->instructions.begin(), func->instructions.end(),
			[&](const obfuscatecff::instruction_t& inst) {
				return inst.inst_id == last_orig.inst_id;
			});

		if (last_inst == func->instructions.end())
			continue;

		// Conditional: two targets (fall-through + taken)
		if (is_jmp_conditional(last_inst->zyinstr.info) && block_iter->dst_block != -1) {

			auto next_block_iter = std::find_if(blocks.begin(), blocks.end(),
				[&](const basic_block& blk) { return blk.block_id == block_iter->next_block; });
			auto dst_block_iter = std::find_if(blocks.begin(), blocks.end(),
				[&](const basic_block& blk) { return blk.block_id == block_iter->dst_block; });

			if (dst_block_iter == blocks.end())
				continue;

			// Fall-through path (if next_block exists)
			if (next_block_iter != blocks.end() && block_iter->next_block >= 0) {
				auto fallthrough_transition = create_dispatcher_transition(next_block_iter->block_id);
				last_inst = func->instructions.insert(last_inst + 1,
					fallthrough_transition.begin(), fallthrough_transition.end());
				last_inst += fallthrough_transition.size() - 1;

				auto branch_transition = create_dispatcher_transition(dst_block_iter->block_id);
				last_inst = func->instructions.insert(last_inst + 1,
					branch_transition.begin(), branch_transition.end());
				last_inst += branch_transition.size() - 1;

				auto conditional_inst = last_inst - (fallthrough_transition.size() + branch_transition.size());
				conditional_inst->relative.target_inst_id =
					(last_inst - branch_transition.size() + 1)->inst_id;
			}
			else {
				// No fall-through: only branch transition; rewrite jcc to always go via dispatcher
				auto branch_transition = create_dispatcher_transition(dst_block_iter->block_id);
				last_inst = func->instructions.insert(last_inst + 1,
					branch_transition.begin(), branch_transition.end());
				last_inst += branch_transition.size() - 1;
				auto conditional_inst = last_inst - branch_transition.size();
				conditional_inst->relative.target_inst_id =
					(last_inst - branch_transition.size() + 1)->inst_id;
			}
		}
		// Unconditional JMP: single target via dispatcher
		else if (is_unconditional_jmp(last_inst->zyinstr.info) && block_iter->dst_block != -1) {
			auto dst_block_iter = std::find_if(blocks.begin(), blocks.end(),
				[&](const basic_block& blk) { return blk.block_id == block_iter->dst_block; });
			if (dst_block_iter == blocks.end())
				continue;

			auto transition_sequence = create_dispatcher_transition(dst_block_iter->block_id);
			// Replace JMP with transition: insert after, then we leave original JMP pointing to transition start
			last_inst = func->instructions.insert(last_inst + 1,
				transition_sequence.begin(), transition_sequence.end());
			// Point original JMP at first transition insn
			auto jmp_inst = last_inst - 1;
			// last_inst now points to first inserted; original is just before
			// After insert(last_inst+1), last_inst was old last; insert returns iterator to first new
			// Re-find original jmp
			auto orig_jmp = std::find_if(func->instructions.begin(), func->instructions.end(),
				[&](const obfuscatecff::instruction_t& inst) {
					return inst.inst_id == last_orig.inst_id;
				});
			if (orig_jmp != func->instructions.end()) {
				auto first_trans = orig_jmp + 1;
				if (first_trans != func->instructions.end()) {
					orig_jmp->relative.target_inst_id = first_trans->inst_id;
					orig_jmp->relative.target_func_id = func->func_id;
				}
			}
		}
		// Fall-through only
		else if (block_iter->next_block >= 0) {
			auto next_block_iter = std::find_if(blocks.begin(), blocks.end(),
				[&](const basic_block& blk) { return blk.block_id == block_iter->next_block; });
			if (next_block_iter == blocks.end())
				continue;

			auto transition_sequence = create_dispatcher_transition(next_block_iter->block_id);
			func->instructions.insert(last_inst + 1,
				transition_sequence.begin(), transition_sequence.end());
		}
	}
	return true;
}
