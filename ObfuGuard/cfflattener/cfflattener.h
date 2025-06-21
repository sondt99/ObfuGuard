#pragma once

#include "../obfuscator/obfuscator.h"
#include <vector>


class obfuscator;

namespace CFF {

    struct BasicBlock {
        int block_id;
        std::vector<obfuscator::instruction_t> instructions;
        int next_block;
        int dst_block = -1;
    };

    bool is_jmp_conditional(ZydisDecodedInstruction instr);
    bool apply_control_flow_flattening(std::vector<obfuscator::function_t>::iterator& func_iter);
}


namespace obfuscator_extensions {
    bool apply_control_flow_flattening(std::vector<obfuscator::function_t>::iterator& func);
}