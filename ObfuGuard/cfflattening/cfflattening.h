#pragma once

#include "../obfuscatecff/obfuscatecff.h"
#include <vector>


class obfuscatecff;

namespace CFF {

    struct BasicBlock {
        int block_id;
        std::vector<obfuscatecff::instruction_t> instructions;
        int next_block;
        int dst_block = -1;
    };

    bool is_jmp_conditional(ZydisDecodedInstruction instr);
    bool apply_control_flow_flattening(std::vector<obfuscatecff::function_t>::iterator& func_iter);
}


namespace obfuscatecff_extensions {
    bool apply_control_flow_flattening(std::vector<obfuscatecff::function_t>::iterator& func);
}