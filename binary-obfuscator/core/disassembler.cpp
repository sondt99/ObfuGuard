#include "capstone/capstone.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: ./disassembler <binary_code_file>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file." << std::endl;
        return 1;
    }

    std::vector<uint8_t> code((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());

    csh handle;
    cs_insn *insn;
    size_t count = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    count = cs_disasm(handle, code.data(), code.size(), 0x400000, 0, &insn);

    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < count; i++) {
        out << "  {\n"
            << "    \"offset\": " << insn[i].address << ",\n"
            << "    \"mnemonic\": \"" << insn[i].mnemonic << "\",\n"
            << "    \"operands\": \"" << insn[i].op_str << "\"\n"
            << "  }";
        if (i < count - 1) out << ",";
        out << "\n";
    }
    out << "]\n";

    cs_free(insn, count);
    cs_close(&handle);

    std::cout << out.str();
    return 0;
}
