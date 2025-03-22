#include "capstone/capstone.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <sstream>

struct SectionInfo {
    uint32_t VirtualAddress;
    uint32_t Size;
    uint32_t PointerToRawData;
};

bool get_text_section_info(const std::vector<uint8_t>& code, SectionInfo& textSection) {
    if (code.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(code.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(code.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_SECTION_HEADER* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        code.data() + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    WORD numSections = nt->FileHeader.NumberOfSections;
    for (int i = 0; i < numSections; i++) {
        const IMAGE_SECTION_HEADER& s = sections[i];
        if (strncmp(reinterpret_cast<const char*>(s.Name), ".text", 5) == 0) {
            textSection.VirtualAddress = s.VirtualAddress;
            textSection.Size = s.SizeOfRawData;
            textSection.PointerToRawData = s.PointerToRawData;
            return true;
        }
    }
    return false;
}

uintptr_t get_image_base(const std::vector<uint8_t>& code) {
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(code.data());
    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(code.data() + dos->e_lfanew);
    return nt->OptionalHeader.ImageBase;
}

uintptr_t get_entry_point_rva(const std::vector<uint8_t>& code) {
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(code.data());
    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(code.data() + dos->e_lfanew);
    return nt->OptionalHeader.AddressOfEntryPoint;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <exe_file>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file." << std::endl;
        return 1;
    }

    std::vector<uint8_t> code((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());

    uintptr_t image_base = get_image_base(code);
    uintptr_t entry_rva = get_entry_point_rva(code);
    uintptr_t entry_addr = image_base + entry_rva;

    SectionInfo textSection;
    if (!get_text_section_info(code, textSection)) {
        std::cerr << "Cannot find .text section." << std::endl;
        return 1;
    }

    const uint8_t* text_code = code.data() + textSection.PointerToRawData;
    size_t text_size = textSection.Size;
    uintptr_t text_va = image_base + textSection.VirtualAddress;

    std::cout << "Disassembling .text section at: 0x" << std::hex << text_va << "\n";
    std::cout << "Entry Point: 0x" << std::hex << entry_addr << "\n";

    csh handle;
    cs_insn* insn;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Capstone init failed." << std::endl;
        return -1;
    }

    size_t count = cs_disasm(handle, text_code, text_size, text_va, 0, &insn);

    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < count; i++) {
        out << "  {\n"
            << "    \"offset\": \"" << std::hex << insn[i].address << "\",\n"
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
