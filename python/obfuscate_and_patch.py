import json
import random
import re
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
import lief
import os

# -------------------- Step 0: Parse Metadata and Instructions --------------------

def parse_metadata_and_instructions(path="../output/data.txt"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    
    with open(path, "r") as f:
        content = f.read()

    # Extract .text VA and EntryPoint to infer ImageBase
    text_match = re.search(r"Disassembling .text section at: 0x([0-9a-fA-F]+)", content)
    entry_match = re.search(r"Entry Point: 0x([0-9a-fA-F]+)", content)
    json_match = re.search(r"(\[\s*{[\s\S]+})\s*\]", content)

    if not (text_match and entry_match and json_match):
        raise RuntimeError("Failed to parse metadata or instructions from data.txt")

    text_va = int(text_match.group(1), 16)
    entry_va = int(entry_match.group(1), 16)
    image_base = entry_va & 0xFFFFFFFFF0000000  # Align to page base
    instructions = json.loads(f"[{json_match.group(1)}]")

    return image_base, text_va, instructions

# -------------------- Step 1: Insert Junk Code --------------------

JUNK_INSTRUCTIONS = [
    "nop",
    "xor eax, eax",
    "add eax, 0",
    "sub eax, 0",
    "mov ebx, ebx"
]

def insert_junk(instructions):
    obf = []
    for insn in instructions:
        obf.append(insn)
        if random.random() < 0.5:
            junk = {
                "offset": "JUNK",
                "mnemonic": random.choice(JUNK_INSTRUCTIONS),
                "operands": ""
            }
            obf.append(junk)
    return obf

# -------------------- Step 2: Instruction Substitution --------------------

def substitute_instruction(insn):
    if insn["mnemonic"] == "mov" and insn["operands"] == "eax, 0":
        return [{"offset": insn["offset"], "mnemonic": "xor", "operands": "eax, eax"}]
    return [insn]

def substitute_all(instructions):
    result = []
    for insn in instructions:
        result.extend(substitute_instruction(insn))
    return result

# -------------------- Step 3: Assemble Code --------------------

def assemble_asm(instruction_list):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    asm_lines = [
        f"{insn['mnemonic']} {insn['operands']}".strip()
        for insn in instruction_list if insn["offset"] != "JUNK"
    ]
    code = "\n".join(asm_lines)

    try:
        encoding, _ = ks.asm(code)
        return bytes(encoding)
    except Exception as e:
        print("[!] Assembly failed:", e)
        return b""

# -------------------- Step 4: Patch PE Using LIEF --------------------

def patch_pe(original_path, patched_code, start_rva, output_path="../output/patched_output.exe"):
    pe = lief.parse(original_path)
    section = None
    for s in pe.sections:
        if s.virtual_address <= start_rva < (s.virtual_address + s.size):
            section = s
            break
    if not section:
        raise RuntimeError("Cannot find section to patch!")

    offset = start_rva - section.virtual_address
    print(f"[*] Patching at offset 0x{offset:x} in section {section.name}")

    # Replace the content in-place
    section.content[offset:offset + len(patched_code)] = list(patched_code)

    # Save to output file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pe.write(output_path)
    print(f"[*] Patched binary saved to {output_path}")

# -------------------- Main Pipeline --------------------

def main():
    print("[*] Parsing metadata and instructions from ../output/data.txt...")
    try:
        image_base, text_va, instructions = parse_metadata_and_instructions("../output/data.txt")
    except Exception as e:
        print(f"[!] Error: {e}")
        return

    print(f"[*] Image Base:        0x{image_base:x}")
    print(f"[*] .text VA:          0x{text_va:x}")
    print(f"[*] First Instruction: {instructions[0]['offset']}")

    start_va = int(instructions[0]["offset"], 16)
    start_rva = start_va - image_base
    print(f"[*] Calculated RVA:    0x{start_rva:x}")

    print("[*] Inserting junk code...")
    junked = insert_junk(instructions)

    print("[*] Substituting instructions...")
    substituted = substitute_all(junked)

    print("[*] Assembling new code...")
    assembled_code = assemble_asm(substituted)
    if not assembled_code:
        print("[!] Assembly failed. Aborting.")
        return

    original_path = input("Enter path to original PE file (e.g., ../output/bin.exe): ").strip()
    if not os.path.exists(original_path):
        print("[!] File does not exist.")
        return

    print("[*] Patching PE...")
    try:
        patch_pe(original_path, assembled_code, start_rva)
    except Exception as e:
        print(f"[!] Patch failed: {e}")

if __name__ == "__main__":
    main()
