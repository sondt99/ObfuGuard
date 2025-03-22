from keystone import *
import random

JUNK_INSTR = [
    "nop",
    "xor eax, eax",
    "mov ebx, ebx",
    "add ecx, 0"
]

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def assemble(instr):
    encoding, _ = ks.asm(instr)
    return bytes(encoding)

def insert_junk_code(code: bytearray, disasm: list) -> bytearray:
    patched = bytearray()
    i = 0
    for ins in disasm:
        offset = ins["offset"] - disasm[0]["offset"]
        if offset > i:
            patched.extend(code[i:offset])
            i = offset

        instr_len = 1  # fallback length
        try:
            instr_len = len(assemble(f"{ins['mnemonic']} {ins['operands']}"))
        except:
            pass

        # Copy original instruction
        patched.extend(code[offset:offset+instr_len])
        i += instr_len

        # Inject random junk instruction after every 5th instruction
        if random.random() < 0.2:
            junk = assemble(random.choice(JUNK_INSTR))
            patched.extend(junk)

    patched.extend(code[i:])
    return patched
