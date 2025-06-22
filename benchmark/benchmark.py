import os
import csv
import math
import angr
import capstone
import logging

# Ẩn log để terminal sạch
logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)
logging.getLogger("pyvex").setLevel(logging.CRITICAL)

OUTPUT_CSV = 'benchmark_comparison_all.csv'

# ---------------- STATIC ANALYSIS ---------------- #

def get_text_section(project):
    return next((s for s in project.loader.main_object.sections if s.name == '.text'), None)

def analyze_code_complexity(code, vaddr):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True
    md.detail = True

    branches = 0
    total_insns = 0
    branch_instrs = {
        capstone.x86.X86_INS_JMP, capstone.x86.X86_INS_JE, capstone.x86.X86_INS_JNE,
        capstone.x86.X86_INS_CALL, capstone.x86.X86_INS_RET,
        capstone.x86.X86_INS_JG, capstone.x86.X86_INS_JGE,
        capstone.x86.X86_INS_JLE, capstone.x86.X86_INS_JL,
        capstone.x86.X86_INS_JNO, capstone.x86.X86_INS_JNP,
        capstone.x86.X86_INS_JNS, capstone.x86.X86_INS_JO,
        capstone.x86.X86_INS_JP, capstone.x86.X86_INS_JS,
    }

    for insn in md.disasm(code, vaddr):
        total_insns += 1
        if insn.id in branch_instrs:
            branches += 1

    cyclomatic = branches + 1
    return branches, cyclomatic, total_insns

def is_valid_function(project, func):
    segment = project.loader.find_segment_containing(func.addr)
    if not segment:
        return False
    if '.text' not in segment.name and 'CODE' not in segment.name:
        return False
    if func.is_simprocedure or func.is_syscall:
        return False
    return True

def get_angr_functions(project):
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    functions = {
        addr: func for addr, func in cfg.kb.functions.items()
        if is_valid_function(project, func)
    }
    return cfg, functions

def get_additional_functions_with_capstone(project, existing_funcs):
    text_section = get_text_section(project)
    if not text_section:
        return {}
    code = project.loader.memory.load(text_section.vaddr, text_section.memsize)
    prologue_patterns = [b'\x55\x48\x89\xe5', b'\x40\x55\x48\x89\xe5']
    potential_funcs = {}
    for offset in range(0, len(code) - 5):
        if code[offset:offset+4] in prologue_patterns or code[offset:offset+5] in prologue_patterns:
            func_addr = text_section.vaddr + offset
            if func_addr not in existing_funcs:
                potential_funcs[func_addr] = f"manual_func_{hex(func_addr)}"
    return potential_funcs

def analyze_binary_full(path):
    project = angr.Project(path, auto_load_libs=False)
    text_sec = get_text_section(project)
    if not text_sec:
        raise Exception("Không tìm thấy section .text")
    code = project.loader.memory.load(text_sec.vaddr, text_sec.memsize)

    branches, cyclomatic, total_insns = analyze_code_complexity(code, text_sec.vaddr)

    cfg, angr_funcs = get_angr_functions(project)
    angr_func_addrs = set(angr_funcs.keys())
    extra_funcs = get_additional_functions_with_capstone(project, angr_func_addrs)
    all_func_addrs = angr_func_addrs.union(extra_funcs.keys())

    all_nodes = list(cfg.graph.nodes)
    all_edges = list(cfg.graph.edges)
    blocks = set()
    for addr in all_func_addrs:
        func = cfg.kb.functions.get(addr)
        if not func:
            continue
        for block in func.blocks:
            blocks.add(block.addr)

    return {
        "path": path,
        "file_size": os.path.getsize(path),
        "branches": branches,
        "instructions": total_insns,
        "branch_density": branches / total_insns if total_insns > 0 else 0.0,
        "cyclomatic_complexity": cyclomatic,
        "functions": len(all_func_addrs),
        "blocks": len(blocks),
        "nodes": len(all_nodes),
        "edges": len(all_edges)
    }

def percent_diff(new, old):
    return 0.0 if old == 0 else ((new - old) / old) * 100

def find_original_binaries(root_dir):
    for subdir, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".exe") and ".cff." not in file and ".junk." not in file:
                yield os.path.join(subdir, file)

def write_header_if_needed(path, fieldnames):
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

def append_result(row):
    with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        writer.writerow(row)

def main():
    metrics = [
        "file_size", "branches", "instructions", "branch_density",
        "cyclomatic_complexity", "functions", "blocks", "nodes", "edges"
    ]
    fieldnames = ["Original", "Variant", "Type"]
    for m in metrics:
        fieldnames.extend([f"{m}_orig", f"{m}_variant", f"{m}_diff(%)"])
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

    for orig in find_original_binaries("../binary_test"):
        try:
            base = analyze_binary_full(orig)
        except Exception as e:
            print(f"[!] Lỗi phân tích gốc {orig}: {e}")
            continue

        base_name, _ = os.path.splitext(orig)
        for suffix in [".cff.exe", ".junk.exe"]:
            vpath = base_name + suffix
            if not os.path.exists(vpath):
                continue
            try:
                variant = analyze_binary_full(vpath)
            except Exception as e:
                print(f"[!] Lỗi phân tích biến thể {vpath}: {e}")
                continue

            row = {
                "Original": os.path.basename(orig),
                "Variant": os.path.basename(vpath),
                "Type": "cff" if ".cff." in vpath else "junk"
            }
            for m in metrics:
                b = base[m]
                v = variant[m]
                row[f"{m}_orig"] = round(b, 4) if isinstance(b, float) else b
                row[f"{m}_variant"] = round(v, 4) if isinstance(v, float) else v
                row[f"{m}_diff(%)"] = round(percent_diff(v, b), 2)
            append_result(row)
            print(f"[✓] Đã ghi {row['Original']} → {row['Variant']}")

    print(f"\n✅ Ghi xong vào: {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
