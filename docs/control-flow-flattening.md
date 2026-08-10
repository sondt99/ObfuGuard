# Control Flow Flattening (CFF)

## Overview

Control Flow Flattening rewrites a function so natural edges between basic blocks disappear. Blocks are **shuffled** and reconnected only through a **central dispatcher** driven by a state variable (`eax` / low part of `rax`). Decompilers then show nested `while`/`if` state checks instead of clean if/else structure.

**Support:** 64-bit PE only · module: `obfuscatecff/` + `cfflattening/` · section name: **`.0Cff`**

## Before / after (concept)

```
Original                         Flattened
────────                         ─────────
  [A]                            [push rax / pushf / mov eax, 0]
 /   \                                  |
[B]  [C]  ──►  direct edges       [Dispatcher: cmp eax, id / jne …]
 \   /                                  |
  [D]                            [block bodies in random order]
                                      each returns via mov eax, next_id; jmp dispatcher
```

PoC screenshots: `PoC/cff/`.

## Pipeline (as implemented)

### 1. Discover and filter

```cpp
ObfuGuard::FunctionDiscovery discovery(pe_path);
auto eligible = ObfuGuard::filter_functions(
    discovery.get_functions(), pe_path, ObfuGuard::MIN_FUNCTION_SIZE);
```

CRT, tiny functions, and blacklisted names are **not** flattened (avoids breaking the runtime).

### 2. Map PE and allocate `.0Cff`

```cpp
pe64 pe(binary_path);
// size ≈ sum(func.size * 4) + overhead, clamped to [DEFAULT_SECTION_SIZE, CFF_SECTION_SIZE]
auto* section = pe.create_section(".0Cff", estimated_bytes,
    IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);
```

### 3. Load instructions (`obfuscatecff::create_functions`)

- Find `.text`, walk each eligible symbol with **Zydis**  
- Build `function_t` / `instruction_t` lists  
- Index `inst_id → index` and runtime address → instruction  

### 4. Analyze (`analyze_functions`)

- Detect **jump tables** (relative mem refs to image base heuristics) → mark `has_jumptables`, skip later  
- Resolve relative jump/call targets to `target_inst_id` / `target_func_id`  
- Record RIP-relative data locations  

### 5. Flatten (`apply_control_flow_flattening`)

Per function (when `cff_flattening` is true and not jump-table):

1. Collect basic-block starts from conditional jumps and short jmps  
2. Split the instruction stream into blocks  
3. Wire `next_block` / `dst_block` for fall-through and taken edges  
4. **Shuffle** blocks with a seeded RNG  
5. Prepend dispatcher prologue:
   - `push rax`  
   - `pushf` (16-bit form used in constants)  
   - `mov eax, 0` (initial state)  
6. Emit per-block compare cascade: `cmp eax, block_id` / `jne` / `popf` / `pop rax` / `jmp body`  
7. At block ends, emit transitions: `push rax` / `pushf` / `mov eax, next` / `jmp dispatcher`  

After inserts, **`rebuild_inst_id_index`** runs so later fixups stay correct.

### 6. Relocate and fix branches

1. Assign `relocated_address` inside `.0Cff`  
2. Expand short jumps that no longer fit (`rel8` → `rel32` / 16-bit Jcc) with recursion depth limit  
3. Patch all relative immediates and write bytes into the PE buffer  
4. In original `.text`, write a **5-byte `jmp`** to the flattened body and pad the rest of the function span  

### 7. Entry-point metadata (optional)

When `run(section, obfuscate_entry_point=true)`:

- Stores a transformed `AddressOfEntryPoint` at the start of the new section (XOR + rotate with PE header fields)  
- Intended for research with a custom entry stub (`custom_main`); the default CLI still passes `true`  

### 8. Save

```cpp
pe.save_to_disk(output_path, new_section, obf.get_added_size());
// → name.cff.exe
```

## Instruction model

```cpp
struct instruction_t {
    int inst_id;
    int func_id;
    bool is_first_instruction;
    std::vector<uint8_t> raw_bytes;
    uint64_t runtime_address;
    uint64_t relocated_address;
    ZydisDisassembledInstruction zyinstr;
    bool has_relative;
    bool isjmpcall;
    // relative { target_inst_id, target_func_id, offset, size }
    uint64_t location_of_data;
};
```

## Safety and limits

| Topic | Behavior |
|-------|----------|
| Jump tables | Function skipped |
| Stack / exceptions | Flattening changes layout; SEH-heavy code may misbehave |
| Self-modifying / integrity checks | May fail after rewrite |
| Section growth | Validated against max image size and section count |
| Opcode constants | Named bytes in `cfflattening` (`x86_opcodes::*`) |

## Related sources

| Path | Role |
|------|------|
| `ObfuGuard/main.cpp` | CLI CFF mode |
| `ObfuGuard/obfuscatecff/*` | Engine orchestration |
| `ObfuGuard/cfflattening/*` | Flatten algorithm |
| `ObfuGuard/constants.h` | `CFF_SECTION_*`, alignments |

## See also

- [junk-code-injection.md](junk-code-injection.md) — second mode  
- [architecture.md](architecture.md) — module graph  
- [user-guide.md](user-guide.md) — how to run CFF  
