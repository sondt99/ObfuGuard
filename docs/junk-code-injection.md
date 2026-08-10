# Junk Code Injection (Trampoline)

## Overview

Junk injection increases instruction noise and scatters real logic into **new PE sections**. Each selected function is:

1. **Copied** (with relative fixups) into a dedicated section  
2. **Hooked** at the original RVA with a **trampoline** (`jmp` to the new VA), padded with neutral junk / multi-byte NOPs  

**Support:** **64-bit PE only** (current builds) · LIEF + Capstone + Keystone · modules: `junkcode/`, `common/`

PoC screenshots: `PoC/junkcode/`.

## Concept

```
.text @ original RVA                    new section ".xxxxN"
─────────────────────                   ────────────────────
 [ junk? ]                               push rbp
 [ E9 rel32  ──────────────► ]           mov rdx, rdx     ; junk
 [ dead junk / NOP pad ]                 mov rbp, rsp
                                         ...
                                         ret
```

Execution always enters at the original RVA, then jumps to the relocated body.

## Pipeline

### 1. Discover functions

```cpp
ObfuGuard::FunctionDiscovery discovery(input_pe_path);
auto all = discovery.get_functions(); // name, pdb_offset, rva, size
```

RVA is computed as:

```
rva = .text.VirtualAddress + pdb_offset
```

### 2. Filter

Shared filter: `ObfuGuard::filter_functions` / blacklist helpers.

| Rule | Auto mode | Manual mode |
|------|-----------|-------------|
| Min size | ≥ 6 bytes | ≥ 5 bytes |
| Blacklist | Yes | Yes |
| Sort | Size descending | User order (after filter) |

### Function blacklist

**File:** `ObfuGuard/blacklist_default.txt` (optional at runtime)

```
# comments and blank lines ignored
mainCRTStartup
memcpy
big:std::filesystem::exists
```

| Form | Meaning |
|------|---------|
| `Name` | Always skip |
| `big:Name` | Skip only if PE size > **350 KB** |

Search order (first hit wins for loading extras): CWD, `ObfuGuard/blacklist_default.txt`, next to target PE. If none load, **built-in** CRT/runtime sets are used.

**Heuristics (always):**

- Name contains `` ` ``  
- Name starts with `_`  
- Prefix `??_` (MSVC specials)  

Mid-name underscores (e.g. `sum_to_n`) are **allowed**.

### 3. Section budget

PE practically allows **96** sections. ObfuGuard keeps a safety margin:

```
max_injectable = PE_MAX_SECTIONS - PE_SECTION_SAFETY_MARGIN
                 - PE_RESERVED_SYSTEM_SECTIONS - current_sections
```

Auto/smart inject takes the top N functions that fit.

### 4. Batch inject (performance)

`TrampolineInjector::inject_multiple_function_trampolines`:

| Phase | Work |
|-------|------|
| **1** | For each function: disassemble/relocate with provisional VA, create section, set content size |
| **2** | **Single** LIEF `Builder::build()` to assign final section VAs |
| **3** | Re-relocate with real VAs, write content, install trampolines |

Capstone and Keystone engines are **reused** for the whole injector lifetime.

### 5. Relocation details

`get_and_relocate_original_function_code(..., known_function_size)`:

- Prefer **PDB size** as the copy bound (continues past early `ret`)  
- If size unknown: scan until first `ret` (legacy fallback)  
- Cap with `MAX_FUNC_SCAN_SIZE` (8192)  
- Fix:
  - `E8`/`E9` rel32 call/jmp  
  - RIP-relative memory operands (64-bit)  

### 6. Trampoline layout

At original VA (length = processed original size, capped by `MAX_TRAMPOLINE_PATCH_SIZE`):

1. Random-length junk region (before)  
2. **`E9` + rel32** to new body  
3. Remaining space: junk / multi-byte NOPs  

Junk patterns are self-canceling (e.g. `add r8, imm; sub r8, imm`, `rol`/`ror` pairs, `push`/`pop` pairs). Pool differs for 32-bit vs 64-bit.

### 7. Save

```cpp
injector.save_pe(output_pe_path); // final LIEF build + write → *.junk.exe
```

## Modes (CLI)

| Sub-mode | Class entry |
|----------|-------------|
| Auto | `JunkCodeManager::run_auto_injection_mode` |
| Manual | `JunkCodeManager::run_manual_injection_mode` |

Both receive a pre-discovered `vector<ObfuGuard::FunctionInfo>` so PDB is not reopened unnecessarily for discovery (filter may still load blacklist files).

## Limits and caveats

| Topic | Notes |
|-------|--------|
| Section count | Hard cap; remaining functions are skipped |
| Exception handling | Moving code can break EH tables for some functions |
| Position-dependent assumptions | Rare absolute address tables may need care |
| Random / time-based programs | `match_check` may differ even when logic is “correct” |
| Logging | Default: one summary line per function (not full hex dumps) |

## Related sources

| Path | Role |
|------|------|
| `ObfuGuard/junkcode/junkcode.*` | Injector + manager |
| `ObfuGuard/common/function_filter.*` | Blacklist + interactive select |
| `ObfuGuard/common/function_discovery.*` | PE+PDB load |
| `ObfuGuard/blacklist_default.txt` | Default names |
| `ObfuGuard/constants.h` | Limits and thresholds |

## See also

- [control-flow-flattening.md](control-flow-flattening.md)  
- [user-guide.md](user-guide.md)  
- [testing.md](testing.md)  
