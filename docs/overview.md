# Overview

## What is ObfuGuard?

**ObfuGuard** is a **post-compilation** binary obfuscation tool for **Windows PE** files. It rewrites machine code in a finished executable so static analysis and decompilation become harder, while the program’s external behavior should stay the same.

It is **not** a source-level obfuscator. Inputs are:

1. A compiled **`.exe`** (PE)  
2. A matching **`.pdb`** (for function names, offsets, and sizes)

Typical use: research, malware analysis education, and legitimate software protection experiments.

## Version context

Documentation describes the **v4.x** codebase:

- Shared `common/` discovery and filtering for both modes  
- Named constants, safer PE/PDB handling  
- Junk injection uses PDB sizes and a **batch** LIEF layout build  
- CFF only flattens **filtered** (non-CRT, large enough) functions  

See [../CHANGELOG.md](../CHANGELOG.md) for exact releases.

## Obfuscation modes

### 1. Control Flow Flattening (CFF)

- **64-bit PE only**  
- Builds basic blocks, shuffles them, routes execution through a **dispatcher** driven by a state in `rax`/`eax`  
- Preserves CPU flags around blocks with `pushf` / `popf`  
- Relocates flattened code into a new section **`.0Cff`**  
- Leaves trampoline-style `jmp` stubs at original function starts  
- Skips functions that look like they use **jump tables**  

### 2. Junk code injection (trampoline)

- **32-bit and 64-bit PE**  
- Moves function bodies into **new PE sections**  
- At the original RVA: optional junk + **`jmp rel32`** to the new body  
- Relocates relative `call`/`jmp` and RIP-relative operands  
- **Auto** mode: all eligible functions (size + blacklist), largest first, section-limited  
- **Manual** mode: interactive multi-select by index  

## Shared pipeline

Both modes share the same discovery path:

```
PE path
  → ObfuGuard::FunctionDiscovery   (pe64 + pdbparser)
  → ObfuGuard::FunctionFilter      (min size, blacklist, optional file)
  → mode-specific engine
  → output PE
```

| Filter rule | Behavior |
|-------------|----------|
| Min size | Below ~5–6 bytes → skip (no room for `jmp rel32`) |
| Leading `_` | Treated as internal/CRT-style → skip |
| Names with `` ` `` | MSVC specials / RTTI → skip |
| Named blacklist | CRT I/O, heap, locale, etc. (see `blacklist_default.txt`) |
| Large binary set | Extra names when PE size > 350 KB |

## Architecture support

| Feature | PE32 (x86) | PE32+ (x64) |
|---------|------------|-------------|
| CFF | No | Yes |
| Junk + trampoline | Yes | Yes |
| Manual PE map (`pe64`) | Used for CFF / discovery (x64) | Yes |
| LIEF PE rewrite | Junk path | Junk path |

## Dependencies

| Library | Used by |
|---------|---------|
| [Zydis](https://github.com/zyantific/zydis) | CFF disassembly |
| [AsmJit](https://github.com/asmjit/asmjit) | CFF-related codegen support |
| [Capstone](https://github.com/capstone-engine/capstone) | Junk disasm / reloc |
| [Keystone](https://github.com/keystone-engine/keystone) | Junk assembly |
| [LIEF](https://github.com/lief-project/LIEF) | Junk PE rewrite |
| DbgHelp (Windows SDK) | PDB enumeration |

## What ObfuGuard is not

- Not a packer or crypter  
- Not a virtualization / VM-protect engine  
- Not a cross-platform ELF/Mach-O tool  
- Not a guarantee against skilled reverse engineers  

Always validate outputs with your own functional tests (see [testing.md](testing.md)).

## Author

Thai Son Dinh (**sondt**) — [github.com/sondt99](https://github.com/sondt99)
