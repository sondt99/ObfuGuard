# Overview

## What is ObfuGuard?

ObfuGuard is a **post-compilation binary obfuscation tool** for Windows PE (Portable Executable) files. It transforms compiled `.exe` binaries at the machine code level to make reverse engineering significantly more difficult, while preserving the original program's behavior.

Unlike source-level obfuscators, ObfuGuard operates directly on compiled binaries and their PDB debug symbols. This means it can be applied to any Windows executable regardless of the source language used to compile it.

## Key Features

### Two Obfuscation Modes

1. **Control Flow Flattening (CFF)** - Restructures the control flow graph of every function by replacing direct block-to-block jumps with a dispatcher-based state machine. This destroys the natural program structure visible to decompilers like IDA Pro.

2. **Junk Code Injection with Trampoline** - Relocates function bodies to new PE sections and fills the original locations with trampoline jumps surrounded by semantically neutral junk instructions. This increases binary complexity and confuses static analysis tools.

### Additional Capabilities

- **Automatic PE architecture detection** (32-bit and 64-bit)
- **PDB symbol parsing** for automatic function discovery
- **Entry point obfuscation** using XOR and rotation encoding (CFF mode)
- **Jump table detection and avoidance** to prevent breaking switch statements
- **Intelligent function blacklisting** to protect CRT and system functions
- **Self-obfuscation** - ObfuGuard can obfuscate its own binary
- **Comprehensive benchmark suite** for measuring obfuscation effectiveness

## Supported Platforms

| Feature | 32-bit PE | 64-bit PE |
|---------|-----------|-----------|
| Control Flow Flattening | No | Yes |
| Junk Code Injection | Yes | Yes |

## How It Works (High Level)

```
Input PE (.exe) + PDB (.pdb)
        |
        v
  +-----------+
  | PE Parser |---> Load binary into memory, map sections
  +-----------+
        |
        v
  +------------+
  | PDB Parser |---> Extract function names, offsets, sizes
  +------------+
        |
        v
  +---------------------+
  | Obfuscation Engine  |---> Apply CFF or Junk Code transformations
  | (CFF / Junk Code)   |     Create new PE sections for obfuscated code
  +---------------------+
        |
        v
  Output PE (.cff.exe / .junk.exe)
```

## Dependencies

| Library | Purpose |
|---------|---------|
| [Zydis](https://github.com/zyantific/zydis) | x86/x64 instruction decoder (CFF analysis) |
| [AsmJit](https://github.com/asmjit/asmjit) | JIT assembler (CFF code generation) |
| [Capstone](https://github.com/capstone-engine/capstone) | x86 disassembly engine (junk code relocation) |
| [Keystone](https://github.com/keystone-engine/keystone) | x86 assembler engine (junk instruction assembly) |
| [LIEF](https://github.com/lief-project/LIEF) | PE file manipulation (junk code injection) |
| DbgHelp | Windows SDK debug help library (PDB parsing) |

## Author

Thai Son Dinh (sondt) - [GitHub](https://github.com/sondt99)
