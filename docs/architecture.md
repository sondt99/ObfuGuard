# Architecture

## Project Structure

```
ObfuGuard/
├── ObfuGuard.sln                    # Visual Studio solution
├── ObfuGuard/                       # Source code
│   ├── main.cpp                     # Entry point and CLI
│   ├── pe/                          # PE file parser module
│   │   ├── pe.h
│   │   └── pe.cpp
│   ├── pdbparser/                   # PDB debug symbol parser
│   │   ├── pdbparser.h
│   │   └── pdbparser.cpp
│   ├── obfuscatecff/                # CFF obfuscation engine
│   │   ├── obfuscatecff.h
│   │   └── obfuscatecff.cpp
│   ├── cfflattening/                # CFF algorithm implementation
│   │   ├── cfflattening.h
│   │   └── cfflattening.cpp
│   ├── junkcode/                    # Junk code injection engine
│   │   ├── junkcode.h
│   │   └── junkcode.cpp
│   └── func2rva/                    # Function-to-RVA resolver
│       ├── func2rva.h
│       └── func2rva.cpp
├── benchmark/                       # Benchmark framework
│   ├── benchmark.py                 # Static analysis benchmark
│   ├── benchmark_runtime.py         # Runtime benchmark
│   ├── benchmark_time_pro.py        # RE time benchmark
│   └── boxplot_*.py                 # Visualization scripts
├── binary_test/                     # Test binaries (60 programs)
│   ├── auto_test.py                 # Automated test runner
│   └── match_check.py              # Output comparison
├── binary_exeption/                 # Edge-case test binaries
├── PoC/                             # Proof-of-concept screenshots
└── x64/Release/                     # Pre-built binaries
```

## Module Dependency Graph

```
                    main.cpp
                   /    |    \
                  /     |     \
                 v      v      v
            pe64    pdbparser   func2rva
              |       |  |        |  |
              |       |  |        v  v
              |       v  |      pe64 + pdbparser
              |      pe64|
              v          v
        [Windows SDK]  [DbgHelp]

         obfuscatecff
          /    |    \
         v     v     v
       pe64  Zydis  AsmJit
         |
         v
    cfflattening
         |
         v
    obfuscatecff (uses instruction_t/function_t)

         TrampolineInjector
          /     |      \
         v      v       v
       LIEF  Capstone  Keystone

         JunkCodeManager
          /          \
         v            v
  TrampolineInjector  func2rva
```

## Module Descriptions

### main.cpp - Entry Point

Responsibilities:
- Display CLI banner and interactive menu
- Validate PE file input paths
- Detect PE architecture (32/64-bit) via header inspection
- Route to CFF or junk code mode
- Build output file paths
- Handle errors and report timing

### pe/pe.h, pe.cpp - PE Parser

Class: `pe64`

Responsibilities:
- Load PE binary into memory buffers (relocated and non-relocated copies)
- Map PE sections to virtual addresses
- Create new PE sections with specified characteristics
- Save modified PE to disk with correct section sizes
- Provide access to NT headers and section headers

### pdbparser/pdbparser.h, pdbparser.cpp - PDB Parser

Class: `pdbparser`

Responsibilities:
- Locate PDB file from PE's debug directory or by name convention
- Load PDB using Windows DbgHelp API (`SymInitialize`, `SymEnumSymbols`)
- Extract function symbols (name, offset, size)
- Return structured function list for downstream processing

### obfuscatecff/obfuscatecff.h, obfuscatecff.cpp - CFF Engine

Class: `obfuscatecff`

Responsibilities:
- Disassemble all functions using Zydis into `instruction_t` structs
- Track instruction-to-address mappings for reference resolution
- Analyze functions for relative references and jump tables
- Coordinate the CFF pipeline (analyze, flatten, relocate, compile)
- Generate machine code for dispatchers using AsmJit
- Relocate obfuscated code to new PE sections
- Fix relative jumps and RIP-relative addressing
- Obfuscate entry points with XOR/rotation encoding

### cfflattening/cfflattening.h, cfflattening.cpp - CFF Algorithm

Namespace: `CFF`, `obfuscatecff_extensions`

Responsibilities:
- Identify basic blocks from conditional jump instructions
- Build block connection graph (next_block, dst_block)
- Shuffle blocks randomly
- Construct dispatcher with `rax` state variable
- Generate `cmp/jne` chains for block dispatch
- Insert `pushf`/`popf` for CPU flag preservation

### junkcode/junkcode.h, junkcode.cpp - Junk Code Engine

Classes: `TrampolineInjector`, `JunkCodeManager`

**TrampolineInjector** responsibilities:
- Load PE via LIEF
- Disassemble functions with Capstone for relocation
- Fix CALL/JMP rel32 and RIP-relative displacements
- Create new PE sections for relocated functions
- Build trampoline jumps at original locations
- Generate random junk instructions
- Assemble junk instructions with Keystone
- Fill remaining space with multi-byte NOPs
- Manage PE section count limits
- Save modified PE via LIEF

**JunkCodeManager** responsibilities:
- Orchestrate auto and manual injection modes
- Apply function blacklist filtering
- Filter functions by minimum size
- Sort functions by size for priority injection
- Apply binary-size-aware additional filtering

### func2rva/func2rva.h, func2rva.cpp - RVA Resolver

Namespace: `FuncToRVA`, Class: `RVAResolver`

Responsibilities:
- Combine PE parsing and PDB parsing
- Calculate actual RVAs: `text_section_rva + pdb_offset`
- Provide interactive CLI for function selection (single and multiple)
- Return structured function info (name, RVA, offset, size)

## Data Flow

### CFF Mode

```
PE file path
    │
    ├──► pe64(path) ──► binary buffer + section map
    │                         │
    ├──► pdbparser(pe) ──► vector<sym_func>
    │                         │
    ├──► pe.create_section(".0Cff") ──► new section header
    │                                        │
    ├──► obfuscatecff(pe)                    │
    │        │                               │
    │        ├── create_functions(sym_funcs)  │
    │        │   └── Zydis disassembly ──► vector<function_t>
    │        │                                    │
    │        └── run(new_section, true)            │
    │             ├── analyze_functions()          │
    │             ├── remove_jumptables()          │
    │             ├── apply_control_flow_flattening() per function
    │             ├── relocate(new_section)        │
    │             ├── convert_relative_jmps()      │
    │             ├── apply_relocations()          │
    │             └── compile(new_section)         │
    │                                              │
    └──► pe.save_to_disk(output, new_section, size)
              │
              ▼
         .cff.exe output
```

### Junk Code Mode

```
PE file path
    │
    ├──► DetectPEArchitecture() ──► is_64_bit
    │
    ├──► [Auto Mode]
    │       ├── RVAResolver(path).initialize()
    │       ├── get_functions_info() ──► vector<FunctionInfo>
    │       ├── filter: blacklist, size, sort
    │       └── inject_multiple_function_trampolines_with_limit()
    │
    ├──► [Manual Mode]
    │       ├── select_multiple_functions_rva_interactive()
    │       └── inject_trampoline_to_multiple_functions()
    │
    └──► Per function:
              ├── create_new_section()
              ├── get_and_relocate_original_function_code()
              │       └── Capstone disassembly + address fixup
              ├── create_trampoline()
              │       ├── Keystone assemble junk
              │       ├── JMP rel32 to new section
              │       └── NOP padding
              └── save_pe(output_path)
                    │
                    ▼
               .junk.exe output
```

## External Library Usage

| Library | Where Used | Purpose |
|---------|-----------|---------|
| Zydis | `obfuscatecff.cpp` | Decode x86/x64 instructions for CFF analysis |
| AsmJit | `obfuscatecff.cpp` | JIT-compile dispatcher and new instruction sequences |
| Capstone | `junkcode.cpp` | Disassemble functions for relocation with address fixup |
| Keystone | `junkcode.cpp` | Assemble junk instruction strings into machine code |
| LIEF | `junkcode.cpp` | Parse, modify, and rebuild PE files |
| DbgHelp | `pdbparser.cpp` | Load and enumerate PDB symbol information |
