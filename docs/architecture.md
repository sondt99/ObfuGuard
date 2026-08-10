# Architecture

## Repository layout

```
ObfuGuard/
├── ObfuGuard.sln
├── ObfuGuard/                      # Tool (C++20)
│   ├── main.cpp                    # CLI, PE arch detect, mode routing
│   ├── constants.h                 # Named limits and section names
│   ├── blacklist_default.txt       # Optional blacklist seed file
│   ├── common/
│   │   ├── function_info.h         # FunctionInfo { name, pdb_offset, rva, size }
│   │   ├── function_discovery.*    # pe64 + pdbparser → FunctionInfo list
│   │   └── function_filter.*       # blacklist, size filter, interactive select
│   ├── pe/                         # pe64: VA-mapped PE, create_section, save
│   ├── pdbparser/                  # DbgHelp Sym* API
│   ├── obfuscatecff/               # CFF engine
│   ├── cfflattening/               # Flatten algorithm + x86_opcodes
│   ├── junkcode/                   # TrampolineInjector, JunkCodeManager
│   └── func2rva/                   # RVAResolver (alias FunctionInfo)
├── binary_test/                    # ~60 sample programs + scripts
├── benchmark/                      # Evaluation Python scripts
├── docs/                           # This documentation
├── PoC/                            # Screenshots
├── binary_exeption/                # Edge cases (e.g. no PDB)
└── x64/Release/                    # Built tool + DLLs (local)
```

## Symmetric mode pipeline

```
                    ┌──────────────────────┐
                    │      main.cpp        │
                    │  menu + path checks  │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │ FunctionDiscovery    │
                    │  pe64 + pdbparser    │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │ FunctionFilter       │
                    │  size + blacklist    │
                    └──────────┬───────────┘
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
        ┌─────────────────┐        ┌─────────────────────┐
        │  pe64 + CFF     │        │ LIEF + Capstone +   │
        │  obfuscatecff   │        │ Keystone junk path  │
        │  cfflattening   │        │ TrampolineInjector  │
        └────────┬────────┘        └──────────┬──────────┘
                 │                            │
                 ▼                            ▼
           *.cff.exe                     *.junk.exe
```

## Module responsibilities

### `main.cpp`

- Banner and menu (`0` / `1` / `2`)  
- File existence checks; strip quotes from paths  
- Lightweight PE magic / machine detection for menu routing  
- **CFF path:** discovery → filter → `pe64` → `obfuscatecff` → save  
- **Junk path:** discovery → auto/manual → `JunkCodeManager`  

### `common/`

| Type / API | Role |
|------------|------|
| `FunctionInfo` | Canonical symbol record |
| `FunctionDiscovery` | One PE+PDB load; fills RVAs |
| `filter_functions` | Eligibility |
| `load_blacklist_file` / `ensure_blacklist_loaded` | External + built-in lists |
| `select_functions_interactive` | Manual multi-select UI |

### `pe/` — `pe64`

- Read PE into raw buffer + **VA-mapped** image (`SizeOfImage`)  
- Validate MZ, PE signature, optional-header magic, AMD64, size bounds  
- `create_section` with max-section and header-space checks  
- `save_to_disk` for CFF outputs  

### `pdbparser/`

- `SymInitialize` / `SymLoadModuleEx` / `SymEnumSymbols`  
- CodeView directory or `.pdb` sibling fallback  
- Dedup offsets with `unordered_set`  
- Cleanup via destructor (`SymCleanup`)  

### `obfuscatecff/` + `cfflattening/`

- Zydis disassembly and relative analysis  
- Block build, shuffle, dispatcher  
- Relocate, fix short jumps, compile stubs into `.text`  
- Rebuild `inst_id_index` after flattening  

### `junkcode/`

| Class | Role |
|-------|------|
| `TrampolineInjector` | LIEF PE, relocate, trampoline, batch layout |
| `JunkCodeManager` | Auto/manual orchestration only |

Engines Capstone/Keystone are held for the injector lifetime.

### `func2rva/`

- `FuncToRVA::FunctionInfo` = **`using` alias** of `ObfuGuard::FunctionInfo`  
- Interactive helpers still used for some manual RVA workflows  

## Data flow notes

1. **CFF** needs a second `pe64` instance after discovery (discovery’s PE is destroyed with SymCleanup before the engine mutates a fresh map).  
2. **Junk** uses LIEF for mutation; discovery still uses `pe64` + DbgHelp once.  
3. Constants live in `constants.h` (`PE_MAX_SECTIONS`, `MAX_JUNK_ITERATIONS`, `CFF_SECTION_SIZE`, …).  

## Build / security-related project settings

Recent releases enable (where configured in the `.vcxproj`):

- `/std:c++20`  
- `/W4`, Control Flow Guard, CET/high-entropy VA on Release|x64  
- Exception handling enabled on Release|x64 (required for try/catch)  

Exact flags: see `ObfuGuard/ObfuGuard.vcxproj` and `CHANGELOG.md`.

## Extension points

| Goal | Where to start |
|------|----------------|
| New junk patterns | `TrampolineInjector::get_random_junk_instruction` |
| Stricter filters | `function_filter.cpp` / `blacklist_default.txt` |
| CFF dispatcher shape | `cfflattening.cpp` |
| Non-interactive CLI | `main.cpp` argument parsing (currently interactive only) |

## See also

- [api-reference.md](api-reference.md)  
- [overview.md](overview.md)  
