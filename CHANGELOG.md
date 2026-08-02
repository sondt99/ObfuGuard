# Changelog

All notable changes to ObfuGuard are documented in this file.
Format follows [Semantic Versioning](https://semver.org/).

## [4.0.0] - 2025-08-02

### Added
- **Symmetric architecture**: shared `common/` module for function discovery
  - `FunctionDiscovery` class — single PE+PDB load for both modes
  - `FunctionFilter` utilities — shared blacklist filtering, size filtering, interactive selection
  - `FunctionInfo` struct — canonical function descriptor used by both CFF and Junk modes
- Named x86 opcode constants (`x86_opcodes::PUSH_RAX`, etc.) in CFF dispatcher
- `constants.h` with named constants for all magic numbers
- `blacklist_default.txt` — documented default function blacklist
- `[[nodiscard]]` attributes on 12 error-returning functions
- GitHub Issue Templates (bug report, feature request, refactor — YAML forms)
- Pull Request template with testing checklist
- 28 color-coded GitHub labels (priority, type, component, risk, status)
- Comprehensive `docs/` documentation (11 files)

### Changed
- **Both modes now follow the same pipeline**: validate → discover → engine → save
- Junk mode PE loading reduced from 2-4 redundant loads to 1 discovery + 1 LIEF
- `JunkCodeManager::run_auto/manual_injection_mode` accept pre-discovered function list
- `obfuscatecff` refactored: removed `using namespace asmjit`, static counters → instance members
- `TrampolineInjector` refactored: removed redundant raw pointer, unused `force_64_bit` param
- Replaced `srand`/`rand` with `std::mt19937` + `std::uniform_int_distribution`
- Replaced `clock()` with `std::chrono::steady_clock`
- Replaced all C-style casts with `static_cast`/`reinterpret_cast` in CFF engine
- `pe64::align()` and `pe64::get_path()` marked `const`
- `find_instruction_by_id` uses `inst_id_index` map (O(log n) vs O(n))
- `fix_relative_jmps` has recursion depth limit (max 100)
- Junk instruction pool is `static const` (was rebuilt every call)
- Extracted `patch_junk_region()` helper from duplicated trampoline code
- Extracted `display_function_table()` from duplicated func2rva code
- Renamed `ctfflattening` → `cff_flattening` (typo fix)
- Renamed `DetectPEArchitecture` → `detect_pe_architecture` (naming consistency)
- `cfflattening.cpp` includes its own header
- `#define NOMINMAX` moved to vcxproj preprocessor definitions
- `__declspec(safebuffers)` wrapped in `#ifdef _MSC_VER`

### Fixed
- **Corrupting junk instructions**: `shl`/`shr` pairs lose bits, `mov r8,r9` swap clobbers registers — replaced with safe `rol`/`ror` and `push`/`pop` patterns
- **func_id mismatch**: instructions were assigned wrong function ID due to post-increment bug
- **Deterministic shuffle**: CFF block shuffle was unseeded, producing same permutation every run
- **Undefined behavior**: writing through `const` pointer (`jmp_shell`), reading uninitialized `is_64_bit`
- **Silent blacklist bug**: missing comma caused `"fegetenv""srand"` string concatenation
- **Build config**: exception handling disabled in Release|x64 (making try/catch dead code)
- **RootNamespace**: was "Alcatraz" (leftover from fork)
- **PE parser safety**: buffer overflow risks from unchecked header fields, broken `align()`, unsafe `_stricmp` on section names
- **PDB parser**: resource leaks (`SymCleanup` not called on error paths), logic bug in fallback path, unbounded debug directory loop, static ID counter leak
- **CFF**: `is_first_instruction` never set to `true` after flattening, unchecked `find_if` results
- **Overflow check**: always-false `signed int` comparison replaced with `int64_t`
- Dead `std::cout << ""` output removed
- Duplicate entries in blacklist sets removed
- Duplicate junk instruction pattern removed

### Security
- Enabled Control Flow Guard (`/guard:cf`) in all build configurations
- Added CET Shadow Stack (`/CETCOMPAT`) for Release|x64
- Added High Entropy ASLR (`HighEntropyVA`) for Release|x64
- Raised warning level from `/W3` to `/W4` across all configurations
- Added `SizeOfImage` upper bound validation (512 MB max)
- Added bounds checks on PE section `memcpy` operations
- Replaced `IMAGE_DOS_SIGNATURE` check (was multi-char constant `'ZM'`)
- Used `_strnicmp` with `IMAGE_SIZEOF_SHORT_NAME` (was unbounded `_stricmp`)

### Architecture
- New `common/` module: `function_info.h`, `function_discovery.h/.cpp`, `function_filter.h/.cpp`
- Source files properly organized in Visual Studio filters (`.cpp` → Source Files, `.h` → Header Files)

## [3.0.0] - 2025-07-15

### Added
- Binary size-aware function blacklisting for binaries > 350 KB
- Auto-limit for junk code injection mode (PE section count awareness)
- Exception handling test binaries (`binary_exeption/`)
- Detailed PDB information logging
- MSVC GitHub tools reference list
- Security policy (`SECURITY.md`)

### Changed
- Translated all Vietnamese comments and documentation to English
- Updated CFF and junk code results for all test binaries
- Increased `MAX_JUNK_ITERATIONS` from 100 to 500

### Fixed
- Junk code iteration limit causing incomplete obfuscation on larger binaries

## [2.0.0] - 2025-06-24

### Added
- Manual junk code injection mode with interactive function selection
- Function size filtering in manual junk code mode
- Bounds checking for junk code injection
- Auto-test runner (`auto_test.py`) for batch obfuscation testing
- Output mismatch checker (`match_check.py`) for behavioral validation
- Installation tutorial (`ObfuGuard_tutorial.md`)

### Changed
- Removed 5-byte function size limit in manual junk injection mode
- Refactored junk code injection logic from `main.cpp` to dedicated `junkcode.cpp` module
- Improved output formatting for junk code mode

### Fixed
- Bounds checking issues in junk code injection

## [1.0.0] - 2025-06-22

### Added
- Control Flow Flattening (CFF) obfuscation for 64-bit PE files
  - Basic block detection from conditional jumps
  - Block shuffling with random reordering
  - Dispatcher construction using `rax` state variable
  - `pushf`/`popf` CPU flag preservation
  - Jump table detection and automatic exclusion
  - Code relocation to new `.0Cff` PE section
  - Entry point obfuscation with XOR/rotation encoding
- Junk Code Injection with Trampoline technique
  - Function relocation to new PE sections
  - ~50 junk instruction patterns for 64-bit, ~20 for 32-bit
  - Multi-byte NOP padding
  - CALL/JMP rel32 and RIP-relative address fixup
  - CRT and system function blacklisting
  - Auto-inject mode for all eligible functions
- PE64 parser module with section creation and virtual address mapping
- PDB parser using Windows DbgHelp API for function discovery
- Function-to-RVA resolver combining PE and PDB parsing
- Automatic PE architecture detection (32-bit / 64-bit)
- Interactive CLI menu
- Benchmark framework
  - Static analysis benchmark with angr
  - Runtime performance benchmark
  - Reverse engineering time benchmark
  - Box plot visualization scripts
- 60 test program binaries with original, CFF, and junk variants
- Self-obfuscation capability

### Architecture
- Modular design: `pe/`, `pdbparser/`, `obfuscatecff/`, `cfflattening/`, `junkcode/`, `func2rva/`
- C++20 with MSVC v143 toolset
- Dependencies managed via vcpkg: Capstone, Keystone, LIEF, AsmJit, Zydis
