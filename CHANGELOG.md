# Changelog

All notable changes to ObfuGuard are documented in this file.

## [3.0] - ObfuGuard V3

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

## [2.0] - ObfuGuard V2

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

## [1.0] - ObfuGuard V1

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
  - Static analysis benchmark with angr (file size, branches, cyclomatic complexity, CFG metrics)
  - Runtime performance benchmark with statistical analysis
  - Reverse engineering time benchmark
  - Box plot visualization scripts
- 60 test program binaries with original, CFF, and junk variants
- Self-obfuscation capability

### Architecture
- Modular design: `pe/`, `pdbparser/`, `obfuscatecff/`, `cfflattening/`, `junkcode/`, `func2rva/`
- C++20 with MSVC v143 toolset
- Dependencies managed via vcpkg: Capstone, Keystone, LIEF, AsmJit, Zydis

## Pre-release

### Early Development
- Initial project structure and binary analysis tools
- Disassembler for binary-to-source extraction
- Benchmark data collection framework
- Web interface prototype (later removed)
