# User Guide

## Getting Started

ObfuGuard is a command-line interactive tool. Run it and follow the on-screen prompts.

```powershell
.\ObfuGuard.exe
```

## Input Requirements

For obfuscation, you need:

1. **PE executable file** (`.exe`) - The binary you want to obfuscate
2. **PDB debug symbols file** (`.pdb`) - Must be located in the same directory as the PE file, with the same base name

Example:
```
my_program.exe
my_program.pdb
```

## Mode 1: Control Flow Flattening

### Supported Architecture
- **64-bit PE files only**

### Steps

1. Launch ObfuGuard and select option `1`
2. Enter the path to the PE file (drag-and-drop is supported with quoted paths)
3. ObfuGuard will:
   - Validate the PE file and detect architecture
   - Locate and parse the PDB file automatically
   - Extract all functions from debug symbols
   - Create a new `.0Cff` section (10 MB)
   - Apply CFF to all eligible functions
   - Obfuscate the entry point
   - Save the result as `<original_name>.cff.exe`

### Example Session

```
========================================
         ObfuGuard Tool - sondt
========================================

Select obfuscation mode:
  1. Control Flow Flattening
  2. Insert Junk Code - Trampoline
  0. Exit
Enter your choice (0-2): 1

=== Control Flow Flattening Mode ===
Enter PE file path for CFF: C:\programs\target.exe
Control Flow Flattening Mode: Detected 64-bit PE
Successfully analyzed all functions.
Creating new section .0Cff
Running Control Flow Flattening Mode

Successfully control-flow-flattened 42 selected function(s).
Output saved to: C:\programs\target.cff.exe
Control Flow Flattening mode completed in 1.234 seconds.
```

### What Gets Skipped

- Functions containing jump tables (switch statements with indirect jumps)
- Functions that are too small to meaningfully flatten

## Mode 2: Junk Code Injection with Trampoline

### Supported Architecture
- **Both 32-bit and 64-bit PE files**

### Sub-modes

After selecting mode 2, you choose between:

#### Auto-inject (Option 1)
Automatically processes all eligible functions. The tool:
- Discovers all functions via PDB symbols
- Filters out blacklisted functions (CRT, system functions)
- Removes functions smaller than 5 bytes
- Sorts functions by size (largest first) for priority injection
- Respects PE section limit (max 96 sections with safety margin)

#### Manual (Option 2)
Allows you to select specific functions to obfuscate:
- Displays a numbered list of all discovered functions with their RVAs and sizes
- You select functions by entering their numbers
- Alternatively, you can enter raw RVA values

### Example Session (Auto-inject)

```
=== Junk Code Injection with Trampoline Mode ===
Enter input PE file path: C:\programs\target.exe
Junk Code Injection Mode: Detected: 64-bit PE file

Select injection mode:
  1. Auto-inject functions
  2. Manually choose multiple functions
Enter your choice (1 or 2): 1

[Processing functions...]
Output saved to: C:\programs\target.junk.exe
Junk Code Injection mode completed in 0.567 seconds.
```

### Function Blacklist

The following function categories are automatically excluded from junk code injection to prevent crashes:

**Always excluded:**
- CRT initialization: `__scrt_common_main_seh`, `mainCRTStartup`, `__security_init_cookie`, etc.
- Exception handling: `_CxxThrowException`, `__CxxFrameHandler`, etc.
- Memory management: `malloc`, `free`, `operator new`, `operator delete`, etc.
- Security: `__security_check_cookie`, `__GSHandlerCheck`, etc.

**Excluded for binaries > 350 KB:**
- Additional CRT functions that become more complex in larger binaries
- C++ standard library internal functions
- Thread-local storage handlers

## Output Files

| Input | CFF Output | Junk Output |
|-------|------------|-------------|
| `program.exe` | `program.cff.exe` | `program.junk.exe` |

Output files are placed in the same directory as the input file.

## Tips and Best Practices

1. **Always keep backups** - Obfuscation modifies program structure; keep original binaries safe
2. **Test obfuscated output** - Run the obfuscated binary to verify it behaves identically to the original
3. **PDB files are required** - Without debug symbols, ObfuGuard cannot discover functions to obfuscate
4. **CFF is stronger** - For maximum protection, use CFF. Junk code alone adds noise but doesn't restructure logic
5. **Combine both modes** - You can first apply junk code injection, then apply CFF to the result (if it has a PDB)
6. **Large binaries** - Junk code injection has additional safety filters for binaries > 350 KB to prevent stability issues
7. **Section limits** - PE files have a maximum of 96 sections. Each junk code injection adds a section, so the tool automatically limits the number of injectable functions
