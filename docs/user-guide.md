# User Guide

## Launch

From a directory that contains the tool and its DLLs:

```powershell
.\ObfuGuard.exe
```

```
========================================
         ObfuGuard Tool - sondt
========================================

Select obfuscation mode:
  1. Control Flow Flattening
  2. Insert Junk Code - Trampoline
  0. Exit
Enter your choice (0-2):
```

Paths may be entered with surrounding quotes (Windows drag-and-drop).

## Prerequisites for every run

1. **Input PE** — valid PE file you are allowed to modify  
2. **PDB** — symbols for that PE (embedded CodeView path or `same-name.pdb` beside the EXE)  
3. **Architecture**  
   - Mode 1 (CFF): **64-bit only**  
   - Mode 2 (junk): **64-bit only** (32-bit is rejected until PE32 discovery exists)

## Mode 1 — Control Flow Flattening

### Steps

1. Select `1`.  
2. Enter the path to a **64-bit** PE.  
3. ObfuGuard will:
   - Detect architecture (rejects non-x64)  
   - Discover functions via `FunctionDiscovery`  
   - **Filter** CRT/runtime and tiny functions  
   - Reserve a **`.0Cff`** section sized from remaining code (capped; not always 10 MB)  
   - Flatten eligible functions; skip jump-table suspects  
   - Optionally encode entry-point metadata when the flag is enabled (CLI passes `true`)  
   - Write **`<stem>.cff.exe`** next to the input  

### Example

```
=== Control Flow Flattening Mode ===
Enter PE file path for CFF: C:\work\target.exe
Control Flow Flattening Mode: Detected 64-bit PE
Successfully analyzed 180 functions.
Eligible for CFF after filtering: 42 function(s).
Running Control Flow Flattening Mode (524288 byte section reservation)

Successfully control-flow-flattened 42 function(s).
Output saved to: C:\work\target.cff.exe
Control Flow Flattening mode completed in 0.85 seconds.
```

### What is skipped

- Functions on the blacklist (or with leading `_` / `` ` ``)  
- Functions smaller than the minimum size  
- Functions flagged as containing jump tables  

### Output artifacts

| Item | Description |
|------|-------------|
| `*.cff.exe` | Flattened PE |
| Section `.0Cff` | Relocated flattened code |
| `.text` stubs | `jmp` into `.0Cff` (+ pad bytes) |

## Mode 2 — Junk code + trampoline

### Steps

1. Select `2`.  
2. Enter PE path (**64-bit**).  
3. Choose sub-mode:

```
Select injection mode:
  1. Auto-inject functions
  2. Manually choose multiple functions
Enter your choice (1 or 2):
```

### Auto (`1`)

1. Discover all PDB functions.  
2. Filter by size (min **6** bytes in auto path) and blacklist.  
3. Sort by size descending.  
4. Inject until PE **section budget** is exhausted.  
5. Write **`<stem>.junk.exe`**.

### Manual (`2`)

1. Print a table: No. | RVA | PDB offset | Size | Name.  
2. Enter comma-separated numbers (e.g. `1,3,8`) or `0` to cancel.  
3. Re-filter selection (min size **5**).  
4. Inject with the same section-aware engine.

### Output artifacts

| Item | Description |
|------|-------------|
| `*.junk.exe` | Injected PE |
| New sections | One per injected function (short name derived from symbol) |
| Original RVA | Trampoline: junk + `E9 rel32` + more junk/NOPs |

Batch layout: all new sections are created, **one** LIEF rebuild assigns VAs, then bodies are re-relocated and trampolines installed.

## Blacklist customization

Edit or place `blacklist_default.txt`:

```
# comment
mainCRTStartup
memcpy
big:std::filesystem::exists
```

- Plain lines → always excluded  
- `big:Name` → excluded only when the PE is larger than **350 KB**  
- If the file is not found, built-in defaults apply  

## Verifying results

### Functional

```powershell
# Prefer your real inputs; suite uses binary_test\input.txt when present
.\target.exe < input.txt > out_orig.txt
.\target.cff.exe < input.txt > out_cff.txt
fc out_orig.txt out_cff.txt
```

Automated suite: [testing.md](testing.md).

### Static (optional)

Load `*.cff.exe` / `*.junk.exe` in IDA/Ghidra and confirm:

- CFF: dispatcher loops and state compares  
- Junk: `jmp` at old RVA, body in a new section with extra neutral ops  

## Tips

| Tip | Why |
|-----|-----|
| Keep PDB next to EXE | Fastest symbol resolution |
| Prefer Release builds of targets | Smaller, fewer weird debug edges |
| Test after each mode | Obfuscation is never risk-free |
| Large apps + junk | Section limit caps inject count |
| Do not flatten untested third-party code | Always run regression tests |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (or clean exit from menu `0`) |
| `1` | Validation error, no eligible functions, inject/CFF failure, invalid menu choice |

## Next

- Algorithms: [control-flow-flattening.md](control-flow-flattening.md), [junk-code-injection.md](junk-code-injection.md)  
- Internals: [architecture.md](architecture.md)  
- Problems: [faq.md](faq.md)
