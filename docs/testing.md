# Testing

## Overview

ObfuGuard ships ~**60** small C++ programs under `binary_test/`, each with:

- Original `name.exe`  
- Matching `name.pdb`  
- Prebuilt `name.cff.exe` / `name.junk.exe` (optional; regenerate with scripts)  

Scripts automate obfuscation and **behavioral** comparison of stdout.

**Platform:** full runs need Windows + a built `ObfuGuard.exe`. Scripts themselves are plain Python 3.

## Layout

```
binary_test/
├── auto_test.py
├── match_check.py
├── create_ObfuGuard_obfu.py
├── input.txt
├── helloworld/
│   ├── helloworld.exe
│   ├── helloworld.pdb
│   ├── helloworld.cff.exe
│   └── helloworld.junk.exe
├── factorial/
└── ... (~60 directories)
```

## Sample programs (real directories)

| Category | Examples |
|----------|----------|
| Basic I/O | `helloworld`, `fizzbuzz`, `tell_story`, `append_text` |
| Math | `factorial`, `armstrong_number`, `gcd_cal`, `lcm`, `power_cal`, `x_power_y`, `sum_to_n`, `sum_digit` |
| Arrays / search | `linear_search`, `avg_array`, `even_array`, `merge_array`, `reverse_array` |
| Strings | `Caesar_cipher`, `check_palindrome`, `check_anagrams`, `reverse_strings`, `count_char` |
| Patterns | `pyramid`, `draw_diamond`, `draw_rec`, `right_triangle` |
| Control | `condition`, `switch_case`, `loop`, `functions`, `compare` |
| Misc | `flip_coin`, `roll_dice`, `traffic_light`, `simple_struct`, `binary_CFF`, `binary_normal` |

Full list: every subdirectory of `binary_test/` that contains a `.pdb`.

## Scripts

Paths are **repo-relative**. Override the tool:

```powershell
$env:OBFUGUARD_EXE = "D:\build\ObfuGuard.exe"
```

Default: `<repo>\x64\Release\ObfuGuard.exe`.

### `auto_test.py`

Runs CFF (menu `1`) and junk auto (menu `2` → `1`) for each program that has a PDB.

```powershell
cd binary_test
python auto_test.py
```

### `match_check.py`

Compares stdout of original vs `.cff.exe` vs `.junk.exe` (feeds `input.txt` if present).

```powershell
python match_check.py
```

### `create_ObfuGuard_obfu.py`

Self-obfuscation smoke test: run the tool on `ObfuGuard.exe`, then check obfuscated copies still start and exit on menu `0`.

```powershell
python create_ObfuGuard_obfu.py
```

## Edge cases

`binary_exeption/`:

| File | Purpose |
|------|---------|
| `test_no_pdb.exe` / `.cpp` | PE without usable PDB |
| `heap_dbf` | Edge binary sample |

## Manual single-target test

```powershell
.\ObfuGuard.exe
# mode 1 or 2, path to target.exe

.\target.exe < binary_test\input.txt > o.txt
.\target.cff.exe < binary_test\input.txt > c.txt
fc o.txt c.txt
```

## Adding a program

1. `mkdir binary_test\my_prog`  
2. `cl /Zi /Fe:binary_test\my_prog\my_prog.exe my_prog.cpp`  
3. `python auto_test.py` / `match_check.py`  

## Failure modes

| Symptom | Likely cause |
|---------|----------------|
| CFF skips many funcs | Jump tables or blacklist |
| Junk inject count low | Section limit |
| stdout mismatch | RNG, time, or real bug — investigate |
| “ObfuGuard executable not found” | Build tool or set `OBFUGUARD_EXE` |
| PDB missing | Recompile with `/Zi` |

## See also

- [user-guide.md](user-guide.md)  
- [benchmarking.md](benchmarking.md)  
