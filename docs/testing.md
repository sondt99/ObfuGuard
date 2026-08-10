# Testing

## Overview

ObfuGuard has a comprehensive test suite with ~60 test programs and automated scripts to verify that obfuscation preserves program behavior.

**Platform note:** Full binary tests require Windows (or a working Wine prefix with Windows PE support) and an MSVC-built `ObfuGuard.exe`. On Linux without Wine PE support, use static review and `python -m py_compile` for scripts.

## Test Suite Structure

```
binary_test/
├── auto_test.py            # Automated obfuscation runner
├── match_check.py          # Output comparison validator
├── create_ObfuGuard_obfu.py # Self-obfuscation test
├── input.txt               # Standard test input
├── helloworld/
│   ├── helloworld.exe      # Original binary
│   ├── helloworld.pdb      # Debug symbols
│   ├── helloworld.cff.exe  # CFF-obfuscated
│   └── helloworld.junk.exe # Junk-obfuscated
├── factorial/
│   ├── factorial.exe
│   ├── factorial.pdb
│   ├── factorial.cff.exe
│   └── factorial.junk.exe
└── ... (~60 program directories)
```

## Test Programs

The suite under `binary_test/` includes (non-exhaustive):

| Category | Programs |
|----------|----------|
| Basic I/O | `helloworld`, `fizzbuzz`, `tell_story`, `append_text` |
| Math | `factorial`, `armstrong_number`, `gcd_cal`, `lcm`, `power_cal`, `x_power_y`, `sum_to_n`, `sum_digit`, `sum_two_nums` |
| Search / arrays | `linear_search`, `avg_array`, `even_array`, `merge_array`, `reverse_array`, `index_largest_num` |
| String | `Caesar_cipher`, `check_palindrome`, `check_anagrams`, `reverse_strings`, `count_char`, `count_occurance` |
| Number theory | `check_perfect`, `check_parity`, `find_divisors`, `bin_to_dec`, `dec_to_bin` |
| Patterns | `pyramid`, `draw_diamond`, `draw_rec`, `hallow_rec`, `right_triangle`, `horizonal_line` |
| Conversion / calc | `celsius_to_fahrenheit`, `convert_from_seconds`, `interest_cal`, `perimeter_and_area`, `solve_linear` |
| Control flow | `condition`, `switch_case`, `loop`, `functions`, `compare`, `const`, `pair` |
| Misc | `flip_coin`, `roll_dice`, `random_color`, `traffic_light`, `simple_struct`, `pass_value_and_reference`, `mul_table`, `max_in_three`, `larger_num`, `binary_CFF`, `binary_normal` |

## Automated Test Scripts

Paths are resolved relative to the repository. Override the tool binary with:

```bash
export OBFUGUARD_EXE=/path/to/ObfuGuard.exe
```

Default: `x64/Release/ObfuGuard.exe` relative to the repo root.

### auto_test.py - Obfuscation Runner

```bash
cd binary_test
python auto_test.py
```

**What it does:**
1. Iterates over all subdirectories in `binary_test/`
2. For each `.exe` that has a matching `.pdb`:
   - Runs ObfuGuard in CFF mode
   - Runs ObfuGuard in junk code auto mode
3. Reports success/failure for each obfuscation attempt

### match_check.py - Behavioral Validation

```bash
cd binary_test
python match_check.py
```

**What it does:**
1. For each test program directory with obfuscated variants:
   - Runs the original `.exe` with stdin from `input.txt` (if present)
   - Runs the `.cff.exe` and `.junk.exe` variants with the same input
   - Compares stdout
2. Reports PASS/FAIL for each comparison

**Validation criteria:**
- Stdout output is identical (stripped)

### create_ObfuGuard_obfu.py - Self-obfuscation Test

```bash
cd binary_test
python create_ObfuGuard_obfu.py
```

**What it does:**
1. Runs ObfuGuard on `ObfuGuard.exe` in CFF and junk modes
2. Verifies obfuscated binaries still start and exit cleanly (menu choice `0`)

## Edge Case Testing

The `binary_exeption/` directory contains edge-case binaries:

| File | Test Case |
|------|-----------|
| `test_no_pdb.exe` | PE file without PDB symbols |
| `test_no_pdb.cpp` | Source for the no-PDB test |
| `heap_dbf` | Heap-related edge case binary |

## Running Tests Manually

### Test a Single Binary

1. Place your `.exe` and `.pdb` in a directory
2. Run ObfuGuard:
   ```powershell
   .\x64\Release\ObfuGuard.exe
   # Select mode 1 or 2
   # Enter path to your .exe
   ```
3. Compare output:
   ```powershell
   .\original.exe < binary_test\input.txt > original_output.txt
   .\original.cff.exe < binary_test\input.txt > cff_output.txt
   fc original_output.txt cff_output.txt
   ```

### Test All Binaries

```powershell
cd binary_test
python auto_test.py      # Generate obfuscated variants
python match_check.py    # Validate behavioral equivalence
```

## Test Input

`binary_test/input.txt` contains standard stdin data used across programs that read input.

## Adding New Test Programs

1. Create a new directory under `binary_test/`:
   ```powershell
   mkdir binary_test\my_program
   ```

2. Compile your program with debug symbols:
   ```powershell
   cl /Zi /Fe:binary_test\my_program\my_program.exe my_program.cpp
   ```

3. Run the automated test suite:
   ```powershell
   python auto_test.py
   python match_check.py
   ```

## Common Test Failures

| Symptom | Cause | Solution |
|---------|-------|----------|
| CFF crashes | Function contains jump tables | Expected; function is skipped |
| Junk output differs | Non-deterministic program (e.g., uses random) | Exclude from match_check |
| Missing PDB | Debug symbols not generated | Recompile with `/Zi` |
| Section limit reached | Too many functions for junk code | Expected; tool reports actual count |
| `ObfuGuard executable not found` | Scripts cannot locate the binary | Set `OBFUGUARD_EXE` or build Release x64 |
