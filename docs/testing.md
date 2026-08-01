# Testing

## Overview

ObfuGuard has a comprehensive test suite with 60 test programs and automated scripts to verify that obfuscation preserves program behavior.

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
└── ... (60 program directories)
```

## Test Programs

The test suite covers a diverse range of program types:

| Category | Programs |
|----------|----------|
| Basic I/O | `helloworld`, `fizzbuzz`, `print_hello` |
| Math | `factorial`, `fibonacci`, `armstrong_number`, `gcd_lcm`, `power_calculator` |
| Search | `binary_search`, `linear_search` |
| Sort | `bubble_sort`, `selection_sort`, `insertion_sort` |
| String | `caesar_cipher`, `palindrome`, `string_reverse`, `string_length`, `vowel_count` |
| Number theory | `prime_check`, `perfect_number`, `leap_year`, `even_odd` |
| Array | `array_sum`, `array_reverse`, `array_max_min`, `matrix_addition`, `matrix_multiply` |
| Patterns | `triangle_pattern`, `diamond_pattern`, `right_triangle_pattern` |
| Conversion | `celsius_fahrenheit`, `decimal_binary`, `decimal_octal` |
| Calculators | `simple_calculator`, `quadratic_solver`, `area_calculator` |
| Misc | `swap_numbers`, `countdown_timer`, `multiplication_table` |

## Automated Test Scripts

### auto_test.py - Obfuscation Runner

Runs ObfuGuard on all test binaries in both modes.

```bash
cd binary_test
python auto_test.py
```

**What it does:**
1. Iterates over all subdirectories in `binary_test/`
2. For each `.exe` (excluding `.cff.exe` and `.junk.exe`):
   - Runs ObfuGuard in CFF mode
   - Runs ObfuGuard in junk code mode
3. Reports success/failure for each obfuscation attempt

### match_check.py - Behavioral Validation

Verifies that obfuscated binaries produce the same output as originals.

```bash
cd binary_test
python match_check.py
```

**What it does:**
1. For each test program directory:
   - Runs the original `.exe` with standard input from `input.txt`
   - Runs the `.cff.exe` variant with the same input
   - Runs the `.junk.exe` variant with the same input
   - Compares stdout output of all three
2. Reports PASS/FAIL for each comparison

**Validation criteria:**
- Exit code matches
- Stdout output is byte-identical

### create_ObfuGuard_obfu.py - Self-obfuscation Test

Tests that ObfuGuard can obfuscate its own binary.

```bash
cd binary_test
python create_ObfuGuard_obfu.py
```

**What it does:**
1. Copies `ObfuGuard.exe` and `ObfuGuard.pdb` to a test directory
2. Runs ObfuGuard on itself in CFF mode -> `ObfuGuard.cff.exe`
3. Runs ObfuGuard on itself in junk code mode -> `ObfuGuard.junk.exe`
4. Verifies that the obfuscated versions can still obfuscate other binaries

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
   .\ObfuGuard.exe
   # Select mode 1 or 2
   # Enter path to your .exe
   ```
3. Compare output:
   ```powershell
   .\original.exe < input.txt > original_output.txt
   .\original.cff.exe < input.txt > cff_output.txt
   fc original_output.txt cff_output.txt
   ```

### Test All Binaries

```powershell
cd binary_test
python auto_test.py      # Generate obfuscated variants
python match_check.py    # Validate behavioral equivalence
```

## Test Input

The file `binary_test/input.txt` contains standard input data used across all test programs. Programs that require user input will receive this data via stdin redirection.

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

4. If the program requires specific input, update `input.txt` accordingly.

## Common Test Failures

| Symptom | Cause | Solution |
|---------|-------|----------|
| CFF crashes | Function contains jump tables | Expected behavior; function is skipped |
| Junk output differs | Non-deterministic program (e.g., uses random) | Exclude from match_check |
| Missing PDB | Debug symbols not generated | Recompile with `/Zi` flag |
| Section limit reached | Too many functions for junk code | Expected; tool reports actual count |
