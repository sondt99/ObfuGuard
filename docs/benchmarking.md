# Benchmarking

## Overview

ObfuGuard includes a comprehensive benchmarking framework in the `benchmark/` directory to evaluate obfuscation effectiveness across three dimensions:

1. **Static analysis complexity** - How much harder is the binary to analyze?
2. **Runtime performance** - What is the execution time overhead?
3. **Reverse engineering time** - How much longer does automated analysis take?

## Prerequisites

```bash
pip install -r benchmark/requirements.txt
```

Required Python packages:
- `angr` - Binary analysis framework
- `capstone` - Disassembly library (usually installed with angr)
- `psutil` - Process monitoring (for runtime benchmarks)
- `matplotlib` - Plotting (for visualization scripts)

## Benchmark Scripts

### 1. Static Analysis Benchmark (`benchmark.py`)

Compares structural metrics between original and obfuscated binaries.

```bash
cd benchmark
python benchmark.py
```

**Metrics measured:**

| Metric | Description |
|--------|-------------|
| `file_size` | Binary file size in bytes |
| `branches` | Number of branch instructions in `.text` |
| `instructions` | Total instruction count in `.text` |
| `branch_density` | Ratio of branches to total instructions |
| `cyclomatic_complexity` | McCabe cyclomatic complexity (branches + 1) |
| `functions` | Number of detected functions |
| `blocks` | Number of basic blocks |
| `nodes` | CFG nodes count |
| `edges` | CFG edges count |

**How it works:**

1. Scans `binary_test/` for original `.exe` files
2. For each original, analyzes both `.cff.exe` and `.junk.exe` variants
3. Uses angr's `CFGFast` for control flow graph construction
4. Uses Capstone for instruction-level analysis
5. Combines angr function detection with Capstone prologue scanning for completeness
6. Computes percentage difference for each metric
7. Outputs results to `benchmark_comparison_all.csv`

**Output format (CSV):**

```
Original, Variant, Type,
file_size_orig, file_size_variant, file_size_diff(%),
branches_orig, branches_variant, branches_diff(%),
...
```

### 2. Runtime Performance Benchmark (`benchmark_runtime.py`)

Measures execution time overhead of obfuscated binaries.

```bash
cd benchmark
python benchmark_runtime.py
```

**Methodology:**
- Runs each binary multiple times with warmup iterations
- Removes statistical outliers
- Calculates coefficient of variation for reliability
- Compares original vs. CFF vs. junk variants

**Output:** `benchmark_runtime_all.csv`

### 3. Reverse Engineering Time Benchmark (`benchmark_time_pro.py`)

Measures how long automated analysis tools (angr) take to process obfuscated binaries.

```bash
cd benchmark
python benchmark_time_pro.py
```

**Metrics measured:**
- PE load time
- CFG construction time
- Full disassembly time

**Output:** `benchmark_time_pro_all.csv`

## Visualization

### Box Plot Scripts

```bash
python boxplot_runtime.py    # Runtime performance comparison
python boxplot_tech.py       # Static analysis metrics comparison
python boxplot_time.py       # RE time comparison
```

These scripts read the CSV output files and generate comparative box plots showing the distribution of metric changes across all test binaries.

## Interpreting Results

### Static Analysis Metrics

**CFF obfuscation typically shows:**
- Significant increase in CFG nodes and edges (new dispatcher blocks)
- Higher cyclomatic complexity (more branch paths through dispatcher)
- Increased instruction count (dispatcher overhead)
- Moderate file size increase (new `.0Cff` section)

**Junk code injection typically shows:**
- Higher instruction count (junk instructions added)
- Increased file size (new sections per function)
- Branch count may increase slightly (some junk patterns include jumps)
- Function count may change (new sections detected as functions)

### Runtime Performance

- CFF adds overhead from dispatcher transitions (typically < 5% for non-tight loops)
- Junk code adds minimal overhead (junk instructions execute fast, trampoline is a single `jmp`)

### Reverse Engineering Time

- CFF significantly increases CFG construction time (more complex graph)
- Junk code moderately increases analysis time (more instructions to decode)

## Test Binary Set

The benchmarks run against 60 test programs in `binary_test/`, covering:

- Basic I/O (`helloworld`, `fizzbuzz`)
- Algorithms (`binary_search`, `linear_search`, `bubble_sort`, `selection_sort`)
- Math (`factorial`, `fibonacci`, `armstrong_number`, `gcd`, `lcm`)
- String operations (`caesar_cipher`, `palindrome`, `string_reverse`)
- Data structures (arrays, matrices)
- Pattern generation (triangles, diamonds)

Each program has original, CFF, and junk code variants pre-built.

## Adding New Benchmarks

To add a new test binary:

1. Create a directory in `binary_test/` with the program name
2. Place the `.exe` and `.pdb` files
3. Run ObfuGuard to generate `.cff.exe` and `.junk.exe` variants
4. Re-run the benchmark scripts

The benchmark scripts automatically discover all test binaries by walking the `binary_test/` directory tree.
