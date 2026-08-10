# Benchmarking

## Overview

The `benchmark/` directory evaluates obfuscation **cost and complexity**, not functional correctness (use `binary_test` for that).

Three axes:

1. **Static structure** — size, branches, CFG metrics  
2. **Runtime** — wall-clock / process cost of running obfuscated binaries  
3. **Analysis time** — how long automated RE-style analysis takes  

## Setup

```powershell
cd benchmark
pip install -r requirements.txt
```

Typical packages: `angr`, `capstone`, `psutil`, `matplotlib` (see `requirements.txt` for the pinned set).

Scripts often assume binaries under `../binary_test/` and may use absolute paths in older CSV workflows — adjust paths at the top of each script if needed.

## Scripts

### Static analysis — `benchmark.py`

Compares original vs obfuscated PE metrics (file size, branch density, cyclomatic complexity, block/edge counts, etc.).

```powershell
python benchmark.py
```

Outputs: CSV tables such as `benchmark_comparison_all.csv` (names may vary by version).

### Runtime — `benchmark_runtime.py`

Runs binaries and records timing / resource samples.

```powershell
python benchmark_runtime.py
```

### Reverse-engineering time — `benchmark_time_pro.py`

Measures automated analysis duration on original vs obfuscated samples.

```powershell
python benchmark_time_pro.py
```

### Plots

| Script | Role |
|--------|------|
| `boxplot_runtime.py` | Runtime distributions |
| `boxplot_tech.py` | Technique comparison plots |
| `boxplot_time.py` | Analysis-time plots |

```powershell
python boxplot_runtime.py
python boxplot_tech.py
python boxplot_time.py
```

## Interpreting results

| Metric direction | Typical CFF effect | Typical junk effect |
|------------------|--------------------|---------------------|
| File size | ↑ (new section) | ↑ (many sections / code) |
| Branch / block counts | ↑ (dispatcher) | ↑ (junk + jumps) |
| Runtime | Moderate–high overhead | Mild–moderate overhead |
| Static RE effort | Higher | Higher |

Results depend heavily on **which functions** were transformed and compiler settings of the test programs.

## Relation to unit tests

| Suite | Question answered |
|-------|-------------------|
| `binary_test/match_check.py` | “Does behavior match?” |
| `benchmark/*` | “How expensive / complex is the result?” |

Always run behavioral checks before trusting benchmark claims.

## See also

- [testing.md](testing.md)  
- [overview.md](overview.md)  
