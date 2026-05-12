import os
import csv
import time
import subprocess
import logging
import statistics
import gc
import psutil
import sys
from typing import List, Tuple, Optional

# Turn off logs
logging.getLogger().setLevel(logging.CRITICAL)

# Output files
OUTPUT_CSV = "benchmark_runtime_only.csv"
OUTPUT_DETAILED = "benchmark_runtime_detailed.csv"

# Benchmark configuration
class BenchmarkConfig:
    WARMUP_RUNS = 3              # Number of warm-up runs
    MEASUREMENT_RUNS = 10        # Number of official measurement runs
    TIMEOUT_SECONDS = 5          # Timeout for each run
    OUTLIER_THRESHOLD = 2.5      # Z-score to remove outliers
    CPU_AFFINITY = 0             # Fixed CPU core (None = don't set)
    HIGH_PRIORITY = True         # Run with high priority
    IDLE_TIME = 0.1              # Wait time between measurements (seconds)
    MIN_VALID_RUNS = 5           # Minimum valid runs for valid results

def set_process_priority():
    """Set high priority for benchmark process"""
    if not BenchmarkConfig.HIGH_PRIORITY:
        return
    
    try:
        p = psutil.Process(os.getpid())
        if sys.platform == "win32":
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        else:
            p.nice(-10)  # Unix/Linux (requires sudo)
    except Exception as e:
        print(f"[!] Cannot set high priority: {e}")

def set_cpu_affinity():
    """Bind process to fixed CPU core"""
    if BenchmarkConfig.CPU_AFFINITY is None:
        return
    
    try:
        p = psutil.Process(os.getpid())
        p.cpu_affinity([BenchmarkConfig.CPU_AFFINITY])
    except Exception as e:
        print(f"[!] Cannot set CPU affinity: {e}")

def wait_for_system_idle():
    """Wait for system to stabilize before measurement"""
    time.sleep(BenchmarkConfig.IDLE_TIME)
    gc.collect()
    gc.disable()  # Turn off GC during measurement

def restore_system_state():
    """Restore system state after measurement"""
    gc.enable()
    gc.collect()

def remove_outliers(values: List[float]) -> List[float]:
    """Remove outliers using Z-score"""
    if len(values) < 3:
        return values
    
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)
    
    if stdev == 0:
        return values
    
    z_scores = [(x - mean) / stdev for x in values]
    filtered = [v for v, z in zip(values, z_scores) 
                if abs(z) < BenchmarkConfig.OUTLIER_THRESHOLD]
    
    # Ensure enough measurements remain
    if len(filtered) < BenchmarkConfig.MIN_VALID_RUNS:
        # If too many are removed, keep MIN_VALID_RUNS values closest to mean
        sorted_by_distance = sorted(values, key=lambda x: abs(x - mean))
        return sorted_by_distance[:BenchmarkConfig.MIN_VALID_RUNS]
    
    return filtered

def single_runtime_measurement(path: str) -> Tuple[float, bool]:
    """
    Measure runtime once
    Returns: (runtime_ms, is_valid)
    """
    wait_for_system_idle()
    
    try:
        # Use perf_counter_ns for highest accuracy
        start_ns = time.perf_counter_ns()
        
        # Configure subprocess to reduce overhead
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        
        result = subprocess.run(
            [path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=BenchmarkConfig.TIMEOUT_SECONDS,
            startupinfo=startupinfo,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        )
        
        end_ns = time.perf_counter_ns()
        runtime_ms = (end_ns - start_ns) / 1_000_000.0
        
        restore_system_state()
        
        # Check exit code
        if result.returncode != 0:
            print(f"  [!] Non-zero exit code: {result.returncode}")
            return runtime_ms, False
        
        return runtime_ms, True
        
    except subprocess.TimeoutExpired:
        restore_system_state()
        return -1, False
    except Exception as e:
        restore_system_state()
        print(f"  [!] Error: {e}")
        return -2, False

def benchmark_runtime_with_stats(path: str) -> Optional[dict]:
    """
    Run benchmark multiple times and calculate statistics
    Returns: dict with metrics or None if error
    """
    print(f"\n[*] Benchmarking: {os.path.basename(path)}")
    
    # Warm-up runs
    print(f"  Warm-up ({BenchmarkConfig.WARMUP_RUNS} runs)...", end='', flush=True)
    for i in range(BenchmarkConfig.WARMUP_RUNS):
        runtime, _ = single_runtime_measurement(path)
        print("." if runtime > 0 else "x", end='', flush=True)
    print(" done")
    
    # Measurement runs
    valid_runs = []
    failed_runs = 0
    
    print(f"  Measuring ({BenchmarkConfig.MEASUREMENT_RUNS} runs)...", end='', flush=True)
    for i in range(BenchmarkConfig.MEASUREMENT_RUNS):
        runtime, is_valid = single_runtime_measurement(path)
        
        if runtime > 0 and is_valid:
            valid_runs.append(runtime)
            print(".", end='', flush=True)
        else:
            failed_runs += 1
            print("x", end='', flush=True)
    print(" done")
    
    if len(valid_runs) < BenchmarkConfig.MIN_VALID_RUNS:
        print(f"  [!] Not enough valid runs ({len(valid_runs)}/{BenchmarkConfig.MIN_VALID_RUNS})")
        return None
    
    # Remove outliers
    filtered_runs = remove_outliers(valid_runs)
    outliers_removed = len(valid_runs) - len(filtered_runs)

    # Calculate statistics
    stats = {
        'mean': statistics.mean(filtered_runs),
        'median': statistics.median(filtered_runs),
        'stdev': statistics.stdev(filtered_runs) if len(filtered_runs) > 1 else 0,
        'min': min(filtered_runs),
        'max': max(filtered_runs),
        'valid_runs': len(filtered_runs),
        'total_runs': BenchmarkConfig.MEASUREMENT_RUNS,
        'outliers_removed': outliers_removed,
        'cv': 0  # Coefficient of variation
    }
    
    # Calculate CV (coefficient of variation)
    if stats['mean'] > 0:
        stats['cv'] = (stats['stdev'] / stats['mean']) * 100
    
    print(f"  Mean: {stats['mean']:.3f}ms ± {stats['stdev']:.3f}ms (CV: {stats['cv']:.1f}%)")
    print(f"  Valid runs: {stats['valid_runs']}/{stats['total_runs']}, Outliers: {stats['outliers_removed']}")
    
    return stats

def percent_diff(new, old):
    return 0.0 if old == 0 else (new - old) / old * 100.0

def find_original_binaries(root="."):
    for subdir, _, files in os.walk(root):
        for f in files:
            if f.endswith(".exe") and ".cff." not in f and ".junk." not in f:
                yield os.path.join(subdir, f)

def write_csv_headers():
    """Create headers for both CSV files"""
    # Main CSV (summary)
    fieldnames_main = [
        "Original", "Variant", "Type",
        "runtime_orig_mean", "runtime_variant_mean", "runtime_diff(%)",
        "orig_cv(%)", "variant_cv(%)"
    ]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=fieldnames_main).writeheader()

    # Detailed CSV
    fieldnames_detail = [
        "Binary", "Type", "Mean", "Median", "StdDev", "Min", "Max",
        "CV(%)", "ValidRuns", "TotalRuns", "OutliersRemoved"
    ]
    with open(OUTPUT_DETAILED, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=fieldnames_detail).writeheader()

def append_detailed_stats(binary_path, binary_type, stats):
    """Write detailed statistics"""
    row = {
        "Binary": os.path.basename(binary_path),
        "Type": binary_type,
        "Mean": round(stats['mean'], 3),
        "Median": round(stats['median'], 3),
        "StdDev": round(stats['stdev'], 3),
        "Min": round(stats['min'], 3),
        "Max": round(stats['max'], 3),
        "CV(%)": round(stats['cv'], 2),
        "ValidRuns": stats['valid_runs'],
        "TotalRuns": stats['total_runs'],
        "OutliersRemoved": stats['outliers_removed']
    }
    with open(OUTPUT_DETAILED, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=row.keys()).writerow(row)

def append_comparison_row(orig_path, variant_path, variant_type, orig_stats, variant_stats):
    """Write comparison to main CSV"""
    row = {
        "Original": os.path.basename(orig_path),
        "Variant": os.path.basename(variant_path),
        "Type": variant_type,
        "runtime_orig_mean": round(orig_stats['mean'], 3),
        "runtime_variant_mean": round(variant_stats['mean'], 3),
        "runtime_diff(%)": round(percent_diff(variant_stats['mean'], orig_stats['mean']), 2),
        "orig_cv(%)": round(orig_stats['cv'], 2),
        "variant_cv(%)": round(variant_stats['cv'], 2)
    }
    with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=row.keys()).writerow(row)

def main():
    print(f"=== Enhanced Runtime Benchmark ===")
    print(f"Warm-up runs: {BenchmarkConfig.WARMUP_RUNS}")
    print(f"Measurement runs: {BenchmarkConfig.MEASUREMENT_RUNS}")
    print(f"Outlier threshold: {BenchmarkConfig.OUTLIER_THRESHOLD} σ")
    print(f"CPU affinity: {BenchmarkConfig.CPU_AFFINITY}")
    print(f"High priority: {BenchmarkConfig.HIGH_PRIORITY}")
    
    # System setup
    set_process_priority()
    set_cpu_affinity()

    # Create CSV headers
    write_csv_headers()
    
    # Benchmark
    for orig in find_original_binaries("../binary_test"):
        orig_stats = benchmark_runtime_with_stats(orig)
        if not orig_stats:
            print(f"[!] Skipping {orig} due to benchmark error")
            continue

        # Write detailed stats of original
        append_detailed_stats(orig, "original", orig_stats)
        
        base_name, _ = os.path.splitext(orig)
        for suffix, variant_type in [(".cff.exe", "cff"), (".junk.exe", "junk")]:
            variant_path = base_name + suffix
            if not os.path.exists(variant_path):
                continue
            
            variant_stats = benchmark_runtime_with_stats(variant_path)
            if not variant_stats:
                print(f"[!] Skipping {variant_path} due to benchmark error")
                continue
            
            # Write detailed stats of variant
            append_detailed_stats(variant_path, variant_type, variant_stats)

            # Write comparison
            append_comparison_row(orig, variant_path, variant_type, orig_stats, variant_stats)

            # Display results
            diff = percent_diff(variant_stats['mean'], orig_stats['mean'])
            print(f"[✓] {variant_type.upper()}: {diff:+.2f}% "
                  f"({orig_stats['mean']:.3f}ms → {variant_stats['mean']:.3f}ms)")

    print(f"\n✅ Completed!")
    print(f"📊 Summary results: {OUTPUT_CSV}")
    print(f"📊 Detailed results: {OUTPUT_DETAILED}")

if __name__ == "__main__":
    main()