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

# Tắt log
logging.getLogger().setLevel(logging.CRITICAL)

# Output files
OUTPUT_CSV = "benchmark_runtime_only.csv"
OUTPUT_DETAILED = "benchmark_runtime_detailed.csv"

# Cấu hình benchmark
class BenchmarkConfig:
    WARMUP_RUNS = 3              # Số lần chạy warm-up
    MEASUREMENT_RUNS = 10        # Số lần đo chính thức
    TIMEOUT_SECONDS = 5          # Timeout cho mỗi lần chạy
    OUTLIER_THRESHOLD = 2.5      # Z-score để loại outliers
    CPU_AFFINITY = 0             # CPU core cố định (None = không set)
    HIGH_PRIORITY = True         # Chạy với priority cao
    IDLE_TIME = 0.1              # Thời gian chờ giữa các lần đo (giây)
    MIN_VALID_RUNS = 5           # Số lần chạy tối thiểu để kết quả hợp lệ

def set_process_priority():
    """Đặt priority cao cho process benchmark"""
    if not BenchmarkConfig.HIGH_PRIORITY:
        return
    
    try:
        p = psutil.Process(os.getpid())
        if sys.platform == "win32":
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        else:
            p.nice(-10)  # Unix/Linux (cần sudo)
    except Exception as e:
        print(f"[!] Không thể set priority cao: {e}")

def set_cpu_affinity():
    """Gán process vào CPU core cố định"""
    if BenchmarkConfig.CPU_AFFINITY is None:
        return
    
    try:
        p = psutil.Process(os.getpid())
        p.cpu_affinity([BenchmarkConfig.CPU_AFFINITY])
    except Exception as e:
        print(f"[!] Không thể set CPU affinity: {e}")

def wait_for_system_idle():
    """Đợi hệ thống ổn định trước khi đo"""
    time.sleep(BenchmarkConfig.IDLE_TIME)
    gc.collect()
    gc.disable()  # Tắt GC trong khi đo

def restore_system_state():
    """Khôi phục trạng thái hệ thống sau khi đo"""
    gc.enable()
    gc.collect()

def remove_outliers(values: List[float]) -> List[float]:
    """Loại bỏ outliers dùng Z-score"""
    if len(values) < 3:
        return values
    
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)
    
    if stdev == 0:
        return values
    
    z_scores = [(x - mean) / stdev for x in values]
    filtered = [v for v, z in zip(values, z_scores) 
                if abs(z) < BenchmarkConfig.OUTLIER_THRESHOLD]
    
    # Đảm bảo còn đủ số lần đo
    if len(filtered) < BenchmarkConfig.MIN_VALID_RUNS:
        # Nếu loại quá nhiều, giữ lại MIN_VALID_RUNS giá trị gần mean nhất
        sorted_by_distance = sorted(values, key=lambda x: abs(x - mean))
        return sorted_by_distance[:BenchmarkConfig.MIN_VALID_RUNS]
    
    return filtered

def single_runtime_measurement(path: str) -> Tuple[float, bool]:
    """
    Đo runtime một lần
    Returns: (runtime_ms, is_valid)
    """
    wait_for_system_idle()
    
    try:
        # Dùng perf_counter_ns cho độ chính xác cao nhất
        start_ns = time.perf_counter_ns()
        
        # Cấu hình subprocess để giảm overhead
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
        
        # Kiểm tra exit code
        if result.returncode != 0:
            print(f"  [!] Exit code khác 0: {result.returncode}")
            return runtime_ms, False
        
        return runtime_ms, True
        
    except subprocess.TimeoutExpired:
        restore_system_state()
        return -1, False
    except Exception as e:
        restore_system_state()
        print(f"  [!] Lỗi: {e}")
        return -2, False

def benchmark_runtime_with_stats(path: str) -> Optional[dict]:
    """
    Chạy benchmark nhiều lần và tính statistics
    Returns: dict với các metrics hoặc None nếu lỗi
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
        print(f"  [!] Không đủ lần chạy hợp lệ ({len(valid_runs)}/{BenchmarkConfig.MIN_VALID_RUNS})")
        return None
    
    # Loại outliers
    filtered_runs = remove_outliers(valid_runs)
    outliers_removed = len(valid_runs) - len(filtered_runs)
    
    # Tính statistics
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
    
    # Tính CV (độ biến thiên tương đối)
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
    """Tạo headers cho cả 2 file CSV"""
    # CSV chính (summary)
    fieldnames_main = [
        "Original", "Variant", "Type",
        "runtime_orig_mean", "runtime_variant_mean", "runtime_diff(%)",
        "orig_cv(%)", "variant_cv(%)"
    ]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=fieldnames_main).writeheader()
    
    # CSV chi tiết
    fieldnames_detail = [
        "Binary", "Type", "Mean", "Median", "StdDev", "Min", "Max",
        "CV(%)", "ValidRuns", "TotalRuns", "OutliersRemoved"
    ]
    with open(OUTPUT_DETAILED, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=fieldnames_detail).writeheader()

def append_detailed_stats(binary_path, binary_type, stats):
    """Ghi statistics chi tiết"""
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
    """Ghi so sánh vào CSV chính"""
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
    
    # Setup hệ thống
    set_process_priority()
    set_cpu_affinity()
    
    # Tạo CSV headers
    write_csv_headers()
    
    # Benchmark
    for orig in find_original_binaries("."):
        orig_stats = benchmark_runtime_with_stats(orig)
        if not orig_stats:
            print(f"[!] Bỏ qua {orig} do lỗi benchmark")
            continue
        
        # Ghi stats chi tiết của original
        append_detailed_stats(orig, "original", orig_stats)
        
        base_name, _ = os.path.splitext(orig)
        for suffix, variant_type in [(".cff.exe", "cff"), (".junk.exe", "junk")]:
            variant_path = base_name + suffix
            if not os.path.exists(variant_path):
                continue
            
            variant_stats = benchmark_runtime_with_stats(variant_path)
            if not variant_stats:
                print(f"[!] Bỏ qua {variant_path} do lỗi benchmark")
                continue
            
            # Ghi stats chi tiết của variant
            append_detailed_stats(variant_path, variant_type, variant_stats)
            
            # Ghi comparison
            append_comparison_row(orig, variant_path, variant_type, orig_stats, variant_stats)
            
            # Hiển thị kết quả
            diff = percent_diff(variant_stats['mean'], orig_stats['mean'])
            print(f"[✓] {variant_type.upper()}: {diff:+.2f}% "
                  f"({orig_stats['mean']:.3f}ms → {variant_stats['mean']:.3f}ms)")

    print(f"\n✅ Hoàn tất!")
    print(f"📊 Kết quả summary: {OUTPUT_CSV}")
    print(f"📊 Kết quả chi tiết: {OUTPUT_DETAILED}")

if __name__ == "__main__":
    main()