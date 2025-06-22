import os
import csv
import time
import logging
import angr

# Ẩn log để terminal gọn
for lib in ["angr", "cle", "pyvex"]:
    logging.getLogger(lib).setLevel(logging.CRITICAL)

OUTPUT_CSV = "benchmark_time_compare.csv"

def get_text_section(project):
    return next((s for s in project.loader.main_object.sections if s.name == ".text"), None)

def analyze_timing_ms(path: str) -> dict:
    # WARM-UP RUN — không đo, chỉ để cache được thiết lập
    try:
        project_warm = angr.Project(path, auto_load_libs=False)
        _ = project_warm.analyses.CFGFast(normalize=True)
        text = get_text_section(project_warm)
        if text:
            _ = project_warm.loader.memory.load(text.vaddr, text.memsize)
    except Exception:
        pass  # nếu warm-up lỗi, cứ tiếp tục đo thật

    # MAIN RUN — bắt đầu đo thực sự
    t0 = time.perf_counter()

    # Load binary
    t_load0 = time.perf_counter()
    project = angr.Project(path, auto_load_libs=False)
    t_load1 = time.perf_counter()

    # Dựng CFGFast
    t_cfg0 = time.perf_counter()
    _ = project.analyses.CFGFast(normalize=True)
    t_cfg1 = time.perf_counter()

    # Load section .text
    text = get_text_section(project)
    t_dis0 = time.perf_counter()
    if text:
        _ = project.loader.memory.load(text.vaddr, text.memsize)
    t_dis1 = time.perf_counter()

    t_end = time.perf_counter()

    return {
        "time_load":   (t_load1 - t_load0) * 1000,
        "time_cfg":    (t_cfg1  - t_cfg0)  * 1000,
        "time_disasm": (t_dis1  - t_dis0)  * 1000,
        "time_total":  (t_end   - t0)      * 1000
    }

def percent_diff(new, old):
    return 0.0 if old == 0 else (new - old) / old * 100.0

def find_original_binaries(root):
    for subdir, _, files in os.walk(root):
        for f in files:
            if f.endswith(".exe") and ".cff." not in f and ".junk." not in f:
                yield os.path.join(subdir, f)

def write_csv_header(path):
    fieldnames = ["Original", "Variant", "Type"]
    metrics = ["time_load", "time_cfg", "time_disasm", "time_total"]
    for m in metrics:
        fieldnames += [f"{m}_orig", f"{m}_variant", f"{m}_diff(%)"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=fieldnames).writeheader()

def append_comparison_row(orig_path, variant_path, variant_type, base_metrics, variant_metrics):
    row = {
        "Original": os.path.basename(orig_path),
        "Variant": os.path.basename(variant_path),
        "Type": variant_type
    }
    for key in ["time_load", "time_cfg", "time_disasm", "time_total"]:
        orig = base_metrics[key]
        var = variant_metrics[key]
        row[f"{key}_orig"] = round(orig, 3)
        row[f"{key}_variant"] = round(var, 3)
        row[f"{key}_diff(%)"] = round(percent_diff(var, orig), 2)
    with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=row.keys()).writerow(row)

def main():
    write_csv_header(OUTPUT_CSV)
    for orig in find_original_binaries("../binary_test"):
        try:
            base_metrics = analyze_timing_ms(orig)
        except Exception as e:
            print(f"[!] Lỗi khi phân tích gốc {orig}: {e}")
            continue

        base_name, _ = os.path.splitext(orig)
        for suffix, variant_type in [(".cff.exe", "cff"), (".junk.exe", "junk")]:
            variant_path = base_name + suffix
            if not os.path.exists(variant_path):
                continue
            try:
                variant_metrics = analyze_timing_ms(variant_path)
                append_comparison_row(orig, variant_path, variant_type, base_metrics, variant_metrics)
                print(f"[✓] So sánh {os.path.basename(orig)} → {os.path.basename(variant_path)} xong.")
            except Exception as e:
                print(f"[!] Lỗi phân tích {variant_path}: {e}")

    print(f"\n✅ Đã hoàn tất. Kết quả lưu tại: {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
