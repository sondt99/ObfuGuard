import os
import subprocess
import time
import angr
import sys

def get_filesize(path):
    """Lấy kích thước file theo bytes."""
    return os.path.getsize(path)


def check_file_exists(path):
    """Kiểm tra file có tồn tại không."""
    if not os.path.isfile(path):
        print(f"Lỗi: File không tồn tại hoặc không phải là file: {path}")
        sys.exit(1)

def measure_runtime(executable_path):
    """Đo thời gian chạy của file thực thi."""
    print(f"Đang thực thi {os.path.basename(executable_path)}...")
    start = time.perf_counter()
    try:
        subprocess.run([executable_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60) # Thêm timeout để tránh treo
    except subprocess.TimeoutExpired:
        print(f"Cảnh báo: {os.path.basename(executable_path)} chạy quá lâu và đã bị dừng.")
        return float('inf')
    end = time.perf_counter()
    runtime = end - start
    return runtime

def analyze_binary_with_angr(binary_path):
    """
    Phân tích file thực thi bằng angr để lấy thông tin CFG và số lượng hàm.
    """
    print(f"Đang phân tích {os.path.basename(binary_path)} với angr (có thể mất vài phút)...")
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    
    num_nodes = len(cfg.graph.nodes)
    num_edges = len(cfg.graph.edges)
    num_functions = len(proj.kb.functions)
    
    return num_nodes, num_edges, num_functions

def calculate_cyclomatic_complexity(edges, nodes):
    """
    Tính độ phức tạp Cyclomatic từ số cạnh và nút của CFG.
    Công thức: M = E - N + 2
    """
    return edges - nodes + 2

def percent_change(before, after):
    """Tính phần trăm thay đổi."""
    if before == 0 and after > 0:
        return float('inf')
    if before == 0 and after == 0:
        return 0.0
    return ((after - before) / before) * 100

def print_comparison(metric, before, after):
    """In kết quả so sánh một cách định dạng."""
    change = percent_change(before, after)
    sign = "+" if change >= 0 else ""
    print(f"{metric}:")
    print(f"  Trước: {before}")
    print(f"  Sau  : {after}")
    print(f"  Thay đổi: {sign}{change:.2f}%\n")

def main(file_before, file_after):
    print("=== Bắt đầu Benchmark Files ===\n")
    
    # Kiểm tra sự tồn tại của file
    check_file_exists(file_before)
    check_file_exists(file_after)

    # 1. So sánh kích thước file
    size_before = get_filesize(file_before)
    size_after = get_filesize(file_after)
    print_comparison("Kích thước file (bytes)", size_before, size_after)

    # 2. So sánh thời gian chạy
    runtime_before = measure_runtime(file_before)
    runtime_after = measure_runtime(file_after)
    print_comparison("Thời gian chạy (giây)", runtime_before, runtime_after)

    # 3. Phân tích bằng Angr
    nodes_before, edges_before, funcs_before = analyze_binary_with_angr(file_before)
    nodes_after, edges_after, funcs_after = analyze_binary_with_angr(file_after)
    
    print_comparison("CFG Nodes", nodes_before, nodes_after)
    print_comparison("CFG Edges", edges_before, edges_after)

    # 4. So sánh số lượng hàm (MỚI)
    print_comparison("Số lượng hàm", funcs_before, funcs_after)

    # 5. So sánh độ phức tạp Cyclomatic (MỚI)
    complexity_before = calculate_cyclomatic_complexity(edges_before, nodes_before)
    complexity_after = calculate_cyclomatic_complexity(edges_after, nodes_after)
    print_comparison("Độ phức tạp Cyclomatic", complexity_before, complexity_after)
    
    print("=== Benchmark Hoàn tất ===")


if __name__ == "__main__":
    # file_before = "../binary_test/x64/Debug/binary_test.exe"
    # file_after = "../core/test/build/Debug/junkcode_test.exe"
    file_before = input("Nhập đường dẫn file binary gốc: ").strip()
    file_after = input("Nhập đường dẫn file binary đã làm rối: ").strip()
    main(file_before, file_after)