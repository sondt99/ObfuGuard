import pandas as pd
import matplotlib.pyplot as plt

# ───────────────────────────────────────────────
# 1) Đọc dữ liệu
df = pd.read_csv('benchmark_comparison_all.csv')  # đổi đường dẫn nếu cần

# 2) Gắn nhãn kỹ thuật
nhan_ky_thuat = {
    'cff': 'Làm Rối Luồng Điều Khiển',
    'junk': 'Chèn Mã Rác'
}
df['Kỹ Thuật'] = df['Type'].map(nhan_ky_thuat)

ten_cot_tieng_viet = {
    "Original": "Gốc",
    "Variant": "Biến Thể",
    "Type": "Loại Kỹ Thuật",
    
    "file_size_orig": "Kích Thước Tập Tin (Gốc)",
    "file_size_variant": "Kích Thước Tập Tin (Biến Thể)",
    "file_size_diff(%)": "Chênh Lệch Kích Thước (%)",
    
    "branches_orig": "Số Nhánh (Gốc)",
    "branches_variant": "Số Nhánh (Biến Thể)",
    "branches_diff(%)": "Chênh Lệch Số Nhánh (%)",
    
    "instructions_orig": "Số Lệnh (Gốc)",
    "instructions_variant": "Số Lệnh (Biến Thể)",
    "instructions_diff(%)": "Chênh Lệch Số Lệnh (%)",
    
    "branch_density_orig": "Mật Độ Nhánh (Gốc)",
    "branch_density_variant": "Mật Độ Nhánh (Biến Thể)",
    "branch_density_diff(%)": "Chênh Lệch Mật Độ Nhánh (%)",
    
    "cyclomatic_complexity_orig": "Độ Phức Tạp Chu Trình (Gốc)",
    "cyclomatic_complexity_variant": "Độ Phức Tạp Chu Trình (Biến Thể)",
    "cyclomatic_complexity_diff(%)": "Chênh Lệch Độ Phức Tạp Chu Trình (%)",
    
    "functions_orig": "Số Hàm (Gốc)",
    "functions_variant": "Số Hàm (Biến Thể)",
    "functions_diff(%)": "Chênh Lệch Số Hàm (%)",
    
    "blocks_orig": "Số Khối (Gốc)",
    "blocks_variant": "Số Khối (Biến Thể)",
    "blocks_diff(%)": "Chênh Lệch Số Khối (%)",
    
    "nodes_orig": "Số Nút (Gốc)",
    "nodes_variant": "Số Nút (Biến Thể)",
    "nodes_diff(%)": "Chênh Lệch Số Nút (%)",
    
    "edges_orig": "Số Cạnh (Gốc)",
    "edges_variant": "Số Cạnh (Biến Thể)",
    "edges_diff(%)": "Chênh Lệch Số Cạnh (%)"
}

# ───────────────────────────────────────────────
# 3) Lọc các cột số có chứa chữ 'diff'
cot_so_sanh = [
    c for c in df.select_dtypes(include='number').columns
    if 'diff' in c.lower()
]

print(f'Đang vẽ {len(cot_so_sanh)} cột so sánh:', cot_so_sanh)

# 4) Hàm loại bỏ giá trị ngoại lai (dựa theo IQR ± 1.5·IQR)
def loai_bo_ngoai_lai(s):
    q1 = s.quantile(0.25)
    q3 = s.quantile(0.75)
    iqr = q3 - q1
    duoi, tren = q1 - 1.5 * iqr, q3 + 1.5 * iqr
    return s[(s >= duoi) & (s <= tren)]

# ───────────────────────────────────────────────
# Vẽ biểu đồ hộp cho từng chỉ số
for chi_so in cot_so_sanh:
    plt.figure(figsize=(6, 5))
    
    nhom1 = loai_bo_ngoai_lai(
        df.loc[df['Kỹ Thuật'] == 'Làm Rối Luồng Điều Khiển', chi_so].dropna())
    nhom2 = loai_bo_ngoai_lai(
        df.loc[df['Kỹ Thuật'] == 'Chèn Mã Rác', chi_so].dropna())
    
    if nhom1.empty or nhom2.empty:
        print(f'Bỏ qua "{chi_so}" (không còn dữ liệu sau khi loại bỏ ngoại lai).')
        continue
    
    plt.boxplot(
        [nhom1, nhom2],
        positions=[1, 1.6],
        widths=0.35,
        labels=['Làm Rối\nLuồng Điều Khiển', 'Chèn\nMã Rác'],
        manage_ticks=False
    )
    plt.xticks([1, 1.6], ['CFF', 'JCI'], fontsize=16)  # tăng kích cỡ chữ
    
    # Đổi tên trục y cho dễ nhìn
    ten_dep = ten_cot_tieng_viet.get(chi_so, chi_so)
    # plt.title(f'Biểu Đồ Boxplot Của {ten_dep}')
    
    # plt.xlabel('Kỹ Thuật')
    plt.ylabel(ten_dep, fontsize=16)  # tăng kích cỡ chữ
    plt.yscale('symlog', linthresh=1)
    plt.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tick_params(axis='y', labelsize=14)  # tăng kích cỡ chữ số trên trục y
    plt.tight_layout()
    plt.show()