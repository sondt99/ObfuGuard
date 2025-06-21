import pandas as pd
import matplotlib.pyplot as plt

# ───────────────────────────────────────────────
# 1) Đọc dữ liệu
df = pd.read_csv('benchmark_time_compare.csv')

# 2) Gắn nhãn kỹ thuật
nhan_ky_thuat = {
    'cff': 'Làm Rối Luồng Điều Khiển',
    'junk': 'Chèn Mã Rác'
}
df['Kỹ Thuật'] = df['Type'].map(nhan_ky_thuat)

# 3) Nhãn tiếng Việt cho các cột diff
ten_cot_tieng_viet = {
    "time_load_diff(%)": "Chênh lệch Thời Gian Tải (%)",
    "time_cfg_diff(%)": "Chênh lệch Thời Gian tái tạo CFG (%)",
    "time_disasm_diff(%)": "Chênh lệch Thời Gian Dịch Ngược (%)",
    "time_total_diff(%)": "Chênh lệch Tổng Thời Gian (%)"
}

# ───────────────────────────────────────────────
# 4) Lọc cột % diff
cot_so_sanh = [
    c for c in df.select_dtypes(include='number').columns
    if 'diff(%)' in c.lower()
]

# 5) Hàm loại bỏ ngoại lai theo IQR
def loai_bo_ngoai_lai(s):
    q1 = s.quantile(0.25)
    q3 = s.quantile(0.75)
    iqr = q3 - q1
    duoi, tren = q1 - 1.5 * iqr, q3 + 1.5 * iqr
    return s[(s >= duoi) & (s <= tren)]

# ───────────────────────────────────────────────
# 6) Vẽ biểu đồ hộp
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
        flierprops=dict(marker='', linestyle='none'),  # 🚫 Ẩn outlier
        manage_ticks=False
    )
    
    plt.xticks([1, 1.6], ['CFF', 'JCI'], fontsize=16)  # tăng kích cỡ chữ
    ten_dep = ten_cot_tieng_viet.get(chi_so, chi_so)
    
    # plt.title(f'Biểu Đồ Boxplot Của {ten_dep}')
    # plt.xlabel('Kỹ Thuật')
    plt.ylabel(ten_dep, fontsize=16)  # tăng kích cỡ chữ
    plt.yscale('symlog', linthresh=1)
    plt.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tick_params(axis='y', labelsize=14)  # tăng kích cỡ chữ số trên trục y
    plt.tight_layout()
    plt.show()