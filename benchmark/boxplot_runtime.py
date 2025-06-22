import pandas as pd
import matplotlib.pyplot as plt

# 1. Đọc dữ liệu từ file CSV
df = pd.read_csv('benchmark_runtime_only.csv')

# 2. Gắn nhãn kỹ thuật tiếng Việt
nhan_ky_thuat = {
    'cff': 'Làm Rối Luồng Điều Khiển',
    'junk': 'Chèn Mã Rác'
}
df['Kỹ Thuật'] = df['Type'].map(nhan_ky_thuat)

# 3. Lọc dữ liệu cho mỗi kỹ thuật
chi_so = "runtime_diff(%)"
nhom1 = df.loc[df['Kỹ Thuật'] == 'Làm Rối Luồng Điều Khiển', chi_so].dropna()
nhom2 = df.loc[df['Kỹ Thuật'] == 'Chèn Mã Rác', chi_so].dropna()

# 4. Vẽ biểu đồ boxplot và ẩn outlier
plt.figure(figsize=(6, 5))
plt.boxplot(
    [nhom1, nhom2],
    positions=[1, 1.6],
    widths=0.35,
    labels=['Làm Rối\nLuồng Điều Khiển', 'Chèn\nMã Rác'],
    manage_ticks=False,
    showfliers=False  # <-- Đã ẩn outlier tại đây
)

# 5. Tùy chỉnh các thành phần của biểu đồ
plt.xticks([1, 1.6], ['CFF', 'JCI'], fontsize=16)  # tăng kích cỡ chữ
# plt.title('Biểu Đồ Boxplot Của Chênh Lệch Thời Gian Thực Thi (%)')
# plt.xlabel('Kỹ Thuật')
plt.ylabel('Chênh lệch Thời Gian Thực Thi (%)', fontsize=16)  # tăng kích cỡ chữ
plt.grid(axis='y', linestyle='--', alpha=0.4)

# 6. Đặt thang đo của trục Y thành 'symlog'
plt.yscale('symlog') # <-- Vẫn giữ thang đo symlog
plt.tick_params(axis='y', labelsize=14)  # tăng kích cỡ chữ số trên trục y

plt.tight_layout()

# 7. Lưu biểu đồ ra file ảnh để hiển thị
plt.show()