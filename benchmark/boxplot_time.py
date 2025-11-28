import pandas as pd
import matplotlib.pyplot as plt

# ───────────────────────────────────────────────
# 1) Read data
df = pd.read_csv('benchmark_time_compare.csv')

# 2) Label techniques
technique_labels = {
    'cff': 'Control Flow Obfuscation',
    'junk': 'Junk Code Insertion'
}
df['Technique'] = df['Type'].map(technique_labels)

# 3) English labels for diff columns
column_names_english = {
    "time_load_diff(%)": "Load Time Difference (%)",
    "time_cfg_diff(%)": "CFG Construction Time Difference (%)",
    "time_disasm_diff(%)": "Disassembly Time Difference (%)",
    "time_total_diff(%)": "Total Time Difference (%)"
}

# ───────────────────────────────────────────────
# 4) Filter % diff columns
comparison_columns = [
    c for c in df.select_dtypes(include='number').columns
    if 'diff(%)' in c.lower()
]

# 5) Function to remove outliers using IQR
def remove_outliers(s):
    q1 = s.quantile(0.25)
    q3 = s.quantile(0.75)
    iqr = q3 - q1
    lower, upper = q1 - 1.5 * iqr, q3 + 1.5 * iqr
    return s[(s >= lower) & (s <= upper)]

# ───────────────────────────────────────────────
# 6) Draw boxplot
for metric in comparison_columns:
    plt.figure(figsize=(6, 5))

    group1 = remove_outliers(
        df.loc[df['Technique'] == 'Control Flow Obfuscation', metric].dropna())
    group2 = remove_outliers(
        df.loc[df['Technique'] == 'Junk Code Insertion', metric].dropna())
    
    if group1.empty or group2.empty:
        print(f'Skipping "{metric}" (no data remaining after removing outliers).')
        continue

    plt.boxplot(
        [group1, group2],
        positions=[1, 1.6],
        widths=0.35,
        labels=['Control Flow\nObfuscation', 'Junk Code\nInsertion'],
        flierprops=dict(marker='', linestyle='none'),  # 🚫 Hide outliers
        manage_ticks=False
    )

    plt.xticks([1, 1.6], ['CFF', 'JCI'], fontsize=16)  # increase font size
    nice_name = column_names_english.get(metric, metric)

    # plt.title(f'Boxplot of {nice_name}')
    # plt.xlabel('Technique')
    plt.ylabel(nice_name, fontsize=16)  # increase font size
    plt.yscale('symlog', linthresh=1)
    plt.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tick_params(axis='y', labelsize=14)  # increase font size on y-axis numbers
    plt.tight_layout()
    plt.show()