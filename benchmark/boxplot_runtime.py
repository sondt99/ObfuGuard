import pandas as pd
import matplotlib.pyplot as plt

# 1. Read data from CSV file
df = pd.read_csv('benchmark_runtime_only.csv')

# 2. Label techniques in English
technique_labels = {
    'cff': 'Control Flow Obfuscation',
    'junk': 'Junk Code Insertion'
}
df['Technique'] = df['Type'].map(technique_labels)

# 3. Filter data for each technique
metric = "runtime_diff(%)"
group1 = df.loc[df['Technique'] == 'Control Flow Obfuscation', metric].dropna()
group2 = df.loc[df['Technique'] == 'Junk Code Insertion', metric].dropna()

# 4. Draw boxplot and hide outliers
plt.figure(figsize=(6, 5))
plt.boxplot(
    [group1, group2],
    positions=[1, 1.6],
    widths=0.35,
    labels=['Control Flow\nObfuscation', 'Junk Code\nInsertion'],
    manage_ticks=False,
    showfliers=False  # <-- Outliers hidden here
)

# 5. Customize chart components
plt.xticks([1, 1.6], ['CFF', 'JCI'], fontsize=16)  # increase font size
# plt.title('Boxplot of Runtime Time Difference (%)')
# plt.xlabel('Technique')
plt.ylabel('Runtime Time Difference (%)', fontsize=16)  # increase font size
plt.grid(axis='y', linestyle='--', alpha=0.4)

# 6. Set Y-axis scale to 'symlog'
plt.yscale('symlog') # <-- Still keeping symlog scale
plt.tick_params(axis='y', labelsize=14)  # increase font size on y-axis numbers

plt.tight_layout()

# 7. Save chart to image file for display
plt.show()