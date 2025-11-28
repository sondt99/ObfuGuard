import pandas as pd
import matplotlib.pyplot as plt

# ───────────────────────────────────────────────
# 1) Read data
df = pd.read_csv('benchmark_comparison_all.csv')  # change path if needed

# 2) Label techniques
technique_labels = {
    'cff': 'Control Flow Obfuscation',
    'junk': 'Junk Code Insertion'
}
df['Technique'] = df['Type'].map(technique_labels)

column_names_english = {
    "Original": "Original",
    "Variant": "Variant",
    "Type": "Technique Type",

    "file_size_orig": "File Size (Original)",
    "file_size_variant": "File Size (Variant)",
    "file_size_diff(%)": "File Size Difference (%)",

    "branches_orig": "Number of Branches (Original)",
    "branches_variant": "Number of Branches (Variant)",
    "branches_diff(%)": "Branch Count Difference (%)",

    "instructions_orig": "Number of Instructions (Original)",
    "instructions_variant": "Number of Instructions (Variant)",
    "instructions_diff(%)": "Instruction Count Difference (%)",

    "branch_density_orig": "Branch Density (Original)",
    "branch_density_variant": "Branch Density (Variant)",
    "branch_density_diff(%)": "Branch Density Difference (%)",

    "cyclomatic_complexity_orig": "Cyclomatic Complexity (Original)",
    "cyclomatic_complexity_variant": "Cyclomatic Complexity (Variant)",
    "cyclomatic_complexity_diff(%)": "Cyclomatic Complexity Difference (%)",

    "functions_orig": "Number of Functions (Original)",
    "functions_variant": "Number of Functions (Variant)",
    "functions_diff(%)": "Function Count Difference (%)",

    "blocks_orig": "Number of Blocks (Original)",
    "blocks_variant": "Number of Blocks (Variant)",
    "blocks_diff(%)": "Block Count Difference (%)",

    "nodes_orig": "Number of Nodes (Original)",
    "nodes_variant": "Number of Nodes (Variant)",
    "nodes_diff(%)": "Node Count Difference (%)",

    "edges_orig": "Number of Edges (Original)",
    "edges_variant": "Number of Edges (Variant)",
    "edges_diff(%)": "Edge Count Difference (%)"
}

# ───────────────────────────────────────────────
# 3) Filter numeric columns containing 'diff'
comparison_columns = [
    c for c in df.select_dtypes(include='number').columns
    if 'diff' in c.lower()
]

print(f'Drawing {len(comparison_columns)} comparison columns:', comparison_columns)

# 4) Function to remove outliers (based on IQR ± 1.5·IQR)
def remove_outliers(s):
    q1 = s.quantile(0.25)
    q3 = s.quantile(0.75)
    iqr = q3 - q1
    lower, upper = q1 - 1.5 * iqr, q3 + 1.5 * iqr
    return s[(s >= lower) & (s <= upper)]

# ───────────────────────────────────────────────
# Draw boxplot for each metric
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
        manage_ticks=False
    )
    plt.xticks([1, 1.6], ['CFF', 'JCI'], fontsize=16)  # increase font size

    # Rename y-axis for better readability
    nice_name = column_names_english.get(metric, metric)
    # plt.title(f'Boxplot of {nice_name}')

    # plt.xlabel('Technique')
    plt.ylabel(nice_name, fontsize=16)  # increase font size
    plt.yscale('symlog', linthresh=1)
    plt.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tick_params(axis='y', labelsize=14)  # increase font size on y-axis numbers
    plt.tight_layout()
    plt.show()