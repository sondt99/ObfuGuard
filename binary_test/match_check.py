import subprocess
import os
from pathlib import Path

root_dir = Path(r"E:\Graduation-Thesis-HUST\binary_test")

same_outputs = []
diff_outputs = []

def run_binary(exe_path: Path):
    try:
        result = subprocess.run(
            [str(exe_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            input=b'',  # thêm input nếu binary yêu cầu
            shell=True  # để chạy được .exe
        )
        return result.stdout.decode(errors='ignore').strip()
    except Exception as e:
        return f"[ERROR] {e}"

def compare_outputs(original, cff, junk):
    out_ori = run_binary(original)
    out_cff = run_binary(cff)
    out_junk = run_binary(junk)

    print(f"\n[+] Checking: {original.name}")
    is_same_cff = (out_ori == out_cff)
    is_same_junk = (out_ori == out_junk)

    if is_same_cff and is_same_junk:
        print("  [OK] Outputs match (original == cff == junk)")
        same_outputs.append(original.name)
    else:
        print("  [!] Output mismatch:")
        if not is_same_cff:
            print("    - original != cff")
        if not is_same_junk:
            print("    - original != junk")
        diff_outputs.append(original.name)

def main():
    for folder in root_dir.iterdir():
        if not folder.is_dir():
            continue

        exes = list(folder.glob("*.exe"))
        pdbs = list(folder.glob("*.pdb"))

        if not pdbs:
            continue

        for pdb in pdbs:
            stem = pdb.stem
            original = folder / f"{stem}.exe"
            cff = folder / f"{stem}.cff.exe"
            junk = folder / f"{stem}.junk.exe"

            if original.exists() and cff.exists() and junk.exists():
                compare_outputs(original, cff, junk)

    print("\n======== SUMMARY ========")
    print(f"[=] Total binaries checked: {len(same_outputs) + len(diff_outputs)}")
    print(f"[+] Matched outputs: {len(same_outputs)}")
    print(f"[!] Mismatched outputs: {len(diff_outputs)}")

    if diff_outputs:
        print("\n[!] Files with differences:")
        for name in diff_outputs:
            print(f"  - {name}")

if __name__ == "__main__":
    main()
