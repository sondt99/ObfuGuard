import subprocess
import os
import re
from pathlib import Path

obfuguard_path = r"E:\Graduation-Thesis-HUST\x64\Release\ObfuGuard-con.exe"
root_dir = Path(r"E:\Graduation-Thesis-HUST\binary_test")

def run_obfuscation(mode_input: str):
    try:
        process = subprocess.run(
            [obfuguard_path],
            input=mode_input.encode('utf-8'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        output = process.stdout.decode(errors='ignore')
        if process.returncode != 0:
            raise RuntimeError("Process returned non-zero exit code")

        match = re.search(r"Output saved to:\s*(.*\.exe)", output)
        return match.group(1) if match else "[!] Output path not found."

    except Exception as e:
        return f"[!] Error: {str(e)}"

def process_binary(binary_path: Path):
    print(f"\n[+] Processing: {binary_path.name}")

    # Control Flow Flattening
    cff_output = run_obfuscation(f"1\n{binary_path}\n")
    if "Error" in cff_output:
        print(f"  [-] CFF Failed: {cff_output}")
        return

    print(f"  [CFF] Output: {cff_output}")

    # Junk Code Injection
    junk_output = run_obfuscation(f"2\n{binary_path}\n1\n")
    if "Error" in junk_output:
        print(f"  [-] Junk Code Injection Failed: {junk_output}")
        return

    print(f"  [JUNK] Output: {junk_output}")

def main():
    for folder in root_dir.iterdir():
        if not folder.is_dir():
            continue

        pdb_files = list(folder.glob("*.pdb"))
        if not pdb_files:
            print(f"[!] No .pdb file found in {folder.name}, skipping.")
            continue

        for pdb_file in pdb_files:
            exe_name = pdb_file.stem + ".exe"
            exe_path = folder / exe_name
            if exe_path.exists():
                process_binary(exe_path)
            else:
                print(f"[!] .exe not found for {pdb_file.name} in {folder.name}, skipping.")

if __name__ == "__main__":
    main()
