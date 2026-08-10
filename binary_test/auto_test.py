#!/usr/bin/env python3
"""Automated ObfuGuard runner for all binaries under binary_test/."""

import os
import re
import subprocess
import sys
from pathlib import Path

# Resolve repo-relative paths (override with OBFUGUARD_EXE env var)
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_EXE = REPO_ROOT / "x64" / "Release" / "ObfuGuard.exe"
obfuguard_path = Path(os.environ.get("OBFUGUARD_EXE", str(DEFAULT_EXE)))
root_dir = SCRIPT_DIR

success_count = 0
fail_count = 0
failed_files = []


def run_obfuscation(mode_input: str):
    try:
        if not obfuguard_path.is_file():
            raise FileNotFoundError(f"ObfuGuard executable not found: {obfuguard_path}")

        process = subprocess.run(
            [str(obfuguard_path)],
            input=mode_input.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            cwd=str(obfuguard_path.parent),
        )
        output = process.stdout.decode(errors="ignore")
        if process.returncode != 0:
            err = process.stderr.decode(errors="ignore")
            raise RuntimeError(f"Process returned non-zero exit code: {err or output}")

        match = re.search(r"Output saved to:\s*(.*\.exe)", output)
        return match.group(1) if match else "[!] Output path not found."

    except Exception as e:
        return f"[!] Error: {str(e)}"


def process_binary(binary_path: Path):
    global success_count, fail_count, failed_files

    print(f"\n[+] Processing: {binary_path.name}")

    # Control Flow Flattening
    cff_output = run_obfuscation(f"1\n{binary_path}\n")
    if "Error" in cff_output or cff_output.startswith("[!]"):
        print(f"  [-] CFF Failed: {cff_output}")
        fail_count += 1
        failed_files.append(binary_path.name)
        return

    print(f"  [CFF] Output: {cff_output}")

    # Junk Code Injection (auto mode)
    junk_output = run_obfuscation(f"2\n{binary_path}\n1\n")
    if "Error" in junk_output or junk_output.startswith("[!]"):
        print(f"  [-] Junk Code Injection Failed: {junk_output}")
        fail_count += 1
        failed_files.append(binary_path.name)
        return

    print(f"  [JUNK] Output: {junk_output}")
    success_count += 1


def main():
    print(f"ObfuGuard: {obfuguard_path}")
    print(f"Test root: {root_dir}")

    if not obfuguard_path.is_file():
        print(f"[!] ObfuGuard executable not found: {obfuguard_path}")
        print("    Set OBFUGUARD_EXE or build x64/Release/ObfuGuard.exe")
        return 1

    for folder in sorted(root_dir.iterdir()):
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

    print("\n========== SUMMARY ==========")
    print(f"[+] Success count : {success_count}")
    print(f"[+] Failed count  : {fail_count}")
    if failed_files:
        print("[!] Failed files :")
        for file in failed_files:
            print(f"    - {file}")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
