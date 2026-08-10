#!/usr/bin/env python3
"""Compare original vs CFF vs junk obfuscated binary outputs."""

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
root_dir = SCRIPT_DIR
input_file = SCRIPT_DIR / "input.txt"

same_outputs = []
diff_outputs = []
skipped = []


def run_binary(exe_path: Path):
    try:
        stdin_data = b""
        if input_file.is_file():
            stdin_data = input_file.read_bytes()

        result = subprocess.run(
            [str(exe_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            input=stdin_data,
        )
        return result.stdout.decode(errors="ignore").strip()
    except Exception as e:
        return f"[ERROR] {e}"


def compare_outputs(original: Path, cff: Path, junk: Path):
    out_ori = run_binary(original)
    out_cff = run_binary(cff) if cff.is_file() else "[MISSING]"
    out_junk = run_binary(junk) if junk.is_file() else "[MISSING]"

    print(f"\n[+] Checking: {original.name}")
    is_same_cff = out_ori == out_cff
    is_same_junk = out_ori == out_junk

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
    print(f"Test root: {root_dir}")
    print(f"Input file: {input_file} ({'found' if input_file.is_file() else 'missing'})")

    for folder in sorted(root_dir.iterdir()):
        if not folder.is_dir():
            continue

        # Prefer stem.exe that is not already a .cff/.junk variant
        candidates = [
            p for p in folder.glob("*.exe")
            if not p.name.endswith(".cff.exe") and not p.name.endswith(".junk.exe")
        ]
        if not candidates:
            continue

        original = candidates[0]
        stem = original.stem
        cff = folder / f"{stem}.cff.exe"
        junk = folder / f"{stem}.junk.exe"

        if not cff.is_file() and not junk.is_file():
            skipped.append(original.name)
            continue

        compare_outputs(original, cff, junk)

    print("\n========== SUMMARY ==========")
    print(f"[+] Match    : {len(same_outputs)}")
    print(f"[!] Mismatch : {len(diff_outputs)}")
    print(f"[-] Skipped  : {len(skipped)} (no obfuscated variants)")
    if diff_outputs:
        print("Mismatched files:")
        for name in diff_outputs:
            print(f"  - {name}")

    return 0 if not diff_outputs else 1


if __name__ == "__main__":
    sys.exit(main())
