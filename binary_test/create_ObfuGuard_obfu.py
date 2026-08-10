#!/usr/bin/env python3
"""Self-obfuscation smoke test: run ObfuGuard on its own binary."""

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_EXE = REPO_ROOT / "x64" / "Release" / "ObfuGuard.exe"
EXE_PATH = Path(os.environ.get("OBFUGUARD_EXE", str(DEFAULT_EXE)))
WORK_DIR = EXE_PATH.parent


def run_obfguard(mode: int):
    """Run ObfuGuard in a specific mode (1 or 2) and return the expected output filename."""
    assert mode in (1, 2), "Mode must be 1 (CFF) or 2 (Junk)"
    if not EXE_PATH.is_file():
        print(f"[!] ObfuGuard not found: {EXE_PATH}")
        return None

    process = subprocess.Popen(
        [str(EXE_PATH)],
        cwd=str(WORK_DIR),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    inputs = "1\nObfuGuard.exe\n" if mode == 1 else "2\nObfuGuard.exe\n1\n"

    try:
        stdout, stderr = process.communicate(input=inputs, timeout=120)
        if process.returncode != 0:
            print(f"[!] Mode {mode} failed (rc={process.returncode}): {stderr or stdout}")
            return None
    except subprocess.TimeoutExpired:
        process.kill()
        print(f"[!] Mode {mode} timed out")
        return None

    return "ObfuGuard.cff.exe" if mode == 1 else "ObfuGuard.junk.exe"


def test_output_file(output_file: str) -> bool:
    """Run the output file and check if it exits cleanly."""
    test_path = WORK_DIR / output_file
    if not test_path.exists():
        print(f"[!] Missing output: {test_path}")
        return False

    try:
        process = subprocess.Popen(
            [str(test_path)],
            cwd=str(WORK_DIR),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, _ = process.communicate(input="0\n", timeout=30)
        ok = "Exiting ObfuGuard" in (stdout or "")
        print(f"  [{'OK' if ok else 'FAIL'}] {output_file}")
        return ok
    except Exception as e:
        print(f"  [!] Error running {output_file}: {e}")
        return False


def main():
    print(f"ObfuGuard: {EXE_PATH}")
    print(f"Work dir : {WORK_DIR}")

    if not EXE_PATH.is_file():
        print("[!] Set OBFUGUARD_EXE or build x64/Release/ObfuGuard.exe")
        return 1

    results = []
    for mode in (1, 2):
        print(f"\n[+] Running mode {mode}...")
        out = run_obfguard(mode)
        if out:
            results.append(test_output_file(out))
        else:
            results.append(False)

    print("\n========== SUMMARY ==========")
    print(f"Passed: {sum(results)}/{len(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
