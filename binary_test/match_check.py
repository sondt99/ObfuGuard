#!/usr/bin/env python3
"""Compare original vs CFF vs junk obfuscated binary outputs.

Oracle: exit code + stdout (stderr ignored unless non-empty crash markers).
Missing variants are SKIPPED, not failed.
"""

import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
root_dir = SCRIPT_DIR
input_file = SCRIPT_DIR / "input.txt"

# Programs known non-deterministic (stdout may differ without a bug)
NONDETERMINISTIC = {
    "flip_coin",
    "roll_dice",
    "random_color",
}

same_outputs = []
diff_outputs = []
skipped = []
nd_ok = []


def run_binary(exe_path: Path):
    """Returns (ok, exit_code, stdout_text, err_tag)."""
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
        out = result.stdout.decode(errors="ignore").strip()
        return True, result.returncode, out, ""
    except subprocess.TimeoutExpired:
        return False, -1, "", "TIMEOUT"
    except Exception as e:
        return False, -1, "", f"ERROR:{e}"


def compare_outputs(original: Path, cff: Path, junk: Path):
    stem = original.stem
    print(f"\n[+] Checking: {original.name}")

    ok_o, rc_o, out_o, tag_o = run_binary(original)
    if not ok_o:
        print(f"  [!] original failed: {tag_o}")
        diff_outputs.append(original.name)
        return

    results = []
    for label, path in (("cff", cff), ("junk", junk)):
        if not path.is_file():
            print(f"  [-] {label}: missing (skip)")
            results.append("skip")
            continue
        ok, rc, out, tag = run_binary(path)
        if not ok:
            print(f"  [!] {label}: {tag}")
            results.append("fail")
            continue
        if rc != rc_o:
            print(f"  [!] {label}: exit {rc} != original {rc_o}")
            results.append("fail")
            continue
        if stem in NONDETERMINISTIC:
            print(f"  [~] {label}: nondeterministic — exit codes match")
            results.append("nd")
            continue
        if out != out_o:
            print(f"  [!] {label}: stdout mismatch")
            results.append("fail")
            continue
        print(f"  [OK] {label}: exit+stdout match")
        results.append("ok")

    if all(r == "skip" for r in results):
        skipped.append(original.name)
    elif any(r == "fail" for r in results):
        diff_outputs.append(original.name)
    elif any(r == "nd" for r in results) and not any(r == "fail" for r in results):
        nd_ok.append(original.name)
        same_outputs.append(original.name)
    else:
        same_outputs.append(original.name)


def main():
    print(f"Test root: {root_dir}")
    print(f"Input file: {input_file} ({'found' if input_file.is_file() else 'missing'})")

    for folder in sorted(root_dir.iterdir()):
        if not folder.is_dir():
            continue

        candidates = [
            p for p in folder.glob("*.exe")
            if not p.name.endswith(".cff.exe") and not p.name.endswith(".junk.exe")
        ]
        if not candidates:
            continue

        # Prefer exact {folder}.exe when present
        preferred = folder / f"{folder.name}.exe"
        original = preferred if preferred.is_file() else candidates[0]
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
    if nd_ok:
        print(f"[~] Nondet OK: {len(nd_ok)}")
    if diff_outputs:
        print("Mismatched files:")
        for name in diff_outputs:
            print(f"  - {name}")

    return 0 if not diff_outputs else 1


if __name__ == "__main__":
    sys.exit(main())
