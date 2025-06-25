import subprocess
import time
import os

EXE_PATH = "E:\\Graduation-Thesis-HUST\\x64\\Release\\ObfuGuard.exe"
WORK_DIR = os.path.dirname(EXE_PATH)

def run_obfguard(mode):
    """Run ObfuGuard in a specific mode (1 or 2) and return the output filename."""
    assert mode in [1, 2], "Mode must be 1 (CFF) or 2 (Junk)"
    process = subprocess.Popen(EXE_PATH, cwd=WORK_DIR,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               text=True)

    inputs = "1\nObfuGuard.exe\n" if mode == 1 else "2\nObfuGuard.exe\n1\n"

    try:
        process.communicate(input=inputs, timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        return None

    return "ObfuGuard.cff.exe" if mode == 1 else "ObfuGuard.junk.exe"

def test_output_file(output_file):
    """Run the output file and test if it exits cleanly."""
    test_path = os.path.join(WORK_DIR, output_file)
    if not os.path.exists(test_path):
        return False

    try:
        process = subprocess.Popen(test_path, cwd=WORK_DIR,
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True)
        stdout, _ = process.communicate(input="0\n", timeout=15)
        return "Exiting ObfuGuard" in stdout
    except:
        return False

def loop_until_success(mode):
    """Run and test until success, quietly retrying on failure."""
    while True:
        output_file = run_obfguard(mode)
        if not output_file:
            continue
        if test_output_file(output_file):
            return output_file
        time.sleep(1)

if __name__ == "__main__":
    print("=== ObfuGuard Automation Started ===")
    print("Running obfuscation and testing...\n")

    cff_result = loop_until_success(mode=1)
    junk_result = loop_until_success(mode=2)

    print("=== All tasks completed successfully ===")
    print(f"Control Flow Flattening Output: {cff_result}")
    print(f"Junk Code Injection Output:    {junk_result}")
