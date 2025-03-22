import lief
import subprocess
import json
from junk_inserter import insert_junk_code

BINARY_PATH = "../target_binary/app.bin"
OUTPUT_PATH = "../output/obfuscated_app.bin"
TEMP_CODE = "temp_code.bin"

binary = lief.parse(BINARY_PATH)
text_section = binary.get_section(".text")
code = bytearray(text_section.content)

with open(TEMP_CODE, "wb") as f:
    f.write(code)

result = subprocess.run(["../core/disassembler", TEMP_CODE], capture_output=True)
disasm = json.loads(result.stdout.decode())

patched_code = insert_junk_code(code, disasm)
text_section.content = list(patched_code)
binary.write(OUTPUT_PATH)
print(f"Obfuscated binary written to: {OUTPUT_PATH}")
