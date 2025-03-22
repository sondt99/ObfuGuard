import json

def hex_to_int(s):
    return int(s, 16)

def main():
    file_path = "data.txt"
    
    with open(file_path, "r") as f:
        lines = f.readlines()
    
    # Skip title lines and get to the JSON array
    json_start_index = None
    for i, line in enumerate(lines):
        if line.strip().startswith("["):
            json_start_index = i
            break

    if json_start_index is None:
        print("Could not find JSON disassembly in the file!")
        return

    json_data = "".join(lines[json_start_index:])
    instructions = json.loads(json_data)

    start_addr = input("Enter start address (hex, e.g., 0x140001010): ").strip()
    end_addr = input("Enter end address (hex, e.g., 0x14000103d): ").strip()

    try:
        start = hex_to_int(start_addr)
        end = hex_to_int(end_addr)
    except ValueError:
        print("Invalid address format! Use hex format like 0x140001000.")
        return

    selected = [insn for insn in instructions if start <= hex_to_int(insn["offset"]) <= end]

    if not selected:
        print("No instructions found in the selected range.")
        return

    print(f"[*] Found {len(selected)} instructions in the selected range:\n")
    for insn in selected:
        print(f"{insn['offset']}: {insn['mnemonic']} {insn['operands']}")

    save = input("\nDo you want to save this selection to a new file? (y/n): ").strip().lower()
    if save == "y":
        output_file = "selected_asm.json"
        with open(output_file, "w") as f:
            json.dump(selected, f, indent=2)
        print(f"[*] Saved to {output_file}")

if __name__ == "__main__":
    main()
