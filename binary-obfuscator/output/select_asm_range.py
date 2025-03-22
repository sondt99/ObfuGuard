import json

def hex_to_int(s):
    return int(s, 16)

def main():
    file_path = "data.txt"
    
    with open(file_path, "r") as f:
        lines = f.readlines()
    
    # Bỏ phần tiêu đề, giữ lại JSON array
    json_start_index = None
    for i, line in enumerate(lines):
        if line.strip().startswith("["):
            json_start_index = i
            break

    if json_start_index is None:
        print("Không tìm thấy JSON disassembly trong file!")
        return

    json_data = "".join(lines[json_start_index:])
    instructions = json.loads(json_data)

    start_addr = input("Nhập địa chỉ bắt đầu (hex, ví dụ 0x140001010): ").strip()
    end_addr = input("Nhập địa chỉ kết thúc (hex, ví dụ 0x14000103d): ").strip()

    try:
        start = hex_to_int(start_addr)
        end = hex_to_int(end_addr)
    except ValueError:
        print("Sai định dạng địa chỉ! Hãy dùng dạng hex như 0x140001000.")
        return

    selected = [insn for insn in instructions if start <= hex_to_int(insn["offset"]) <= end]

    if not selected:
        print("Không tìm thấy instruction nào trong khoảng đã nhập.")
        return

    print(f"[*] Đã tìm thấy {len(selected)} instruction trong khoảng đã chọn:\n")
    for insn in selected:
        print(f"{insn['offset']}: {insn['mnemonic']} {insn['operands']}")

    # Nếu muốn lưu lại file mới
    save = input("\nBạn có muốn lưu đoạn này ra file mới? (y/n): ").strip().lower()
    if save == "y":
        output_file = "selected_asm.json"
        with open(output_file, "w") as f:
            json.dump(selected, f, indent=2)
        print(f"[*] Đã lưu vào {output_file}")

if __name__ == "__main__":
    main()
