import pefile

def count_sections(pe_path):
    try:
        pe = pefile.PE(pe_path)
        num_sections = len(pe.sections)
        print(f"Số lượng section trong '{pe_path}': {num_sections}")
        return num_sections
    except FileNotFoundError:
        print("❌ File không tồn tại.")
    except pefile.PEFormatError:
        print("❌ Không phải file PE hợp lệ.")

# Ví dụ sử dụng
if __name__ == "__main__":
    file_path = "E:\ObfuGuard\Binary_CFF.exe"  # <-- Thay bằng đường dẫn file của bạn
    count_sections(file_path)
