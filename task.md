
# 🛠️ Binary Obfuscation Tool - Tổng Quan Quy Trình

## 📌 Mục tiêu
Xây dựng một công cụ **obfuscate binary đã được biên dịch** (PE, ELF, firmware), thông qua việc phân tích và viết lại mã máy sau khi đã compile.

---

## 🔁 Quy trình tổng quát

### 1. Disassemble Binary
- **Công cụ**: [Capstone Engine](https://www.capstone-engine.org/)
- **Mục tiêu**: Trích xuất các lệnh ASM từ binary.

```python
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(code, base_addr):
    print(i.mnemonic, i.op_str)
```

---

### 2. Phân tích Control Flow Graph (CFG)
- **Dùng để**: Xác định cấu trúc hàm, block, nhánh rẽ.
- **Thư viện gợi ý**: `networkx`, IDA Pro API, Ghidra, hoặc build thủ công bằng Capstone.

---

### 3. Áp dụng kỹ thuật Obfuscation

| Kỹ thuật | Mô tả |
|----------|-------|
| **Junk Code Insertion** | Chèn lệnh vô nghĩa (`NOP`, `XOR`, `PUSH/POP`) |
| **Control Flow Flattening** | Tạo 1 dispatcher chính dùng `switch-case` để xử lý flow |
| **Instruction Substitution** | Thay thế bằng lệnh tương đương logic |
| **Opaque Predicates** | Điều kiện giả gây rối `if (x*x >= 0)` |
| **String Encryption** | Mã hóa chuỗi, giải mã tại runtime |
| **Call Stack Tampering** | Gây rối call stack để phá decompiler |

---

### 4. Assemble lại mã ASM
- **Công cụ**: [Keystone Engine](https://www.keystone-engine.org/)
- **Mục tiêu**: Chuyển lại thành mã máy.

```python
from keystone import *
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm("mov eax, 1")
```

---

### 5. Patch hoặc rebuild lại binary
- **Công cụ**: [LIEF](https://lief.quarkslab.com/)
- **Tác vụ**: Chỉnh sửa section `.text`, `.data`, cập nhật lại header.

---

## 🗂 Cấu trúc thư mục gợi ý

```
firmobfuscator/
├── main.py
├── modules/
│   ├── disassembler.py
│   ├── assembler.py
│   ├── obfuscator.py
│   ├── patcher.py
│   └── cfg_builder.py
├── utils/
│   └── helpers.py
├── test_binaries/
└── README.md
```

---

## 🔧 Yêu cầu cài đặt

```bash
pip install capstone keystone-engine lief networkx
```

---

## 📌 Gợi ý mở rộng
- Hỗ trợ cả PE (Windows), ELF (Linux), hoặc firmware nhị phân thô.
- Tùy chọn: tự động xác định hàm entry point hoặc phân tích toàn bộ `.text`.
