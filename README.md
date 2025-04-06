# Graduation Thesis - HUST

## Thông tin sinh viên
- Họ tên: Đinh Thái Sơn  
- MSSV: 20210750  
- Lớp: IT2-04  
- Mã lớp: 750665  
- Điện thoại liên lạc: 84915487872  
- Email:  
  - Cá nhân: [sondinh99999@gmail.com](mailto:sondinh99999@gmail.com)  
  - HUST Mail: [son.dt210750@sis.hust.edu.vn](mailto:son.dt210750@sis.hust.edu.vn)  

## Giảng viên hướng dẫn
- Họ tên: PGS.TS. Trần Quang Đức  
- Đơn vị: Trường Công nghệ Thông tin và Truyền thông – HUST

## Thời gian thực hiện
- Bắt đầu: 10/02/2025  
- Kết thúc: 17/06/2025  

## Tên đề tài
Phát triển công cụ làm rối tập tin nhị phân bảo vệ phần mềm khỏi phân tích đảo ngược  
(Developing a Binary Obfuscation Tool for Software Protection Against Reverse Engineering)

## Lĩnh vực đề tài
An toàn không gian số

---

## Mục tiêu đồ án

### 1. Kiến thức tích lũy
- Kỹ thuật phân tích đảo ngược: Reverse Engineering, Debugging, Disassembling, Decompiling
- Cấu trúc tập tin nhị phân: Headers, Sections, Symbols,...
- Kỹ thuật bảo vệ phần mềm: Obfuscation, chống phân tích đảo ngược

### 2. Công nghệ sử dụng
- Ngôn ngữ lập trình: Python, C, C++
- Thư viện và công cụ:
  - Capstone (Disassembler)
  - Keystone (Assembler)
  - LIEF (PE File Manipulation)
  - IDA Pro, Ghidra (Disassembler/Debugger)

- Kỹ thuật obfuscation áp dụng:
  - Chèn mã giả (Junk Code Insertion)
  - Làm phẳng luồng điều khiển (Control Flow Flattening)
  - Mã hóa chuỗi (String Encryption)
  - Đổi tên biến, hàm (Renaming)
  - Ẩn dữ liệu (Data Hiding)

### 3. Kỹ năng phát triển
- Kỹ năng nghiên cứu, đọc hiểu tài liệu chuyên ngành tiếng Anh
- Kỹ năng lập trình hệ thống và xử lý file nhị phân
- Kỹ năng đánh giá hiệu quả bảo vệ phần mềm sau khi obfuscate

### 4. Sản phẩm kỳ vọng
- Công cụ làm rối mã nhị phân:
  - Có khả năng áp dụng nhiều kỹ thuật obfuscation
  - Giao diện dòng lệnh hoặc đơn giản, dễ sử dụng
- Công cụ phân tích:
  - Liệt kê các lệnh, offset, thông tin PE Header
  - Hỗ trợ đánh giá hiệu quả bảo vệ sau obfuscation

---

## Lựa chọn ngôn ngữ xây dựng công cụ theo mục tiêu

| Mục tiêu | Ngôn ngữ đề xuất |
|---------|------------------|
| Làm POC nghiên cứu nhanh, dễ demo | Python (dùng lief, keystone) |
| Viết tool mạnh dùng trong thực tế | C/C++ (dùng capstone, lief) |
| Xây dựng CLI đa nền tảng | Golang + C bindings |
| Làm malware mẫu (educational) hoặc bypass AV nâng cao | C/ASM hoặc kết hợp |

Ngôn ngữ dự kiến sử dụng chính: **Python hoặc C/C++**

---

## Kế hoạch triển khai (17 tuần)

| Giai đoạn | Tuần | Nội dung |
|----------|------|---------|
| Tìm hiểu bài toán | 1–2 | Phân tích các kỹ thuật reverse engineering, công cụ dịch ngược, vai trò obfuscation |
| Nghiên cứu công nghệ liên quan | 3–4 | Junk Code, Control Flow Flattening, Capstone, Keystone, LIEF |
| Phân tích thiết kế | 5–6 | Xây dựng luồng xử lý, chọn kỹ thuật, tích hợp công cụ |
| Xây dựng chương trình | 7–14 | Phát triển tool CLI/GUI, chèn mã rối, điều khiển offset, bảo vệ string/code |
| Đánh giá & báo cáo | 15–17 | Obfuscate thực tế, đánh giá hiệu quả bảo vệ, viết báo cáo tổng kết |

---

## Kết quả mong đợi
- Công cụ có thể chèn code rác, biến đổi luồng điều khiển, mã hóa chuỗi, chống phân tích tĩnh
- Giao diện đơn giản cho phép chọn file đầu vào và xuất file đầu ra đã obfuscate
- Báo cáo kỹ thuật chi tiết về quá trình làm rối và đánh giá hiệu quả bảo vệ phần mềm

