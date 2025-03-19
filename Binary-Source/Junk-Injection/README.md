# Junk-Injection

## Kỹ Thuật Chèn Mã
### Chèn Lệnh Rác (Junk Instructions)
#### Kỹ Thuật NOP và Junk Code

Các lệnh `NOP` (No Operation) không ảnh hưởng đến logic chương trình và có thể được chèn vào bất kỳ vị trí nào.

```asm=
nop
nop
```

Junk code:

```asm=
mov eax, eax
mov ebx, ebx
``` 

2 lệnh này không thay đổi logic chương trình
--> Làm tăng độ phức tạp xử lý cho từng block <-- graph <-- function

#### Sắp Xếp Lại Lệnh (Instruction Reordering)
Bên cạnh việc chèn các lệnh `NOP` và lệnh không ảnh hưởng đến kết quả tính toán, một kỹ thuật khác là **Instruction Reordering**. Kỹ thuật này nhằm thay đổi thứ tự của một số lệnh để làm cho mã khó đọc hơn mà không ảnh hưởng đến logic.

Ví dụ, các phép toán cộng/trừ và XOR có thể được hoán đổi vị trí một cách khéo léo để tránh bị nhận dạng một cách dễ dàng:
```asm=
xor eax, eax
mov ebx, ebx
```
Đây là các lệnh không thay đổi giá trị của thanh ghi nhưng khi kết hợp với một số phép toán khác sẽ làm cho việc phân tích trở nên khó khăn hơn.
### Kỹ Thuật Xử Lý Hàm
#### Nhúng Hàm (Function Inlining)

Thay vì sử dụng đúng chuẩn control flow là khai báo hàm và call hàm thì vẫn để khai báo hàm nhưng không call hàm nữa mà đẩy trực tiếp code của hàm đó vào thay thế lệnh gọi.

Hiệu quả obfu: 
Các hàm được gọi nhưng không được sử dụng làm cho việc xác định ranh rới các hàm khó khăn hơn 

Ví dụ: 
```asm=
; Hàm gốc
_add:
    add eax, ebx
    ret
```
Lưu ý sau:
```asm
; Trước khi nhúng
call _add        ; Gọi hàm trực tiếp (Điều này làm control flow dễ được nhìn ra)

; Sau khi nhúng
add eax, ebx     ; Nhúng thẳng code vào thay thế cho lệnh `CALL` khiến các function trở nên vô nghĩa
; --> làm loạn flow
```

#### Function Inlining - Multi-Version Functions
Để nâng cao mức độ phức tạp của Function Inlining, một cách tiếp cận nữa là sử dụng **Multi-Version Functions**. Đó là tạo ra nhiều phiên bản khác nhau của cùng một hàm và inline từng phiên bản khác nhau vào các vị trí khác nhau trong mã nguồn. Điều này khiến cho các công cụ phân tích không dễ dàng phát hiện ra rằng các đoạn mã này thực tế là giống nhau.

Ví dụ:
- Thay vì có một hàm `_add`, bạn có thể tạo ra `_add_v1`, `_add_v2`, và `_add_v3`, trong đó có thể thay đổi thứ tự các lệnh hoặc thêm một số junk instruction, sau đó inline chúng vào các nơi cần thiết.

#### Tách Hàm (Function Outlining)
Thay vì sử dụng 1 hàm đơn duy nhất thì sẽ tách ra làm nhiều hàm con khiến flow-map của disassemble trở nên hỗn loạn.

![image](https://hackmd.io/_uploads/Sy5zuwXG1l.png)


Ví dụ có 1 hàm lớn là:

```asm=
_original_function:
    mov eax, 1
    add eax, 2
    mov ebx, eax
    sub ebx, 1
    ret
```

Sẽ tách thành 2 hàm con:

```asm=
_part1:
    mov eax, 1
    add eax, 2
    ret

_part2:
    mov ebx, eax
    sub ebx, 1
    ret

_original_function:
    call _part1
    call _part2
    ret
```

#### Đánh giá
Func inlining & outlining thường được dùng để VMProtect, Themida, hoặc Obfuscator-LLVM 
