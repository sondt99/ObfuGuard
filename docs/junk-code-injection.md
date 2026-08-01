# Junk Code Injection with Trampoline

## Overview

Junk Code Injection is an obfuscation technique that increases binary complexity by inserting semantically neutral instructions between the original program instructions. Combined with the trampoline technique, original function bodies are relocated to new PE sections, leaving trampoline jumps at the original locations.

## How It Works

### Before Obfuscation

```
.text section:
  [function @ RVA 0x12380]
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    call some_func
    add rsp, 0x20
    pop rbp
    ret
```

### After Obfuscation

```
.text section:
  [function @ RVA 0x12380]
    jmp new_section         ; Trampoline jump
    nop; nop; nop; ...      ; NOP padding

new section:
  [relocated function]
    push rbp
    mov rdx, rdx            ; <-- junk
    mov rbp, rsp
    lea rbx, [rbx]          ; <-- junk
    sub rsp, 0x20
    xor r9, 0x5678          ; <-- junk
    xor r9, 0x5678          ; <-- junk (reverses above)
    call some_func          ; address fixed for new location
    add rsp, 0x20
    add r8, 0x10            ; <-- junk
    sub r8, 0x10            ; <-- junk (reverses above)
    pop rbp
    ret
```

## Technical Pipeline

### Step 1: PE Loading

The binary is loaded using LIEF for PE manipulation:

```cpp
TrampolineInjector injector;
injector.load_pe(input_pe_path);
```

LIEF provides full PE parsing and rebuilding capabilities, including section management and header updates.

### Step 2: Function Discovery (Auto Mode)

In auto mode, `RVAResolver` combines PE and PDB parsing:

```cpp
FuncToRVA::RVAResolver resolver(input_pe_path);
resolver.initialize();
auto& functions = resolver.get_functions_info();
```

Each function's RVA is calculated as:
```
RVA = text_section_rva + pdb_offset
```

### Step 3: Function Filtering

Functions go through multiple filters:

**Size filter:**
- Minimum function size: 5 bytes (room for a `jmp rel32`)

**Name blacklist - always excluded:**
```
__scrt_common_main_seh, mainCRTStartup, WinMainCRTStartup,
__security_init_cookie, _CxxThrowException, __CxxFrameHandler3,
__CxxFrameHandler4, _RTC_CheckStackVars, __std_exception_copy,
__std_exception_destroy, _guard_check_icall, _guard_dispatch_icall,
__report_gsfailure, __GSHandlerCheck, __security_check_cookie
```

**Prefix blacklist - names starting with:**
```
_RTC_, __scrt_, _CRT_, __dyn_tls, _onexit, _atexit,
__telemetry, __vcrt, __acrt
```

**Large binary filter (> 350 KB) - additional exclusions:**
```
__isa_available_init, _guard_check_icall_nop, _guard_xfg_check_icall_nop,
__raise_securityfailure, __report_securityfailure, _calloc_base,
_malloc_base, _free_base, _realloc_base, _msize_base,
_recalloc_base, __std_type_info_destroy_list
```

**Sort order:** Functions are sorted by size in descending order for priority injection.

### Step 4: Section Creation

For each function, a new PE section is created:

```cpp
bool create_new_section(const std::string& section_name, uint32_t initial_size = 0x1000);
```

Section names are generated as unique identifiers based on the function name and index.

**Section limit management:**
- PE format maximum: 96 sections
- Safety margin maintained
- `calculate_max_injectable_functions()` determines how many functions can be processed

### Step 5: Code Relocation

The original function code is disassembled with Capstone and relocated:

```cpp
bool get_and_relocate_original_function_code(
    uint64_t original_func_va,
    uint64_t new_func_base_va,
    std::vector<uint8_t>& relocated_code_buffer,
    size_t& determined_original_function_size
);
```

**Address fixups during relocation:**
- `CALL rel32` - Recalculate 32-bit relative displacement for new location
- `JMP rel32` - Recalculate 32-bit relative displacement for new location
- RIP-relative operands (e.g., `mov rax, [rip+0x1234]`) - Recalculate displacement to maintain correct data reference

### Step 6: Trampoline Creation

The original function location is replaced with:

```cpp
bool create_trampoline(uint64_t original_func_va, uint64_t new_func_va, size_t original_size);
```

Layout at original location:
```
[junk instructions] [JMP rel32 to new section] [junk instructions] [NOP padding]
```

### Step 7: Junk Instruction Insertion

Junk instructions are randomly selected from a pool of ~50 patterns (64-bit) or ~20 patterns (32-bit).

**64-bit junk instruction examples:**

| Category | Example | Effect |
|----------|---------|--------|
| Identity moves | `mov rax, rax` | No-op |
| LEA identity | `lea rbx, [rbx]` | No-op |
| Self-cancel pair | `add r8, 0x10; sub r8, 0x10` | Net zero |
| Self-cancel pair | `xor r9, 0x5678; xor r9, 0x5678` | Net zero |
| Push/pop pair | `push rdi; pop rdi` | Net zero |
| Flag preservation | `pushfq; popfq` | No-op |
| Zero register trick | `xor r10, r10; or r10, r10` | Sets r10 to 0 (may affect flags) |

**32-bit junk instruction examples:**

| Category | Example | Effect |
|----------|---------|--------|
| Identity moves | `mov eax, eax` | No-op |
| Self-cancel pair | `add ecx, 0x10; sub ecx, 0x10` | Net zero |
| NOP variants | `nop` | No-op |
| Push/pop pair | `push edi; pop edi` | Net zero |

### Step 8: NOP Padding

Remaining space in original function locations is filled with multi-byte NOP sequences:

```cpp
void fill_remaining_space_with_nops(uint64_t address, size_t size);
```

NOP sizes from 1 to 9 bytes are used, with larger NOPs preferred for efficiency:
- 1 byte: `90`
- 2 bytes: `66 90`
- 3 bytes: `0F 1F 00`
- 4 bytes: `0F 1F 40 00`
- ...up to 9 bytes

### Step 9: PE Rebuild and Save

The modified binary is rebuilt and saved using LIEF:

```cpp
injector.save_pe(output_pe_path);
```

LIEF handles all PE header updates, section table modifications, and size recalculations.

## Effect on Static Analysis

### Original (IDA View)
```nasm
sub_12380:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 20h
    lea     rcx, aHelloWorld
    call    printf
    add     rsp, 20h
    pop     rbp
    retn
```

### After Obfuscation

**At original RVA:**
```nasm
sub_12380:
    jmp     loc_new_section
    nop
    nop
    nop
    ...
```

**At new section:**
```nasm
loc_new_section:
    push    rbp
    mov     rdx, rdx        ; junk
    mov     rbp, rsp
    lea     rbx, [rbx]      ; junk
    sub     rsp, 20h
    xor     r9, 5678h       ; junk
    xor     r9, 5678h       ; junk
    lea     rcx, aHelloWorld
    add     r8, 10h         ; junk
    sub     r8, 10h         ; junk
    call    printf
    add     rsp, 20h
    pushfq                  ; junk
    popfq                   ; junk
    pop     rbp
    retn
```

## Limitations

- **PE section limit** - Each injected function creates a new section; max ~90 functions depending on existing sections
- **Function size minimum** - Functions smaller than 5 bytes cannot be injected (no room for `jmp rel32`)
- **CRT functions** - System and runtime functions are blacklisted to prevent crashes
- **Code analysis tools** - Sophisticated tools may detect and filter junk instructions; this technique is best combined with CFF
- **Binary size growth** - Each new section adds overhead; very aggressive injection can significantly increase file size
