# API Reference

Public-facing types used by ObfuGuard’s own modules. There is no installed library package; headers live under `ObfuGuard/`.

---

## Namespace `ObfuGuard`

### `struct FunctionInfo`

**Header:** `common/function_info.h`

```cpp
struct FunctionInfo {
    std::string name;
    uint32_t pdb_offset;
    uint32_t rva;
    uint32_t size;
};
```

Canonical function descriptor for discovery, filtering, and junk injection.

### `class FunctionDiscovery`

**Header:** `common/function_discovery.h`

```cpp
explicit FunctionDiscovery(const std::string& pe_path);

const std::vector<FunctionInfo>& get_functions() const;
uint32_t get_text_section_rva() const;
uint64_t get_image_base() const;
```

Loads PE via `pe64`, opens PDB via `pdbparser`, fills `FunctionInfo` list.

**Throws:** `std::runtime_error` on PE/PDB failure.

### Function filter API

**Header:** `common/function_filter.h`

```cpp
bool load_blacklist_file(const std::string& path);
void ensure_blacklist_loaded(const std::string& binary_path = "");

std::vector<FunctionInfo> filter_functions(
    const std::vector<FunctionInfo>& all_functions,
    const std::string& binary_path,
    uint32_t min_size = 5);

void sort_functions_by_size_desc(std::vector<FunctionInfo>& functions);

bool is_function_blacklisted(const std::string& func_name);
bool is_function_blacklisted_by_binary_size(
    const std::string& func_name, const std::string& binary_path);

bool select_functions_interactive(
    const std::vector<FunctionInfo>& all_functions,
    std::vector<uint32_t>& out_rvas,
    std::vector<std::string>& out_names);
```

---

## `class pe64`

**Header:** `pe/pe.h`

Manual PE32+ loader used by CFF and discovery.

```cpp
pe64(std::string binary_path);

uint32_t align(uint32_t address, uint32_t alignment) const;
std::vector<uint8_t>* get_buffer();                 // VA-mapped image
std::vector<uint8_t>* get_buffer_not_relocated(); // raw file bytes
PIMAGE_NT_HEADERS get_nt();
PIMAGE_SECTION_HEADER get_section(std::string sectionname);
PIMAGE_SECTION_HEADER create_section(
    std::string name, uint32_t size, uint32_t characteristic);
void save_to_disk(
    std::string path, PIMAGE_SECTION_HEADER new_section, uint32_t total_size);
std::string get_path() const;
```

**Constructor validation includes:** MZ, PE signature, 64-bit optional header, AMD64 machine, `SizeOfImage` bounds, section table bounds.

**`create_section`:** rejects empty section table, `NumberOfSections >= PE_MAX_SECTIONS`, insufficient header space, image size overflow.

---

## `class pdbparser`

**Header:** `pdbparser/pdbparser.h`

```cpp
struct sym_func {
    int id = -1;
    uint32_t offset = 0;
    std::string name;
    uint32_t size = 0;
    bool obfuscate = true;
    bool cff_flattening = true;
};

explicit pdbparser(pe64* pe);
~pdbparser();
std::vector<sym_func> parse_functions();
```

Uses DbgHelp. Load base: `ObfuGuard::SYM_LOAD_BASE_ADDRESS`.

---

## `class obfuscatecff`

**Header:** `obfuscatecff/obfuscatecff.h`

```cpp
explicit obfuscatecff(pe64* pe);

void create_functions(const std::vector<pdbparser::sym_func>& functions);
void run(PIMAGE_SECTION_HEADER new_section, bool obfuscate_entry_point);
uint32_t get_added_size() const;
```

Nested types: `instruction_t`, `function_t` (instruction list, `inst_id_index`, jumptable flag).

Flattening implementation: `cfflattening/cfflattening.cpp` (member of `obfuscatecff`).

---

## Junk path

### `class TrampolineInjector`

**Header:** `junkcode/junkcode.h`

```cpp
TrampolineInjector();
~TrampolineInjector();

bool load_pe(const std::string& pe_path);
bool save_pe(const std::string& output_path);

bool inject_function_trampoline(uint32_t function_rva, uint32_t function_size = 0);

bool inject_multiple_function_trampolines(
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    const std::vector<uint32_t>& function_sizes = {});

bool inject_multiple_function_trampolines_with_limit(
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    uint32_t& actual_injected_count,
    const std::vector<uint32_t>& function_sizes = {});

uint32_t get_current_section_count() const;
uint32_t calculate_max_injectable_functions() const;
bool get_is_64_bit() const;
uint64_t get_image_base() const;

// static helpers
static bool inject_trampoline_to_function(...);
static bool inject_trampoline_to_multiple_functions(...);
static bool inject_trampoline_to_multiple_functions_smart(...);
```

`function_sizes[i]` is the PDB size for `function_rvas[i]` (0 → first-`RET` fallback).

### `class JunkCodeManager`

```cpp
static int run_auto_injection_mode(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    bool is_64_bit,
    const std::vector<ObfuGuard::FunctionInfo>& discovered_functions);

static int run_manual_injection_mode(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    bool is_64_bit,
    const std::vector<ObfuGuard::FunctionInfo>& discovered_functions);
```

Returns `0` on success, non-zero on failure.

---

## Namespace `FuncToRVA`

**Header:** `func2rva/func2rva.h`

```cpp
using FunctionInfo = ObfuGuard::FunctionInfo;

class RVAResolver {
    explicit RVAResolver(const std::string& pe_path);
    bool initialize();
    const std::vector<FunctionInfo>& get_functions_info() const;
    bool select_function_rva_interactive(uint32_t& out_rva);
    bool select_multiple_functions_rva_interactive(
        std::vector<uint32_t>& out_rvas, std::vector<std::string>& out_names);
};

bool get_rva_by_interactive_selection(...);
bool get_multiple_rvas_by_interactive_selection(...);
```

---

## Constants (`constants.h`)

| Constant | Purpose |
|----------|---------|
| `PE_MAX_SECTIONS` | 96 |
| `PE_SECTION_SAFETY_MARGIN` / `PE_RESERVED_SYSTEM_SECTIONS` | Junk budget |
| `MAX_PE_IMAGE_SIZE` | 512 MiB |
| `CFF_SECTION_SIZE` / `CFF_SECTION_NAME` | CFF cap / `.0Cff` |
| `CFF_DEV_SECTION_NAME` | `.0Dev` |
| `MAX_JUNK_ITERATIONS` | Junk fill loop |
| `MIN_TRAMPOLINE_PATCH_SIZE` / `MAX_TRAMPOLINE_PATCH_SIZE` | Trampoline span |
| `MAX_FUNC_SCAN_SIZE` | Relocate scan cap |
| `LARGE_BINARY_SIZE_THRESHOLD` | 350 KiB |
| `MIN_FUNCTION_SIZE` | Default min |
| `SYM_LOAD_BASE_ADDRESS` | PDB load base |

---

## CLI surface

Interactive only (no argv mode flags today). Entry: `main()` in `main.cpp`.

| Choice | Function |
|--------|----------|
| `1` | `mode_control_flow_flattening()` |
| `2` | `mode_trampoline_junkcode()` |
| `0` | Exit |

Output path helper: `build_output_path(input, ".cff"|".junk")`.
