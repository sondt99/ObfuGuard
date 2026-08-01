# API Reference

## pe64 Class

**Header:** `pe/pe.h`

PE64 file parser and manipulator.

### Constructor

```cpp
pe64(std::string binary_path);
```
Loads a 64-bit PE binary into memory, validates PE headers, and maps sections to virtual addresses.

**Parameters:**
- `binary_path` - Path to the PE executable file

**Throws:** `std::runtime_error` if the file cannot be opened or is not a valid PE file.

### Methods

```cpp
uint32_t align(uint32_t address, uint32_t alignment);
```
Aligns an address to the specified boundary.

---

```cpp
std::vector<uint8_t>* get_buffer();
```
Returns pointer to the relocated PE buffer (sections mapped to virtual addresses).

---

```cpp
std::vector<uint8_t>* get_buffer_not_relocated();
```
Returns pointer to the raw PE buffer (as stored on disk).

---

```cpp
PIMAGE_NT_HEADERS get_nt();
```
Returns pointer to the NT headers within the buffer.

---

```cpp
PIMAGE_SECTION_HEADER get_section(std::string sectionname);
```
Finds and returns a section header by name. Returns `nullptr` if not found.

---

```cpp
PIMAGE_SECTION_HEADER create_section(std::string name, uint32_t size, uint32_t characteristic);
```
Creates a new PE section with the specified name, size, and characteristics.

**Parameters:**
- `name` - Section name (max 8 characters)
- `size` - Section size in bytes
- `characteristic` - Section flags (e.g., `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ`)

**Returns:** Pointer to the new section header.

---

```cpp
void save_to_disk(std::string path, PIMAGE_SECTION_HEADER new_section, uint32_t total_size);
```
Saves the modified PE to disk with the new section included.

---

```cpp
std::string get_path();
```
Returns the path of the loaded PE file.

---

## pdbparser Class

**Header:** `pdbparser/pdbparser.h`

Parses PDB debug symbols to extract function information.

### Types

```cpp
struct sym_func {
    int id = -1;           // Function ID
    uint32_t offset = 0;   // Offset within .text section
    std::string name;      // Symbol name
    uint32_t size = 0;     // Function size in bytes
    bool obfuscate = true; // Whether to obfuscate
    bool ctfflattening = true; // Whether to apply CFF
};
```

### Constructor / Destructor

```cpp
pdbparser(pe64* pe);
~pdbparser();
```
Initializes the PDB parser using the PE file's debug directory to locate the PDB file. Falls back to name-based convention if the debug directory does not contain a PDB path.

### Methods

```cpp
std::vector<sym_func> parse_functions();
```
Parses all function symbols from the PDB and returns them as a vector. Uses `SymInitialize` and `SymEnumSymbols` from the Windows DbgHelp library.

---

## obfuscatecff Class

**Header:** `obfuscatecff/obfuscatecff.h`

Orchestrates the Control Flow Flattening obfuscation pipeline.

### Types

```cpp
struct instruction_t {
    int inst_id;
    int func_id;
    bool is_first_instruction;
    std::vector<uint8_t> raw_bytes;
    uint64_t runtime_address;
    uint64_t relocated_address;
    ZydisDisassembledInstruction zyinstr;
    bool has_relative;
    bool isjmpcall;
    struct {
        int target_inst_id;
        int target_func_id;
        uint32_t offset;
        uint32_t size;
    } relative;
    uint64_t location_of_data;

    void load_relative_info();
    void load(int funcid, std::vector<uint8_t> raw_data);
    void load(int funcid, ZydisDisassembledInstruction zyinstruction, uint64_t runtime_address);
    void reload();
    void print();
};

struct function_t {
    int func_id;
    std::string name;
    std::vector<instruction_t> instructions;
    std::map<int, uint64_t> inst_id_index;
    uint32_t offset;
    uint32_t size;
    bool ctfflattening = true;
    bool has_jumptables = false;
};
```

### Constructor

```cpp
obfuscatecff(pe64* pe);
```
Initializes the CFF engine with a loaded PE file.

### Public Methods

```cpp
void create_functions(std::vector<pdbparser::sym_func> functions);
```
Disassembles all functions using Zydis and builds `function_t` representations.

---

```cpp
void run(PIMAGE_SECTION_HEADER new_section, bool obfuscate_entry_point);
```
Executes the full CFF pipeline:
1. `analyze_functions()` - Resolve relative references
2. `remove_jumptables()` - Mark functions with jump tables
3. `apply_control_flow_flattening()` - Per eligible function
4. `relocate()` - Calculate new addresses
5. `convert_relative_jmps()` - Expand short jumps
6. `apply_relocations()` - Patch relative offsets
7. `compile()` - Write final code and trampolines

**Parameters:**
- `new_section` - The newly created PE section for obfuscated code
- `obfuscate_entry_point` - Whether to apply entry point encoding

---

```cpp
uint32_t get_added_size();
```
Returns the total size of obfuscated code written to the new section.

---

## CFF Namespace

**Header:** `cfflattening/cfflattening.h`

### Types

```cpp
struct BasicBlock {
    int block_id;
    std::vector<obfuscatecff::instruction_t> instructions;
    int next_block;      // Fall-through successor block ID
    int dst_block = -1;  // Conditional jump target block ID
};
```

### Functions

```cpp
bool CFF::apply_control_flow_flattening(
    std::vector<obfuscatecff::function_t>::iterator& func_iter
);
```
Applies the CFF algorithm to a single function. Modifies the function's instruction list in place.

---

## TrampolineInjector Class

**Header:** `junkcode/junkcode.h`

Handles PE loading, function relocation, junk code insertion, and trampoline creation.

### Constructor / Destructor

```cpp
TrampolineInjector();
~TrampolineInjector();
```

### Instance Methods

```cpp
bool load_pe(const std::string& pe_path);
```
Loads a PE file via LIEF. Detects architecture automatically.

---

```cpp
bool inject_function_trampoline(uint32_t function_rva);
```
Injects a trampoline for a single function by RVA.

---

```cpp
bool inject_multiple_function_trampolines(
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names
);
```
Injects trampolines for multiple functions.

---

```cpp
bool inject_multiple_function_trampolines_with_limit(
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    uint32_t& actual_injected_count
);
```
Injects trampolines respecting section count limits. Returns actual number injected.

---

```cpp
bool save_pe(const std::string& output_path);
```
Saves the modified PE binary.

---

```cpp
uint32_t get_current_section_count() const;
uint32_t calculate_max_injectable_functions() const;
bool check_section_limit_before_injection(uint32_t planned_injections) const;
```
Section management utilities.

---

```cpp
bool get_is_64_bit() const;
uint64_t get_image_base() const;
```
PE property accessors.

### Static Methods

```cpp
static bool inject_trampoline_to_function(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    uint32_t function_rva,
    bool force_64_bit = false
);

static bool inject_trampoline_to_multiple_functions(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    bool force_64_bit = false
);

static bool inject_trampoline_to_multiple_functions_smart(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    const std::vector<uint32_t>& function_rvas,
    const std::vector<std::string>& function_names,
    uint32_t& actual_injected_count,
    bool force_64_bit = false
);
```
Convenience methods that handle load, inject, and save in one call.

---

## JunkCodeManager Class

**Header:** `junkcode/junkcode.h`

High-level orchestrator for junk code injection with function filtering and safety checks.

### Static Methods

```cpp
static int run_auto_injection_mode(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    bool is_64_bit
);
```
Automatically discovers and injects all eligible functions. Returns 0 on success.

---

```cpp
static int run_manual_injection_mode(
    const std::string& input_pe_path,
    const std::string& output_pe_path,
    bool is_64_bit
);
```
Interactive mode for manual function selection. Returns 0 on success.

---

## FuncToRVA Namespace

**Header:** `func2rva/func2rva.h`

### Types

```cpp
struct FunctionInfo {
    std::string name;      // Function name
    uint32_t rva;          // Calculated RVA
    uint32_t pdb_offset;   // Original offset from PDB
    uint32_t size;         // Function size
};
```

### RVAResolver Class

```cpp
RVAResolver(const std::string& pe_path);
~RVAResolver();

bool initialize();
const std::vector<FunctionInfo>& get_functions_info() const;
bool select_function_rva_interactive(uint32_t& out_rva);
bool select_multiple_functions_rva_interactive(
    std::vector<uint32_t>& out_rvas,
    std::vector<std::string>& out_names
);
```

### Free Functions

```cpp
bool get_rva_by_interactive_selection(
    const std::string& pe_file_path,
    uint32_t& selected_rva
);

bool get_multiple_rvas_by_interactive_selection(
    const std::string& pe_file_path,
    std::vector<uint32_t>& selected_rvas,
    std::vector<std::string>& selected_names
);
```

---

## Global Functions (main.cpp)

```cpp
bool DetectPEArchitecture(const std::string& filePath, bool& is64Bit);
```
Reads MZ/PE headers to determine if a file is 32-bit or 64-bit PE.

```cpp
std::string build_output_path(const std::string& input_path, const std::string& suffix);
```
Generates output file path by inserting a suffix before the extension (e.g., `.cff`, `.junk`).
