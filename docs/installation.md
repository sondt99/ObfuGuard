# Installation

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| OS | Windows 10/11 **x64** |
| IDE / toolchain | **Visual Studio 2022** with *Desktop development with C++* |
| Toolset | MSVC **v143**, C++20 |
| Package manager | **[vcpkg](https://github.com/microsoft/vcpkg)** with VS integration |
| SDK | Windows 10/11 SDK (DbgHelp) |

Linux can host the repo and scripts, but **building and running `ObfuGuard.exe` requires Windows** (or a full Windows PE environment). Wine is not supported as a primary target.

### Visual Studio 2022

1. Install VS 2022 from [visualstudio.microsoft.com](https://visualstudio.microsoft.com/).  
2. Workload: **Desktop development with C++**.  
3. Include MSVC v143 and a recent Windows SDK.

### vcpkg

```powershell
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
```

## Dependencies

```powershell
vcpkg install capstone:x64-windows
vcpkg install keystone:x64-windows
vcpkg install lief:x64-windows
vcpkg install asmjit:x64-windows
vcpkg install zydis:x64-windows
```

Transitive packages (e.g. `fmt`, `spdlog`) may appear under `vcpkg list`.

Confirm:

```powershell
vcpkg list | findstr /i "capstone keystone lief asmjit zydis"
```

## Clone and build

```powershell
git clone https://github.com/sondt99/ObfuGuard.git
cd ObfuGuard
```

1. Open **`ObfuGuard.sln`** in Visual Studio 2022.  
2. Configuration: **Release**  
3. Platform: **x64**  
4. Build Solution (`Ctrl+Shift+B`).

Primary output:

```
x64\Release\ObfuGuard.exe
```

Debug builds work for development; use **Release|x64** for evaluation and tests (exception handling and hardening flags are enabled for that config in recent versions).

## Runtime DLLs

Keep these next to `ObfuGuard.exe` (vcpkg often copies them via app-local on build):

| DLL | Origin |
|-----|--------|
| `capstone.dll` | vcpkg |
| `keystone.dll` | vcpkg |
| `LIEF.dll` | vcpkg |
| `asmjit.dll` | vcpkg |
| `Zydis.dll` | vcpkg |
| `fmt.dll` / `spdlog.dll` | transitive |

## Inputs for obfuscation

For each target program:

| File | Required |
|------|----------|
| `program.exe` | Yes |
| `program.pdb` | Yes (same folder preferred; tool also resolves CodeView path or `.pdb` sibling) |

Compile with debug info, for example:

```powershell
cl /O2 /Zi /Fe:myapp.exe myapp.cpp
```

## Optional: blacklist file

Ship-time defaults live in:

```
ObfuGuard\blacklist_default.txt
```

At runtime ObfuGuard looks for this file under common paths (working directory, `ObfuGuard/`, next to the target PE). If missing, built-in CRT/runtime names are used. Format: one symbol per line; `#` comments; optional `big:Name` for large-binary-only exclusions.

See [junk-code-injection.md](junk-code-injection.md#function-blacklist).

## Verify install

```powershell
cd x64\Release
.\ObfuGuard.exe
# Choose 0 to exit
```

Then run the suite (with a built tool):

```powershell
cd ..\..\binary_test
python auto_test.py
python match_check.py
```

Override binary path if needed:

```powershell
$env:OBFUGUARD_EXE = "D:\path\to\ObfuGuard.exe"
```

## Common build problems

| Symptom | Fix |
|---------|-----|
| Missing headers (Zydis, LIEF, …) | Install all five packages with `:x64-windows`; re-run `vcpkg integrate install` |
| Unresolved external symbols | Match **x64** platform to vcpkg triplet; rebuild Release|x64 |
| Missing DLL at run time | Copy vcpkg app-local DLLs next to `ObfuGuard.exe` |
| PDB not found | Ensure `name.pdb` exists; rebuild target with `/Zi` |

More troubleshooting: [faq.md](faq.md).
