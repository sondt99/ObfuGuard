# Installation Guide

## Prerequisites

### Required Software

- **Windows 10/11** (x64)
- **Visual Studio 2022** with "Desktop Development with C++" workload
- **vcpkg** package manager

### Installing Visual Studio 2022

1. Download Visual Studio 2022 from [visualstudio.microsoft.com](https://visualstudio.microsoft.com/)
2. In the Visual Studio Installer, select the **"Desktop development with C++"** workload
3. Ensure the following components are selected:
   - MSVC v143 build tools
   - Windows 10/11 SDK
   - C++ CMake tools (optional, for vcpkg)

### Installing vcpkg

```powershell
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
```

## Installing Dependencies

Install all required libraries through vcpkg:

```powershell
vcpkg install capstone:x64-windows
vcpkg install keystone:x64-windows
vcpkg install lief:x64-windows
vcpkg install asmjit:x64-windows
vcpkg install zydis:x64-windows
```

These libraries will also install their transitive dependencies (fmt, spdlog, etc.).

## Building ObfuGuard

### Step 1: Clone the Repository

```powershell
git clone https://github.com/sondt99/ObfuGuard.git
cd ObfuGuard
```

### Step 2: Open the Solution

Open `ObfuGuard.sln` in Visual Studio 2022.

### Step 3: Configure Build

1. Set the solution configuration to **Release**
2. Set the solution platform to **x64**
3. Ensure vcpkg integration is active (the `.vcxproj` references vcpkg targets automatically)

### Step 4: Build

Build the solution (`Ctrl+Shift+B` or Build > Build Solution).

The output binary will be placed in `x64/Release/ObfuGuard.exe`.

### Step 5: Runtime DLLs

The following DLLs must be in the same directory as `ObfuGuard.exe`:

| DLL | Source |
|-----|--------|
| `capstone.dll` | vcpkg |
| `keystone.dll` | vcpkg |
| `LIEF.dll` | vcpkg |
| `asmjit.dll` | vcpkg |
| `Zydis.dll` | vcpkg |
| `fmt.dll` | vcpkg (transitive) |
| `spdlog.dll` | vcpkg (transitive) |

These are automatically copied to the output directory during build.

## Build Configurations

| Configuration | Optimizations | Debug Info | Use Case |
|--------------|---------------|------------|----------|
| Debug\|x64 | Disabled | Full PDB | Development and debugging |
| Release\|x64 | MaxSpeed | Minimal | Production use |
| Debug\|Win32 | Disabled | Full PDB | 32-bit development |
| Release\|Win32 | MaxSpeed | Minimal | 32-bit production |

### Release Build Specifics

- Optimization: Maximum Speed (`/O2`)
- Function-level linking enabled
- Intrinsic functions enabled
- COMDAT folding enabled
- Exception handling: disabled
- RTTI: disabled
- Runtime library: Multi-threaded (`/MT`)
- C++ Standard: C++20
- C Standard: C17

## Using Pre-built Binaries

Pre-built binaries are available in the `x64/Release/` directory:

| File | Description |
|------|-------------|
| `ObfuGuard.exe` | Standard release build |
| `ObfuGuard.cff.exe` | Self-obfuscated with CFF |
| `ObfuGuard.junk.exe` | Self-obfuscated with junk code |
| `ObfuGuard.pdb` | Debug symbols |

## Verifying Installation

Run ObfuGuard to verify it starts correctly:

```powershell
.\ObfuGuard.exe
```

Expected output:
```
========================================
         ObfuGuard Tool - sondt
========================================

Select obfuscation mode:
  1. Control Flow Flattening
  2. Insert Junk Code - Trampoline
  0. Exit
Enter your choice (0-2):
```
