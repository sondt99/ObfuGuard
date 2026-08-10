# ObfuGuard Documentation

Official documentation for **ObfuGuard** — a Windows PE post-link obfuscation tool (Control Flow Flattening and junk-code trampolines).

**Current line:** v4.2.0 · C++20 · MSVC · Release|x64  

## Contents

| Document | Description |
|----------|-------------|
| [Overview](overview.md) | Purpose, features, supported PE formats |
| [Installation](installation.md) | VS 2022, vcpkg, build, runtime DLLs |
| [User Guide](user-guide.md) | Interactive CLI for CFF and junk modes |
| [Control Flow Flattening](control-flow-flattening.md) | CFF algorithm and PE layout |
| [Junk Code Injection](junk-code-injection.md) | Trampoline relocation, blacklist, batch inject |
| [Architecture](architecture.md) | Modules, `common/`, dependency graph |
| [API Reference](api-reference.md) | Classes and public entry points |
| [Testing](testing.md) | `binary_test/` suite and scripts |
| [Benchmarking](benchmarking.md) | Static / runtime / RE-time benchmarks |
| [FAQ](faq.md) | Common issues and limits |

## Quick start

```powershell
# Dependencies (once)
vcpkg install capstone:x64-windows keystone:x64-windows lief:x64-windows asmjit:x64-windows zydis:x64-windows

# Build ObfuGuard.sln → Release | x64
.\x64\Release\ObfuGuard.exe
```

You need a **64-bit PE + PDB** for CFF, and PE + PDB for junk (32- or 64-bit).

## Related repo files

| Path | Role |
|------|------|
| [../README.md](../README.md) | Project landing page |
| [../CHANGELOG.md](../CHANGELOG.md) | Version history |
| [../SECURITY.md](../SECURITY.md) | Security policy |
| [../LICENSE](../LICENSE) | MIT |

## License

MIT — Copyright (c) 2025 Thai Son Dinh (sondt).
