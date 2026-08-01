# ObfuGuard Documentation

Welcome to the official documentation for **ObfuGuard** - a Windows PE binary obfuscation tool.

## Table of Contents

| Document | Description |
|----------|-------------|
| [Overview](overview.md) | Introduction, features, and high-level architecture |
| [Installation](installation.md) | Prerequisites, build instructions, and environment setup |
| [User Guide](user-guide.md) | How to use ObfuGuard step by step |
| [Control Flow Flattening](control-flow-flattening.md) | Technical deep-dive into the CFF obfuscation engine |
| [Junk Code Injection](junk-code-injection.md) | Technical deep-dive into the junk code/trampoline engine |
| [Architecture](architecture.md) | Source code structure, modules, and data flow |
| [API Reference](api-reference.md) | Classes, methods, and data structures |
| [Benchmarking](benchmarking.md) | Evaluation framework, metrics, and how to run benchmarks |
| [Testing](testing.md) | Test suite, automated testing, and validation |
| [FAQ](faq.md) | Frequently asked questions and troubleshooting |

## Quick Start

```bash
# 1. Install dependencies via vcpkg
vcpkg install capstone:x64-windows
vcpkg install keystone:x64-windows
vcpkg install lief:x64-windows
vcpkg install asmjit:x64-windows
vcpkg install zydis:x64-windows

# 2. Open ObfuGuard.sln in Visual Studio 2022

# 3. Build in Release|x64

# 4. Run ObfuGuard.exe and follow the interactive menu
```

## License

MIT License - Copyright (c) 2025 Thai Son Dinh (sondt)
