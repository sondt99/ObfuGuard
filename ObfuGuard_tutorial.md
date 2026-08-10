# ObfuGuard tutorial (short)

This file is a pointer. Full documentation lives under **`docs/`**.

| Step | Document |
|------|----------|
| Install VS + vcpkg + build | [docs/installation.md](docs/installation.md) |
| Run CFF / junk modes | [docs/user-guide.md](docs/user-guide.md) |
| How CFF works | [docs/control-flow-flattening.md](docs/control-flow-flattening.md) |
| How junk works | [docs/junk-code-injection.md](docs/junk-code-injection.md) |
| Project landing | [README.md](README.md) |

## Minimal run

```powershell
# After Release|x64 build
.\x64\Release\ObfuGuard.exe
# 1 = Control Flow Flattening (x64 PE + PDB)
# 2 = Junk + trampoline (x86/x64 PE + PDB)
# 0 = Exit
```

Output: `input.cff.exe` or `input.junk.exe` beside the input PE.
