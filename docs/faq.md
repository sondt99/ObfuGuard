# FAQ and troubleshooting

## General

### What is ObfuGuard?

A Windows **PE post-link obfuscator** with two modes: **control-flow flattening** (x64) and **junk + trampoline** relocation (x86/x64). It needs a **PDB** for function discovery.

### Will it make my software uncrackable?

No. It raises reverse-engineering cost. Determined analysts can still succeed. Treat it as one layer of a broader protection strategy.

### Will my program still work?

Usually yes for simple programs; not guaranteed for:

- Heavy SEH / C++ exceptions tied to original code layout  
- Self-checksum or self-modifying code  
- Absolute address tables that are not relocated  
- Jump tables inside functions (CFF skips these; still test)  

**Always** run your own tests after obfuscation.

### Can I apply CFF and junk to the same binary?

You can chain modes, but the second pass still needs accurate symbols/RVAs. A first-pass PE no longer has a matching PDB for the new layout. Prefer one mode per research experiment, or drive the second pass with known RVAs.

### Is Linux supported for the tool itself?

**Building/running `ObfuGuard.exe` targets Windows + MSVC.** The repo and Python helpers can live on Linux, but PE mutation requires a Windows environment.

---

## Modes and behavior

### Why is CFF 64-bit only?

The dispatcher and encoding assume x64 conventions (`rax`, RIP-relative patterns). A PE32 port would be a separate engine.

### Why are some functions not flattened?

- Blacklisted / CRT-like names  
- Too small  
- Detected jump tables  
- Filter after discovery (v4.x no longer flattens every PDB symbol)  

### Why is the `.0Cff` section not always 10 MB?

Section size is **estimated** from filtered function sizes (with a hard cap at `CFF_SECTION_SIZE`). Older docs assumed a fixed 10 MB reservation.

### What is `.0Dev`?

A reserved name for entry-point related metadata / research stubs (`CFF_DEV_SECTION_NAME`). Encoding runs when `obfuscate_entry_point` is true.

### Why one PE section per junk function?

Simplifies relocation and trampolines. Cost: PE section count (~96). The tool auto-limits inject count.

### Why does junk prefer PDB size over first `ret`?

Early `return` paths leave more of the function after the first `ret`. Using PDB size avoids truncating multi-exit functions.

### Why is junk injection faster than older versions?

Multi-function inject does **one** LIEF layout build for all new sections instead of rebuilding after every function.

---

## Blacklist

### How do I customize exclusions?

Edit or provide `blacklist_default.txt` (see [junk-code-injection.md](junk-code-injection.md)). Use `big:Symbol` for large-binary-only entries.

### Why was `sum_to_n` skipped in old builds?

A filter treated **any** underscore as dangerous. That is fixed: only **leading** `_` and backticks are heuristic skips.

---

## Build and run

### vcpkg install fails

```powershell
cd path\to\vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
.\vcpkg install capstone:x64-windows keystone:x64-windows lief:x64-windows asmjit:x64-windows zydis:x64-windows
```

### Missing headers / link errors

- Platform must be **x64**  
- Triplet must be **x64-windows**  
- Rebuild after `vcpkg integrate install`  

### Missing DLLs at runtime

Copy Capstone, Keystone, LIEF, AsmJit, Zydis (and fmt/spdlog if needed) next to `ObfuGuard.exe`.

### “PDB not found”

- Ensure `name.pdb` exists  
- Rebuild target with `/Zi`  
- Check CodeView path inside the PE  

### “Control Flow Flattening only supports 64-bit”

You passed a 32-bit PE to mode 1. Use mode 2 for x86, or rebuild the target as x64.

### “No eligible functions”

Everything was filtered (size/blacklist) or the PDB had no usable functions. Inspect symbols and blacklist.

### Section limit / few junk injections

Normal for large function counts. Prefer manual selection of critical functions or reduce inject set.

### Antivirus alerts on output

New sections and trampolines look suspicious. Expected for research tools; whitelist lab machines if appropriate.

---

## Testing

### Scripts cannot find ObfuGuard

```powershell
$env:OBFUGUARD_EXE = "C:\path\to\ObfuGuard.exe"
python auto_test.py
```

### `match_check` fails on random programs

Programs that call `rand`/`time` without fixed seeds will differ. Exclude them or seed deterministically.

---

## Ethics and security

- Only obfuscate binaries you own or may modify.  
- Do not use ObfuGuard to hide malware.  
- Report tool vulnerabilities via [SECURITY.md](../SECURITY.md).  

---

## Still stuck?

1. Read [installation.md](installation.md) and [user-guide.md](user-guide.md)  
2. Check [CHANGELOG.md](../CHANGELOG.md) for behavior changes  
3. Open an issue on [github.com/sondt99/ObfuGuard](https://github.com/sondt99/ObfuGuard) with OS, VS version, sample type (x86/x64), and logs  
