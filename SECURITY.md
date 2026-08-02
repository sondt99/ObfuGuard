# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.0.x (latest) | :white_check_mark: |
| 3.0.x | :x: |
| 2.0.x | :x: |
| 1.0.x | :x: |

## Important Notice

ObfuGuard is a **binary obfuscation research tool**. It modifies PE executable files at the machine code level. Please be aware of the following:

- Only use ObfuGuard on binaries you own or have explicit permission to modify
- Obfuscated binaries may trigger antivirus/EDR false positives due to structural changes (new sections, relocated code, entry point modification)
- Do not use ObfuGuard to conceal malicious software. This tool is intended for legitimate software protection and academic research

## Reporting a Vulnerability

If you discover a security vulnerability in ObfuGuard, please report it responsibly:

1. **Email:** Contact the maintainer at the email listed in the GitHub profile [@sondt99](https://github.com/sondt99)
2. **GitHub Issues:** For non-sensitive bugs, open an issue at [github.com/sondt99/ObfuGuard/issues](https://github.com/sondt99/ObfuGuard/issues)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact

### Response Timeline

- **Acknowledgment:** Within 7 days
- **Assessment:** Within 14 days
- **Fix/Patch:** Depends on severity; critical issues will be prioritized

## Known Considerations

### Binary Integrity

ObfuGuard modifies PE structure extensively. The following changes are expected and not considered vulnerabilities:

- New PE sections (`.0Cff`, `.0Dev`, and per-function sections)
- Modified entry point
- Relocated function code
- Increased binary size

### PDB File Handling

ObfuGuard loads PDB files using the Windows DbgHelp API. Only process PDB files from trusted sources, as malformed PDB files could potentially cause unexpected behavior.

### Third-party Dependencies

ObfuGuard depends on several third-party libraries. Security issues in these dependencies should be reported to their respective maintainers:

| Library | Repository |
|---------|-----------|
| Capstone | [github.com/capstone-engine/capstone](https://github.com/capstone-engine/capstone) |
| Keystone | [github.com/keystone-engine/keystone](https://github.com/keystone-engine/keystone) |
| LIEF | [github.com/lief-project/LIEF](https://github.com/lief-project/LIEF) |
| AsmJit | [github.com/asmjit/asmjit](https://github.com/asmjit/asmjit) |
| Zydis | [github.com/zyantific/zydis](https://github.com/zyantific/zydis) |
