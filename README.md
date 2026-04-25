<p align="center">
  <img src="https://img.shields.io/badge/Claude_Code-Compatible-blueviolet?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiPjxwYXRoIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6Ii8+PHBhdGggZD0iTTIgMTdsMTAgNSAxMC01Ii8+PHBhdGggZD0iTTIgMTJsMTAgNSAxMC01Ii8+PC9zdmc+" alt="Claude Code Compatible" />
  <img src="https://img.shields.io/badge/skills.sh-Published-success?style=for-the-badge" alt="Published on skills.sh" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License" />
</p>

# r00tedbrain-backup/skills

> Agent skills for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and other AI coding agents. Published on [skills.sh](https://skills.sh).

---

## 🔬 reverse-engineering

Expert-level reverse engineering and binary analysis skill. Provides complete methodologies, tool references, and scripting patterns for analyzing binaries, debugging executables, reversing firmware, bypassing protections, and developing exploits.

### Install

```bash
npx skills add r00tedbrain-backup/skills
```

### Modules

| Module | File | Coverage |
|--------|------|----------|
| **Static Analysis** | `references/static-analysis.md` | Ghidra, radare2, IDA, Binary Ninja, objdump, readelf, patching |
| **Dynamic Debugging** | `references/dynamic-debugging.md` | GDB + pwndbg/gef/peda, LLDB, strace, ltrace, crash analysis |
| **Android RE** | `references/android-re.md` | APK, DEX, smali, jadx, apktool, ADB, Frida on Android |
| **iOS RE** | `references/ios-re.md` | IPA, Mach-O, class-dump, Frida ObjC/Swift, Keychain |
| **macOS & Kernel** | `references/macos-kernel-re.md` | XPC, launchd, kext, SIP bypass, Linux kernel modules |
| **Windows RE** | `references/windows-re.md` | PE, WinDbg, x64dbg, .NET/dnSpy, kernel drivers |
| **Frida Scripting** | `references/frida.md` | Hooking Java/Native/ObjC, SSL unpinning, Frida gadget |
| **Managed Code** | `references/managed-code-re.md` | .NET IL, dnSpy, de4dot, Java/JVM, Kotlin, Unity/IL2CPP |
| **Malware Analysis** | `references/malware-analysis.md` | Obfuscation, packer analysis, IOC extraction, Volatility |
| **Exploit Development** | `references/exploit-dev.md` | BOF, ROP, heap exploitation, pwntools, angr, Z3 |
| **Protocol RE** | `references/protocol-re.md` | Wireshark, mitmproxy, Protobuf, gRPC, Lua dissectors, Boofuzz fuzzing |
| **Firmware & IoT** | `references/firmware-embedded.md` | binwalk, QEMU emulation, JTAG/UART, U-Boot |
| **Anti-Cheat RE** | `references/anticheat-re.md` | EAC, BattlEye, Vanguard, FACEIT, VAC, kernel AC |
| **Ghidra Scripting** | `references/ghidra-scripting.md` | Python/Java scripts, headless mode, custom analyzers |
| **IDAPython & IDALib** | `references/idapython.md` | 800+ lines of scripts: common API, Hex-Rays, Appcall, OLLVM, headless batch, IDA access modes (MCP / file export / IDALib) |
| **Unicorn Emulation** | `references/unicorn-emulation.md` | Function-level emulation, JNI stubbing, syscall sim, decryption |
| **Symbol Recovery** | `references/symbol-recovery.md` | Magic number catalog, paired call patterns, xref analysis |
| **Struct Recovery** | `references/struct-recovery.md` | C++ vtables, std::string/vector/map layouts, field type inference |

### Bundled Tools (`tools/`)

| Tool | Purpose |
|------|---------|
| `tools/ida_export_plugin.py` | IDA Pro plugin (Ctrl-Shift-E) — exports IDB to a `decompile/` directory of plain-text files for AI agents |
| `tools/dex_memory_dumper.js` | Frida agent — dumps DEX from running Android apps (memory scan + ClassLoader traversal) |
| `tools/mcp/` | Setup docs + JSON snippets for connecting agents to MCP servers (`ida-pro-mcp`, `GhidraMCP`, `r2mcp`) |

All bundled tools are **original MIT-licensed code**. We link to upstream MCP servers and plugins instead of redistributing them.

### Triggers

This skill auto-loads when Claude detects tasks involving:

- `reverse engineer` · `decompile` · `disassemble` · `patch binary`
- `debug crash` · `analyze malware` · `bypass protection`
- `hook function` · `intercept traffic` · `find vulnerability`
- CTF pwn/rev challenges · app security assessments · firmware analysis

---

## Structure

```
skills/
├── LICENSE                                # MIT
├── README.md
└── reverse-engineering/
    ├── SKILL.md                           # Main skill definition
    ├── references/                        # 18 methodology modules
    │   ├── static-analysis.md
    │   ├── dynamic-debugging.md
    │   ├── android-re.md
    │   ├── ios-re.md
    │   ├── macos-kernel-re.md
    │   ├── windows-re.md
    │   ├── frida.md
    │   ├── managed-code-re.md
    │   ├── malware-analysis.md
    │   ├── exploit-dev.md
    │   ├── protocol-re.md
    │   ├── firmware-embedded.md
    │   ├── anticheat-re.md
    │   ├── ghidra-scripting.md
    │   ├── idapython.md
    │   ├── unicorn-emulation.md
    │   ├── symbol-recovery.md
    │   └── struct-recovery.md
    └── tools/                             # Bundled MIT-licensed utilities
        ├── README.md
        ├── ida_export_plugin.py
        ├── dex_memory_dumper.js
        └── mcp/
            ├── README.md
            ├── ida-pro-mcp.md
            ├── ghidra-mcp.md
            ├── claude-config-snippets.json
            └── cursor-config-snippets.json
```

## License

MIT
