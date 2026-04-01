---
name: reverse-engineering
description: >
  Expert-level reverse engineering and binary debugging skill. Use this skill whenever the user
  wants to analyze, decompile, disassemble, or debug binaries, executables, APKs, iOS apps,
  firmware, or obfuscated code. Triggers for: static analysis, dynamic analysis, malware analysis,
  exploit development, CTF challenges, binary patching, anti-debug bypass, protocol reversing,
  memory forensics, hooking, frida scripting, GDB/LLDB debugging, radare2, Ghidra, jadx, apktool,
  strings analysis, symbol resolution, or any request involving "reverse engineer", "RE", "decompile",
  "disassemble", "patch binary", "debug crash", "analyze malware", "bypass protection",
  "hook function", "intercept traffic", "find vulnerability", or examining unknown file formats.
  Always load this skill for CTF pwn/rev challenges, app security assessments, and firmware analysis.
---

# Reverse Engineering & Debugging

Professional methodology for static analysis, dynamic analysis, debugging, and binary exploitation.

## Quick Reference — Load the Right Reference File

| Task | Reference File |
|------|---------------|
| Static analysis, disassembly, Ghidra, radare2, objdump, patching | `references/static-analysis.md` |
| GDB (+ pwndbg/gef/peda), LLDB, strace/ltrace, crash analysis | `references/dynamic-debugging.md` |
| Android APK, DEX, smali, ADB, Frida on Android, repackaging | `references/android-re.md` |
| iOS IPA, Mach-O, class-dump, Frida ObjC/Swift, Keychain | `references/ios-re.md` |
| macOS XPC, launchd, kext, SIP, Linux kernel modules | `references/macos-kernel-re.md` |
| Windows PE, WinDbg, x64dbg, .NET/dnSpy, kernel drivers | `references/windows-re.md` |
| Frida scripting, hooking Java/Native/ObjC, SSL unpin, gadget | `references/frida.md` |
| .NET IL, dnSpy, de4dot, Java/JVM, Kotlin, Unity/IL2CPP, Mono | `references/managed-code-re.md` |
| Malware, obfuscation, packer analysis, IOC extraction, Volatility | `references/malware-analysis.md` |
| CTF pwn/rev, BOF, ROP, heap exploitation, pwntools, angr/Z3 | `references/exploit-dev.md` |
| Network protocol RE, Wireshark, mitmproxy, Protobuf, gRPC, mobile MITM | `references/protocol-re.md` |
| Firmware, binwalk, QEMU emulation, JTAG/UART, U-Boot, IoT | `references/firmware-embedded.md` |
| EAC, BattlEye, Vanguard, FACEIT, VAC, kernel AC analysis | `references/anticheat-re.md` |
| Ghidra Python/Java scripts, headless, vulnerability finding, custom analyzers | `references/ghidra-scripting.md` |

---

## Universal First Steps

Before loading any reference file, establish context:

### 1. Identify the Target

```bash
file <binary>           # file type, arch, bits, stripped?
xxd <binary> | head -4  # magic bytes
strings -a <binary> | head -60
checksec --file=<binary>  # NX, PIE, RELRO, stack canary, ASLR
```

**Binary format decision tree:**
- ELF → Linux native → `references/static-analysis.md` + `references/dynamic-debugging.md`
- PE/PE32+ → Windows native → `references/windows-re.md` + `references/static-analysis.md`
- PE with .NET metadata → `references/managed-code-re.md` (dnSpy first)
- Mach-O → macOS/iOS → `references/macos-kernel-re.md` + `references/ios-re.md`
- DEX/APK/AAB → Android → `references/android-re.md`
- JAR/WAR/AAR → Java → `references/managed-code-re.md`
- .sys driver → `references/windows-re.md` (kernel section) or `references/anticheat-re.md`
- Assembly-CSharp.dll → Unity → `references/managed-code-re.md` (Unity section)
- Unknown/firmware → `references/firmware-embedded.md` (binwalk + entropy)

### 2. Establish Scope

Ask the user (or infer from context):

- **Goal**: understand logic / find vuln / bypass protection / patch / CTF flag / malware IOCs?
- **Platform**: Linux / Windows / macOS / Android / iOS / embedded?
- **Tools available**: Ghidra / IDA / radare2 / Binary Ninja / Hopper?
- **Dynamic possible?**: Can we run it? VM? Emulator? Physical device?

### 3. Choose Analysis Mode

```
Static only  → No execution risk, slower understanding
Dynamic only → Fast but misses dead code
Static + Dynamic (recommended) → Static for map, dynamic for runtime truth
```

---

## Core Toolchain Summary

### Static
| Tool | Best For |
|------|----------|
| `Ghidra` | Full decompilation, scripting, free |
| `radare2` / `cutter` | CLI powerhouse, scripting, embedded |
| `Binary Ninja` | API-first, fast, commercial |
| `IDA Pro` / `IDA Free` | Industry standard, best signatures |
| `objdump` | Quick disassembly, no install |
| `readelf` / `nm` | ELF symbol/section inspection |
| `jadx` | Android DEX → Java, GUI |
| `apktool` | APK unpack / repack / smali |

### Dynamic
| Tool | Best For |
|------|----------|
| `GDB` + `pwndbg`/`peda`/`gef` | Linux ELF debugging |
| `LLDB` | macOS/iOS/Swift debugging |
| `Frida` | Cross-platform hooking, no source |
| `strace` / `ltrace` | Syscall / library call tracing |
| `Valgrind` | Memory errors, Helgrind |
| `WinDbg` | Windows kernel + user mode |
| `x64dbg` | Windows GUI debugger |

### Network
| Tool | Best For |
|------|----------|
| `Wireshark` / `tshark` | Packet capture + dissection |
| `mitmproxy` / `Burp Suite` | HTTP/S MITM |
| `Frida` | In-process SSL unpin |
| `tcpdump` | Headless capture |

---

## Methodology Frameworks

### Static Analysis Workflow
```
1. file + strings + checksec           → quick triage
2. Entropy analysis                    → packed/encrypted?
3. Import table / symbol table         → understand capabilities
4. Load in decompiler                  → rename, retype, annotate
5. Identify key functions              → main(), crypto, network, anti-debug
6. Trace data flow                     → user input → sink
7. Document findings                   → comment inline
```

### Dynamic Analysis Workflow
```
1. Set up isolated environment         → VM / container / device
2. Run with strace/ltrace first        → understand syscall footprint
3. Attach debugger                     → set breakpoints at key functions
4. Observe runtime behavior            → memory, registers, branches taken
5. Correlate with static              → validate decompiler output
6. Patch / hook as needed             → bypass checks, log values
```

### Vulnerability Discovery Workflow
```
1. Attack surface mapping             → inputs: file, network, env vars, args
2. Dangerous function search          → strcpy, gets, sprintf, memcpy, system
3. Integer overflow candidates        → size calculations, loops
4. Format string candidates           → printf(user_input)
5. UAF / double-free candidates       → heap allocation patterns
6. Trigger + confirm                  → crash → controlled → exploitable
```

---

## Anti-Analysis Bypass — Quick Reference

### Anti-Debug Detection
```bash
# Check if binary detects debugger
strings <bin> | grep -iE "ptrace|debugger|isDebuggerPresent|TracerPid"

# Linux: ptrace self-detection
# Bypass: preload hook or patch the ptrace call
```

### Common Protections
| Protection | Detection | Bypass |
|-----------|-----------|--------|
| `ptrace` anti-debug | `strace` shows ptrace(TRACEME) | Patch JNZ→JMP or LD_PRELOAD fake ptrace |
| Timing checks | `rdtsc` / `clock_gettime` in loop | Patch comparison or NOP |
| Checksum/integrity | Hash of own .text section | Patch after decryption, before check |
| Packer (UPX etc.) | High entropy + small imports | `upx -d` / dump from memory after unpack |
| Obfuscated strings | No readable strings | Run + extract from memory / Frida hook |
| SSL pinning (mobile) | Network fail in app | Frida ssl-unpin / see `references/frida.md` |

---

## Output Standards

When reporting RE findings, always structure output as:

```markdown
## Binary: <name>
- **Format**: ELF64 / PE32+ / DEX / Mach-O
- **Arch**: x86_64 / ARM64 / ARMv7 / MIPS
- **Stripped**: Yes/No | **PIE**: Yes/No | **NX**: Yes/No

## Key Findings
1. <function name @ offset> — <what it does>
2. ...

## Vulnerability / Behavior
- <description with evidence>
- Offset: 0x<addr>
- Triggerable via: <input vector>

## Recommended Next Steps
- [ ] <action>
```

---

## Naming Conventions for Decompiler Work

Follow these standards when annotating in Ghidra / IDA / r2:

```
Functions:  verb_noun_context      → decrypt_config_xor, check_license_hwid
Variables:  type_purpose           → buf_user_input, sz_packet, ptr_heap_chunk
Structs:    ST_<name>              → ST_PacketHeader, ST_LicenseData
Labels:     loc_<purpose>         → loc_anti_debug_fail, loc_success
```

---

## Scripting Quick Starters

See `references/frida.md` for full Frida patterns.

### GDB Python one-liner (log function args)
```python
# In GDB: source this file
import gdb
class LogArgs(gdb.Breakpoint):
    def stop(self):
        frame = gdb.selected_frame()
        print(f"[*] {frame.name()} rdi={gdb.parse_and_eval('$rdi')} rsi={gdb.parse_and_eval('$rsi')}")
        return False  # don't stop, just log
LogArgs("target_function")
```

### radare2 batch analysis
```bash
r2 -A -q -c "afl~suspicious; pdf @ sym.check_license" <binary>
```

### Ghidra headless analysis
```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/proj MyProject \
  -import <binary> -postScript PrintAST.java -scriptPath ~/ghidra_scripts
```
