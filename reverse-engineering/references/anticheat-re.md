# Anti-Cheat Reverse Engineering Reference

> **Scope:** Understanding anti-cheat mechanisms for security research, game integrity analysis,
> vulnerability disclosure, and academic study. This reference documents detection techniques
> and architectural patterns.

## Table of Contents
1. [Anti-Cheat Architecture Overview](#overview)
2. [EasyAntiCheat (EAC)](#eac)
3. [BattlEye](#battleye)
4. [Vanguard (Riot)](#vanguard)
5. [FACEIT / VAC](#faceit)
6. [Common Detection Methods](#detection)
7. [Kernel-Level AC Analysis](#kernel)
8. [Driver Integrity & Signing](#signing)
9. [Memory Scanning Patterns](#memory)
10. [Analysis Toolchain](#toolchain)

---

## 1. Anti-Cheat Architecture Overview {#overview}

```
Anti-cheat systems generally operate at one or more of these levels:

┌─────────────────────────────────────┐
│         Game Process (User)         │  ← Module integrity, hook detection
├─────────────────────────────────────┤
│      AC Client (User mode)          │  ← Process scanning, API monitoring
├─────────────────────────────────────┤
│      AC Driver (Kernel mode)        │  ← Memory scanning, callback hooks
├─────────────────────────────────────┤
│      AC Server (Remote)             │  ← Behavior analysis, stats anomalies
└─────────────────────────────────────┘

User-mode AC:  VAC, some EAC versions, older BattlEye
Kernel-mode AC: Vanguard, modern EAC, modern BattlEye, FACEIT
Hypervisor-level: Some Vanguard research suggests VM detection

Detection categories:
1. Signature scanning     → known cheat patterns in memory
2. Behavioral analysis    → suspicious API calls, timing
3. Integrity verification → game module tampering
4. Hardware fingerprinting → HWID bans
5. Driver enumeration     → known cheat/tool drivers
6. Callback monitoring    → registered kernel callbacks
```

---

## 2. EasyAntiCheat (EAC) {#eac}

### Architecture
```
Components:
- EasyAntiCheat_EOS.sys   → kernel driver (loaded at game start)
- EasyAntiCheat.exe       → user-mode service
- EasyAntiCheat_launcher  → pre-game launcher

Driver loading:
- Registered as a service: HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat
- Kernel callbacks: PsSetCreateProcessNotifyRoutine, PsSetLoadImageNotifyRoutine
- ObRegisterCallbacks: handle stripping (prevents OpenProcess with full access)
```

### Static Analysis Approach
```bash
# EAC driver analysis (Ghidra/IDA)
# 1. Load EasyAntiCheat_EOS.sys
# 2. Set architecture: x86_64, OS: Windows
# 3. Find DriverEntry → trace dispatch routines
# 4. Find IOCTL handler (IRP_MJ_DEVICE_CONTROL)
# 5. Identify kernel API calls: MmCopyMemory, PsLookupProcessByProcessId, etc.

# Key functions to identify:
# - Process enumeration routine
# - Module integrity check
# - Driver enumeration
# - Memory scanner
# - Handle stripper (ObRegisterCallbacks callback)

# String decryption: EAC uses XOR/RC4 on strings
# Find: decrypt_string() calls → log results with x64dbg conditional BP
```

### Detection Mechanisms
```
Process/Module scanning:
- Walks PEB module list looking for known cheat DLL names/hashes
- Scans non-module backed memory regions (VAD walk)
- Checks for unsigned/self-signed modules in process

Hardware fingerprinting:
- Reads disk serial numbers (IOCTL_STORAGE_QUERY_PROPERTY)
- NIC MAC addresses (GetAdaptersInfo)
- CPU CPUID
- BIOS/SMBIOS strings
- Motherboard serial
- Combines → HWID hash

Anti-debug:
- NtQueryInformationProcess(ProcessDebugPort)
- Timing checks (RDTSC)
- Checking for known debugger window titles
- IsDebuggerPresent, CheckRemoteDebuggerPresent
```

---

## 3. BattlEye {#battleye}

### Architecture
```
Components:
- BEService.exe         → user-mode service (starts before game)
- BEDaisy.sys           → kernel driver
- BattlEye/BEClient.dll → injected into game process

Initialization:
1. BEService starts
2. Game launches
3. BEClient.dll injected into game
4. BEDaisy.sys kernel driver loaded
5. Bidirectional encrypted channel: Game ↔ BEClient ↔ BEService ↔ BE servers

Server-side:
- BEClient sends encrypted reports to BE servers
- Server-side analysis of received data
- Ban can happen post-session (delayed ban)
```

### Scanning Behavior
```
Memory scanning:
- Periodically scans entire process memory for signature patterns
- Signatures updated server-side (fetched at game launch)
- Scans both user and kernel memory via driver

Driver blacklist:
- Maintains list of known cheat driver signatures
- Enumerates loaded drivers via ZwQuerySystemInformation(SystemModuleInformation)
- Checks driver names, hashes, import patterns

Callback hooks:
- PsSetCreateProcessNotifyRoutineEx → process creation monitoring
- PsSetLoadImageNotifyRoutine → DLL load monitoring
- Checks each loaded image against blacklist
```

### Analysis
```bash
# Analyze BEClient.dll (dumped from game process)
# 1. Dump: use x64dbg "Scylla" plugin after injection
# 2. Load in Ghidra
# 3. Find: scan loop, signature matching, report encryption

# BEDaisy.sys analysis
# Look for:
# - MmCopyVirtualMemory calls (memory scanning)
# - ZwQuerySystemInformation usage (driver enumeration)
# - IoCreateDevice + symbolic link (communication channel)
# - Registered callbacks

# Communication protocol analysis (Wireshark)
# BattlEye uses UDP to BE servers
# Capture: port 2302-2305 range common for games using BE
tshark -i eth0 -Y "udp" -f "udp portrange 2302-2305" -w be_traffic.pcap
```

---

## 4. Vanguard (Riot Games) {#vanguard}

### Architecture
```
Components:
- vgk.sys       → kernel driver (STARTS AT BOOT, before OS fully loads)
- vgc.exe       → user-mode client
- Riot Client   → game launcher

Key distinction: vgk.sys loads at boot (not at game launch)
This means it's active even when not playing — controversial design.

Privileges:
- Runs at kernel level with full system access
- Can read/write any process memory
- Monitors all kernel callbacks
- DSE (Driver Signature Enforcement) must be enabled
```

### Detection Capabilities
```
Kernel integrity:
- Verifies PatchGuard is active (no kernel patches)
- Detects DKOM (Direct Kernel Object Manipulation)
- Monitors kernel code pages for modifications
- Detects unsigned code execution

Driver enumeration:
- Full driver list via PsLoadedModuleList
- Hashes each driver and compares to whitelist/blacklist
- Checks for "cheater" driver signatures

Hypervisor detection:
- CPUID hypervisor bit check
- Timing anomalies with VM exits
- Checks for VirtualBox/VMware artifacts in registry/drivers

Hardware fingerprinting:
- TPM measurements (if available)
- HWID components: disk serial, NIC MAC, CPUID, BIOS
- Windows machine GUID
```

### Analysis Approach
```bash
# vgk.sys static analysis
# Load in IDA/Ghidra
# Find DriverEntry → setup callbacks

# Key areas:
# 1. Boot-time initialization (before most drivers)
# 2. Anti-VM detection routines
# 3. HWID collection functions
# 4. Communication with vgc.exe (IOCTL interface)
# 5. Process/module scanner

# Kernel debugging vgk.sys:
# Requires KD enabled + vgk may detect and block
# Use VM with VirtualKD or kdnet

# WinDbg symbols (partial, public PDB sometimes available)
.sympath+ srv*https://msdl.microsoft.com/download/symbols
.reload /f vgk.sys
lm m vgk
x vgk!*   # list symbols
```

---

## 5. FACEIT / VAC {#faceit}

### FACEIT AC
```
Architecture:
- faceit.exe           → user-mode client (always-on like Vanguard)
- FACEIT kernel driver → kernel-level scanning
- Anti-screen capture
- Mandatory before queue

Detects:
- DLL injection (monitors LoadLibrary callbacks)
- Memory writes to game process
- Cheat signatures
- VM detection (some versions)
- Screen capture hooks (for coach/stream concerns)
```

### VAC (Valve Anti-Cheat)
```
Architecture:
- Part of Steam client (steamservice.exe)
- Fully server-side ban system (delayed)
- Modules downloaded and executed locally
- "VAC modules" scanned periodically

Key characteristics:
- Delayed bans (can be weeks after cheat use)
- Module-based: Valve pushes new scan modules silently
- Scans for known cheat signatures in memory
- Checks loaded DLLs hashes
- Reads hardware IDs for HWID bans

Analysis:
- VAC modules are encrypted+compressed
- Downloaded to: Steam\appcache\VAC\
- Can monitor with Process Monitor when they load
- Decryption has been reverse engineered historically
```

---

## 6. Common Detection Methods {#detection}

### Memory Integrity Checks
```c
// Pattern: hash game module pages, re-check periodically
// If hash differs → integrity violation → ban/kick

// Analysis: find the hash function + comparison in AC binary
// Ghidra: search for CRC32/SHA1/custom hash implementations
// Look for: loop over .text section → hash → compare stored value

// Common hash functions used:
// CRC32 (fast, simple)
// Custom XOR-based rolling hash
// MD5/SHA1 (less common, slower)
```

### Handle Stripping (ObRegisterCallbacks)
```c
// AC registers OB_OPERATION_HANDLE_CREATE callback
// When any process calls OpenProcess(game_pid) with WRITE access:
// Callback fires → strips PROCESS_VM_WRITE | PROCESS_VM_OPERATION
// Result: cheat can open handle but can't write memory

// Detection in Ghidra:
// Search for ObRegisterCallbacks import
// Trace to callback function: OB_PRE_OPERATION_INFORMATION handling
// See which access rights are stripped
```

### Kernel Callback Enumeration
```windbg
# Find all registered process creation callbacks
# (PsSetCreateProcessNotifyRoutine array)
# WinDbg kernel:
dt nt!_EX_CALLBACK_ROUTINE_BLOCK
# Search: !for_each_module ... (enumerate all ACs active)

# Using KDU (Kernel Driver Utility) for research:
kdu -list   # list known vulnerable drivers
```

---

## 7. Kernel-Level AC Analysis {#kernel}

```bash
# Setup for kernel driver analysis (safe, static):
# 1. Copy .sys file to analysis machine (never run untrusted drivers!)
# 2. Load in Ghidra/IDA as PE file, set OS to Windows, arch x86_64

# Find key Windows kernel APIs used:
# MmCopyVirtualMemory     → reading other process memory
# PsLookupProcessByProcessId → get EPROCESS from PID  
# ZwQuerySystemInformation → enumerate processes/drivers/handles
# KeStackAttachProcess     → attach to process context
# MmGetSystemRoutineAddress → dynamic import resolution (evasion)
# ObRegisterCallbacks      → handle operation hooks
# PsSetCreateProcessNotifyRoutineEx → process lifecycle hooks
# PsSetLoadImageNotifyRoutine → module load hooks
# CmRegisterCallback       → registry monitoring
# FltRegisterFilter        → filesystem minifilter

# Dynamic import resolution pattern (common in AC):
# Instead of direct import, they call MmGetSystemRoutineAddress("ZwQuerySystemInformation")
# This hides imports from static analysis
# Find: all MmGetSystemRoutineAddress calls → log strings

# x64dbg / WinDbg: set BP on MmGetSystemRoutineAddress
bp nt!MmGetSystemRoutineAddress "du @rcx; g"
```

---

## 8. Driver Integrity & Signing {#signing}

```bash
# Windows requires kernel drivers to be signed (DSE)
# How ACs verify this:
# 1. Check CI.dll exports (CiValidateImageHeader, etc.)
# 2. Check PatchGuard is enabled
# 3. Verify loaded drivers in PsLoadedModuleList have valid sigs

# Analyze driver signature enforcement:
# Find: calls to CiValidateFileObject or similar
# Understand: what happens when unsigned driver detected

# sigcheck (Sysinternals) to analyze AC driver certs
sigcheck.exe -i EasyAntiCheat_EOS.sys
sigcheck.exe -i BEDaisy.sys

# Certificate pinning:
# Some ACs verify their OWN driver cert specifically
# Look for: hardcoded certificate hash comparison
```

---

## 9. Memory Scanning Patterns {#memory}

```c
// Generic AC memory scan pseudocode (reconstructed from RE):

void scan_process_memory(PEPROCESS target) {
    PVOID address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    
    while (VirtualQueryEx(target, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            mbi.Type == MEM_PRIVATE &&           // not backed by file
            (mbi.Protect & PAGE_EXECUTE)) {       // executable
            
            // Read region
            BYTE* buffer = alloc(mbi.RegionSize);
            MmCopyVirtualMemory(target, address, current, buffer, mbi.RegionSize);
            
            // Scan for signatures
            for each signature in blacklist {
                if (memmem(buffer, mbi.RegionSize, sig.pattern, sig.len)) {
                    REPORT_CHEAT(target, address, sig.id);
                }
            }
        }
        address += mbi.RegionSize;
    }
}

// Key insight: ACs focus on MEM_PRIVATE + executable regions
// These are not backed by a file → likely injected code
```

---

## 10. Analysis Toolchain {#toolchain}

```bash
# Essential tools for AC research:

# Static analysis
IDA Pro / Ghidra               # primary disassembler/decompiler
BinDiff                        # diff AC versions to find changes
FLOSS                          # extract obfuscated strings

# Dynamic analysis (user mode)
x64dbg + ScyllaHide            # debugger with anti-anti-debug
API Monitor                    # log all API calls
Process Monitor (Sysinternals) # file/registry/process activity
Process Hacker                 # advanced process inspector

# Kernel analysis  
WinDbg (kernel mode)           # kernel debugging
Driver Buddy Reloaded (IDA)    # identify Windows kernel structs
KmdManager                     # kernel module manager
OSRLoader                      # test driver loader

# Network
Wireshark + NetworkMiner        # capture AC→server comms
Fiddler / mitmproxy             # HTTPS interception

# Virtualization (for safe testing)
VMware Workstation              # best VM compatibility
VirtualKD                       # fast kernel debugging over VM
QEMU                            # open source option

# Monitoring
WinPmem                         # memory acquisition
Volatility                      # memory forensics on dumps
PE-sieve                        # detect injected code in processes
```
