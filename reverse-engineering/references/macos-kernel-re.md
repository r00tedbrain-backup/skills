# macOS & Kernel Reverse Engineering Reference

## Table of Contents
1. [macOS Binary Formats](#binary)
2. [macOS Security Architecture](#security)
3. [XPC Services Analysis](#xpc)
4. [launchd & Persistence](#launchd)
5. [macOS Kernel Extensions (kext)](#kext)
6. [SIP & Security Bypass Research](#sip)
7. [macOS Dynamic Analysis](#dynamic)
8. [Entitlements & Sandbox](#sandbox)
9. [Linux Kernel Module RE](#lkm)

---

## 1. macOS Binary Formats {#binary}

```bash
# Mach-O internals
file binary                         # arch, type
otool -h binary                     # Mach-O header
otool -l binary                     # all load commands
otool -l binary | grep -A3 LC_ENCRYPTION  # encrypted? (App Store)
otool -L binary                     # linked dylibs
otool -tV binary                    # disassemble __text
otool -s __DATA __cfstring binary   # Core Foundation strings
nm -a binary                        # all symbols
nm -u binary                        # undefined (imported) symbols
nm binary | c++filt                 # demangle C++ symbols

# Fat binary (Universal Binary)
lipo -info binary                   # list architectures
lipo -extract x86_64 binary -output binary_x64
lipo -extract arm64 binary -output binary_arm64

# dylib analysis
otool -D binary.dylib               # install name
otool -l binary.dylib | grep -A2 LC_ID_DYLIB
install_name_tool -change old_path new_path binary  # patch dylib path

# Mach-O sections of interest
# __TEXT __text          → code
# __TEXT __stubs         → PLT-equivalent (dylib stubs)
# __TEXT __stub_helper   → lazy binding
# __DATA __got           → non-lazy pointers (like GOT)
# __DATA __la_symbol_ptr → lazy symbol pointers
# __DATA __cfstring      → CF strings (readable)
# __DATA __objc_methnames → ObjC method names
# __DATA __objc_selrefs  → ObjC selector refs
# __DATA __objc_classrefs → ObjC class refs
```

### Mach-O Parsing with Python
```python
import lief

binary = lief.parse("target")
print(f"Arch: {binary.header.cpu_type}")
print(f"Entry: {hex(binary.entrypoint)}")

for cmd in binary.commands:
    print(f"  {cmd.command}")

for sym in binary.symbols:
    if not sym.is_external and sym.value:
        print(f"  {sym.name} @ {hex(sym.value)}")

for lib in binary.libraries:
    print(f"  → {lib.name}")
```

---

## 2. macOS Security Architecture {#security}

```
Security layers (outer to inner):
┌──────────────────────────────────────┐
│  Gatekeeper  → code signing check    │
│  XProtect    → malware signatures    │
│  Notarization → Apple server check  │
│  App Sandbox → filesystem isolation  │
│  SIP         → system integrity      │
│  Secure Boot → firmware integrity   │
└──────────────────────────────────────┘

Code Signing:
- All apps must be signed to run (GK)
- Entitlements embedded in signature
- codesign -dv --verbose=4 binary    → show signing info

Key security daemons:
- syspolicyd      → Gatekeeper enforcement
- trustd          → certificate trust
- amfid            → code signing enforcement  
- endpointd        → Endpoint Security framework
- eslogger         → ES event logger (macOS 13+)
```

### Code Signing Analysis
```bash
codesign -dv --verbose=4 target              # full signing info
codesign -dv --entitlements - target         # show entitlements XML
codesign --verify --deep --strict target     # verify signature

# Check if notarized
spctl --assess --verbose target
spctl -a -v target

# Remove signature (for patching)
codesign --remove-signature target

# Ad-hoc sign (local only, no Apple account)
codesign -s - target                         # ad-hoc sign
codesign -f -s - target                      # force re-sign

# Sign with developer cert
codesign -s "Developer ID Application: Name (TEAMID)" target
```

---

## 3. XPC Services Analysis {#xpc}

```bash
# XPC = inter-process communication on macOS
# Used extensively for privilege separation

# Find XPC services
find /System/Library /Library /Applications -name "*.xpc" 2>/dev/null
# Each .xpc bundle contains the service binary

# Inspect XPC service
ls /Applications/App.app/Contents/XPCServices/
otool -L service_binary               # linked frameworks
strings service_binary | grep xpc     # XPC message keys

# XPC interface analysis (Ghidra/IDA)
# Look for: xpc_dictionary_get_string, xpc_dictionary_get_uint64
# These are the message handlers → understand protocol
# Find: xpc_connection_set_event_handler → main handler

# Audit XPC interface (using xpcspy or manual)
# 1. Identify exported XPC methods
# 2. Find privilege checks (auth right checks)
# 3. Look for: authorization_create, SecAccessControlCreate
# 4. Identify if caller validation is done

# xpcspy (runtime XPC monitor)
# github.com/hot3eed/xpcspy
xpcspy -p <pid>    # monitor XPC traffic for process
```

### Privilege Escalation via XPC
```
Common vulnerability patterns:
1. Missing caller validation → any process can talk to privileged XPC
2. PID-based auth (TOCTOU) → PID can be recycled
3. Insufficient parameter validation → type confusion, overflow
4. Symlink following in privileged operations
5. Missing audit token checks

Correct pattern (what to look for being ABSENT):
xpc_connection_get_audit_token() → xpc_dictionary_set_audit_token()
or SecCodeCopyGuestWithAttributes() → validate calling process
```

---

## 4. launchd & Persistence {#launchd}

```bash
# List launch agents/daemons
launchctl list                             # all loaded
launchctl list | grep -v "com.apple"       # third-party

# Persistence locations
# User agents (runs as user):
~/Library/LaunchAgents/
/Library/LaunchAgents/

# System daemons (runs as root):
/Library/LaunchDaemons/
/System/Library/LaunchDaemons/  (SIP protected)

# Inspect plist
cat /Library/LaunchDaemons/com.malware.plist
plutil -p /Library/LaunchDaemons/com.malware.plist

# Key plist keys:
# ProgramArguments  → what runs
# RunAtLoad         → runs at boot/login
# KeepAlive         → restart if killed (persistence!)
# StartInterval     → run every N seconds
# WatchPaths        → run when path changes
# Label             → service name

# Login items (macOS 13+: System Settings → General → Login Items)
sfltool dumpbtm                 # Boot/Login Item database dump

# Other persistence mechanisms
# - Login items: /Library/Application Support/com.apple.backgroundtaskmanagementd/
# - Cron: crontab -l, /etc/cron.d/, /etc/periodic/
# - AT jobs: atq
# - Emond: /etc/emond.d/ (legacy)
# - Scripting additions: /Library/ScriptingAdditions/
# - Kernel extensions: /Library/Extensions/ (needs approval)
```

---

## 5. macOS Kernel Extensions (kext) {#kext}

```bash
# List loaded kernel extensions
kextstat
kextstat | grep -v "com.apple"   # third-party only
kextstat | grep "signed:yes"

# kext structure
ls /Library/Extensions/somekext.kext/
# Contents/MacOS/<binary>  → kext binary
# Contents/Info.plist       → bundle info, CFBundleExecutable

# Analyze kext binary
otool -h SomeKext                   # verify it's kext (MH_KEXT_BUNDLE)
nm SomeKext | grep " T "            # exported symbols (IOKit methods)

# IOKit analysis (most kexts use IOKit)
# Key classes: IOService, IOUserClient
# Attack surface: IOUserClient::externalMethod → handles userland calls

# Find IOUserClient methods (Ghidra):
# 1. Find IOUserClient subclass
# 2. Look for getTargetAndMethodForIndex or externalMethod override
# 3. Each entry point = potential attack surface
# 4. Validate: buffer sizes, pointer dereferences

# iokit-utils
ioclasscount          # IOKit class instance counts
ioreg -l              # IOKit registry (hardware tree)
iouserclient-enum     # enumerate IOUserClient methods (third-party)

# Modern kext replacement: DriverKit (runs in user space)
# Safer, but still analyzable same way (user-space binary)
```

---

## 6. SIP & Security Research {#sip}

```bash
# Check SIP status
csrutil status

# SIP protected paths (read-only even as root):
# /System, /usr (except /usr/local), /bin, /sbin
# /Library/Apple

# For security research (in VM only):
# 1. Boot Recovery (Cmd+R at startup)
# 2. Terminal → csrutil disable
# 3. Reboot

# What SIP protects:
# - Kernel patching (prevents rootkits)
# - System file modification
# - Loading unsigned kexts
# - Runtime attachment to system processes (lldb -p <system_daemon>)

# Research without disabling SIP:
# Use Endpoint Security framework (needs entitlement)
# Use DTrace (partially allowed with SIP)
# Use dtrace system calls monitor:
sudo dtrace -n 'syscall::open*:entry { printf("%s %s", execname, copyinstr(arg0)); }'
sudo dtrace -n 'syscall:::entry /execname == "target"/ { trace(probefunc); }'

# Instruments (Xcode) → System Trace: excellent for macOS internals
# Attach to any process without SIP disabling
```

---

## 7. macOS Dynamic Analysis {#dynamic}

```bash
# LLDB (full reference in dynamic-debugging.md)
lldb target
# Attach: lldb -p <pid>
# Note: SIP prevents attaching to system processes without disabling SIP

# dtruss (strace equivalent)
sudo dtruss ./target 2>&1 | head -50
sudo dtruss -p <pid>
sudo dtruss -a ./target   # all info including args

# fs_usage — filesystem activity
sudo fs_usage -w -f filesystem <pid>
sudo fs_usage -w target_binary

# opensnoop (DTrace-based)
sudo opensnoop -n target_binary      # files opened

# nettop — network activity
sudo nettop -p <pid>

# Frida on macOS
frida -n "Target App" -l script.js
frida -p <pid> -l script.js

# Hopper Disassembler (native macOS, excellent for Apple platforms)
# File → Read Executable → supports Mach-O natively
# Built-in ObjC class browser, Swift demangling

# class-dump (ObjC headers)
class-dump -H -o headers/ /Applications/Target.app/Contents/MacOS/Target

# Swift symbol demangling
swift-demangle < <(nm /Applications/Target.app/Contents/MacOS/Target | grep "_T")
nm Target | xcrun swift-demangle
```

---

## 8. Entitlements & Sandbox {#sandbox}

```bash
# View entitlements
codesign -dv --entitlements - target
codesign -dv --entitlements :- target  # XML format

# Key entitlements for research:
# com.apple.security.cs.disable-library-validation  → can load unsigned libs
# com.apple.security.cs.allow-dyld-environment-vars → DYLD_INSERT_LIBRARIES works
# com.apple.system-task-ports → can get task port of other processes
# com.apple.private.security.no-container → no sandbox
# com.apple.security.get-task-allow → lldb can attach (dev builds)

# Sandbox analysis
sandbox-exec -f profile.sb ./target   # run with sandbox profile
# Profile language: SBPL (Scheme-based)

# Convert compiled sandbox profile to readable
# (sandbox-dump tool, third-party)

# Check if process is sandboxed
sandbox_check(getpid(), NULL, SANDBOX_FILTER_NONE) # returns 1 if sandboxed

# DYLD_INSERT_LIBRARIES injection (if entitlement allows)
DYLD_INSERT_LIBRARIES=/path/to/mylib.dylib ./target
# Great for hooking without Frida
# Requires: library validation disabled OR target has get-task-allow
```

---

## 9. Linux Kernel Module RE {#lkm}

```bash
# LKM = Linux Kernel Module (.ko files)
# Used by: rootkits, security tools, AC on Linux, device drivers

# Basic analysis
file module.ko              # ELF relocatable
nm module.ko               # symbols
objdump -d module.ko       # disassemble
readelf -a module.ko       # full info
modinfo module.ko          # module metadata, parameters, license

# Load/unload (analysis environment only)
insmod module.ko
lsmod | grep module_name
rmmod module_name
dmesg | tail -20           # kernel log output

# Key Linux kernel APIs to recognize:
# sys_call_table hooking (classic rootkit)
# kallsyms_lookup_name → find unexported symbols
# __builtin_return_address → get callers
# register_kprobe → kernel probes
# kthread_create → kernel threads
# filp_open / kernel_read → file operations from kernel
# sock_create / kernel_sendmsg → network from kernel

# Rootkit detection patterns:
# - sys_call_table modification (compare with /boot/System.map)
# - hidden processes: compare /proc with actual task list
# - hidden files: compare dentry cache with directory read

# Dynamic analysis
# Add printk() calls → see in dmesg
# Use kprobes: probe any kernel function without modifying it
# SystemTap / BCC (eBPF): trace kernel functions safely

# eBPF for kernel tracing (modern, safe)
sudo bpftrace -e 'kprobe:do_sys_open { printf("%s %s\n", comm, str(arg1)); }'
sudo bpftrace -e 'kretprobe:sys_clone { printf("fork pid=%d\n", retval); }'

# Ftrace
echo function > /sys/kernel/debug/tracing/current_tracer
echo target_func > /sys/kernel/debug/tracing/set_ftrace_filter
cat /sys/kernel/debug/tracing/trace
```
