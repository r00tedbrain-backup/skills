# Windows Reverse Engineering Reference

## Table of Contents
1. [PE Format Internals](#pe)
2. [WinDbg](#windbg)
3. [x64dbg Advanced](#x64dbg)
4. [.NET Reversing (dnSpy / de4dot)](#dotnet)
5. [Windows API & Internals](#winapi)
6. [Registry & Persistence](#registry)
7. [Kernel & Driver Analysis](#kernel)
8. [COM / ActiveX](#com)
9. [Process Injection Techniques](#injection)
10. [Windows Sandbox / Automation](#sandbox)

---

## 1. PE Format Internals {#pe}

```bash
# Python pefile
pip install pefile

python3 << 'EOF'
import pefile, sys
pe = pefile.PE(sys.argv[1])

print("=== HEADERS ===")
print(f"  Machine:    {hex(pe.FILE_HEADER.Machine)}")
print(f"  Timestamp:  {pe.FILE_HEADER.TimeDateStamp}")
print(f"  EntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
print(f"  ImageBase:  {hex(pe.OPTIONAL_HEADER.ImageBase)}")
print(f"  Subsystem:  {pe.OPTIONAL_HEADER.Subsystem}")
print(f"  imphash:    {pe.get_imphash()}")

print("\n=== SECTIONS ===")
for s in pe.sections:
    print(f"  {s.Name.decode().rstrip(chr(0)):10} VA={hex(s.VirtualAddress)} "
          f"SZ={hex(s.SizeOfRawData)} Chars={hex(s.Characteristics)}")

print("\n=== IMPORTS ===")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"  {entry.dll.decode()}")
    for imp in entry.imports:
        print(f"    {hex(imp.address)} {imp.name.decode() if imp.name else f'ord({imp.ordinal})'}")

print("\n=== EXPORTS ===")
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print(f"  {hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)} {exp.name.decode() if exp.name else ''}")
EOF <target.exe>

# Quick triage one-liner
python3 -c "
import pefile; pe=pefile.PE('target.exe')
print('Arch:', hex(pe.FILE_HEADER.Machine))
print('EP:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print('imphash:', pe.get_imphash())
for s in pe.sections: print(s.Name, hex(s.VirtualAddress), hex(s.SizeOfRawData))
"

# Detect anomalies
python3 -c "
import pefile, math
pe = pefile.PE('target.exe')
for s in pe.sections:
    data = s.get_data()
    if not data: continue
    freq=[0]*256
    for b in data: freq[b]+=1
    n=len(data)
    e=-sum((f/n)*math.log2(f/n) for f in freq if f)
    print(f'{s.Name.decode().rstrip(chr(0)):10} entropy={e:.2f} {\"PACKED\" if e>7 else \"\"}')
"
```

### PE Overlay / Appended Data
```bash
# Data after end of last section = overlay (common in malware droppers)
python3 -c "
import pefile
pe = pefile.PE('target.exe')
overlay_off = pe.get_overlay_data_start_offset()
if overlay_off:
    print(f'Overlay at {hex(overlay_off)}, size={len(pe.__data__)-overlay_off}')
    open('overlay.bin','wb').write(pe.__data__[overlay_off:])
"
```

---

## 2. WinDbg {#windbg}

### Setup
```
Download: WinDbg Preview (Microsoft Store) or WDK
Symbols: .sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols
         .reload /f
```

### Essential Commands
```windbg
# Process / thread
|           list processes
|0s         switch to process 0
~           list threads
~0s         switch to thread 0
~*k         stack trace all threads
~*e !teb    TEB for all threads

# Execution
g           go (continue)
p           step over
t           step into
gu          step out (go up)
pc          step to next call
tb          step to next branch
ba r4 addr  hardware breakpoint on read (4 bytes)
bp addr     software breakpoint
bl          list breakpoints
bc *        clear all breakpoints
bp module!function
bp kernel32!CreateFileW

# Memory
d   addr        display bytes
db  addr        display bytes (hex+ascii)
dw  addr        display WORDs
dd  addr        display DWORDs
dq  addr        display QWORDs
da  addr        display ASCII string
du  addr        display Unicode string
dp  addr        display pointer-sized values
dt  _TEB @$teb  display struct (with PDB type info)
dt  nt!_EPROCESS addr

# Search
s -b addr L?range pattern  # search bytes
s -a addr L?range "string" # search ASCII
s -u addr L?range "str"    # search Unicode

# Registers
r           all registers
r rax       specific register
r rax=0x42  set register

# Stack
k           call stack
kv          call stack + frame vars
kb          call stack + first 3 args
kn          stack with frame numbers
.frame N    switch to frame N
dv          display local variables (needs symbols)

# Modules
lm          list loaded modules
lmvm ntdll  verbose module info
x ntdll!*CreateFile*  find symbols matching pattern

# Exceptions
.exr -1     last exception record
.cxr -1     last exception context
!analyze -v verbose crash analysis
!analyze -hang  hang analysis

# Heap
!heap -s    heap summary
!heap -stat -h HEAPADDR  heap statistics
!heap -flt s SIZE  allocations of SIZE

# Kernel mode extras
!process 0 0        list all processes
!process 0 7        list + full info
!thread             current thread info
!pcr                processor control region
!pte addr           page table entry
!vtop cr3 vaddr     virtual to physical
```

### WinDbg Scripts (.wds)
```windbg
# Log all CreateFile calls
bp kernel32!CreateFileW "du poi(@rsp+8); g"

# Break on specific string argument
bp kernel32!CreateFileW ".if (poi(@rsp+8) != 0) { .if ($spat(@poi(@rsp+8), \"*target*\")) { .echo hit; } .else { g } } .else { g }"

# Trace function with args
bp target!interesting_function "r rcx, rdx, r8; g"

# Automated crash dump analysis
!analyze -v
.logopen crash_analysis.txt
k 50
!analyze -v
.logclose
q
```

---

## 3. x64dbg Advanced {#x64dbg}

```
# Essential plugins to install (x64dbg plugin manager):
- ScyllaHide     → anti-anti-debug
- xAnalyzer      → better function analysis
- OllyDumpEx     → process dumper
- SwissArmyKnife → utilities
- Labeless        → IDA↔x64dbg sync

# Useful keyboard shortcuts
F2  → toggle breakpoint
F4  → run to cursor
F7  → step into
F8  → step over
F9  → run
Ctrl+G → go to address / expression
Ctrl+F → search in current module
Ctrl+B → find pattern (hex)
Ctrl+A → analyze selection
Alt+M  → memory map
Alt+B  → breakpoints list
Alt+L  → log window
```

### x64dbg Scripting (x64dbgpy3)
```python
import x64dbgpy3.x64dbg as dbg

# Set breakpoint + callback
def on_hit():
    rax = dbg.GetRegister("rax")
    rcx = dbg.GetRegister("rcx")
    print(f"[*] rax={rax:#x} rcx={rcx:#x}")
    # Read string argument
    ptr = dbg.GetRegister("rcx")
    s = dbg.MemReadString(ptr)
    print(f"[*] arg: {s}")

addr = dbg.RemoteGetProcAddress("kernel32.dll", "CreateFileW")
dbg.SetBreakpoint(addr, on_hit)
dbg.Run()
```

---

## 4. .NET Reversing {#dotnet}

### dnSpy — Primary Tool
```
Download: https://github.com/dnSpy/dnSpy (or dnSpyEx fork)

Workflow:
1. File → Open → target.exe / .dll
2. Assembly Explorer: browse namespaces → classes → methods
3. Double-click method → full C# decompilation
4. Edit method: right-click → Edit Method (C#) → compile + save
5. Debug: File → Start Debugging (attach or spawn)
   - Set breakpoints in decompiled C# code
   - Watch variables, step through code
6. Save modified assembly: File → Save All
```

### de4dot — .NET Deobfuscator
```bash
de4dot.exe target.exe                    # auto-detect + deobfuscate
de4dot.exe target.exe -o clean.exe
de4dot.exe --detect target.exe          # just identify obfuscator
de4dot.exe -f target.exe --strenc       # also decrypt strings

# Supported obfuscators: ConfuserEx, Dotfuscator, SmartAssembly, 
# Babel, Crypto Obfuscator, .NET Reactor, Agile.NET, many more
```

### .NET CLI Tools
```bash
# ildasm — Microsoft IL disassembler
ildasm target.exe /out:output.il

# ilasm — reassemble modified IL
ilasm output.il /exe /output:patched.exe

# ILSpy (cross-platform alternative to dnSpy)
ilspycmd target.exe -o ./decompiled/ -p  # decompile to project

# Mono (Linux)
monodis target.exe > output.il
mono target.exe

# Inspect with dotnet-dump
dotnet-dump collect -p <pid>
dotnet-dump analyze core_dump
> dumpheap -type System.String
> gcroot <obj_addr>
```

### .NET Reflection-based Runtime Analysis
```csharp
// Inject via CLR hosting or use dnSpy debugger
// Enumerate loaded assemblies at runtime:
foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
    Console.WriteLine(asm.FullName);

// Invoke private method via reflection
var type = assembly.GetType("Namespace.ClassName");
var method = type.GetMethod("PrivateMethod", 
    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
method.Invoke(instance, new object[] { arg1, arg2 });
```

---

## 5. Windows API & Internals {#winapi}

### Process & Memory
```
Key structures (dt in WinDbg or read in documentation):
_EPROCESS     → kernel process object
_ETHREAD      → kernel thread object
_TEB          → Thread Environment Block (FS:[0] on x86, GS:[0] on x64)
_PEB          → Process Environment Block (TEB->ProcessEnvironmentBlock)
_LDR_DATA     → loaded module list (PEB->Ldr->InMemoryOrderModuleList)
_RTL_USER_PROCESS_PARAMETERS → commandline, image path

# Walk PEB module list (shellcode technique):
# PEB → Ldr → InMemoryOrderModuleList → each entry has DllBase, FullDllName
```

### Suspicious API Patterns
```
Process Injection:
  VirtualAllocEx + WriteProcessMemory + CreateRemoteThread  → classic injection
  NtMapViewOfSection                                         → map injection
  SetWindowsHookEx                                          → hook injection
  QueueUserAPC                                              → APC injection
  UpdateProcThreadAttribute + PROC_THREAD_ATTRIBUTE_PARENT  → PPID spoofing

Defense Evasion:
  NtUnmapViewOfSection / ZwUnmapViewOfSection               → process hollowing
  Module32First/Next without LoadLibrary                    → manual mapping
  GetProcAddress(GetModuleHandle("ntdll"), "Nt...")          → direct syscalls
  CryptUnprotectData                                        → DPAPI credential decryption

Persistence:
  RegSetValueEx HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  CreateService / OpenService
  SchtasksW / ITaskScheduler COM
  IFEO (Image File Execution Options) hijacking

Privilege Escalation:
  ImpersonateLoggedOnUser / CreateProcessWithTokenW
  AdjustTokenPrivileges
  NtSetInformationToken
```

---

## 6. Registry & Persistence {#registry}

```bash
# Common persistence locations
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\SYSTEM\CurrentControlSet\Services\  (services)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon  (userinit, shell)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load
HKLM\SOFTWARE\Classes\*\shell\open\command  (file association hijack)

# Query persistence (PowerShell)
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Autoruns (Sysinternals) - best tool for persistence enumeration
autorunsc.exe -accepteula -a * -c -h -s '*' > autoruns.csv

# Compare before/after (RegShot)
regshot /1sn  # take first shot
# ... run malware ...
regshot /2sn  # take second shot → compare
```

---

## 7. Kernel & Driver Analysis {#kernel}

```windbg
# Kernel debugging setup:
# Target VM: bcdedit /debug on, bcdedit /dbgsettings net hostip:X.X.X.X port:50000
# Host: WinDbg → Kernel → Net → port 50000

# Driver enumeration
lm m *   # list all modules including drivers
!drvobj \Driver\maldriver  # driver object info
!devobj \Device\maldev     # device object info

# Check loaded drivers for anomalies
!object \Driver   # all driver objects
sc query type= driver  # via Services

# DKOM (Direct Kernel Object Manipulation) detection
!process 0 0  # compare with tasklist — hidden processes?

# Callbacks (rootkit persistence)
# Enumerate PsSetCreateProcessNotifyRoutine callbacks:
dt nt!_CALLBACK_ENTRY  # structure
# Use tools: Windows Callback Monitor, KmdManager

# IDT / SSDT hooks
!idt           # interrupt descriptor table
!ssdt          # service descriptor table (undocumented in modern WinDbg, use scripts)
```

### Driver Static Analysis (IDA/Ghidra)
```
Key driver entry points to find:
- DriverEntry              → main entry, sets up dispatch routines
- IRP_MJ_CREATE            → DeviceIoControl opens
- IRP_MJ_DEVICE_CONTROL    → IOCTL handler (attack surface!)
- IRP_MJ_READ / WRITE      → read/write handlers

IOCTL code analysis:
METHOD_BUFFERED    (0) → safest, kernel copies buffer
METHOD_IN_DIRECT   (1) → MDL, check buffer sizes
METHOD_OUT_DIRECT  (2) → MDL
METHOD_NEITHER     (3) → raw user pointer → most dangerous

# IOCTL code format: (DeviceType<<16) | (Access<<14) | (Function<<2) | Method
# Decode: IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode
```

---

## 8. COM / ActiveX {#com}

```bash
# Enumerate COM servers (PowerShell)
Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" | 
  Select-Object -First 50 |
  ForEach-Object { 
    $clsid = $_.PSChildName
    $inproc = (Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue)."(default)"
    if ($inproc) { "$clsid → $inproc" }
  }

# COM Hijacking enumeration (missing registrations user can create)
# Tool: COMHunter, Process Monitor (filter for "NAME NOT FOUND" in HKCU CLSID)

# Analyze COM server in IDA/Ghidra
# Look for: DllGetClassObject → IClassFactory::CreateInstance → target interface
# Find IDispatch::Invoke for automation-compatible servers
```

---

## 9. Process Injection Techniques {#injection}

### Detection Reference
```c
// Classic DLL injection signatures to look for:
// 1. OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibraryA)
// 2. NtCreateSection → NtMapViewOfSection (reflective injection)
// 3. SetWindowsHookEx with WH_KEYBOARD / WH_GETMESSAGE
// 4. Process Hollowing: CreateProcess(SUSPENDED) → NtUnmapViewOfSection → WriteProcessMemory → ResumeThread

// Detect via:
// - VirtualQueryEx: look for MEM_PRIVATE RX regions not backed by file
// - pe-sieve /pid X → scans for injected code automatically
// - hollows_hunter → finds hollowed processes

// Frida: monitor injection attempts
const openProcess = Module.findExportByName("kernel32.dll", "OpenProcess");
Interceptor.attach(openProcess, {
  onEnter(args) {
    const pid = args[2].toInt32();
    const access = args[0].toInt32();
    if (access & 0x1F0FFF) // PROCESS_ALL_ACCESS or write
      console.log(`[!] OpenProcess(pid=${pid}, access=${hex(access)})`);
  }
});
```

---

## 10. Windows Sandbox / Automation {#sandbox}

```bash
# Cuckoo Sandbox
pip install cuckoo
cuckoo submit target.exe
cuckoo web  # view reports at localhost:8000

# Any.run / Hybrid Analysis / VirusTotal (online)
# Upload sample → automated behavior report

# Windows Sandbox (built-in Win10/11 Pro)
# Settings → Windows Features → Windows Sandbox
# Clean snapshot every run

# FLARE-VM setup (automated Windows RE environment)
# https://github.com/mandiant/flare-vm
# Installs: x64dbg, Ghidra, dnSpy, Sysinternals, de4dot, PEiD, etc.
```
