# Static Analysis Reference

## Table of Contents
1. [Triage & Identification](#triage)
2. [Ghidra](#ghidra)
3. [radare2](#radare2)
4. [objdump / binutils](#binutils)
5. [Entropy & Packer Detection](#entropy)
6. [Symbol & Import Analysis](#symbols)
7. [String Extraction](#strings)
8. [Struct Recovery](#structs)
9. [Patching Binaries](#patching)

---

## 1. Triage & Identification {#triage}

```bash
file <binary>                          # format, arch, endian, stripped
checksec --file=<binary>               # security mitigations
readelf -h <binary>                    # ELF header
readelf -S <binary>                    # section headers
readelf -d <binary>                    # dynamic section (imports)
nm -D <binary>                         # dynamic symbols
nm --defined-only <binary>             # defined symbols only
ldd <binary>                           # shared library dependencies
objdump -x <binary>                    # all headers
size <binary>                          # section sizes

# PE (Windows) - use wine or cross-tools
peinfo <binary>
pescan -v <binary>                     # pefile Python

# Quick Python triage
python3 -c "
import sys
data = open(sys.argv[1],'rb').read()
magic = {b'\\x7fELF':'ELF', b'MZ':'PE', b'\\xcf\\xfa':'Mach-O 64', b'\\xca\\xfe':'Mach-O FAT', b'PK':'ZIP/APK/JAR', b'dex\\n':'DEX'}
for sig,name in magic.items():
    if data.startswith(sig): print(name); break
" <binary>
```

---

## 2. Ghidra {#ghidra}

### Project Setup
```bash
# Launch GUI
ghidra

# Headless import + auto-analysis
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_projects MyProject \
  -import <binary> \
  -overwrite \
  -scriptPath ~/ghidra_scripts \
  -postScript ExportDecompiled.java
```

### Essential Keyboard Shortcuts
| Action | Shortcut |
|--------|----------|
| Decompile function | `F` (in listing) |
| Rename symbol | `L` |
| Retype variable | `Ctrl+L` |
| Cross-references (XRefs) | `Ctrl+Shift+F` |
| Go to address | `G` |
| Search strings | `S` (window) |
| Define struct | `T` on variable |
| Patch bytes | Right-click → Patch Instruction |
| Function graph | `V` |
| Search memory | `S` → Memory Search |

### Navigation Strategy
```
1. Window → Symbol Tree → filter "main" → start here
2. Window → Defined Strings → look for URLs, keys, suspicious values
3. References → show all refs to interesting function
4. Right-click function → Call Trees → understand call graph
5. Analysis → One Shot → Class Analyzer (for C++ vtables)
```

### Ghidra Python Script (Jython)
```python
# List all functions with "crypt" in name
from ghidra.program.model.listing import FunctionManager
fm = currentProgram.getFunctionManager()
for f in fm.getFunctions(True):
    if "crypt" in f.getName().lower():
        print(f"{f.getEntryPoint()}: {f.getName()}")
```

### Fixing Decompiler Output
```python
# Retype variable to pointer to struct
from ghidra.program.model.data import PointerDataType, StructureDataType
# 1. Data Type Manager → New Structure → add fields
# 2. In decompiler: right-click variable → Retype → select struct*
# 3. Rename params: right-click → Rename Parameter

# Force function signature
# Edit → Function... → set return type, params
```

---

## 3. radare2 {#radare2}

### Essential Commands
```bash
# Open for analysis
r2 -A <binary>          # open + autoanalyze (slow but thorough)
r2 -A -q -c "..." <bin> # headless one-liner

# Inside r2 shell:
i          # file info
iI         # binary info (checksec-like)
ia         # all info
is         # symbols
ii         # imports
iS         # sections
iz         # strings in data section
izz        # all strings in binary
afl        # list all functions
afl~main   # filter functions containing "main"
pdf @ main # disassemble + decompile function
pdf @ sym.func_name
pdc @ main # decompile (r2dec plugin needed)
s 0xaddr   # seek to address
x 64 @ esp # hexdump 64 bytes at esp
VV         # visual function graph (q to quit)
V!         # visual panels mode
```

### Search Operations
```bash
/ password          # search string
/x deadbeef        # search hex pattern
/r sym.strcpy      # find references to symbol
axt @ sym.strcmp   # cross-references TO sym.strcmp
axf @ 0x401000     # cross-references FROM address
```

### Patching
```bash
r2 -w <binary>     # open in write mode
s 0x401234
wa nop             # write NOP
wa jmp 0x401240    # write jump
wao nop            # NOP out current instruction
wB 0x90            # write single byte
```

### r2pipe (Python scripting)
```python
import r2pipe
r2 = r2pipe.open("<binary>", flags=["-A"])
funcs = r2.cmdj("aflj")  # functions as JSON
for f in funcs:
    if f.get("size", 0) > 500:
        print(f"Large: {f['name']} @ {hex(f['offset'])} size={f['size']}")
r2.quit()
```

### Useful Plugins
```bash
r2pm install r2dec    # decompiler
r2pm install r2frida  # live frida bridge
r2pm install r2ghidra # ghidra decompiler engine in r2
```

---

## 4. objdump / binutils {#binutils}

```bash
# Disassemble all code sections
objdump -d <binary>
objdump -d -M intel <binary>        # Intel syntax
objdump -d --no-show-raw-insn <binary>

# Disassemble specific function
objdump -d <binary> | awk '/^[0-9a-f]+ <func_name>/,/^$/'

# All sections with content
objdump -s <binary>

# Relocation entries
objdump -r <binary>
readelf -r <binary>

# Dynamic relocations (GOT/PLT)
objdump -R <binary>

# Section dump
objdump -j .rodata -s <binary>
```

---

## 5. Entropy & Packer Detection {#entropy}

```bash
# Check entropy (>7.0 = likely packed/encrypted)
python3 -c "
import math, sys
data = open(sys.argv[1],'rb').read()
if not data: print('empty'); exit()
freq = [0]*256
for b in data: freq[b]+=1
n = len(data)
entropy = -sum((f/n)*math.log2(f/n) for f in freq if f)
print(f'Entropy: {entropy:.2f}/8.00')
print('Likely packed!' if entropy > 7.0 else 'Normal')
" <binary>

# Per-section entropy
pip install lief --quiet
python3 -c "
import lief, math
bin = lief.parse('<binary>')
for s in bin.sections:
    d = bytes(s.content)
    if not d: continue
    freq = [0]*256
    for b in d: freq[b]+=1
    n=len(d)
    e=-sum((f/n)*math.log2(f/n) for f in freq if f)
    print(f'{s.name:20} entropy={e:.2f}')
"

# Detect known packers
upx -t <binary>           # UPX
die <binary>              # Detect-It-Easy (best all-around)
exeinfo <binary>          # Windows packers
```

### Unpacking Strategies
```bash
# UPX
upx -d <binary> -o <unpacked>

# Generic: run + dump
# 1. Run in debugger until OEP (original entry point)
# 2. At OEP: dump process memory
# Linux: /proc/<pid>/mem  or use gcore
# Windows: pe-sieve, hollows_hunter

# Frida dump (see references/frida.md → Memory Dumping)
```

---

## 6. Symbol & Import Analysis {#symbols}

```bash
# ELF symbols
nm -D <binary>                      # dynamic
nm --defined-only <binary>          # defined only
readelf -s <binary>                 # full symbol table
readelf -W -s <binary>              # wide output (no truncation)

# Filter dangerous functions
nm -D <binary> | grep -E "gets|strcpy|sprintf|system|exec|popen|scanf"

# Imports (what capabilities does it have?)
readelf -d <binary> | grep NEEDED   # shared libs
objdump -T <binary>                 # dynamic symbol table
ltrace -e '*' <binary>             # trace all lib calls at runtime

# PLT entries (function call stubs)
objdump -d <binary> | grep "@plt"
```

---

## 7. String Extraction {#strings}

```bash
strings <binary>                    # default (printable, min 4 chars)
strings -a <binary>                 # all sections
strings -n 8 <binary>               # minimum length 8
strings -t x <binary>               # with hex offset
strings -e l <binary>               # UTF-16 LE (Windows)
strings -e b <binary>               # UTF-16 BE

# Find interesting patterns
strings -a <binary> | grep -iE "http|ftp|key|pass|secret|token|api|flag|admin|debug"
strings -a <binary> | grep -E "[0-9a-fA-F]{32,}"  # hashes/keys
strings -a <binary> | grep -E "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"  # IPs

# With offset → navigate in Ghidra
strings -a -t x <binary> | grep "interesting_string"
# Then in Ghidra: G → 0x<offset>
```

---

## 8. Struct Recovery {#structs}

### Manual Recovery Pattern (Ghidra/IDA)
```
1. Find alloc: malloc(N) or stack alloc
2. Note N → that's the struct size
3. Trace uses of returned pointer
4. Each ptr+offset access → struct field
5. Data Type Manager → New Structure
6. Add fields at discovered offsets
7. Retype all variables using this struct
```

### C++ Class Recovery
```bash
# Find vtables (Ghidra: Analysis → One Shot → C++ Class Analyzer)
# Look for: pointer-to-pointer patterns in .rodata
# Each vtable entry is a virtual function

# RTTI (Run-Time Type Info) if not stripped:
readelf -s <binary> | grep "_ZTI"   # typeinfo symbols
c++filt _ZN5MyApp7connectEv         # demangle C++ symbol
```

---

## 9. Patching Binaries {#patching}

```bash
# Python patch (safe, keeps original)
python3 << 'EOF'
import shutil
shutil.copy("binary", "binary.patched")
with open("binary.patched", "r+b") as f:
    f.seek(0x1234)          # offset to patch
    f.write(b"\x90\x90")    # NOP NOP
EOF

# Patch with hex editor
xxd <binary> > binary.hex
# Edit binary.hex at relevant offset
xxd -r binary.hex > binary.patched
chmod +x binary.patched

# Patch ELF entry point
# In Ghidra: right-click instruction → Patch Instruction
# Then: File → Export Program → ELF

# Patch comparison (JNE → JE)
# x86: 75 XX → 74 XX  (JNZ → JZ)
# x86: 0F 85 → 0F 84  (JNZ far → JZ far)
# NOP: 90 (single), 66 90 (2-byte), 0F 1F 00 (3-byte)
```
