# IDAPython / IDALib Script Reference

Script snippets for IDA interactive use and IDALib headless analysis. Use as reference when generating IDAPython code.

- **IDAPython**: scripts run inside IDA GUI (Script Command, plugin, or IDC console)
- **IDALib**: headless mode introduced in IDA 9.0 — run analysis scripts without opening the IDA GUI

## Table of Contents
0. [Pre-check: How is the agent accessing IDA?](#access-modes)
1. [Common API](#common-api)
2. [Code Snippets](#snippets)
3. [Import Table](#imports)
4. [Type Information](#types)
5. [Hex-Rays Decompiler API](#hexrays)
6. [Obfuscation Helpers](#obfuscation)
7. [Instruction & Block Utilities](#utilities)
8. [NOP / Patching](#patching)
9. [IDALib (Headless IDA, 9.0+)](#idalib)
10. [Export workflow — decompile/ directory pattern](#export-workflow)

---

## 0. Pre-check: How is the agent accessing IDA? {#access-modes}

Before applying scripts from this reference, identify which IDA access mode is in use. Each mode has different capabilities and constraints.

### Mode A — IDA Pro MCP server (live queries)
The agent has an active MCP connection to a running IDA instance.

- **How to detect**: look for an active `ida-pro` (or equivalently named) MCP connection in the agent's tool list.
- **Capabilities**: query functions, decompilation, types, names, xrefs in real time. No exported files needed.
- **Reference**: `mrexodia/ida-pro-mcp` is a community MCP server that exposes IDA Pro to MCP clients.
- **When to use**: live analysis sessions where the user has IDA Pro open.

### Mode B — Pre-exported decompilation directory
The agent reads decompilation output from a directory of `.c` files exported beforehand.

- **How to detect**: a `decompile/` directory exists in the working directory containing files named by hex address (e.g., `0x401000.c`).
- **Capabilities**: read-only analysis of decompiled functions; no live IDA interaction.
- **Reference**: see [Section 10](#export-workflow) for the directory layout and how to generate it (a stand-alone export script is provided, plus integration with community plugins like `P4nda0s/IDA-NO-MCP`).
- **When to use**: large-scale or batch analysis, or when the user wants to share IDA state without giving live access.

### Mode C — IDALib headless
The agent itself runs Python scripts via IDALib (no GUI, no MCP).

- **How to detect**: IDA 9.0+ installed, `idapro` Python module available.
- **Capabilities**: full programmatic control of analysis without IDA GUI. Scripts use the `ida_*` modules directly.
- **Reference**: see [Section 9 (IDALib)](#idalib).
- **When to use**: CI pipelines, batch processing, or scripted analysis.

### Mode D — Direct IDAPython in IDA GUI
User executes scripts inside an open IDA window (Script Command / `File → Script File…`).

- **How to detect**: user has IDA open and runs scripts manually (the agent provides scripts to copy-paste).
- **Capabilities**: full IDA scripting API.
- **When to use**: interactive exploratory analysis.

### If no mode is available
Prompt the user with the choices:

```
No IDA access method detected. Choose one of the following:

A) IDA Pro MCP — connect an MCP server (e.g. mrexodia/ida-pro-mcp) so I
   can query IDA in real time.

B) Pre-exported decompilation directory — open IDA, run an export script
   (see references/idapython.md §10) or use a community plugin
   (e.g. P4nda0s/IDA-NO-MCP, Ctrl-Shift-E to export), then point me at
   the resulting decompile/ directory.

C) IDALib headless — give me a path to the binary and I will run IDAPython
   scripts directly via IDALib (requires IDA 9.0+ with the idapro Python
   module installed).

D) Manual IDAPython — I will give you scripts to run inside IDA's GUI;
   you paste the output back to me.
```

---

## 1. Common API {#common-api}

### Register Operations
```python
idc.get_reg_value('rax')
idaapi.set_reg_val("rax", 1234)
```

### Debug Memory Operations
```python
idc.read_dbg_byte(addr)
idc.read_dbg_memory(addr, size)
idc.read_dbg_dword(addr)
idc.read_dbg_qword(addr)
idc.patch_dbg_byte(addr, val)
idc.add_bpt(0x409437)          # add breakpoint
idaapi.get_imagebase()         # get image base address
```

### Local Memory Operations (modifies IDB database)
```python
idc.get_qword(addr)
idc.patch_qword(addr, val)
idc.patch_dword(addr, val)
idc.patch_word(addr, val)
idc.patch_byte(addr, val)
idc.get_db_byte(addr)
idc.get_bytes(addr, size)
idaapi.get_dword(addr)
idc.get_strlit_contents(addr)  # read string literal
```

### Disassembly
```python
GetDisasm(addr)                  # get disassembly text
idc.next_head(ea)                # get next instruction address
idc.create_insn(addr)            # C key, Make Code
ida_bytes.create_strlit          # create string, same as 'A' key
ida_funcs.add_func(addr)         # P key, create function
idc.del_items(addr)              # U key, undefine
```

### Address Conversion
```python
idc.get_name_ea(0, '_sub_6051')  # get address by function name
```

### Function Operations
```python
ida_funcs.get_func(ea)           # get function descriptor

# enumerate all functions
for func in idautils.Functions():
    print("0x%x, %s" % (func, idc.get_func_name(func)))
```

---

## 2. Code Snippets {#snippets}

### Byte Pattern Search
```python
import ida_bytes
import ida_idaapi
import ida_funcs
import idc

# find_bytes_list("90 90 90 90 90")
# find_bytes_list("55 ??")
# returns list of matching addresses
def find_bytes_list(bytes_pattern):
    ea = -1
    result = []
    while True:
        ea = idc.find_bytes(bytes_pattern, ea + 1)
        if ea == ida_idaapi.BADADDR:
            break
        result.append(ea)
    return result
```

### Appcall — Call Debuggee Functions
```python
# Call check_passwd(char *passwd) -> int from IDA debugger
passwd = ida_idd.Appcall.byref("MyFirstGuess")
res = ida_idd.Appcall.check_passwd(passwd)
if res.value == 0:
  print("Good passwd !")
else:
  print("Bad passwd...")
```

```python
# Explicitly create the buffer as a byref object
s_in = Appcall.byref("SomeEncryptedBuffer")
# Buffers are always returned byref
s_out = Appcall.buffer(" ", SizeOfBuffer)
# Call the debuggee function
Appcall.decrypt_buffer(s_in, s_out, SizeOfBuffer)
# Print the result
print("decrypted=", s_out.value)
```

```python
# Using Appcall.proto to define function signature
loadlib = Appcall.proto("kernel32_LoadLibraryA", "int __stdcall loadlib(const char *fn);")
hmod = loadlib("dll_to_inject.dll")

getlasterror = Appcall.proto("kernel32_GetLastError", "DWORD __stdcall GetLastError();")
print("lasterror=", getlasterror())

getcmdline = Appcall.proto("kernel32_GetCommandLineA", "const char *__stdcall getcmdline();")
print("command line:", getcmdline())
```

### Cross References
```python
# All references to an address
for ref in idautils.XrefsTo(ea):
    print(hex(ref.frm))

# Shorthand — all addresses that reference start_ea
[ref.frm for ref in idautils.XrefsTo(start_ea)]

# All references FROM a function
for ref in idautils.XrefsFrom(ea):
    print(hex(ref.to))
```

### Basic Block Traversal
```python
fn = 0x4800
f_blocks = idaapi.FlowChart(idaapi.get_func(fn), flags=idaapi.FC_PREDS)
for block in f_blocks:
    print(hex(block.start_ea))
```

```python
# Successor and predecessor blocks
for succ in block.succs():
    print(hex(succ.start_ea))

for pred in block.preds():
    print(hex(pred.start_ea))
```

### Debug Memory Read/Write Helpers
```python
def patch_dbg_mem(addr, data):
    for i in range(len(data)):
        idc.patch_dbg_byte(addr + i, data[i])

def read_dbg_mem(addr, size):
    dd = []
    for i in range(size):
        dd.append(idc.read_dbg_byte(addr + i))
    return bytes(dd)
```

### Read std::string (64-bit)
```python
def dbg_read_cppstr_64(objectAddr):
    """Read a std::string from the debugger (GCC layout, 64-bit)."""
    strPtr = idc.read_dbg_qword(objectAddr)
    result = ''
    i = 0
    while True:
        onebyte = idc.read_dbg_byte(strPtr + i)
        if onebyte == 0:
            break
        result += chr(onebyte)
        i += 1
    return result
```

### Read C String (64-bit, debug mode)
```python
def dbg_read_cstr_64(objectAddr):
    strPtr = objectAddr
    result = ''
    i = 0
    while True:
        onebyte = idc.read_dbg_byte(strPtr + i)
        if onebyte == 0:
            break
        result += chr(onebyte)
        i += 1
    return result
```

### Parse GNU C++ std::map
```python
import idautils
import idaapi
import idc

def parse_gnu_map_header(address):
    root = idc.read_dbg_qword(address + 0x10)
    return root

def parse_gnu_map_node(address):
    left  = idc.read_dbg_qword(address + 0x10)
    right = idc.read_dbg_qword(address + 0x18)
    data  = address + 0x20
    return left, right, data

def parse_gnu_map_travel(address):
    """Traverse GNU std::map structure (red-black tree) and return element addresses."""
    result = []
    worklist = [parse_gnu_map_header(address)]
    while len(worklist) > 0:
        addr = worklist.pop()
        (left, right, data) = parse_gnu_map_node(addr)
        if left > 0: worklist.append(left)
        if right > 0: worklist.append(right)
        result.append(data)
    return result

# Example
elements = parse_gnu_map_travel(0x0000557518073EB0)
for elem in elements:
    print(hex(elem))
```

### Read XMM Register (Debug)
```python
import struct

def read_xmm_reg(name):
    rv = idaapi.regval_t()
    idaapi.get_reg_val(name, rv)
    return struct.unpack('Q', rv.bytes())[0]
```

### Step Over and Wait for Debug Event
```python
from ida_dbg import wait_for_next_event, WFNE_ANY

while ida_dbg.step_over():
    wait_for_next_event(WFNE_ANY, -1)
    rip = idc.get_reg_value("rip")
    # ... custom logic per step
```

### Iterate Instructions in a Function
```python
for ins in idautils.FuncItems(0x401000):
    print(hex(ins))
```

### Get Function Callees (Instruction-Based)
```python
def ida_get_callees(func_addr: int) -> list:
    """Return a list of addresses called by the function at func_addr."""
    callees = []
    for head in idautils.Heads(func_addr, idaapi.get_func(func_addr).end_ea):
        if idaapi.is_call_insn(head):
            callee_ea = idc.get_operand_value(head, 0)
            callees.append(callee_ea)
    return callees
```

### Double / Complex Number Memory Operations
```python
import ctypes

def float_to_double_bytearray(value):
    double_value = ctypes.c_double(value)
    byte_array = bytearray(ctypes.string_at(ctypes.byref(double_value), ctypes.sizeof(double_value)))
    return byte_array

def set_pos(x, y):  # complex<double, double> at rbp-0x260
    rbp = idc.get_reg_value("rbp")
    complex_base = rbp - 0x260
    patch_dbg_mem(complex_base, float_to_double_bytearray(x))
    patch_dbg_mem(complex_base + 8, float_to_double_bytearray(y))

# Example
set_pos(5.0, 6.0)
```

---

## 3. Import Table {#imports}

### Enumerate Import Table
```python
import ida_nalt

nimps = ida_nalt.get_import_module_qty()
print("Found %d import(s)..." % nimps)

for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    if not name:
        print("Failed to get import module name for #%d" % i)
        name = "<unnamed>"

    print("Walking imports for module %s" % name)
    def imp_cb(ea, name, ordinal):
        if not name:
            print("%08x: ordinal #%d" % (ea, ordinal))
        else:
            print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
        return True
    ida_nalt.enum_import_names(i, imp_cb)

print("All done.")
```

### Check if Address is an Import Function
```python
def ida_is_import_function(addr: int) -> bool:
    is_find = False
    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        def imp_cb(ea, name, ordinal):
            nonlocal is_find
            if ea == addr:
                is_find = True
                return False
            return True
        ida_nalt.enum_import_names(i, imp_cb)

    return is_find
```

### Enumerate All Import Addresses
```python
from typing import List

def ida_enum_import_addr() -> List[int]:
    import_addrs = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        def imp_cb(ea, name, ordinal):
            nonlocal import_addrs
            import_addrs.append(ea)
            return True
        ida_nalt.enum_import_names(i, imp_cb)
    return import_addrs
```

---

## 4. Type Information {#types}

### Struct Member Traversal
```python
import ida_typeinf

def extract_struct_members(type_name):
    fields = []
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, type_name):
        offset = 0
        for iter in tif.iter_struct():  # udm_t iterator
            fsize = iter.type.get_size()
            fields.append({
                "offset": iter.offset // 8,  # bit offset → byte offset
                "size": fsize,
                "type": iter.type._print()
            })
            offset += fsize
    else:
        print(f"Unable to get {type_name} type info.")
    return fields

# Example
extract_struct_members("sqlite3_vfs")
```

### Enumerate All Types
```python
til = ida_typeinf.get_idati()
for type_name in til.get_type_names():
    print(type_name)
```

### List All Struct Types
```python
def list_struct_types():
    types = []
    til = ida_typeinf.get_idati()
    for type_name in til.get_type_names():
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, type_name):
            if tif.is_struct():
                types.append(type_name)
    return types
```

---

## 5. Hex-Rays Decompiler API {#hexrays}

### Decompile a Function
```python
import ida_hexrays

# Verified on IDA 9.0
dec = ida_hexrays.decompile(func_addr)
# dec is a cfunc_t object; str(dec) converts to text
print(str(dec))
```

### Print Microcode at Different Maturity Levels
```python
def print_microcode(func_ea):
    """
    Print Hex-Rays microcode at a given maturity level.

    Maturity levels:
      MMAT_ZERO,         microcode does not exist
      MMAT_GENERATED,    generated microcode
      MMAT_PREOPTIMIZED, preoptimized pass is complete
      MMAT_LOCOPT,       local optimization of each basic block is complete
      MMAT_CALLS,        detected call arguments
      MMAT_GLBOPT1,      first pass of global optimization
      MMAT_GLBOPT2,      most global optimization passes done
      MMAT_GLBOPT3,      all global optimization complete — microcode fixed
      MMAT_LVARS,        allocated local variables
    """
    maturity = ida_hexrays.MMAT_GLBOPT3
    hf = ida_hexrays.hexrays_failure_t()
    pfn = idaapi.get_func(func_ea)
    rng = ida_hexrays.mba_ranges_t(pfn)
    mba = ida_hexrays.gen_microcode(rng, hf, None,
                ida_hexrays.DECOMP_WARNINGS, maturity)
    vp = ida_hexrays.vd_printer_t()
    mba._print(vp)

print_microcode(0x1229)
```

### Custom Instruction → User-Defined Call
```python
# Convert a custom instruction (e.g., SVC 0x900001) into a call in decompilation
class udc_exit_t(ida_hexrays.udc_filter_t):
    def __init__(self, code, name):
        ida_hexrays.udc_filter_t.__init__(self)
        if not self.init("int __usercall %s@<R0>(int status@<R1>);" % name):
            raise Exception("Couldn't initialize udc_exit_t instance")
        self.code = code
        self.installed = False

    def match(self, cdg):
        return cdg.insn.itype == ida_allins.ARM_svc and cdg.insn.Op1.value == self.code

    def install(self):
        ida_hexrays.install_microcode_filter(self, True)
        self.installed = True

    def uninstall(self):
        ida_hexrays.install_microcode_filter(self, False)
        self.installed = False

    def toggle_install(self):
        if self.installed:
            self.uninstall()
        else:
            self.install()

udc_exit = udc_exit_t(0x900001, "svc_exit")
udc_exit.toggle_install()
```

### Hexrays_Hooks
```python
class MicrocodeCallback(ida_hexrays.Hexrays_Hooks):
    def __init__(self, *args):
        super().__init__(*args)

    def microcode(self, mba: ida_hexrays.mba_t) -> "int":
        print("microcode generated.")
        return 0

r = MicrocodeCallback()
r.hook()
```

---

## 6. Obfuscation Helpers {#obfuscation}

### OLLVM — Set Breakpoints on Real Blocks
Set breakpoints on all real block entry addresses. Real blocks are identified by finding predecessors of the OLLVM dispatcher merge point.

> Note: identifying real blocks by xrefs to the merge point is a heuristic and may not be fully accurate. Use IDA breakpoint groups for batch management.

```python
fn = 0x401F60
ollvm_tail = 0x405D4B  # OLLVM real block merge point
f_blocks = idaapi.FlowChart(idaapi.get_func(fn), flags=idaapi.FC_PREDS)
for block in f_blocks:
    for succ in block.succs():
        if succ.start_ea == ollvm_tail:
            print(hex(block.start_ea))
            idc.add_bpt(block.start_ea)
```

### Batch Add Breakpoints
```python
def brkall(addr_list):
    for addr in addr_list:
        idc.add_bpt(addr)
```

---

## 7. Instruction & Block Utilities {#utilities}

### Search x86 Function Prologues and Create Functions
```python
# Verified on IDA 9.0
def make_x86_func():
    """Find '55 8B' (push ebp; mov ebp, esp) prologues and create functions."""
    func_headers = find_bytes_list("55 8B")
    for h in func_headers:
        idc.del_items(h)
        idc.create_insn(h)
        ida_funcs.add_func(h)
```

### Get Basic Block Size
```python
# Verified on IDA 9.0
def get_bb_size(bbaddr):
    fn = bbaddr
    f_blocks = idaapi.FlowChart(idaapi.get_func(fn), flags=idaapi.FC_PREDS)
    for block in f_blocks:
        if block.start_ea == bbaddr:
            return block.end_ea - block.start_ea
    raise Exception("Not found")
```

### Get Basic Block by Address
```python
def ida_get_bb(ea):
    f_blocks = idaapi.FlowChart(idaapi.get_func(ea), flags=idaapi.FC_PREDS)
    for block in f_blocks:
        if block.start_ea <= ea and ea < block.end_ea:
            return block
    return None
```

### Search Next Instruction by Keyword
```python
# Verified on IDA 9.0
def search_next_insn(addr, insnkey, max_search=0x100):
    cnt = 0
    while cnt < max_search:
        addr = idc.next_head(addr)
        dis = GetDisasm(addr)
        if insnkey in dis:
            return addr
        cnt += 1
    return None

# Example
# search_next_insn(addr, 'movdqa')
```

### Undefine a Range (U key equivalent)
```python
# Verified on IDA 9.0
def undefine_range(start, end):
    for i in range(start, end):
        idc.del_items(i)

# Example
# undefine_range(func_start, func_end)
```

### Search Disassembly Text
```python
# Verified on IDA 9.0
def search_text_all(text):
    import idaapi, idc
    start_ea = 0
    result = []
    while True:
        start_ea = idaapi.find_text(ustr=text, x=0, y=0,
            sflag=idaapi.SEARCH_DOWN, start_ea=start_ea)
        if start_ea == idc.BADADDR:
            break
        result.append(start_ea)
        start_ea = idc.next_head(start_ea)
    return result

# Example
for x in search_text_all('movdqa'):
    print(GetDisasm(x))
```

---

## 8. NOP / Patching {#patching}

### NOP an Entire Function
```python
import idaapi
import idautils
import idc
import ida_ua
import ida_funcs

def nop_func(addr_func, arch='arm'):
    """Replace all instructions in a function with NOPs."""
    func = ida_funcs.get_func(addr_func)
    if not func:
        print("Function not found!")
        return

    start = func.start_ea
    end = func.end_ea
    print(f"Nopping function at: 0x{start:x} - 0x{end:x}")

    if arch == 'x86':
        nop_bytes = [0x90]                    # x86 NOP
    elif arch == 'arm':
        nop_bytes = [0x1F, 0x20, 0x03, 0xD5]  # ARM AArch64 NOP
    else:
        print(f"Unsupported architecture: {arch}")
        return

    ea = start
    while ea < end:
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, ea)
        if length == 0:
            print(f"Failed to decode instruction at: 0x{ea:x}")
            break

        nop_len = len(nop_bytes)
        for i in range(0, length, nop_len):
            for j in range(nop_len):
                if i + j < length:
                    idc.patch_byte(ea + i + j, nop_bytes[j])

        ea += length

    print("Nopping complete.")

# Example
nop_func(0x401000, 'arm')
```

---

## 9. IDALib (Headless IDA, 9.0+) {#idalib}

IDALib allows running IDAPython analysis scripts without opening the IDA GUI — ideal for batch analysis and CI/CD integration.

### Installation
```bash
cd idalib/python
pip install .
python py-activate-idalib.py
```

### Basic Usage
```python
import idapro        # must be the first import
import idautils
import idc

# Open IDB or binary file
idapro.open_database("samples/patch.so", True)

# Enumerate functions
for func in idautils.Functions():
    func_name = idc.get_func_name(func)
    print("Function Name: {}, Address: {}".format(func_name, hex(func)))

# Close and save IDB
idapro.close_database(save=True)
```

### Batch Decompile to JSON
```bash
# Usage: decompile.py <input_file_elf> <output_file_json>
```

```python
# decompile.py
import idapro
import ida_hexrays
import idautils
import idc

import os
import sys
import json

def _decompile_internal():
    result = []
    for func in idautils.Functions():
        func_name = idc.get_func_name(func)
        print("Function Name: {}, Address: {}".format(func_name, hex(func)))
        dec_obj = ida_hexrays.decompile(func)
        if dec_obj is None:
            continue
        dec_str = str(dec_obj)
        result.append({
            'name': func_name,
            'address': hex(func),
            'decompiled': dec_str
        })
    return result

def decompile_export(file, out_file):
    idapro.open_database(file, True)
    r = _decompile_internal()
    idapro.close_database(save=False)
    open(out_file, "w").write(json.dumps(r, indent=4))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} <input_file_elf> <output_file_json>".format(sys.argv[0]))
        sys.exit(1)
    decompile_export(sys.argv[1], sys.argv[2])
```

### Multiprocess Batch Decompile
```python
import os
import time
from multiprocessing import Pool

args = {
    "NUM_WORKERS": 8,
    "INPUT_DIR": "/path/to/binaries",
    "OUTPUT_DIR": "/path/to/decompiled",
    "NUM_MAX_RETRY": 3
}

def decompile_one(file, out_file):
    retry = 0
    while True:
        os.system("python3 decompile.py {} {}".format(file, out_file))
        if os.path.exists(out_file):
            break
        retry += 1
        if retry >= args["NUM_MAX_RETRY"]:
            return "Failed to decompile {}".format(file)
        time.sleep(1)
    return None

if __name__ == "__main__":
    if not os.path.exists(args["OUTPUT_DIR"]):
        os.makedirs(args["OUTPUT_DIR"])
    files = os.listdir(args["INPUT_DIR"])
    files = [os.path.join(args["INPUT_DIR"], f) for f in files]
    out_files = [os.path.join(args["OUTPUT_DIR"], os.path.basename(f) + ".json") for f in files]

    with Pool(args["NUM_WORKERS"]) as p:
        r = p.starmap(decompile_one, zip(files, out_files))
        for i in r:
            if i is not None:
                print(i)
```

---

## 10. Export workflow — `decompile/` directory pattern {#export-workflow}

A common pattern for sharing IDA analysis state with an AI agent is to export every function as an individual `.c` file alongside auxiliary metadata. The agent then reads the directory directly without needing live IDA access.

### Standard directory layout

```
./
├── decompile/              # decompiled C code, one file per function
│   ├── 0x401000.c          # named by function start address (hex)
│   ├── 0x401234.c
│   └── ...
├── decompile_failed.txt    # functions where decompilation failed
├── decompile_skipped.txt   # functions explicitly skipped (e.g., thunks)
├── strings.txt             # strings table (address, length, type, content)
├── imports.txt             # imports (address:function_name per line)
├── exports.txt             # exports (address:function_name per line)
└── memory/                 # raw memory hexdumps in 1 MB chunks (optional)
```

### Function file format
Each `.c` file in `decompile/` contains a metadata header followed by Hex-Rays output:

```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * callers:  0x402000, 0x403000   // who calls this function
 * callees:  0x404000, 0x405000   // who this function calls
 */

int __fastcall sub_401000(int a1, int a2)
{
    // decompiled code...
}
```

### Stand-alone IDAPython export script
If you don't want to install a third-party plugin, this script generates the layout above. Run inside IDA (`File → Script File…`):

```python
# export_decomp.py — stand-alone export of IDA analysis state
# Run inside IDA: File → Script File… → select this file
import os
import idautils
import idc
import idaapi
import ida_hexrays
import ida_nalt
import ida_funcs

OUTPUT_DIR = "./decompile_export"   # adjust as needed

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def get_callers(func_ea):
    return sorted({ref.frm for ref in idautils.XrefsTo(func_ea)
                   if ida_funcs.get_func(ref.frm)})

def get_callees(func_ea):
    callees = set()
    f = ida_funcs.get_func(func_ea)
    if not f:
        return []
    for head in idautils.Heads(f.start_ea, f.end_ea):
        if idaapi.is_call_insn(head):
            target = idc.get_operand_value(head, 0)
            if target != idc.BADADDR:
                callees.add(target)
    return sorted(callees)

def export_function(func_ea, out_dir, failed, skipped):
    name = idc.get_func_name(func_ea)
    fpath = os.path.join(out_dir, "decompile", f"{func_ea:#x}.c")
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception as e:
        failed.append(f"{func_ea:#x}: {e}")
        return
    if cfunc is None:
        skipped.append(f"{func_ea:#x}: decompilation returned None")
        return
    callers = get_callers(func_ea)
    callees = get_callees(func_ea)
    header = (
        f"/*\n"
        f" * func-name: {name}\n"
        f" * func-address: {func_ea:#x}\n"
        f" * callers: {', '.join(f'{c:#x}' for c in callers)}\n"
        f" * callees: {', '.join(f'{c:#x}' for c in callees)}\n"
        f" */\n\n"
    )
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(header + str(cfunc))

def export_strings(out_dir):
    with open(os.path.join(out_dir, "strings.txt"), "w", encoding="utf-8") as f:
        for s in idautils.Strings():
            f.write(f"{int(s.ea):#x}\t{s.length}\t{s.strtype}\t{str(s)}\n")

def export_imports(out_dir):
    lines = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        mod = ida_nalt.get_import_module_name(i) or "<unnamed>"
        def cb(ea, name, _ord):
            if name:
                lines.append(f"{ea:#x}:{mod}!{name}")
            return True
        ida_nalt.enum_import_names(i, cb)
    with open(os.path.join(out_dir, "imports.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def export_exports(out_dir):
    lines = []
    for index, ordinal, ea, name in idautils.Entries():
        if name:
            lines.append(f"{ea:#x}:{name}")
    with open(os.path.join(out_dir, "exports.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def main():
    ensure_dir(OUTPUT_DIR)
    ensure_dir(os.path.join(OUTPUT_DIR, "decompile"))

    failed, skipped = [], []
    funcs = list(idautils.Functions())
    print(f"[export] {len(funcs)} functions")

    for i, func_ea in enumerate(funcs):
        if i % 50 == 0:
            print(f"  {i}/{len(funcs)}")
        export_function(func_ea, OUTPUT_DIR, failed, skipped)

    export_strings(OUTPUT_DIR)
    export_imports(OUTPUT_DIR)
    export_exports(OUTPUT_DIR)

    with open(os.path.join(OUTPUT_DIR, "decompile_failed.txt"), "w") as f:
        f.write("\n".join(failed))
    with open(os.path.join(OUTPUT_DIR, "decompile_skipped.txt"), "w") as f:
        f.write("\n".join(skipped))

    print(f"[export] done → {OUTPUT_DIR}")
    print(f"  failed:  {len(failed)}")
    print(f"  skipped: {len(skipped)}")

if __name__ == "__main__":
    main()
```

After running, the agent can analyze the export with simple file reads — no live IDA needed.

### Community plugins for the same workflow
- **`P4nda0s/IDA-NO-MCP`** — drop-in plugin: copy `INP.py` into IDA's plugins directory, then press `Ctrl-Shift-E` to export. Produces the same layout described above.
- **`mrexodia/ida-pro-mcp`** — alternative MCP-based approach (no file export, live querying).

### Consuming the export from the agent
Once the directory exists, simple Python is enough to walk it:

```python
# read_export.py — agent-side helper
import os, re, glob

ROOT = "./decompile_export"

def load_function(addr_hex):
    """Load a single function file by address (e.g. '0x401000')."""
    path = os.path.join(ROOT, "decompile", f"{addr_hex}.c")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    # Parse metadata header
    meta = {}
    for line in text.splitlines()[:8]:
        m = re.match(r"\s*\*\s*([\w-]+):\s*(.*)", line)
        if m:
            meta[m.group(1)] = m.group(2).strip()
    return meta, text

def list_functions():
    return [os.path.basename(p)[:-2]
            for p in glob.glob(os.path.join(ROOT, "decompile", "*.c"))]

def load_imports():
    with open(os.path.join(ROOT, "imports.txt")) as f:
        return [line.strip().split(":", 1) for line in f if line.strip()]

# Example: print metadata for a function
meta, code = load_function("0x401000")
print(meta)              # {'func-name': 'sub_401000', 'func-address': '0x401000', ...}
```

Pair this with `references/symbol-recovery.md` and `references/struct-recovery.md` — both methodologies expect to read functions and metadata from this exact directory layout (or via MCP equivalent).

---

## Notes

- IDAPython runs inside IDA's GUI — use `Python` window or `File → Script File...`
- IDALib requires IDA 9.0+ and a separate activation
- `ida_hexrays` requires the Hex-Rays decompiler license
- Most `idc.*` functions have modern `ida_*` equivalents (prefer the `ida_*` versions in new code)
- When operating on debugger memory, use `idc.read_dbg_*` / `idc.patch_dbg_*`
- When operating on the IDB database, use `idc.get_*` / `idc.patch_*`
