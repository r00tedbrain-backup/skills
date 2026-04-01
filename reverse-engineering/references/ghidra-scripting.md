# Advanced Ghidra Scripting Reference

## Table of Contents
1. [Ghidra API Overview](#api)
2. [Python (Jython) Scripts](#python)
3. [Java Scripts](#java)
4. [Headless Analysis](#headless)
5. [Custom Analyzers](#analyzers)
6. [Data Type Recovery](#datatypes)
7. [Vulnerability Finding Scripts](#vulnscripts)
8. [Useful Community Scripts](#community)

---

## 1. Ghidra API Overview {#api}

```
Core objects available in scripts:
currentProgram       → current Program object
currentAddress       → cursor address (Address)
currentLocation      → ProgramLocation
currentSelection     → ProgramSelection
currentHighlight     → ProgramSelection
state                → GhidraState (all of the above)
monitor              → TaskMonitor (progress)
println()            → print to console

Key managers (from currentProgram):
getFunctionManager()    → functions
getListing()            → instructions, data, code units
getReferenceManager()   → cross-references
getSymbolTable()        → symbols
getBookmarkManager()    → bookmarks
getDataTypeManager()    → data types
getMemory()             → memory blocks
getEquateTable()        → named constants
getAddressFactory()     → address utilities
```

---

## 2. Python (Jython) Scripts {#python}

### Enumerate All Functions
```python
#@category Analysis
from ghidra.program.model.listing import FunctionManager

fm = currentProgram.getFunctionManager()
funcs = list(fm.getFunctions(True))
print(f"Total functions: {len(funcs)}")

# Filter large functions (complex logic)
large = [f for f in funcs if f.getBody().getNumAddresses() > 200]
for f in sorted(large, key=lambda x: -x.getBody().getNumAddresses()):
    print(f"{f.getEntryPoint()}: {f.getName()} ({f.getBody().getNumAddresses()} addrs)")
```

### Find Dangerous Function Calls
```python
#@category Vulnerability Research
from ghidra.program.model.symbol import RefType

DANGEROUS = ["gets", "strcpy", "strcat", "sprintf", "vsprintf",
             "scanf", "fscanf", "sscanf", "memcpy", "memmove",
             "system", "popen", "exec", "execl", "execv"]

sym_table = currentProgram.getSymbolTable()
ref_mgr = currentProgram.getReferenceManager()

for name in DANGEROUS:
    syms = sym_table.getSymbols(name)
    for sym in syms:
        refs = ref_mgr.getReferencesTo(sym.getAddress())
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = currentProgram.getFunctionManager().getFunctionContaining(from_addr)
            func_name = func.getName() if func else "unknown"
            print(f"[{name}] called from {func_name} @ {from_addr}")
            # Set bookmark
            currentProgram.getBookmarkManager().setBookmark(
                from_addr, "Analysis", "DangerousFunc", f"Call to {name}")
```

### String Reference Finder
```python
#@category Analysis
from ghidra.program.model.data import StringDataType
from ghidra.program.model.listing import DataIterator

listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()

patterns = ["http", "password", "secret", "api_key", "token", "flag{", "admin"]

data_iter = listing.getDefinedData(currentProgram.getMinAddress(), True)
for data in data_iter:
    if isinstance(data.getDataType(), StringDataType):
        value = str(data.getValue())
        if any(p.lower() in value.lower() for p in patterns):
            refs = ref_mgr.getReferencesTo(data.getAddress())
            for ref in refs:
                func = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress())
                print(f"[STRING] '{value[:60]}' @ {data.getAddress()} → {func.getName() if func else '?'} @ {ref.getFromAddress()}")
```

### Auto-Rename Functions by Strings
```python
#@category Automation
from ghidra.program.model.data import StringDataType

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()

renamed = 0
for func in fm.getFunctions(True):
    if not func.getName().startswith("FUN_"):
        continue  # already named
    
    # Get all string refs within this function
    strings_found = []
    body = func.getBody()
    addr_set = body
    
    for instr in listing.getInstructions(addr_set, True):
        for ref in ref_mgr.getReferencesFrom(instr.getAddress()):
            target = ref.getToAddress()
            data = listing.getDataAt(target)
            if data and isinstance(data.getDataType(), StringDataType):
                s = str(data.getValue()).strip()
                if 4 < len(s) < 50 and s.isascii():
                    strings_found.append(s)
    
    if strings_found:
        # Use first meaningful string as hint
        hint = strings_found[0].replace(" ", "_")[:30].replace("/","_")
        new_name = f"fn_{hint}"
        try:
            func.setName(new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            print(f"Renamed: FUN_{func.getEntryPoint()} → {new_name}")
            renamed += 1
        except Exception as e:
            pass

print(f"Total renamed: {renamed}")
```

### XRef Graph to Root
```python
#@category Analysis
# Find all functions that can reach a target function (call chain analysis)

target_name = "dangerous_function"  # change this

sym_table = currentProgram.getSymbolTable()
fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()

def get_callers(func, visited=None):
    if visited is None:
        visited = set()
    if func.getEntryPoint() in visited:
        return []
    visited.add(func.getEntryPoint())
    
    callers = []
    for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
        if ref.getReferenceType().isCall():
            caller = fm.getFunctionContaining(ref.getFromAddress())
            if caller:
                callers.append(caller)
                callers.extend(get_callers(caller, visited))
    return callers

# Find target
syms = list(sym_table.getSymbols(target_name))
if syms:
    target_func = fm.getFunctionAt(syms[0].getAddress())
    if target_func:
        callers = get_callers(target_func)
        print(f"Functions that reach {target_name}:")
        for c in set(c.getName() for c in callers):
            print(f"  → {c}")
```

### Crypto Constant Detector
```python
#@category Vulnerability Research
# Detect well-known crypto constants (AES S-box, MD5 init, SHA1, etc.)
from ghidra.program.model.listing import DataIterator

CRYPTO_CONSTANTS = {
    0x67452301: "MD5_A",
    0xEFCDAB89: "MD5_B",
    0x98BADCFE: "MD5_C",
    0x10325476: "MD5_D",
    0x67452301: "SHA1_H0",
    0x9079b226: "AES_RCON",
    0x63636363: "AES_SBOX_START",
    0xDEADBEEF: "debug_marker",
}

memory = currentProgram.getMemory()
addr_factory = currentProgram.getAddressFactory()

for const_val, const_name in CRYPTO_CONSTANTS.items():
    search_bytes = const_val.to_bytes(4, 'little')
    results = memory.findBytes(currentProgram.getMinAddress(), search_bytes, None, True, monitor)
    while results:
        print(f"[CRYPTO] {const_name} ({hex(const_val)}) @ {results}")
        currentProgram.getBookmarkManager().setBookmark(
            results, "Analysis", "CryptoConstant", const_name)
        results = memory.findBytes(results.add(1), search_bytes, None, True, monitor)
```

---

## 3. Java Scripts {#java}

```java
// @category Analysis
// @menupath Analysis.Custom Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindVulnerabilities extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        SymbolTable st = currentProgram.getSymbolTable();
        
        String[] targets = {"gets", "strcpy", "memcpy", "sprintf"};
        
        for (String target : targets) {
            SymbolIterator syms = st.getSymbols(target);
            while (syms.hasNext()) {
                Symbol sym = syms.next();
                ReferenceIterator refs = rm.getReferencesTo(sym.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function func = fm.getFunctionContaining(ref.getFromAddress());
                    String funcName = func != null ? func.getName() : "unknown";
                    println(String.format("[%s] called from %s @ %s", 
                        target, funcName, ref.getFromAddress()));
                    createBookmark(ref.getFromAddress(), "DangerousCall", 
                        "Call to " + target);
                }
            }
        }
    }
}
```

---

## 4. Headless Analysis {#headless}

```bash
# Full headless pipeline (no GUI)
GHIDRA=$HOME/ghidra_11.x

# Import + analyze + run script
$GHIDRA/support/analyzeHeadless \
    /tmp/ghidra_projects \
    MyProject \
    -import /path/to/binary \
    -overwrite \
    -scriptPath ~/ghidra_scripts \
    -postScript FindDangerousFunctions.py \
    -scriptlog /tmp/ghidra_output.log \
    -noanalysis  # skip auto-analysis (faster, manual control)

# Run script on already-imported binary
$GHIDRA/support/analyzeHeadless \
    /tmp/ghidra_projects \
    MyProject \
    -process binary_name \
    -postScript MyAnalysis.py "arg1 arg2"

# Export to C headers (for further analysis)
$GHIDRA/support/analyzeHeadless \
    /tmp/ghidra_projects MyProject \
    -process binary \
    -postScript ExportHeaderFile.java "output.h"

# Batch analyze multiple binaries
for f in /path/to/firmware/*.elf; do
    $GHIDRA/support/analyzeHeadless /tmp/proj FirmwareProject \
        -import "$f" \
        -overwrite \
        -postScript FindCryptoConstants.py \
        2>> ghidra_batch.log
done
```

---

## 5. Custom Analyzers {#analyzers}

```java
// Register as an auto-analyzer (runs automatically on import)
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;

public class VulnScanner extends AbstractAnalyzer {
    
    public VulnScanner() {
        super("Vuln Scanner", "Finds dangerous function calls", 
              AnalyzerType.INSTRUCTION_ANALYZER);
    }
    
    @Override
    public boolean getDefaultEnablement(Program program) {
        return true; // enabled by default
    }
    
    @Override
    public boolean canAnalyze(Program program) {
        // Only for ELF/PE executables
        String format = program.getExecutableFormat();
        return format.contains("ELF") || format.contains("PE");
    }
    
    @Override
    public boolean added(Program program, AddressSetView set, 
                         TaskMonitor monitor, MessageLog log) {
        // Analysis logic here
        // return true if changes were made to the program
        return false;
    }
}
```

---

## 6. Data Type Recovery {#datatypes}

```python
#@category DataTypes
# Create and apply a struct definition
from ghidra.program.model.data import *
from ghidra.program.model.symbol import SourceType

dtm = currentProgram.getDataTypeManager()
listing = currentProgram.getListing()

# Create struct
struct = StructureDataType("NetworkPacket", 0)
struct.add(WordDataType(), 2, "magic", "Packet magic 0xDEAD")
struct.add(ByteDataType(), 1, "msg_type", "Message type")
struct.add(DWordDataType(), 4, "payload_len", "Payload length")
struct.add(ArrayDataType(ByteDataType(), 128, 1), 128, "payload", "Payload data")

# Add to data type manager
dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)

# Apply at address
target_addr = currentProgram.getAddressFactory().getAddress("0x602020")
listing.clearCodeUnits(target_addr, target_addr.add(struct.getLength()-1), False)
listing.createData(target_addr, struct)

print(f"Applied {struct.getName()} at {target_addr}")
```

---

## 7. Vulnerability Finding Scripts {#vulnscripts}

```python
#@category Vulnerability Research
# Find all functions with large stack allocations (potential overflow candidates)
from ghidra.program.model.listing import FunctionIterator

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

LARGE_STACK_THRESHOLD = 0x200  # 512 bytes

results = []
for func in fm.getFunctions(True):
    # Get stack frame
    frame = func.getStackFrame()
    if frame:
        local_size = abs(frame.getLocalSize())
        param_size = frame.getParameterSize()
        if local_size > LARGE_STACK_THRESHOLD:
            results.append((local_size, func))

results.sort(reverse=True)
for size, func in results[:30]:
    print(f"Stack {hex(size)} @ {func.getEntryPoint()}: {func.getName()}")
    currentProgram.getBookmarkManager().setBookmark(
        func.getEntryPoint(), "Analysis", "LargeStack", 
        f"Stack frame size: {hex(size)}")
```

```python
#@category Vulnerability Research
# Format string vulnerability detector (find printf with non-constant format)
from ghidra.program.model.pcode import PcodeOp

fm = currentProgram.getFunctionManager()
sym_table = currentProgram.getSymbolTable()
ref_mgr = currentProgram.getReferenceManager()
decompiler_api = None

# Functions where format string is the FIRST argument
FMT_FUNCS_ARG0 = ["printf", "vprintf", "wprintf"]
# Functions where format string is the SECOND argument  
FMT_FUNCS_ARG1 = ["fprintf", "sprintf", "snprintf", "dprintf"]

def check_func(name, arg_idx):
    for sym in sym_table.getSymbols(name):
        for ref in ref_mgr.getReferencesTo(sym.getAddress()):
            if ref.getReferenceType().isCall():
                print(f"[FMT_CHECK] Call to {name} @ {ref.getFromAddress()} — verify arg {arg_idx} is constant")
                currentProgram.getBookmarkManager().setBookmark(
                    ref.getFromAddress(), "Analysis", "FormatString",
                    f"Verify {name} format arg")

for f in FMT_FUNCS_ARG0: check_func(f, 0)
for f in FMT_FUNCS_ARG1: check_func(f, 1)
print("Done. Review bookmarks in Format String category.")
```

---

## 8. Useful Community Scripts {#community}

```
# Must-have Ghidra scripts/plugins:

# GhidraNative (JNI helper for Android)
# → Auto-labels Java_* functions with Java signatures
# https://github.com/mobilesecurity96/GhidraNative

# Ret-Sync (sync with GDB/x64dbg while debugging)
# → Cursor in Ghidra follows debugger execution in real time
# https://github.com/bootleg/ret-sync

# GhidraX86Deobfuscator (handle opaque predicates/junk code)
# https://github.com/PAGalaxyLab/ghidra_scripts

# OOAnalyzer (recover C++ classes/vtables)
# https://github.com/cmu-sei/pharos

# Capa integration (FLARE capa in Ghidra)
# Identifies malware capabilities automatically

# BinDiff Ghidra plugin
# → Diff two versions of a binary directly in Ghidra

# PWNdbg + Ghidra bridge (ret-sync)
# Connect pwndbg to Ghidra for synchronized analysis

# Quick script locations to install:
# Copy .py / .java files to: ~/ghidra_scripts/
# Or: Script Manager → Script Directories → add path
```
