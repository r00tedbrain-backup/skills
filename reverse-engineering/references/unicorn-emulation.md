# Unicorn Engine — Function Emulation Reference

> For authorized reverse engineering, algorithm analysis, and CTF challenges.

Emulate specific code fragments or functions using the Unicorn engine. Useful for:

- Running a single function outside the context of its full binary
- Recovering plaintext from decrypt/decode routines by emulating the algorithm
- Tracing binary execution without running the full program in a live environment
- Bypassing environment dependencies (JNI, syscalls, libc) during analysis

## Table of Contents
1. [Core Principles](#principles)
2. [Environment Simulation Strategy](#environment)
3. [Callback Types](#callbacks)
4. [Iterative Workflow](#workflow)
5. [Architecture Quick Reference](#arch)
6. [Code Templates](#templates)
7. [Common Patterns](#patterns)

---

## 1. Core Principles {#principles}

1. **Load file raw first** — do NOT parse ELF/PE/Mach-O headers. Read the file as raw bytes and map directly into Unicorn memory. We only need to emulate specific functions, not the entire binary. If raw loading fails (code references segments at specific addresses), parse minimally — only map the segments needed.

2. **Identify context dependencies** — analyze the target code for external calls (JNI, syscalls, libc, imports) and hook them to provide simulated responses.

3. **Use callbacks extensively** — leverage Unicorn's hook system for debugging, tracing, error recovery, and environment simulation.

4. **Iterative fix** — when emulation crashes, use the callback info to diagnose and fix (map missing memory, hook unhandled calls, fix register state).

5. **Minimal trace output** — prefer block-level tracing over instruction-level. Only enable instruction trace on small targeted ranges. Use counters and summaries instead of per-step logging.

---

## 2. Environment Simulation Strategy {#environment}

Before emulating, read the target function and identify what it calls. Hook external dependencies by address and simulate them in Python:

| Category | Examples | Simulation Strategy |
|----------|----------|---------------------|
| libc | `malloc`, `free`, `memcpy`, `strlen`, `printf` | Hook address, implement logic in Python (bump allocator for `malloc`) |
| JNI | `GetStringUTFChars`, `FindClass`, `GetMethodID` | Build fake JNIEnv function table in UC memory, write RET stubs at each entry, hook stub addresses |
| Syscalls | `read`, `write`, `mmap`, `ioctl` | Hook `UC_HOOK_INTR`, dispatch by syscall number |
| C++ runtime | `operator new`, `__cxa_throw` | Hook and simulate |
| Library calls | `pthread_mutex_lock`, `dlopen` | Hook and return success/stub |

**Hook pattern:** Register a `UC_HOOK_CODE` callback. When PC hits a known import address, execute the Python simulation, then set PC = LR to skip the original function.

---

## 3. Callback Types {#callbacks}

| Callback | Purpose |
|----------|---------|
| `UC_HOOK_CODE` | Intercept import calls by address; instruction-level trace (use sparingly, narrow range only) |
| `UC_HOOK_BLOCK` | Block-level trace (preferred over instruction trace) |
| `UC_HOOK_MEM_UNMAPPED` | Auto-map missing pages to recover from unmapped access errors |
| `UC_HOOK_MEM_READ \| UC_HOOK_MEM_WRITE` | Trace memory access on targeted data ranges only |
| `UC_HOOK_INTR` | Intercept SVC/INT for syscall simulation |

---

## 4. Iterative Workflow {#workflow}

When emulation fails, follow this loop:

1. **Run** — start emulation, let it crash
2. **Read callback output** — which address faulted? What type (read/write/fetch)?
3. **Diagnose**:
   - Unmapped memory fetch → missing code page, map it
   - Unmapped memory read/write → missing data section or uninitialized pointer, map or hook
   - Hitting an import stub → identify the function, add a simulation hook
   - Infinite loop → add a code hook with execution counter, stop after threshold
4. **Fix** — add the hook / map the memory / adjust registers
5. **Re-run** — repeat until the target function completes

---

## 5. Architecture Quick Reference {#arch}

| Arch | Uc Const | Mode | SP | LR | Args | Return | Syscall |
|------|----------|------|----|----|------|--------|---------|
| ARM64 | `UC_ARCH_ARM64` | `UC_MODE_LITTLE_ENDIAN` | SP | X30 | X0-X7 | X0 | X8 + SVC #0 |
| ARM32 | `UC_ARCH_ARM` | `UC_MODE_THUMB` / `UC_MODE_ARM` | SP | LR | R0-R3 | R0 | R7 + SVC #0 |
| x86-64 | `UC_ARCH_X86` | `UC_MODE_64` | RSP | (stack) | RDI,RSI,RDX,RCX,R8,R9 | RAX | RAX + syscall |
| x86-32 | `UC_ARCH_X86` | `UC_MODE_32` | ESP | (stack) | (stack) | EAX | EAX + int 0x80 |
| MIPS32 | `UC_ARCH_MIPS` | `UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN` | $sp | $ra | $a0-$a3 | $v0 | $v0 + syscall |

---

## 6. Code Templates {#templates}

### Template: ARM64 Function Emulation
```python
from unicorn import *
from unicorn.arm64_const import *

# 1. Read binary raw
with open("target.so", "rb") as f:
    code = f.read()

# 2. Create emulator
mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)

# 3. Memory layout
BASE   = 0x00400000                  # where to map the binary
STACK  = 0x10000000                  # stack base
STACK_SIZE = 0x10000                 # 64 KB stack

mu.mem_map(BASE, 0x100000)           # 1 MB for code
mu.mem_map(STACK, STACK_SIZE)        # stack
mu.mem_write(BASE, code)             # load binary

# 4. Set up registers
mu.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE - 8)
mu.reg_write(UC_ARM64_REG_X0, 0x1234)  # first argument
mu.reg_write(UC_ARM64_REG_X1, 0x5678)  # second argument

# 5. Hook unmapped memory to auto-map
def hook_mem_invalid(uc, access, address, size, value, user_data):
    print(f"[unmapped] access={access} addr={address:#x} size={size}")
    # Auto-map the page
    page = address & ~0xFFF
    uc.mem_map(page, 0x1000)
    return True                      # retry access

mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_invalid)

# 6. Hook block trace (optional, lightweight)
def hook_block(uc, address, size, user_data):
    print(f"[block] {address:#x} size={size}")

mu.hook_add(UC_HOOK_BLOCK, hook_block)

# 7. Run the target function
FUNC_START = BASE + 0x1000           # address of target function
FUNC_END   = BASE + 0x1200           # where to stop (or end of func)
try:
    mu.emu_start(FUNC_START, FUNC_END)
    ret = mu.reg_read(UC_ARM64_REG_X0)
    print(f"[result] X0 = {ret:#x}")
except UcError as e:
    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f"[error] {e} at PC={pc:#x}")
```

### Template: x86-64 Function Emulation
```python
from unicorn import *
from unicorn.x86_const import *

with open("target.bin", "rb") as f:
    code = f.read()

mu = Uc(UC_ARCH_X86, UC_MODE_64)

BASE  = 0x400000
STACK = 0x10000000

mu.mem_map(BASE, 0x100000)
mu.mem_map(STACK, 0x10000)
mu.mem_write(BASE, code)

# Set up standard x86-64 calling convention (System V)
mu.reg_write(UC_X86_REG_RSP, STACK + 0x10000 - 8)
mu.reg_write(UC_X86_REG_RDI, 0x1234)  # arg 1
mu.reg_write(UC_X86_REG_RSI, 0x5678)  # arg 2
mu.reg_write(UC_X86_REG_RDX, 100)     # arg 3

FUNC = BASE + 0x500
mu.emu_start(FUNC, FUNC + 0x200)

result = mu.reg_read(UC_X86_REG_RAX)
print(f"rax = {result:#x}")
```

---

## 7. Common Patterns {#patterns}

### Pattern: Bump Allocator for malloc
```python
# Global heap pointer
HEAP_BASE = 0x20000000
HEAP_SIZE = 0x100000
heap_ptr = HEAP_BASE

def hook_malloc(uc, address, size, user_data):
    """Simulate malloc: read size from X0, allocate, return pointer in X0."""
    global heap_ptr
    req_size = uc.reg_read(UC_ARM64_REG_X0)
    # Align to 16 bytes
    req_size = (req_size + 15) & ~15
    ptr = heap_ptr
    heap_ptr += req_size
    print(f"[malloc] size={req_size} -> {ptr:#x}")
    uc.reg_write(UC_ARM64_REG_X0, ptr)     # return value
    # Skip the original malloc — set PC to LR
    lr = uc.reg_read(UC_ARM64_REG_LR)
    uc.reg_write(UC_ARM64_REG_PC, lr)

# Pre-map the heap region
mu.mem_map(HEAP_BASE, HEAP_SIZE)

# Hook the malloc address (look up via IDA/Ghidra first)
MALLOC_ADDR = BASE + 0x8000
mu.hook_add(UC_HOOK_CODE, hook_malloc,
            begin=MALLOC_ADDR, end=MALLOC_ADDR + 4)
```

### Pattern: Stub for strlen
```python
def hook_strlen(uc, address, size, user_data):
    """Read string from memory, return length in X0."""
    s_ptr = uc.reg_read(UC_ARM64_REG_X0)
    length = 0
    while length < 0x1000:
        b = uc.mem_read(s_ptr + length, 1)[0]
        if b == 0:
            break
        length += 1
    uc.reg_write(UC_ARM64_REG_X0, length)
    lr = uc.reg_read(UC_ARM64_REG_LR)
    uc.reg_write(UC_ARM64_REG_PC, lr)

STRLEN_ADDR = BASE + 0x9000
mu.hook_add(UC_HOOK_CODE, hook_strlen,
            begin=STRLEN_ADDR, end=STRLEN_ADDR + 4)
```

### Pattern: Stub for memcpy
```python
def hook_memcpy(uc, address, size, user_data):
    """memcpy(dst, src, n): X0=dst, X1=src, X2=n. Return X0=dst."""
    dst = uc.reg_read(UC_ARM64_REG_X0)
    src = uc.reg_read(UC_ARM64_REG_X1)
    n   = uc.reg_read(UC_ARM64_REG_X2)
    data = uc.mem_read(src, n)
    uc.mem_write(dst, bytes(data))
    # dst is already in X0, just return
    lr = uc.reg_read(UC_ARM64_REG_LR)
    uc.reg_write(UC_ARM64_REG_PC, lr)
```

### Pattern: Syscall Simulation (ARM64 Linux)
```python
def hook_intr(uc, intno, user_data):
    """Handle SVC #0 — dispatch by syscall number in X8."""
    if intno != 2:   # 2 = SVC
        return
    syscall = uc.reg_read(UC_ARM64_REG_X8)
    x0 = uc.reg_read(UC_ARM64_REG_X0)

    if syscall == 63:          # read(fd, buf, count)
        buf   = uc.reg_read(UC_ARM64_REG_X1)
        count = uc.reg_read(UC_ARM64_REG_X2)
        # Simulate reading some fixed data
        data = b"fake_input\n"[:count]
        uc.mem_write(buf, data)
        uc.reg_write(UC_ARM64_REG_X0, len(data))
    elif syscall == 64:        # write(fd, buf, count)
        buf   = uc.reg_read(UC_ARM64_REG_X1)
        count = uc.reg_read(UC_ARM64_REG_X2)
        data = uc.mem_read(buf, count)
        print(f"[write fd={x0}] {bytes(data)}")
        uc.reg_write(UC_ARM64_REG_X0, count)
    elif syscall == 93:        # exit(code)
        print(f"[exit] code={x0}")
        uc.emu_stop()
    else:
        print(f"[unhandled syscall] #{syscall}")
        uc.reg_write(UC_ARM64_REG_X0, 0)

mu.hook_add(UC_HOOK_INTR, hook_intr)
```

### Pattern: Fake JNI Environment
```python
# Map a region for the fake JNIEnv vtable
JNIENV_ADDR   = 0x30000000
JNIENV_SIZE   = 0x10000
JNI_STUB_BASE = JNIENV_ADDR + 0x1000   # stubs start after vtable

mu.mem_map(JNIENV_ADDR, JNIENV_SIZE)

# Write the vtable: array of pointers to stub addresses
# JNI function index reference:
#   0xE = FindClass
#   0x54 = GetStringUTFChars
#   0x55 = ReleaseStringUTFChars
#   0x84 = NewStringUTF
jni_slots = {
    0xE:  ("FindClass",          JNI_STUB_BASE + 0x00),
    0x54: ("GetStringUTFChars",  JNI_STUB_BASE + 0x10),
    0x55: ("ReleaseStringUTFChars", JNI_STUB_BASE + 0x20),
    0x84: ("NewStringUTF",       JNI_STUB_BASE + 0x30),
}

# Write 8-byte stub pointers at each slot in the vtable
for idx, (_name, stub_addr) in jni_slots.items():
    vtable_offset = JNIENV_ADDR + idx * 8
    mu.mem_write(vtable_offset, stub_addr.to_bytes(8, 'little'))

# Write RET instruction at each stub (ARM64: D65F03C0 = RET)
RET_ARM64 = b"\xc0\x03\x5f\xd6"
for idx, (_name, stub_addr) in jni_slots.items():
    mu.mem_write(stub_addr, RET_ARM64)

# Hook each stub to simulate the JNI call
def hook_FindClass(uc, address, size, user_data):
    class_name_ptr = uc.reg_read(UC_ARM64_REG_X1)
    name = read_cstring(uc, class_name_ptr)
    print(f"[JNI] FindClass({name!r})")
    uc.reg_write(UC_ARM64_REG_X0, 0xC1A55001)  # fake jclass handle

def hook_GetStringUTFChars(uc, address, size, user_data):
    jstring = uc.reg_read(UC_ARM64_REG_X1)
    # Lookup string data for this jstring handle in your own map
    # Return a pointer to the UTF-8 bytes
    fake_str_ptr = 0x40000000
    mu.mem_write(fake_str_ptr, b"HelloFromJNI\x00")
    uc.reg_write(UC_ARM64_REG_X0, fake_str_ptr)

def read_cstring(uc, addr, max_len=256):
    out = b""
    for i in range(max_len):
        b = uc.mem_read(addr + i, 1)[0]
        if b == 0:
            break
        out += bytes([b])
    return out.decode(errors="replace")

mu.hook_add(UC_HOOK_CODE, hook_FindClass,
            begin=jni_slots[0xE][1], end=jni_slots[0xE][1] + 4)
mu.hook_add(UC_HOOK_CODE, hook_GetStringUTFChars,
            begin=jni_slots[0x54][1], end=jni_slots[0x54][1] + 4)

# When calling JNI functions, the target expects:
#   X0 = JNIEnv** (pointer to pointer to vtable)
# So build: X0 -> [env_ptr] -> [vtable_ptr]
env_ptr = 0x30100000
mu.mem_map(env_ptr, 0x1000)
mu.mem_write(env_ptr, JNIENV_ADDR.to_bytes(8, 'little'))
mu.reg_write(UC_ARM64_REG_X0, env_ptr)
```

### Pattern: Infinite Loop Detection
```python
from collections import Counter

block_count = Counter()
BLOCK_LIMIT = 10000  # abort if any block runs this many times

def hook_block_count(uc, address, size, user_data):
    block_count[address] += 1
    if block_count[address] > BLOCK_LIMIT:
        print(f"[infinite loop?] block {address:#x} hit {block_count[address]} times")
        uc.emu_stop()

mu.hook_add(UC_HOOK_BLOCK, hook_block_count)
```

### Pattern: Auto-Map Missing Pages
```python
def hook_mem_invalid(uc, access, address, size, value, user_data):
    """Auto-map 4KB pages on unmapped access. Returns True to retry."""
    page = address & ~0xFFF
    try:
        uc.mem_map(page, 0x1000)
        print(f"[auto-mapped] page {page:#x}")
        return True
    except UcError as e:
        print(f"[map failed] {e}")
        return False

mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_invalid)
```

### Pattern: Instruction Trace (Narrow Range)
```python
def hook_insn(uc, address, size, user_data):
    code = uc.mem_read(address, size)
    print(f"[ins] {address:#x}: {code.hex()}")

# Only trace a small range to avoid noise
TRACE_BEGIN = BASE + 0x1050
TRACE_END   = BASE + 0x1080
mu.hook_add(UC_HOOK_CODE, hook_insn, begin=TRACE_BEGIN, end=TRACE_END)
```

### Pattern: Memory Watchpoint
```python
def hook_mem_rw(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(f"[write] {address:#x} <- {value:#x} (size={size})")
    elif access == UC_MEM_READ:
        data = uc.mem_read(address, size)
        print(f"[read]  {address:#x} -> {data.hex()} (size={size})")

WATCH_BEGIN = 0x20000000
WATCH_END   = 0x20001000
mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            hook_mem_rw,
            begin=WATCH_BEGIN, end=WATCH_END)
```

---

## Tips

- Start simple: emulate the function with just code + stack, then add hooks as errors appear
- Use `uc.mem_regions()` to list all mapped regions when debugging memory issues
- If the function uses TLS (thread-local storage), simulate it by allocating a region and pointing the TLS register to it
- For iOS/Android binaries, many JNI calls can be stubbed — focus on those that affect the algorithm output
- Save emulation state between runs: dump `reg_read` for all registers + memory snapshot
- For decryption routines: set input in memory, emulate, then read output — no environment setup needed beyond the buffer itself
