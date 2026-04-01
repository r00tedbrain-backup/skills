# Dynamic Debugging Reference

## Table of Contents
1. [GDB](#gdb)
2. [GDB Enhanced (pwndbg / gef / peda)](#gdb-enhanced)
3. [LLDB](#lldb)
4. [strace / ltrace](#strace)
5. [Valgrind](#valgrind)
6. [x64dbg (Windows)](#x64dbg)
7. [Crash Analysis](#crash-analysis)
8. [Core Dumps](#core-dumps)

---

## 1. GDB {#gdb}

### Launch Modes
```bash
gdb <binary>                        # standard
gdb <binary> <corefile>             # with core dump
gdb --args <binary> arg1 arg2       # with arguments
gdb -p <pid>                        # attach to running process
gdb --batch -ex "..." <binary>      # headless scriptable
```

### Essential Commands
```bash
# Execution control
run [args]          # r     — start
continue            # c     — resume
next                # n     — step over
step                # s     — step into
nexti               # ni    — step over (instruction level)
stepi               # si    — step into (instruction level)
finish              # fin   — run until function returns
until <addr>        # run until address
jump *0x401234      # force jump to address

# Breakpoints
break main          # b main
break *0x401234     # break at address
break func if $rdi == 0   # conditional
watch <var>         # watchpoint (memory write)
rwatch <var>        # read watchpoint
awatch <var>        # read+write watchpoint
info breakpoints    # ib
delete 2            # delete breakpoint #2
disable 1           # disable breakpoint
enable 1

# Registers
info registers      # ir — all registers
info registers rax rdi rsi
print $rax          # p $rax
set $rax = 0x1337   # modify register

# Memory
x/10xg $rsp         # examine: 10 giant(8B) words as hex from rsp
x/20xw 0x601000     # 20 words (4B) as hex
x/s 0x402000        # as string
x/i $rip            # disassemble at rip
x/10i main          # disassemble 10 instrs from main

# Stack & frames
backtrace           # bt — call stack
frame 2             # select frame
info frame          # current frame info
info locals         # local variables
info args           # function arguments

# Search memory
find 0x600000, 0x700000, "password"  # search string in range
find /b 0x600000, +0x1000, 0xde, 0xad  # search bytes
```

### Useful One-liners
```bash
# Dump function disassembly
gdb -batch -ex "disas main" <binary>

# Run until signal + show backtrace
gdb -batch -ex "run" -ex "bt" --args <binary> <args>

# Log all calls to malloc
gdb -batch -ex "break malloc" -ex "commands\nsilent\nbt 3\ncontinue\nend" -ex "run" <binary>

# Patch a byte and continue
gdb -ex "break *0x401234" -ex "run" -ex "set *(unsigned char*)0x401234 = 0x90" -ex "continue" <binary>
```

### GDB Init (~/.gdbinit)
```
set disassembly-flavor intel
set pagination off
set print pretty on
set print array on
set print array-indexes on
set follow-fork-mode child
set detach-on-fork off
set history save on
set history size 10000
```

---

## 2. GDB Enhanced Plugins {#gdb-enhanced}

### pwndbg (recommended for pwn/RE)
```bash
pip install pwndbg
# or: git clone <PWNDBG_REPO> && ./setup.sh  (github.com/pwndbg/pwndbg)

# Key commands added:
context          # show full context (regs, stack, code, backtrace)
nearpc           # disassemble around RIP
telescope $rsp   # smart dereference stack
vmmap            # memory mappings with perms
checksec         # binary protections
heap             # heap chunks overview
bins             # tcache/fastbin/smallbin state
got              # GOT table entries
plt              # PLT entries
canary           # show stack canary value
rop              # ROP gadget search
search -s "flag" # search memory for string
```

### GEF (GDB Enhanced Features)
```bash
# Install GEF: visit gef.blah.cat for install instructions
# bash -c "$(curl -fsSL <GEF_INSTALL_URL>)"

# Key commands:
gef               # show all custom commands
heap chunks       # heap visualization
heap arenas
format-string-helper   # detect format string vulns
pattern create 200     # cyclic pattern (crash offset)
pattern search $rsp    # find offset after crash
xinfo 0x401234         # cross-info about address
```

### PEDA (Python Exploit Development Assistance)
```bash
# PEDA — github.com/longld/peda
git clone <PEDA_REPO_URL>
echo "source ~/peda/peda.py" >> ~/.gdbinit

pattern create 200     # cyclic De Bruijn pattern
pattern offset $eip    # find EIP offset after crash
searchmem "AAAA"       # search pattern in memory
ropgadget              # find ROP gadgets
```

---

## 3. LLDB {#lldb}

### Launch
```bash
lldb <binary>
lldb -- <binary> arg1 arg2
lldb -p <pid>                      # attach
lldb -c <corefile>                 # core dump
```

### Commands (LLDB ↔ GDB equivalents)
| Action | GDB | LLDB |
|--------|-----|------|
| Run | `run` | `run` / `r` |
| Continue | `continue` | `continue` / `c` |
| Step over | `next` | `next` / `n` |
| Step into | `step` | `step` / `s` |
| Step instruction | `nexti` | `nexti` / `ni` |
| Break at func | `break main` | `br set -n main` |
| Break at addr | `break *0x1234` | `br set -a 0x1234` |
| Print register | `p $rax` | `register read rax` |
| Examine mem | `x/10xg $rsp` | `memory read -f x -c 10 $rsp` |
| Backtrace | `bt` | `bt` / `thread backtrace` |
| List breakpoints | `info breakpoints` | `br list` |
| Disassemble | `disas` | `disassemble` / `di` |

### LLDB Python Scripting
```python
# In lldb: script
import lldb
def log_ret(frame, bp_loc, extra_args, dict):
    val = frame.FindRegister("rax")
    print(f"[RET] rax = {val.GetValueAsUnsigned():#x}")

target = lldb.debugger.GetSelectedTarget()
bp = target.BreakpointCreateByName("target_function")
bp.SetScriptCallbackFunction("log_ret")
```

---

## 4. strace / ltrace {#strace}

### strace — System Call Tracing
```bash
strace <binary>                       # trace all syscalls
strace -o trace.log <binary>          # save to file
strace -f <binary>                    # follow forks
strace -e trace=network <binary>      # network syscalls only
strace -e trace=file <binary>         # file operations only
strace -e trace=read,write <binary>   # specific syscalls
strace -e trace=openat,read,write,connect <binary>
strace -s 256 <binary>                # longer string output (default 32)
strace -y <binary>                    # annotate fds with paths
strace -p <pid>                       # attach to running process

# Useful filters
strace -e trace=%file <binary>        # all file-related
strace -e trace=%network <binary>     # all network-related
strace -e trace=%process <binary>     # fork/exec/wait
strace -e trace=%signal <binary>      # signals
strace -e trace=%ipc <binary>         # IPC (shared mem, etc.)

# Count + summarize
strace -c <binary>                    # statistics summary
```

### ltrace — Library Call Tracing
```bash
ltrace <binary>                       # all library calls
ltrace -l libssl.so.* <binary>        # specific library
ltrace -e strcmp <binary>             # specific function
ltrace -e 'malloc+free' <binary>      # malloc/free tracking
ltrace -n 2 <binary>                  # indent nested calls
ltrace -f <binary>                    # follow forks
ltrace -o ltrace.log <binary>

# Combine with strace
strace -e trace=network ltrace -e send,recv <binary>
```

---

## 5. Valgrind {#valgrind}

```bash
# Memory error detection (use-after-free, buffer overflow, leaks)
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=valgrind.log \
         <binary> [args]

# Heap profiling
valgrind --tool=massif --pages-as-heap=yes <binary>
ms_print massif.out.<pid>

# Thread error detection
valgrind --tool=helgrind <binary>

# Cache / branch prediction profiling
valgrind --tool=callgrind <binary>
kcachegrind callgrind.out.<pid>   # visualize

# Custom suppression (ignore known false positives)
valgrind --gen-suppressions=all <binary> > my.supp
valgrind --suppressions=my.supp <binary>
```

---

## 6. x64dbg (Windows) {#x64dbg}

### Key Shortcuts
| Action | Shortcut |
|--------|----------|
| Step over | `F8` |
| Step into | `F7` |
| Run | `F9` |
| Run to cursor | `F4` |
| Breakpoint toggle | `F2` |
| Go to address | `Ctrl+G` |
| Follow in dump | `Ctrl+D` |
| Search all modules | `Ctrl+Shift+F` |
| Memory map | `Alt+M` |
| Patch | `Ctrl+P` (after edit) |

### Scripting (x64dbgpy)
```python
import x64dbg
x64dbg.SetBreakpoint(0x401234)
x64dbg.Run()
rax = x64dbg.GetRegister("rax")
print(f"RAX = {rax:#x}")
```

---

## 7. Crash Analysis {#crash-analysis}

### SIGSEGV / SIGABRT Investigation
```bash
# Enable core dumps first
ulimit -c unlimited
echo '/tmp/core.%e.%p' | sudo tee /proc/sys/kernel/core_pattern

# Run crashing binary
./<binary> [args]   # should generate /tmp/core.*

# Analyze core
gdb <binary> /tmp/core.<n>
(gdb) bt            # backtrace
(gdb) info registers
(gdb) x/20xg $rsp  # stack at crash
(gdb) list          # source if available
```

### AddressSanitizer (fastest for UAF/overflow)
```bash
# Recompile with ASAN (if you have source)
gcc -fsanitize=address -fno-omit-frame-pointer -g -O1 <src.c> -o <out>
./<out>   # ASAN will print detailed report on any memory error

# Without source: LD_PRELOAD approach
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.5 ./<binary>
```

### Crash Triage Checklist
```
1. What signal? (SIGSEGV=11, SIGABRT=6, SIGBUS=7, SIGFPE=8)
2. What address caused fault? (info registers → $rip, cr2)
3. Is RIP/EIP corrupted? → likely stack overflow, BOF
4. Is fault in NULL range (0x0-0x1000)? → null ptr deref
5. Is fault in heap? → UAF, double-free, heap overflow
6. Backtrace valid? → if garbled, likely stack smash
7. Stack canary check: look for __stack_chk_fail in bt
```

---

## 8. Core Dumps {#core-dumps}

```bash
# Configure
ulimit -c unlimited                              # current session
echo '* soft core unlimited' >> /etc/security/limits.conf  # permanent
sysctl -w kernel.core_pattern='/tmp/core.%e.%p.%t'

# Analyze
gdb <binary> <corefile>
(gdb) bt full          # full backtrace with locals
(gdb) thread apply all bt  # all threads
(gdb) info proc mappings   # memory map at crash time

# Python automated crash analysis
python3 -c "
import subprocess, sys
result = subprocess.run(['gdb', '--batch',
    '-ex', 'bt full',
    '-ex', 'info registers',
    '-ex', 'x/20xg \$rsp',
    sys.argv[1], sys.argv[2]],
    capture_output=True, text=True)
print(result.stdout)
" <binary> <corefile>
```
