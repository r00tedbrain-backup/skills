# Symbol Recovery Methodology

Systematic approach to identifying and recovering function names in stripped binaries. This file provides the methodology; pair it with `references/idapython.md` or `references/ghidra-scripting.md` for the actual tooling.

## Table of Contents
1. [Recovery Workflow](#workflow)
2. [Magic Number Catalog](#magic-numbers)
3. [Paired Call Patterns](#paired-patterns)
4. [Argument & Return Value Patterns](#argument-patterns)
5. [Caller/Callee Analysis](#xref-analysis)
6. [String-Based Identification](#strings)
7. [Open-Source Matching](#open-source)
8. [Output Format](#output)

---

## 1. Recovery Workflow {#workflow}

### Step 1: Analyze Internal Characteristics

Carefully examine the target function for:

- **String constants** — strings used in the function often reveal its purpose (error messages, format strings, file paths, API names)
- **Numeric constants / Magic Numbers** — compare against the catalog below
- **Code structure** — loop patterns, bitwise operations, specific algorithm flows
- **Instruction count & stack usage** — very short functions often map to simple wrappers (strlen, memcpy)
- **Calling convention anomalies** — `__fastcall` with many args may indicate compiler-specific runtime functions

If you can identify a known algorithm through constants/structure, tell the user directly and stop — no further analysis needed.

### Step 2: Analyze Cross-References (Xrefs)

**Callees (functions called by this one):**
- Read each callee address
- Cross-reference against the import table — if the callee is an import, you already have the name
- Recognize call patterns (see Section 3) even when symbols are missing

**Callers (functions that call this one):**
- If a caller has a symbol, infer the callee's purpose from context
- Recursive check: trace up the call chain until you find a function with a symbol
- Analyze how the return value is used by callers (checked for NULL? -1? compared against constant?)

### Step 3: Information Gathering and Search

Collect:
- Strings referenced in the function
- Magic numbers / constants
- Known imports called (from import table cross-reference)
- Caller/callee symbols (from export table)
- Paired function patterns identified

Based on collected information:

1. **First attempt local reasoning** based on:
   - Function signature (number and types of parameters)
   - Paired call patterns (alloc/free, lock/unlock)
   - Known imports in the call chain
   - Code structure similarity to known algorithms

2. **If uncertain, use web search**:
   - Search magic numbers: `0x67452301 0xEFCDAB89 algorithm`
   - Search code patterns: `rotate left xor constant algorithm`
   - Search unique strings found in the function
   - Search parameter patterns: `function(int, int, 0) socket`

---

## 2. Magic Number Catalog {#magic-numbers}

### Cryptographic Constants
| Algorithm | Constants | Notes |
|-----------|-----------|-------|
| **MD5** | `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476` | Initial hash state (IV) |
| **MD5** | `0xD76AA478`, `0xE8C7B756`, `0x242070DB`, `0xC1BDCEEE` | K table (first 4) |
| **SHA-1** | `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`, `0xC3D2E1F0` | IV (same first 4 as MD5 + extra) |
| **SHA-1** | `0x5A827999`, `0x6ED9EBA1`, `0x8F1BBCDC`, `0xCA62C1D6` | Round constants |
| **SHA-256** | `0x6A09E667`, `0xBB67AE85`, `0x3C6EF372`, `0xA54FF53A` | IV (first 4) |
| **SHA-256** | `0x428A2F98`, `0x71374491`, `0xB5C0FBCF`, `0xE9B5DBA5` | K table (first 4) |
| **SHA-512** | `0x6A09E667F3BCC908` | IV (64-bit values) |
| **CRC32** | `0xEDB88320` | Reversed polynomial |
| **CRC32-C** | `0x82F63B78` | Castagnoli (iSCSI) |
| **AES S-Box** | `0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5...` | 256-byte substitution table |
| **AES Inv S-Box** | `0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38...` | Inverse 256-byte table |
| **DES S-Box** | `0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8...` | Multiple 4-bit S-boxes |
| **RC4** | 256-byte state + swap loop | Identify by KSA `S[i] = i` init |
| **Blowfish** | `0x243F6A88, 0x85A308D3, ...` | π constants as initial S-boxes |
| **Salsa20 / ChaCha20** | `0x61707865, 0x3320646E, 0x79622D32, 0x6B206574` | "expand 32-byte k" as 4 DWORDs |
| **Poly1305** | `0x0FFFFFFC, 0x0FFFFFFC, 0x0FFFFFFF, 0x0FFFFFFC` | Key clamp mask |

### Encoding Tables
| Algorithm | Marker | Notes |
|-----------|--------|-------|
| **Base64** | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` | Standard alphabet |
| **Base64 URL-safe** | Same but `+` → `-` and `/` → `_` | RFC 4648 §5 |
| **Base32** | `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567` | RFC 4648 |
| **Hex** | `0123456789abcdef` or `0123456789ABCDEF` | Lowercase / uppercase |
| **UUEncode** | ASCII printable starting at space (0x20) | `begin NNN filename` prefix |

### Format Magic Numbers
| Format | Magic | Offset |
|--------|-------|--------|
| **Zlib** | `0x78 0x01` / `0x78 0x9C` / `0x78 0xDA` | 0 (stream start) |
| **Gzip** | `0x1F 0x8B` | 0 |
| **ZIP** | `50 4B 03 04` ("PK\x03\x04") | 0 |
| **7z** | `37 7A BC AF 27 1C` | 0 |
| **bzip2** | `42 5A 68` ("BZh") | 0 |
| **LZMA** | `5D 00 00` + dictionary size | 0 |
| **ELF** | `7F 45 4C 46` ("\x7FELF") | 0 |
| **PE** | `4D 5A` ("MZ") at 0, `50 45 00 00` ("PE\0\0") at e_lfanew | 0 / variable |
| **Mach-O 32** | `FE ED FA CE` (BE) / `CE FA ED FE` (LE) | 0 |
| **Mach-O 64** | `FE ED FA CF` (BE) / `CF FA ED FE` (LE) | 0 |
| **DEX** | `64 65 78 0A 30 33 35 00` ("dex\n035\0") | 0 |
| **Java class** | `CA FE BA BE` | 0 |
| **PNG** | `89 50 4E 47 0D 0A 1A 0A` | 0 |
| **JPEG** | `FF D8 FF` | 0 |
| **PDF** | `25 50 44 46` ("%PDF") | 0 |
| **SQLite** | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` ("SQLite format 3\0") | 0 |

### Runtime / Compiler Magic
| Marker | Meaning |
|--------|---------|
| `0xDEADBEEF`, `0xDEADC0DE` | Debug fill / uninitialized |
| `0xCAFEBABE` | Java class file, sometimes generic sentinel |
| `0xFEEDFACE` | Mach-O, sometimes generic sentinel |
| `0xBAADF00D` | Windows HeapAlloc uninitialized (checked builds) |
| `0xABABABAB` | Windows HeapAlloc guard bytes |
| `0xFEEEFEEE` | Windows HeapFree pattern |
| `0xCCCCCCCC` | MSVC uninitialized stack (debug) |
| `0xCDCDCDCD` | MSVC new-allocated heap (debug) |

---

## 3. Paired Call Patterns {#paired-patterns}

Identify functions by their pairing relationships with other calls. Even when symbols are missing, these patterns strongly suggest function purpose.

### Allocation / Deallocation Pairs
```c
// malloc/free, new/delete, alloc/dealloc
xx = sub_A(0x100);        // alloc: takes size, returns pointer
...
sub_B(xx);                // free: takes the same pointer
```

### Lock / Unlock Pairs
```c
// mutex_lock/mutex_unlock, pthread_mutex_lock/unlock, CriticalSection
sub_A(lock_ptr);          // lock
...                       // critical section (often short)
sub_B(lock_ptr);          // unlock (same lock object)
```

### Open / Close Pairs
```c
// open/close, fopen/fclose, CreateFile/CloseHandle, socket/close
fd = sub_A("/path", 0);   // open: path + flags, returns handle
...
sub_B(fd);                // close: takes the handle
```

### Create / Join Pairs (threads)
```c
// pthread_create/pthread_join
sub_A(&tid, 0, func, arg); // create: out param, attr, func, arg
...
sub_B(tid, &ret);          // join: tid, out param
```

### Init / Destroy Pairs
```c
// mutex_init/mutex_destroy, curl_easy_init/curl_easy_cleanup
ctx = sub_A();            // init: no args or config, returns handle
...                       // use ctx for multiple operations
sub_B(ctx);               // destroy/cleanup: takes the handle
```

### Push / Pop Pairs (state saving)
```c
sub_A(ctx);               // save state (push)
...                       // do something
sub_B(ctx);               // restore state (pop)
```

### Ref / Unref Pairs (reference counting)
```c
sub_A(obj);               // retain/addref: increments refcount at obj+N
...
sub_B(obj);               // release/unref: decrements, frees if 0
```

---

## 4. Argument & Return Value Patterns {#argument-patterns}

### Common Argument Signatures
```c
// socket(AF_INET, SOCK_STREAM, 0) — fixed constants
sub_XXX(2, 1, 0);         // socket: domain=2(AF_INET), type=1(SOCK_STREAM), protocol=0

// connect/bind(sockfd, addr, addrlen)
sub_XXX(fd, &var, 16);    // 16 = sizeof(sockaddr_in) IPv4
sub_XXX(fd, &var, 28);    // 28 = sizeof(sockaddr_in6) IPv6

// memcpy/memmove(dst, src, size)
sub_XXX(dst, src, n);     // 3 params: dst, src, count

// memset(ptr, value, size)
sub_XXX(ptr, 0, 0x100);   // 3 params: ptr, byte value, count (value often 0)

// read/write(fd, buf, count)
ret = sub_XXX(fd, buf, n); // returns bytes read/written

// strcmp/strncmp(s1, s2) or (s1, s2, n)
if (sub_XXX(s1, s2) == 0)  // returns 0 on equal

// strncpy(dst, src, n)
sub_XXX(dst, src, sizeof(dst) - 1);

// snprintf(buf, size, fmt, ...)
sub_XXX(buf, 0x100, "%s: %d", ...);

// qsort(base, nmemb, size, compar)
sub_XXX(arr, 10, 4, cmp_fn);  // cmp_fn is function pointer

// bsearch(key, base, nmemb, size, compar)
sub_XXX(&key, arr, 10, 4, cmp_fn);
```

### Return Value Patterns
```c
// File/socket operations: -1 on error
if ((fd = sub_XXX(...)) == -1) goto error;

// Allocation: NULL on failure
if (!(ptr = sub_XXX(size))) goto error;

// Success/error: 0 = success (POSIX convention)
if (sub_XXX(...) != 0) goto error;

// Windows: non-zero = success
if (!sub_XXX(...)) goto error;   // Windows API convention

// strlen: returns size_t, then used as count
len = sub_XXX(str);
sub_YYY(dst, src, len);          // len used in memcpy/strncpy

// GetLastError / errno wrapper: returns error code
errcode = sub_XXX();
if (errcode == ERROR_FILE_NOT_FOUND) { ... }

// Handle-returning: high-value "magic" pointer (not NULL, not -1)
h = sub_XXX(...);
if (h == INVALID_HANDLE_VALUE) goto error;  // INVALID_HANDLE_VALUE = -1
```

### Parameter Count Heuristics
```c
// 0 args, returns pointer → getter (current thread, errno, time, ...)
// 1 arg (pointer), returns int → property query (strlen, HeapSize, sizeof)
// 1 arg (pointer), returns void → destructor/free
// 2 args, compares → cmp function (strcmp, memcmp, qsort callback)
// 3 args (ptr, ptr, int) → memory op (memcpy, memcmp, memset)
// (ptr, int, int) → memory op with offset
// 4+ args with file/socket handle first → I/O operation
```

---

## 5. Caller/Callee Analysis {#xref-analysis}

### Trace Up the Call Chain
```
unknown_fn
    ↑ called by ↑
sub_401000 (unknown)
    ↑ called by ↑
main (SYMBOL KNOWN)
    → main calls sub_401000 right after reading argc/argv
    → sub_401000 likely handles arg parsing or initialization
```

### Trace Down the Call Chain
```
unknown_fn
    → calls malloc (KNOWN)
    → calls memset with 0 (KNOWN)
    → calls pthread_mutex_init (KNOWN)
    → returns a pointer
    ⇒ Likely: object_create / object_new / constructor
```

### Callee Signature Inference
When a callee is an import like `strlen`, the argument passed to it must be a string pointer. Propagate that type backward through the function to identify other pointers.

```c
// Callee analysis
size = strlen(a1);           // ⇒ a1 is char*
memcpy(buf, a1, size);        // ⇒ a1 is still char*, buf is writable
printf("%s\n", a1);           // confirms a1 is printable char*
```

---

## 6. String-Based Identification {#strings}

### High-Value Strings
- **Error messages** — `"malloc failed"`, `"cannot open %s: %s"`, `"assertion failed: %s"`
- **Format strings** — `"%d %d %d"`, `"key=%s value=%s"`
- **API names as strings** — `"GetProcAddress"`, `"LoadLibraryA"` (often dlopen/dlsym targets)
- **File paths** — `"/etc/passwd"`, `"%WINDIR%\\system32"`
- **Registry keys** — `"SOFTWARE\\..."`, `"HKEY_LOCAL_MACHINE"`
- **URLs / hostnames** — `"https://api..."`, version check endpoints
- **Debug markers** — `__FUNCTION__` expansion: `"sub_xyz"`, function name literals
- **Copyright / author** — often hints at library origin (OpenSSL, zlib, etc.)

### String-Guided Identification
```
Function references "PNG IHDR missing"    ⇒ libpng parser
Function references "zlib error %d"       ⇒ zlib wrapper
Function references "openssl %s"          ⇒ OpenSSL wrapper
Function references "SELECT * FROM"       ⇒ SQL query builder
Function references "Content-Length: %d"  ⇒ HTTP handler
Function references stack trace format    ⇒ logger / crash handler
```

---

## 7. Open-Source Matching {#open-source}

When patterns suggest a known library:

1. **Search the unique strings** on GitHub search or Google
2. **Match constants** — specific IV/K tables pinpoint exact algorithm versions
3. **Check function layout** — 64-byte hash blocks with 4 rounds → MD5
4. **Compare call graphs** — reference implementations of known libraries

### Common Libraries to Check
- `libc` / `libm` — stdlib functions
- `OpenSSL` / `mbedtls` / `BoringSSL` — crypto
- `zlib` / `liblzma` — compression
- `curl` — HTTP
- `sqlite3` — database
- `protobuf` — serialization
- `Boost` — C++ utilities (often produces large, template-heavy functions)

### Tools for Signature Matching
- **BinDiff** — binary similarity with known good
- **Diaphora** — IDA plugin for binary diffing
- **FunctionSimSearch** — Google's function similarity
- **FLIRT/FLAIR** — IDA's built-in library signature system
- **Lumen / LumenIDA** — crowdsourced function names

---

## 8. Output Format {#output}

When reporting symbol recovery findings, use this structure:

```markdown
## Symbol Recovery Analysis: <function_address>

### Function Characteristics
- **Strings**: <list discovered strings>
- **Constants**: <list key constants / magic numbers>
- **Called imports**: <list>
- **Code structure**: <short / loop-heavy / branch-heavy / etc.>

### Cross-Reference Analysis
- **Callers**: <callers and their symbols, if any>
- **Callees**: <callees and their symbols>
- **Call chain depth**: <levels up to a known symbol>

### Pattern Matches
- **Paired with**: <e.g., sub_401200 which looks like free()>
- **Argument pattern**: <e.g., (fd, buf, size) matches read/write>
- **Return pattern**: <e.g., -1 on error, handle otherwise>

### Inference Result
- **Suggested symbol name**: `<suggested_name>`
- **Confidence**: High / Medium / Low
- **Reasoning**: <explain why this name is suggested>

### Similar Open-Source Implementation
- <if similar open source code is found, provide reference>
- <e.g., "matches OpenSSL EVP_EncryptUpdate layout">

### Alternative Candidates (if Low confidence)
- `candidate_name_1` — <reason>
- `candidate_name_2` — <reason>
```
