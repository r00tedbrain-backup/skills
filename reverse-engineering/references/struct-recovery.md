# C/C++ Structure Recovery Methodology

> For authorized reverse engineering, binary analysis, and CTF challenges.

Systematic approach to reconstructing C/C++ data structures from decompiled code. This file provides the methodology; pair it with `references/idapython.md` or `references/ghidra-scripting.md` for tooling.

## Table of Contents
1. [Recovery Workflow](#workflow)
2. [Memory Access Patterns](#access-patterns)
3. [Caller Analysis](#caller-analysis)
4. [Callee Analysis](#callee-analysis)
5. [Field Type Inference](#type-inference)
6. [Common Structure Patterns](#patterns)
7. [C++ Specific Patterns](#cpp-patterns)
8. [Output Format](#output)

---

## 1. Recovery Workflow {#workflow}

### Step 1: Read Target Function
1. Open the decompiled code of the function using the structure
2. Parse function metadata (callers, callees)
3. Identify pointer parameters — these are candidate structure pointers

### Step 2: Collect Memory Access Patterns
Search the function for all offset accesses relative to the structure pointer. Record each as:
```
offset=0x00, size=8, access=read/write, type=QWORD
offset=0x08, size=4, access=read,       type=DWORD
offset=0x0C, size=4, access=write,      type=DWORD
...
```

### Step 3: Traverse Callers
Read each caller function to find:
- What is passed as the struct parameter (stack var, malloc'd, field of another struct?)
- Operations performed on the struct before/after the call (initialization, destruction)

### Step 4: Traverse Callees
Read each callee to find:
- How the same struct is used in deeper functions (new offsets accessed)
- Whether callees pass sub-fields to other functions (potential nested structs)

### Step 5: Aggregate and Infer
- Merge all offset information, sort by offset
- Calculate struct size: `max(offset) + last_field_size`
- Infer field types from usage context
- Identify common patterns (vtables, linked lists, refcounts)

---

## 2. Memory Access Patterns {#access-patterns}

### Direct Offset Access
```c
*(a1 + 0x10)           // offset 0x10, default size (depends on arch)
*(_DWORD *)(a1 + 8)    // offset 0x8, 4-byte DWORD
*(_QWORD *)(a1 + 0x20) // offset 0x20, 8-byte QWORD
*(_WORD *)(a1 + 4)     // offset 0x4, 2-byte WORD
*(_BYTE *)(a1 + 2)     // offset 0x2, 1-byte BYTE
```

### Array Access
```c
*(a1 + 8 * i)          // array, element size 8 bytes (pointer or QWORD)
*(a1 + 4 * i)          // array, element size 4 bytes (int/DWORD)
a1[i]                  // array access; size depends on a1's declared type
```

### Nested Structure Access
```c
*(*a1 + 0x10)          // first field of a1 is a pointer; dereference and access offset 0x10
(*a1)->field           // same, higher-level C notation
a1->inner.field        // direct embedded struct (no pointer indirection)
```

### Array-of-Struct vs Struct-of-Array
```c
// Array of struct: stride = sizeof(struct)
for (int i = 0; i < n; i++) {
    process(*(base + i * 0x20));   // struct size 0x20
}

// Struct of arrays (SOA): separate arrays for each field
for (int i = 0; i < n; i++) {
    int x = *(x_array + i * 4);
    int y = *(y_array + i * 4);
}
```

### Bit Field Access
```c
// Bitfields are usually combined with masks
flags = *(_DWORD *)(a1 + 0x10);
is_ready = flags & 0x1;           // bit 0
is_locked = (flags >> 1) & 0x1;   // bit 1
priority  = (flags >> 2) & 0x7;   // bits 2-4 (3 bits)
```

### Atomic / Volatile Access
```c
// Often signals concurrent access → locks/atomics nearby
__atomic_load_n(a1 + 0x20, 5);           // GCC atomic
InterlockedIncrement((volatile LONG *)(a1 + 0x20));  // Windows
```

---

## 3. Caller Analysis {#caller-analysis}

Each caller gives hints about the struct's lifecycle and contents.

### Parameter Passing Patterns
```c
sub_401000(v1);           // v1 might be a struct pointer (check v1's definition)
sub_401000(&v2);          // v2 is a stack struct (sizeof hint: sizeof(v2))
sub_401000(malloc(0x40)); // struct size is likely ≤ 0x40 bytes
sub_401000(this);         // C++ method — 'this' is the struct
sub_401000(&g_config);    // global instance → often a singleton config
```

### Pre-Call Operations (Initialization)
```c
v1 = malloc(0x40);             // allocation → struct size 0x40
memset(v1, 0, 0x40);           // zero-init
*v1 = 0x1234;                  // offset 0x00 set to magic/version
*(v1 + 8) = callback;          // offset 0x08 is a function pointer
*(v1 + 16) = 5;                // offset 0x10 initial value (e.g., max_entries)
sub_401000(v1);                // pass to target function
```

### Post-Call Operations (Cleanup)
```c
sub_401000(v1);
sub_401100(*(v1 + 8));         // release sub-resource at offset 8
free(v1);                      // destruction → struct is heap-allocated
```

### Aggregation Across Multiple Callers
Different callers may access different subsets of fields. Union the observations:
```
Caller A uses offsets: 0x00, 0x08, 0x20
Caller B uses offsets: 0x00, 0x10, 0x28
Caller C uses offsets: 0x18, 0x20, 0x30
⇒ Combined observed fields: 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30
```

---

## 4. Callee Analysis {#callee-analysis}

Propagate struct layout information through called functions.

### Parameter Propagation
```c
// In caller
sub_caller(void *a1) {
    sub_callee_1(a1 + 0x20);       // callee gets &a1->field_at_0x20
    sub_callee_2(a1);              // callee gets whole struct
}

// In callee_1 (working on field_at_0x20)
sub_callee_1(void *a1) {
    *(a1 + 0) = ...;               // this is actually a1+0x20+0 of the parent
    *(a1 + 8) = ...;               // this is a1+0x28 of the parent
}
// ⇒ Parent struct has nested sub-struct starting at 0x20
```

### Type Escalation
```c
// Callee uses the argument as a known type
sub_callee(a1) {
    return strlen(a1);             // ⇒ a1 is char*
}
// Propagating back: the field passed to this callee is char*
```

### Callee as Accessor/Mutator
```c
// Getter pattern
int get_size(void *a1) {
    return *(_DWORD *)(a1 + 0x18);  // field at 0x18 is 'size' (DWORD)
}

// Setter pattern
void set_handler(void *a1, void *h) {
    *(_QWORD *)(a1 + 0x28) = h;     // field at 0x28 is 'handler' (function ptr)
}
```

---

## 5. Field Type Inference {#type-inference}

### Inferring Types from Usage
| Usage Pattern | Likely Type |
|---------------|-------------|
| Called as `(*(field))()` or `(*(field))(args)` | Function pointer |
| Passed to `strlen` / `printf("%s")` / `strcpy` | `char *` (C string) |
| Compared with 0 via `if (!ptr)` | Pointer (any type) |
| Used as size in `memcpy(dst, src, field)` | `size_t` / integer count |
| Incremented with `++` or `+= 1` | Counter / index |
| Decremented to 0 then freed | Reference count |
| Compared against small constants (0-10) | Enum / state |
| Masked with `& 0x1`, `& 0xFF` | Flags / bitfield |
| Used in `time(...)` / converted to date | Unix timestamp (`time_t`) |
| Multiplied with another field | Array dimension (width/height) |
| First field, always written first in init | Magic / version / type discriminator |

### Inferring Size from Alignment
```c
// Offsets aligned to 8 → likely QWORDs on 64-bit
0x00, 0x08, 0x10, 0x18, 0x20

// Offsets aligned to 4 → DWORDs
0x00, 0x04, 0x08, 0x0C, 0x10

// Mixed alignment → compiler padding reveals types
0x00 (QWORD), 0x08 (DWORD), 0x0C (DWORD), 0x10 (QWORD)
⇒ Two QWORDs separated by two DWORDs
```

### Inferring Strings vs Byte Buffers
```c
// Embedded fixed-size string (name[32])
strcpy(a1 + 0x10, "hello");        // offset 0x10 is a fixed-size char array
strncpy(a1 + 0x10, src, 0x20);     // 0x20 bytes starting at 0x10

// vs. pointer to string
*(char **)(a1 + 0x10) = strdup(src);  // offset 0x10 is a char pointer
```

---

## 6. Common Structure Patterns {#patterns}

### Linked List Node
```c
struct list_node {
    struct list_node *next;     // 0x00
    struct list_node *prev;     // 0x08
    void *data;                 // 0x10
    // ... possibly more
};
```
**Detection**: two pointer fields near the start, and traversal via `cur = cur->next`.

### Reference-Counted Object
```c
struct refcounted {
    int refcount;               // 0x00 or near start, ++ on retain, -- on release
    void (*destructor)(void *); // function pointer used when refcount hits 0
    // payload ...
};
```
**Detection**: pattern like:
```c
if (--*(_DWORD *)(obj) == 0) {
    (*(_QWORD *)(obj + 8))(obj);   // call destructor
    free(obj);
}
```

### Opaque Handle + Ops Table
```c
struct handle {
    struct ops *vtable;         // 0x00 — points to function table
    // private data follows
};

struct ops {
    int  (*init)(void *);
    int  (*read)(void *, void *, size_t);
    int  (*write)(void *, const void *, size_t);
    void (*close)(void *);
};
```
**Detection**: first field is read and then used to call multiple different functions: `(*(handle->0x00 + 0x10))(handle)` calls init/read/write.

### Thread-Safe Resource
```c
struct resource {
    pthread_mutex_t lock;       // 0x00 — 40 or 64 bytes (platform-dependent)
    int refcount;
    void *data;
    // ...
};
```
**Detection**: first field is always passed to `pthread_mutex_lock` / `pthread_mutex_unlock`.

### Event / Message
```c
struct message {
    uint32_t type;              // 0x00 — switched on in handler
    uint32_t size;              // 0x04
    uint64_t timestamp;         // 0x08
    uint8_t  payload[];         // 0x10+ — variable-length
};
```
**Detection**: `switch (*(msg + 0)) case 1: ... case 2: ...` in handler.

### State Machine Context
```c
struct state_machine {
    int current_state;          // 0x00 — compared with many enum values
    int (*transition)(void *);  // 0x08 — state function pointer
    void *user_data;            // 0x10
    // state-specific data
};
```

### Configuration / Options
```c
struct config {
    uint32_t magic;             // 0x00 — validated first
    uint32_t version;           // 0x04
    uint32_t flags;             // 0x08 — bitfield
    char     name[32];          // 0x0C — fixed string
    uint32_t reserved[4];       // 0x2C — padding / future use
};
```
**Detection**: init function sets magic/version, then reads/validates them elsewhere.

### Hash Table
```c
struct hash_table {
    size_t  capacity;           // 0x00
    size_t  count;              // 0x08
    struct bucket **buckets;    // 0x10 — array of bucket pointers
    hash_fn hash;               // 0x18 — function pointer
};

struct bucket {
    void *key;
    void *value;
    struct bucket *next;        // chaining
};
```

### Ring Buffer / FIFO
```c
struct ringbuf {
    uint8_t *data;              // 0x00 — backing array
    size_t   capacity;          // 0x08
    size_t   head;              // 0x10 — write index
    size_t   tail;              // 0x18 — read index
};
```
**Detection**: modular arithmetic on `head` / `tail` with `% capacity`.

---

## 7. C++ Specific Patterns {#cpp-patterns}

### vtable (Virtual Function Table)
```c
// First field is almost always a pointer to a read-only array of function pointers
struct Base {
    void **vtable;              // 0x00
    // member fields...
};

// Call patterns
(*(*(obj) + 0))(obj);           // call first virtual method (usually destructor)
(*(*(obj) + 8))(obj, arg);      // call second virtual method
(*(*(obj) + 0x10))(obj, a, b);  // call third virtual method
```
**Detection**: first field is a pointer into a read-only section, and the target contains consecutive function pointers.

### Multiple Inheritance (MI)
```c
// Multiple vtables, one per base class
struct Derived {
    void **vtable_base1;        // 0x00
    int   base1_fields;         // ...
    void **vtable_base2;        // offset where second base starts
    int   base2_fields;
    int   derived_fields;
};
```

### std::string (libstdc++ short-string-optimization)
```c
// GCC libstdc++ std::string (SSO, 16-byte optimized buffer)
struct std_string {
    char   *ptr;                // 0x00 — points to heap or to inline buffer
    size_t  size;               // 0x08
    union {
        size_t capacity;        // 0x10
        char   sso_buf[16];     // inline buffer for short strings
    };
};
// Total size: 0x20 (32 bytes)
```
**Detection**: 3 pointer-sized fields in a row, where first is sometimes `self + 0x10`.

### std::vector
```c
struct std_vector {
    T *begin;                   // 0x00
    T *end;                     // 0x08 — end of used elements
    T *capacity_end;            // 0x10 — end of allocated memory
};
// Total size: 0x18 (24 bytes)

// size()     = (end - begin) / sizeof(T)
// capacity() = (capacity_end - begin) / sizeof(T)
```

### std::unique_ptr / std::shared_ptr
```c
// unique_ptr: just a raw pointer (if no custom deleter)
struct unique_ptr {
    T *ptr;                     // 0x00
};

// shared_ptr: pointer + control block
struct shared_ptr {
    T *ptr;                     // 0x00 — actual object
    struct control_block *ctrl; // 0x08 — contains refcount + deleter
};

struct control_block {
    long strong_count;          // atomic
    long weak_count;
    // vtable or deleter follows
};
```

### std::map (red-black tree, libstdc++)
```c
struct std_map_header {
    int          color;         // 0x00 — RB tree color bit (plus padding)
    struct node *parent;        // 0x08 — root of tree
    struct node *leftmost;      // 0x10 — smallest
    struct node *rightmost;     // 0x18 — largest
    size_t       node_count;    // 0x20
};

struct node {
    int          color;         // 0x00
    struct node *parent;        // 0x08
    struct node *left;          // 0x10
    struct node *right;         // 0x18
    Key          key;           // 0x20
    Value        value;         // follows key
};
```
**Detection**: red-black tree traversal code with left/right/parent pointers.

---

## 8. Output Format {#output}

When reporting structure recovery findings, use this format:

```c
/*
 * Structure Recovery Analysis
 * Source function: <func_address>
 * Analysis scope:  <N callers + M callees analyzed>
 *
 * Functions using this struct:
 *   - 0x401000 (constructor / init)
 *   - 0x401100 (accessor / get_size)
 *   - 0x401200 (mutator / set_handler)
 *   - 0x401300 (destructor / cleanup)
 *
 * Estimated size: 0x48 bytes
 * Confidence:     High / Medium / Low
 * Allocation:     heap (malloc) / stack / global / C++ object
 */

struct suggested_name {
    /* 0x00 */ void          *vtable;       // vtable pointer, called: (*(*this))()
    /* 0x08 */ int            refcount;     // reference count, has ++/-- operations
    /* 0x0C */ uint32_t       flags;        // bitfield: AND with 0x1, 0x2, 0x4
    /* 0x10 */ char          *name;         // string, passed to strlen/printf
    /* 0x18 */ void          *data;         // generic data pointer
    /* 0x20 */ size_t         size;         // size field, used in memcpy
    /* 0x28 */ struct node   *next;         // linked list next
    /* 0x30 */ struct node   *prev;         // linked list prev
    /* 0x38 */ void         (*handler)(void *);  // callback function
    /* 0x40 */ void          *user_data;    // opaque context for handler
};
// Total size: 0x48 bytes

/*
 * Field access examples (for verification):
 *   0x401000: *(this + 0x08) += 1;          // refcount++
 *   0x401100: printf("%s", *(this + 0x10)); // print name
 *   0x401200: (*(this + 0x38))(this + 0x40); // call handler(user_data)
 */

/*
 * Open questions / Low-confidence fields:
 *   - offset 0x0C: assumed flags based on bitwise operations, but
 *                  might be a small enum
 *   - offset 0x20: could be size_t or a count (unclear from current observations)
 */
```
