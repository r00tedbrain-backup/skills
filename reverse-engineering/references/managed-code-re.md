# Managed Code Reverse Engineering (.NET / Java / JVM)

## Table of Contents
1. [.NET IL Internals](#il)
2. [dnSpy Advanced](#dnspy)
3. [.NET Obfuscators & Deobfuscation](#dotnet-obf)
4. [Java / JVM RE](#java)
5. [Kotlin RE](#kotlin)
6. [JVM Bytecode Patching](#jvm-patch)
7. [Runtime Hooking (Java Agents)](#java-agent)
8. [Unity / Mono RE](#unity)

---

## 1. .NET IL Internals {#il}

```bash
# IL (Intermediate Language) = .NET bytecode
# Decompiles cleanly to C# with dnSpy/ILSpy

# Key concepts:
# Assembly  → .exe or .dll file (PE with .NET metadata)
# Module    → compilation unit within assembly
# Type      → class/struct/interface/enum
# Method    → IL code + metadata
# Token     → 4-byte metadata identifier (0x06xxxxxx = method)

# Inspect IL directly
ildasm target.exe                            # GUI IL viewer (Windows SDK)
ildasm target.exe /out:target.il            # dump to text

# IL opcodes you'll see often:
# ldarg.0       → load 'this' pointer
# ldarg.1/2...  → load argument
# ldfld         → load field
# stfld         → store field
# call/callvirt → method call
# ldstr         → load string literal
# ret           → return
# br/brfalse/brtrue → branch instructions
# box/unbox     → value type ↔ object
# newobj        → new instance
# ldtoken       → load type/method token
```

### .NET Assembly Metadata
```python
# Python: use dnlib or pythonnet for metadata inspection
# Or: use monodis on Linux

# Extract all strings from .NET assembly
python3 << 'EOF'
import sys, struct

with open(sys.argv[1], 'rb') as f:
    data = f.read()

# Find #Strings heap (simple approach: look for .NET string heap)
# Better: use dnSpy "Metadata Tokens" view

# Quick: just extract all unicode strings
import re
strings = re.findall(b'[\x20-\x7e]{4,}', data)
for s in strings:
    decoded = s.decode('ascii', errors='ignore')
    if len(decoded) > 4:
        print(decoded)
EOF target.exe
```

---

## 2. dnSpy Advanced {#dnspy}

```
Download: github.com/dnSpyEx/dnSpy (active fork)

# Power features:

## Debugging .NET without source
File → Start Debugging → select .exe
→ Set breakpoints directly in decompiled C# code
→ Inspect variables, step through, modify values at runtime

## Edit and Continue
Right-click method → Edit Method (C#)
→ Modify decompiled code
→ Compile → patch runs in memory immediately
→ No need to rebuild and restart

## Save modified assembly
File → Save Module → saves patched .dll/.exe
File → Save All → saves all modified assemblies

## Search
Ctrl+Shift+F → search ALL strings/types/methods across all assemblies
→ Search: "password", "decrypt", "license", "trial"

## Method decompilation modes
Right-click in code → Decompile → toggle between:
- C# (default, readable)
- Visual Basic
- IL (raw bytecode, most accurate)
- IL + C# (side by side)

## Assembly diff
Extensions → Open Assembly Diff → compare two versions
```

### Patching .NET via IL Manipulation
```csharp
// Scenario: method returns false for license check
// IL view shows:
// ldsfld bool LicenseManager::_licensed
// ret
// 
// Patch: force return true
// Change to:
// ldc.i4.1    (load constant 1 = true)
// ret

// In dnSpy IL editor:
// Right-click method → Edit IL Instructions
// Delete ldsfld line
// Add: ldc.i4.1
// Save
```

---

## 3. .NET Obfuscators {#dotnet-obf}

```bash
# Detect obfuscator
de4dot --detect target.exe

# Common obfuscators and de4dot support:
# ConfuserEx          → de4dot -f target.exe (partial, strong obf)
# Dotfuscator         → de4dot -f target.exe
# SmartAssembly       → de4dot -f target.exe
# .NET Reactor        → de4dot -f target.exe
# Agile.NET           → de4dot -f target.exe
# Crypto Obfuscator   → de4dot -f target.exe
# Babel               → de4dot -f target.exe
# Eazfuscator         → de4dot -f target.exe (partial)
# ILProtector         → difficult, not fully supported

# de4dot usage
de4dot.exe target.exe -o cleaned.exe              # auto-detect + clean
de4dot.exe target.exe --strenc -o cleaned.exe     # also decrypt strings
de4dot.exe -f target.exe --keep-names nfd         # preserve namespace/field/delegate names

# Manual string decryption (when de4dot fails)
# 1. Find the string decryption method (usually: takes int/string, returns string)
# 2. In dnSpy: set BP on that method, log all return values
# 3. Or: use dnSpy "Call Finder" to find all calls to decryptor
# 4. Write emulator: extract the XOR key, replicate the algorithm in Python
```

### ConfuserEx Deobfuscation
```
ConfuserEx features (and analysis approach):
1. Control flow obfuscation → switch-based spaghetti code → trace manually
2. String encryption → encrypted at compile time, decrypted at runtime
   → BP on decrypt method or use ConfuserEx Deobfuscation tools
3. Anti-tamper → hash check of assembly → patch or skip
4. Anti-debug → IsDebuggerPresent / Debugger.IsAttached → patch
5. Name obfuscation → random names → de4dot for renaming by type
6. Constants mutation → arithmetic obfuscation → simplify manually

# NoFuserEx: ConfuserEx-specific deobfuscator
# ConfuserEx-Unpacker tools on GitHub
```

---

## 4. Java / JVM RE {#java}

```bash
# Decompilers (choose based on quality for your target)
# cfr       → best for modern Java (lambdas, generics)
# procyon   → good alternative
# fernflower → IntelliJ's built-in decompiler
# jd-gui    → quick GUI viewer

# cfr
java -jar cfr.jar target.jar --outputdir decompiled/
java -jar cfr.jar target.class

# procyon
java -jar procyon.jar -o decompiled/ target.jar

# jadx (also handles Java, not just Android)
jadx -d output/ target.jar

# Bytecode viewer
java -jar bytecode-viewer.jar   # GUI: multiple decompilers side by side

# javap — built-in disassembler
javap -c ClassName              # bytecode
javap -verbose ClassName        # full constant pool + bytecode
javap -p ClassName              # private members too
javap -c -classpath target.jar com.example.ClassName

# Inspect JAR
jar tf target.jar               # list contents
unzip target.jar -d extracted/
```

### JVM Bytecode
```
Key JVM opcodes:
invokevirtual → virtual method call (most common)
invokestatic  → static method call
invokespecial → constructor / super call
invokeinterface → interface method call
invokedynamic → lambda / bootstrap (Java 8+)

getstatic / putstatic → static field access
getfield  / putfield  → instance field access

iload/aload/lload → load local variable (int/ref/long)
istore/astore     → store local variable
iconst_0..5       → int constants 0-5
ldc               → load constant from pool

if_icmpeq/ne/lt   → int comparison branch
ifnull / ifnonnull → null check
goto              → unconditional branch
```

---

## 5. Kotlin RE {#kotlin}

```bash
# Kotlin compiles to JVM bytecode → same tools as Java
# But: Kotlin generates extra metadata and sugar

# Decompile Kotlin bytecode
# cfr with Kotlin metadata support:
java -jar cfr.jar target.jar --decodekotlamdas true --decodelambdas LAMBDAS

# kotlinp: inspect Kotlin metadata
# Included in Kotlin compiler:
kotlinp ClassName.class

# Common Kotlin patterns in bytecode:
# Object singletons → INSTANCE field, <clinit> initialization
# Companion objects → inner class named Companion
# Data classes → componentN() methods, copy(), toString()
# Coroutines → state machine with LABEL field, complex switch
# Extension functions → static methods with receiver as first param
# Null safety → Intrinsics.checkNotNull() calls everywhere
```

---

## 6. JVM Bytecode Patching {#jvm-patch}

```bash
# Method 1: decompile → modify source → recompile
java -jar cfr.jar target.jar --outputdir src/
# Edit src/com/example/Target.java
javac -cp target.jar src/com/example/Target.java -d patched_classes/
# Rebuild JAR:
jar uf target.jar -C patched_classes/ .

# Method 2: bytecode editing with ASM (programmatic)
# Maven: org.ow2.asm:asm:9.x
```

```java
// ASM bytecode transformer
import org.objectweb.asm.*;
import java.io.*;

public class Patcher extends ClassVisitor {
    public Patcher(ClassVisitor cv) { super(Opcodes.ASM9, cv); }
    
    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (name.equals("checkLicense")) {
            return new MethodVisitor(Opcodes.ASM9, mv) {
                @Override
                public void visitCode() {
                    // Replace method body: always return true
                    mv.visitInsn(Opcodes.ICONST_1);  // push 1 (true)
                    mv.visitInsn(Opcodes.IRETURN);   // return int
                }
            };
        }
        return mv;
    }
    
    public static void main(String[] args) throws Exception {
        ClassReader cr = new ClassReader(new FileInputStream("Target.class"));
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        cr.accept(new Patcher(cw), 0);
        new FileOutputStream("Target_patched.class").write(cw.toByteArray());
    }
}
```

### recaf — Modern Java RE Tool
```bash
# Recaf: github.com/Col-E/Recaf
# Features:
# - Decompile + edit in GUI
# - Bytecode hex editor
# - Patching without recompiling
# - Search across entire JAR
java -jar recaf.jar
# File → Open → target.jar
# Right-click class → Edit → modify bytecode or source
# Export → save patched JAR
```

---

## 7. Runtime Hooking (Java Agents) {#java-agent}

```java
// Java Agent: inject into running JVM (like Frida for JVM)
// MANIFEST.MF must include: Premain-Class or Agent-Class

// Agent class:
import java.lang.instrument.*;
import java.security.ProtectionDomain;

public class MyAgent {
    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className,
                                    Class<?> cls, ProtectionDomain domain,
                                    byte[] classfileBuffer) {
                if (className.equals("com/example/LicenseChecker")) {
                    // Use ASM to patch classfileBuffer
                    System.out.println("[*] Patching LicenseChecker");
                    return patchClass(classfileBuffer);
                }
                return null; // no change
            }
        });
    }
}
```

```bash
# Attach agent to running JVM (dynamic attach)
java -jar agent.jar attach <pid>

# Or at startup:
java -javaagent:agent.jar -jar target.jar

# Byte Buddy (easier agent framework)
# Arthas (Alibaba): production Java diagnostics tool
java -jar arthas-boot.jar <pid>
# Inside Arthas:
# watch com.example.Class method "{params,returnObj}" -x 2  # trace method
# jad com.example.Class method  # decompile live class
# ognl "@com.example.Singleton@INSTANCE.secret"  # eval expression
# trace com.example.Class method  # trace call tree
```

---

## 8. Unity / Mono RE {#unity}

```bash
# Unity games compile to Mono or IL2CPP
# Check: look for Assembly-CSharp.dll (Mono) or GameAssembly.dll (IL2CPP)

# ===== MONO (older Unity) =====
# All game logic in: <GameName>_Data/Managed/Assembly-CSharp.dll
# Open directly in dnSpy → full C# source!
# Also check: Assembly-CSharp-firstpass.dll, plugins

dnspy Assembly-CSharp.dll   # ← everything is here, unobfuscated usually

# ===== IL2CPP (modern Unity) =====
# AOT compiled to native code → no IL to decompile
# BUT: metadata file contains type/method info

# Key files (Windows):
# GameAssembly.dll          → native code
# <GameName>_Data/il2cpp_data/Metadata/global-metadata.dat → metadata

# Il2CppDumper: reconstruct headers from metadata
Il2CppDumper.exe GameAssembly.dll global-metadata.dat output/
# Generates: dump.cs (all class/method signatures) + script.json

# Load into Ghidra:
# 1. Load GameAssembly.dll
# 2. Run Il2CppDumper ghidra script to apply names from script.json
# → All functions labeled with original C# names!

# Il2CppInspector (alternative, more features)
Il2CppInspector -i GameAssembly.dll -m global-metadata.dat \
  --cpp-compiler=MSVC --separate-namespaces -o output/

# Runtime analysis with Frida + Il2CppDumper
# frida-il2cpp-bridge: hook IL2CPP methods by class/method name
# → github.com/vfsfitvnm/frida-il2cpp-bridge
```

```javascript
// frida-il2cpp-bridge example (Unity IL2CPP)
const il2cpp = require("frida-il2cpp-bridge");

il2cpp.perform(() => {
    const MyClass = il2cpp.domain.assembly("Assembly-CSharp")
        .image.class("MyNamespace.MyClass");
    
    MyClass.method("CheckLicense").implementation = function() {
        console.log("[*] CheckLicense hooked");
        return true; // bypass
    };
    
    // Hook with args
    MyClass.method("Login").implementation = function(username, password) {
        console.log(`[*] Login("${username}", "${password}")`);
        return this.method("Login").invoke(username, password);
    };
});
```
