# Frida Scripting Reference

## Table of Contents
1. [Setup & Basics](#setup)
2. [Hooking Functions](#hooking)
3. [Memory Operations](#memory)
4. [SSL Unpinning](#ssl)
5. [Anti-Debug Bypass](#antidebug)
6. [Android Patterns](#android)
7. [iOS Patterns](#ios)
8. [RPC & Communication](#rpc)
9. [Persistence & Injection](#injection)

---

## 1. Setup & Basics {#setup}

```bash
pip install frida-tools

# List processes
frida-ps -U          # USB device (Android/iOS)
frida-ps -D <id>     # specific device
frida-ps -a          # with app names

# Attach and run script
frida -U -n <app_name> -l script.js         # attach by name
frida -U -f com.target.app -l script.js     # spawn + inject
frida -U --no-pause -f com.target.app -l script.js  # don't pause at start
frida -H 127.0.0.1:27042 -n <name> -l script.js    # remote frida server

# Interactive REPL
frida -U -n <app>

# Run script non-interactively
frida -U -n <app> --no-pause -l script.js -o output.log

# Compile TypeScript scripts
frida-compile script.ts -o _script.js
```

---

## 2. Hooking Functions {#hooking}

### Java Method Hook (Android)
```javascript
Java.perform(() => {
    // Hook instance method
    const TargetClass = Java.use("com.example.TargetClass");
    
    TargetClass.targetMethod.implementation = function(arg1, arg2) {
        console.log(`[+] targetMethod called: arg1=${arg1}, arg2=${arg2}`);
        const result = this.targetMethod(arg1, arg2); // call original
        console.log(`[+] targetMethod returned: ${result}`);
        return result;
    };

    // Hook overloaded method (specify signature)
    TargetClass.check.overload("java.lang.String", "int").implementation = function(s, i) {
        console.log(`[*] check("${s}", ${i})`);
        return true; // bypass
    };

    // Replace return value
    TargetClass.isLicensed.implementation = function() {
        return true;
    };

    // Hook constructor
    TargetClass.$init.implementation = function(arg) {
        console.log(`[*] new TargetClass(${arg})`);
        this.$init(arg); // call original constructor
    };
});
```

### Native Hook (Linux/Android/iOS)
```javascript
// Hook by export name
const funcPtr = Module.getExportByName(null, "strcmp");
Interceptor.attach(funcPtr, {
    onEnter(args) {
        this.s1 = args[0].readUtf8String();
        this.s2 = args[1].readUtf8String();
        console.log(`strcmp("${this.s1}", "${this.s2}")`);
    },
    onLeave(retval) {
        console.log(`  → ${retval.toInt32()}`);
        // retval.replace(0); // make it return 0 (equal)
    }
});

// Hook by address
Interceptor.attach(ptr("0x401234"), {
    onEnter(args) {
        console.log("hit!", this.context.rdi);
    }
});

// Replace function entirely
Interceptor.replace(ptr("0x401234"), new NativeCallback((a, b) => {
    console.log(`replaced: a=${a}, b=${b}`);
    return 1;
}, 'int', ['int', 'int']));
```

### ObjC Method Hook (iOS)
```javascript
// Hook Objective-C method
const method = ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"];
method.implementation = ObjC.implement(method, function(self, sel, request, handler) {
    const url = request.URL().absoluteString();
    console.log(`[NSURLSession] → ${url}`);
    return method.apply(this, arguments);
});

// List all methods of a class
ObjC.classes.SomeClass.$ownMethods.forEach(m => console.log(m));

// Find classes matching pattern
Object.keys(ObjC.classes)
    .filter(n => n.toLowerCase().includes("auth"))
    .forEach(n => console.log(n));
```

---

## 3. Memory Operations {#memory}

```javascript
// Read memory
ptr("0x401000").readByteArray(64);           // raw bytes
ptr("0x401000").readUtf8String();             // UTF-8
ptr("0x401000").readUtf16String();            // UTF-16
ptr("0x401000").readPointer();                // pointer value
ptr("0x401000").readU32();                    // uint32
ptr("0x401000").readS64();                    // int64

// Write memory
Memory.protect(ptr("0x401000"), 4096, 'rwx'); // make writable
ptr("0x401000").writeByteArray([0x90, 0x90]); // write bytes
ptr("0x401000").writeUtf8String("new value");
ptr("0x401000").writeU32(0x1337);

// Scan memory for pattern
Memory.scan(Process.enumerateRangesSync("r--")[0].base,
            Process.enumerateRangesSync("r--")[0].size,
            "?? ?? de ad be ef", {
    onMatch(address, size) {
        console.log(`Found at ${address}`);
    },
    onComplete() { console.log("Scan done"); }
});

// Dump memory region
const range = Process.enumerateRangesSync("r-x")[0];
const data = range.base.readByteArray(range.size);
send("dump", data);  // send to Python host

// Allocate memory
const buf = Memory.alloc(1024);
buf.writeUtf8String("injected string");
```

### Module Enumeration
```javascript
// List all loaded modules
Process.enumerateModules().forEach(m => {
    console.log(`${m.name} @ ${m.base} size=${m.size}`);
});

// Find module by name
const mod = Process.getModuleByName("libssl.so");
console.log(`base: ${mod.base}, size: ${mod.size}`);

// Enumerate exports
mod.enumerateExports().filter(e => e.name.includes("write"))
    .forEach(e => console.log(`${e.name} @ ${e.address}`));
```

---

## 4. SSL Unpinning {#ssl}

### Universal SSL Unpin Script
```javascript
// Works for OkHttp3, TrustManager, X509TrustManager, NSURLSession
// Source: based on apk-mitm / frida-universal-sslpinning-bypass

Java.perform(() => {
    // TrustManager bypass
    const TrustManager = Java.registerClass({
        name: "com.sslbypass.TrustManager",
        implements: [Java.use("javax.net.ssl.X509TrustManager")],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // OkHttp3 CertificatePinner bypass
    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function() {
                console.log("[*] CertificatePinner.check bypassed");
            };
    } catch(e) {}

    // WebView SSL bypass
    try {
        const WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
        };
    } catch(e) {}

    console.log("[+] SSL pinning bypassed");
});
```

```bash
# All-in-one SSL unpin
frida -U -f com.target.app \
  --codeshare sowdust/universal-android-ssl-pinning-bypass-2 \
  --no-pause
```

---

## 5. Anti-Debug Bypass {#antidebug}

### Linux ptrace bypass
```javascript
Interceptor.attach(Module.getExportByName(null, "ptrace"), {
    onLeave(retval) {
        retval.replace(0);  // always return "not traced"
    }
});
```

### Android isDebuggerConnected
```javascript
Java.perform(() => {
    Java.use("android.os.Debug").isDebuggerConnected
        .implementation = function() { return false; };
    
    Java.use("android.os.Debug").waitingForDebugger
        .implementation = function() { return false; };
});
```

### iOS ptrace / sysctl bypass
```javascript
["ptrace", "sysctl", "syscall"].forEach(sym => {
    const ptr = Module.findExportByName(null, sym);
    if (ptr) {
        Interceptor.attach(ptr, {
            onLeave(retval) { retval.replace(0); }
        });
    }
});
```

### Root/Jailbreak Detection Bypass (Android)
```javascript
Java.perform(() => {
    // RootBeer
    try {
        const rb = Java.use("com.scottyab.rootbeer.RootBeer");
        rb.isRooted.implementation = function() { return false; };
        rb.isRootedWithBusyBoxCheck.implementation = function() { return false; };
    } catch(e) {}

    // File existence checks
    const File = Java.use("java.io.File");
    File.exists.implementation = function() {
        const path = this.getAbsolutePath();
        if (["/su", "/sbin/su", "/system/bin/su", "/system/xbin/su",
             "Superuser.apk", "busybox"].some(p => path.includes(p))) {
            console.log(`[*] Faking not-exists for: ${path}`);
            return false;
        }
        return this.exists();
    };
});
```

---

## 6. Android Patterns {#android}

### Log All HTTP Traffic
```javascript
Java.perform(() => {
    const URL = Java.use("java.net.URL");
    URL.$init.overload("java.lang.String").implementation = function(url) {
        console.log(`[URL] ${url}`);
        return this.$init(url);
    };
});
```

### Dump Shared Preferences
```javascript
Java.perform(() => {
    const ctx = Java.use("android.app.ActivityThread")
        .currentApplication().getApplicationContext();
    const prefs = ctx.getSharedPreferences("app_prefs", 0);
    const all = prefs.getAll();
    const map = Java.cast(all, Java.use("java.util.Map"));
    const entries = map.entrySet().toArray();
    entries.forEach(e => {
        const entry = Java.cast(e, Java.use("java.util.Map$Entry"));
        console.log(`${entry.getKey()} = ${entry.getValue()}`);
    });
});
```

### Hook Crypto
```javascript
Java.perform(() => {
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(input) {
        console.log(`[Cipher.doFinal] input: ${input}`);
        const result = this.doFinal(input);
        console.log(`[Cipher.doFinal] output: ${result}`);
        return result;
    };
    
    const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String")
        .implementation = function(key, algo) {
            console.log(`[SecretKeySpec] algo=${algo} key=${key}`);
            return this.$init(key, algo);
        };
});
```

---

## 7. iOS Patterns {#ios}

### Hook NSUserDefaults
```javascript
ObjC.classes.NSUserDefaults["- objectForKey:"].implementation =
    ObjC.implement(ObjC.classes.NSUserDefaults["- objectForKey:"],
    function(self, sel, key) {
        const result = ObjC.classes.NSUserDefaults["- objectForKey:"].apply(this, arguments);
        console.log(`[NSUserDefaults] ${key} → ${result}`);
        return result;
    });
```

### Dump Keychain
```javascript
// Uses SecItemCopyMatching
const SecItemCopyMatching = new NativeFunction(
    Module.getExportByName("Security", "SecItemCopyMatching"),
    "int", ["pointer", "pointer"]
);
// Full keychain dump: use frida-ios-dump or iphone-backup-analyzer
```

---

## 8. RPC Communication {#rpc}

### Python host + Frida script
```python
import frida, sys, json

def on_message(message, data):
    if message["type"] == "send":
        print(f"[*] {message['payload']}")
    elif message["type"] == "error":
        print(f"[!] {message['stack']}")

device = frida.get_usb_device()
pid = device.spawn(["com.target.app"])
session = device.attach(pid)

with open("script.js") as f:
    script = session.create_script(f.read())

script.on("message", on_message)
script.load()
device.resume(pid)
input()  # keep alive
```

```javascript
// In script.js — send data back to Python
send({ type: "key_found", value: "secret123" });
send("dump", Memory.readByteArray(ptr("0x1000"), 256));
```

---

## 9. Persistence & Injection {#injection}

```bash
# Inject into existing process
frida -p <pid> -l script.js

# Spawn + inject
frida -U -f com.package --no-pause -l script.js

# Gadget (no jailbreak/root required)
# 1. Unpack APK with apktool
# 2. Add FridaGadget.so to lib/
# 3. Add System.loadLibrary("FridaGadget") to MainActivity
# 4. Repack + sign

# frida-gadget config.json
{
    "interaction": {
        "type": "listen",
        "address": "127.0.0.1",
        "port": 27042,
        "on_port_conflict": "fail"
    }
}
```
