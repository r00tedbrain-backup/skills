# iOS Reverse Engineering Reference

## Table of Contents
1. [IPA Triage](#triage)
2. [Mach-O Analysis](#macho)
3. [class-dump](#classdump)
4. [Frida on iOS](#frida)
5. [SSL Unpinning](#ssl)
6. [Jailbreak Detection Bypass](#jailbreak)
7. [Hopper / IDA](#disasm)
8. [Keychain & Storage](#storage)

---

## 1. IPA Triage {#triage}

```bash
# IPA is a ZIP
unzip app.ipa -d app_extracted/
cd app_extracted/Payload/App.app/

# Key files:
# Info.plist          → bundle ID, version, permissions
# <AppName>           → main Mach-O binary
# Frameworks/         → embedded frameworks
# _CodeSignature/     → code signature

# Parse Info.plist
plutil -p Info.plist
cat Info.plist | grep -A1 -E "NSCamera|NSMicro|NSContact|NSLocation"

# Binary info
file AppName
otool -h AppName       # Mach-O headers
otool -l AppName       # load commands
otool -L AppName       # linked libraries
```

### Decrypt App Store IPA (on jailbroken device)
```bash
# frida-ios-dump (automated)
python3 dump.py com.target.app

# Manual with r2frida
r2 frida://com.target.app
[0x0]> i  # binary info (decrypted in memory)
[0x0]> :dumpAll /tmp/dump/
```

---

## 2. Mach-O Analysis {#macho}

```bash
# otool (macOS built-in)
otool -tV AppName              # disassemble text section
otool -s __DATA __cfstring AppName  # CF strings
otool -l AppName | grep -A4 LC_ENCRYPTION  # encryption info
otool -l AppName | grep -A2 LC_RPATH

# nm — symbols
nm -a AppName                  # all symbols
nm -U AppName                  # undefined (imported) symbols
nm AppName | grep " T "        # exported functions

# strings
strings AppName
strings -a AppName | grep -E "http|api|key|token|secret|password"

# Fat binary (multi-arch)
lipo -info AppName             # which architectures
lipo -extract arm64 AppName -output AppName_arm64  # extract single arch

# Mach-O sections
otool -l AppName | grep -E "sectname|segname"
# __TEXT __text       → code
# __DATA __data       → initialized data
# __DATA __bss        → uninitialized
# __DATA __cfstring   → Core Foundation strings (readable!)
# __DATA __objc_methnames → ObjC method names
# __DATA __objc_classnames
```

---

## 3. class-dump {#classdump}

```bash
# Dump all ObjC class interfaces (headers)
class-dump -H -o headers/ AppName
class-dump --arch arm64 AppName

# Result: one .h file per class with all methods, properties, ivars
# Great for understanding class hierarchy without decompiler

# Alternatives for Swift:
# swift-demangle — demangle Swift symbols
swift-demangle < <(nm AppName | grep "_T")

# nm + demangle
nm AppName | grep " t " | head -30 | xargs swift-demangle
```

---

## 4. Frida on iOS {#frida}

```bash
# Requirements: jailbroken device with frida-server running as root
# Install: Cydia/Sileo → Frida

# On device:
frida-server -l 0.0.0.0   # start frida server

# From host:
frida-ps -U               # list processes
frida -U -n AppName -l script.js
frida -U -f com.bundle.id --no-pause -l script.js
```

### ObjC Method Hooks
```javascript
// Hook method
const cls = ObjC.classes.AuthManager;
const method = cls["- validateToken:"];
method.implementation = ObjC.implement(method, function(self, sel, token) {
    console.log(`[*] validateToken: ${token}`);
    return 1; // bypass → return true
});

// Hook all methods of a class
Object.keys(ObjC.classes).forEach(name => {
    if (!name.includes("Auth")) return;
    const cls = ObjC.classes[name];
    cls.$ownMethods.forEach(method => {
        const orig = cls[method];
        if (!orig) return;
        try {
            orig.implementation = ObjC.implement(orig, function() {
                console.log(`[${name} ${method}]`);
                return orig.apply(this, arguments);
            });
        } catch(e) {}
    });
});

// Find all instances of a class
ObjC.choose(ObjC.classes.NSURLRequest, {
    onMatch(req) {
        console.log(req.URL().absoluteString());
    },
    onComplete() {}
});
```

### Swift Hooks (Frida)
```javascript
// Swift functions (mangled names)
// Find mangled name: nm AppName | grep "functionName" | swift-demangle
const funcAddr = Module.findExportByName("AppName", "_$s7AppName4AuthC8validateSbSS_tF");
Interceptor.attach(funcAddr, {
    onEnter(args) {
        // args[0] = self, args[1] = selector (ObjC), or just args for Swift
        const str = ObjC.Object(args[2]).toString(); // Swift String
        console.log(`validate: ${str}`);
    },
    onLeave(retval) {
        retval.replace(1); // return true
    }
});
```

---

## 5. SSL Unpinning {#ssl}

```bash
# Quick: Frida codeshare
frida -U -f com.bundle.id --no-pause \
  --codeshare "ay-kay/ios-ssl-kill-switch"

# Or SSL Kill Switch 2 (Cydia tweak)
# After install: Settings → SSL Kill Switch → Disable cert validation
```

```javascript
// Manual Frida SSL bypass
// Hook SecTrustEvaluate
const SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
Interceptor.replace(SecTrustEvaluate, new NativeCallback((trust, result) => {
    result.writeU32(1); // kSecTrustResultProceed
    return 0;          // errSecSuccess
}, "int", ["pointer", "pointer"]));

// NSURLSession delegate bypass
ObjC.classes.NSURLSession["- URLSession:didReceiveChallenge:completionHandler:"]
    .implementation = ObjC.implement(
        ObjC.classes.NSURLSession["- URLSession:didReceiveChallenge:completionHandler:"],
        function(self, sel, session, challenge, handler) {
            const NSURLSessionAuthChallengeUseCredential = 0;
            const credential = ObjC.classes.NSURLCredential
                ["+ credentialForTrust:"].call(ObjC.classes.NSURLCredential,
                challenge.protectionSpace().serverTrust());
            handler(NSURLSessionAuthChallengeUseCredential, credential);
        });
```

---

## 6. Jailbreak Detection Bypass {#jailbreak}

```javascript
Java.perform is NOT needed for iOS — use ObjC.perform or direct hooks

// Common jailbreak file paths
const jbPaths = [
    "/Applications/Cydia.app", "/usr/sbin/sshd", "/bin/bash",
    "/etc/apt", "/private/var/lib/apt", "/usr/bin/ssh"
];

// Hook file existence checks
const fopen = Module.findExportByName(null, "fopen");
Interceptor.attach(fopen, {
    onEnter(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave(retval) {
        if (jbPaths.some(p => this.path.includes(p))) {
            retval.replace(ptr(0)); // return NULL = file not found
        }
    }
});

// NSFileManager bypass
ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation =
    ObjC.implement(ObjC.classes.NSFileManager["- fileExistsAtPath:"],
    function(self, sel, path) {
        if (jbPaths.some(p => path.toString().includes(p))) return 0;
        return ObjC.classes.NSFileManager["- fileExistsAtPath:"].apply(this, arguments);
    });

// Cydia URL scheme detection
ObjC.classes.UIApplication["- canOpenURL:"].implementation =
    ObjC.implement(ObjC.classes.UIApplication["- canOpenURL:"],
    function(self, sel, url) {
        if (url.absoluteString().toString().startsWith("cydia://")) return 0;
        return ObjC.classes.UIApplication["- canOpenURL:"].apply(this, arguments);
    });
```

---

## 7. Hopper / IDA {#disasm}

```
Hopper Disassembler (macOS-native, great for iOS):
1. File → Read Executable → select decrypted Mach-O
2. Navigate: Go to Address (Cmd+G)
3. Decompile: View → Pseudo-code of current procedure
4. Strings: View → References → string → navigate to usage
5. ObjC classes: Objective-C → Classes → browse hierarchy
6. Cross-refs: right-click symbol → References to this address
```

---

## 8. Keychain & Storage {#storage}

```bash
# On jailbroken device: dump keychain
# Keychain-Dumper
./keychain-dumper -a   # all items
./keychain-dumper -k   # keys only
./keychain-dumper -c   # certificates

# Frida keychain dump
frida -U -n AppName -l keychain_dump.js
```

```javascript
// Hook SecItemCopyMatching to intercept keychain reads
const SecItemCopyMatching = Module.findExportByName("Security", "SecItemCopyMatching");
Interceptor.attach(SecItemCopyMatching, {
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            // success — but result is in output arg (args[1])
            // use ObjC to inspect result
        }
    }
});
```

### UserDefaults / Files
```bash
# SSH into jailbroken device
ssh root@<device-ip>   # default pass: alpine

# App data location
ls /var/containers/Bundle/Application/<UUID>/
ls /var/mobile/Containers/Data/Application/<UUID>/

# UserDefaults (plist)
find / -name "*.plist" -path "*<bundle.id>*" 2>/dev/null
plutil -p /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.bundle.id.plist

# SQLite databases
find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.sqlite" -o -name "*.db"
sqlite3 app.db ".dump"
```
