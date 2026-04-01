# Android Reverse Engineering Reference

## Table of Contents
1. [APK Triage](#triage)
2. [jadx — Decompiler](#jadx)
3. [apktool — Smali](#apktool)
4. [ADB Forensics](#adb)
5. [Dynamic Analysis](#dynamic)
6. [Native Libraries (.so)](#native)
7. [Obfuscation & ProGuard](#obfuscation)
8. [Repackaging & Signing](#repack)

---

## 1. APK Triage {#triage}

```bash
# Basic info
file app.apk
unzip -p app.apk AndroidManifest.xml | strings   # raw manifest
aapt dump badging app.apk             # package name, version, perms
aapt dump permissions app.apk

# Full unzip (APK is a ZIP)
unzip app.apk -d app_extracted/

# Key files to inspect immediately:
# AndroidManifest.xml   → activities, perms, exported components
# META-INF/             → signing certificate
# classes.dex           → main DEX (Java bytecode)
# classes2.dex          → multidex
# lib/<abi>/            → native .so libraries
# assets/               → bundled files, config, sometimes encrypted DBs
# res/                  → resources, layouts
```

### Certificate Analysis
```bash
# Extract certificate
unzip -p app.apk META-INF/*.RSA > cert.der
openssl pkcs7 -inform DER -in cert.der -print_certs -text -noout

# Or with apksigner
apksigner verify --verbose --print-certs app.apk
keytool -printcert -jarfile app.apk
```

---

## 2. jadx — Decompiler {#jadx}

```bash
# GUI (recommended for exploration)
jadx-gui app.apk

# CLI decompile
jadx -d output/ app.apk
jadx -d output/ --no-res app.apk        # skip resources
jadx -d output/ --deobf app.apk         # deobfuscation pass
jadx -d output/ --show-bad-code app.apk # include failed decompilations

# Export Gradle project
jadx --export-gradle -d output/ app.apk
```

### jadx Navigation Strategy
```
1. Resources → AndroidManifest.xml → find all Activities, exported?
2. Source → search "BuildConfig" → find packageName, DEBUG flag, keys
3. Search text → "api_key" "secret" "password" "token" "http://"
4. Source → MainActivity → trace onCreate() flow
5. Search by usage → right-click class → "Find usages"
6. Check ProGuard mapping if available: File → Load ProGuard mappings
```

### Useful jadx Searches
```
# In jadx-gui: Ctrl+Shift+F (full text search)
- "SharedPreferences"       → stored credentials?
- "BASE64" / "encrypt"      → crypto usage
- "http://"                 → hardcoded endpoints
- "exec(" / "Runtime"       → command execution
- "WebView" + "javascript:" → JS injection surface
- "FLAG_DEBUGGABLE"         → debug checks
- "certificate" / "pinning" → SSL pinning implementation
```

---

## 3. apktool — Smali {#apktool}

```bash
# Decompile (smali + resources)
apktool d app.apk -o app_decoded/
apktool d --no-src app.apk            # resources only
apktool d --force app.apk             # overwrite existing

# Recompile
apktool b app_decoded/ -o app_recompiled.apk

# Framework management (for system APKs)
apktool if framework-res.apk
```

### Smali Cheatsheet
```smali
# Method call
invoke-virtual {v0, v1}, Lcom/example/Foo;->bar(I)V

# Return values
move-result v0          # non-object
move-result-object v0   # object

# Comparisons + branches
if-eqz v0, :cond_0     # if v0 == 0 goto cond_0
if-nez v0, :cond_0     # if v0 != 0
if-gtz v0, :cond_0     # if v0 > 0

# Useful patches:
# Force method to return true:
const/4 v0, 0x1
return v0

# NOP a check (skip a branch):
nop
nop  # (replace if-* with nops)

# Return false:
const/4 v0, 0x0
return v0
```

### Common Smali Patches
```bash
# 1. Find the check in smali
grep -r "isRooted\|checkLicense\|isPremium" app_decoded/smali/

# 2. Edit .smali file:
#    Find method, change if-eqz to if-nez or force return value

# 3. Rebuild + sign
apktool b app_decoded/ -o patched.apk
```

---

## 4. ADB Forensics {#adb}

```bash
# Device info
adb devices
adb shell getprop ro.build.version.release   # Android version
adb shell getprop ro.product.cpu.abi         # arch

# App info
adb shell pm list packages -f | grep target  # package + APK path
adb shell pm path com.target.app             # APK location
adb pull /data/app/com.target.app.../base.apk .  # pull APK

# App data (requires root or adb backup)
adb shell run-as com.target.app ls /data/data/com.target.app/
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml
adb shell run-as com.target.app ls /data/data/com.target.app/databases/

# Pull database
adb shell run-as com.target.app cp databases/app.db /sdcard/
adb pull /sdcard/app.db .
sqlite3 app.db ".dump"

# Logcat
adb logcat | grep "com.target.app"
adb logcat -s ActivityManager,DEBUG
adb logcat -b crash                          # crash buffer

# Shell
adb shell
su                                           # root shell (if rooted)

# Port forward (for Frida)
adb forward tcp:27042 tcp:27042

# Capture traffic
adb shell tcpdump -i any -w /sdcard/capture.pcap
adb pull /sdcard/capture.pcap .

# Install / uninstall
adb install app.apk
adb install -r app.apk                      # reinstall keeping data
adb uninstall com.target.app
```

### Content Provider Enumeration
```bash
adb shell content query --uri content://com.target.app.provider/table
adb shell content insert --uri content://... --bind col:TYPE:val
```

---

## 5. Dynamic Analysis {#dynamic}

### Frida (see references/frida.md for full patterns)
```bash
# Quick hook all network calls
frida -U -f com.target.app --no-pause \
  --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida

# Trace all Java methods in package
frida-trace -U -j "com.target.app!*" -f com.target.app

# Trace native functions
frida-trace -U -i "strcmp" -i "strncmp" -f com.target.app
```

### Objection (Frida-based toolkit)
```bash
pip install objection

objection -g com.target.app explore

# Inside objection REPL:
android hooking list classes
android hooking list class_methods com.target.app.Auth
android hooking watch class com.target.app.Auth         # hook all methods
android hooking watch method com.target.app.Auth.check  # specific method
android intent launch_activity com.target.app.MainActivity
android sslpinning disable
android root disable
android clipboard monitor
android keystore list
memory search --string "password"
memory dump all /tmp/dump.bin
```

---

## 6. Native Libraries {#native}

```bash
# Quick triage of .so
file lib/arm64-v8a/libnative.so
nm -D lib/arm64-v8a/libnative.so        # exported symbols
strings lib/arm64-v8a/libnative.so | grep -E "http|key|pass"
readelf -d lib/arm64-v8a/libnative.so   # dependencies

# JNI function naming convention
# Java_com_example_ClassName_methodName
nm -D libnative.so | grep "^Java_"

# Decompile with Ghidra or r2
r2 -A lib/arm64-v8a/libnative.so
afl~Java_          # list all JNI exports

# Load into Ghidra
# 1. File → Import → select .so
# 2. Analysis → Auto-analyze
# 3. Symbol Tree → Exports → find Java_* functions
```

### JNI Reverse Engineering
```c
// JNI function signature always:
JNIEXPORT <RetType> JNICALL Java_pkg_Class_method(
    JNIEnv *env,
    jobject thiz,  // or jclass for static
    <args>...
);

// Common JNI ops to recognize in decompiler:
(*env)->NewStringUTF(env, "string")      // create Java string
(*env)->GetStringUTFChars(env, str, 0)   // read Java string
(*env)->CallObjectMethod(...)            // call Java method from native
(*env)->FindClass(env, "com/example/X")  // find Java class
(*env)->GetMethodID(...)                 // get method handle
```

---

## 7. Obfuscation & ProGuard {#obfuscation}

```bash
# Check if obfuscated (short class/method names → yes)
jadx -d output/ app.apk
ls output/sources/   # classes named a.java, b.java → obfuscated

# Deobfuscation with mapping file (if available)
jadx --deobf --deobf-min 3 --deobf-max 64 -d output/ app.apk

# Load ProGuard map in jadx-gui:
# File → Load ProGuard mappings → mapping.txt

# Without map: manual rename strategy
# 1. Identify key classes by their behavior, not name
# 2. Start from AndroidManifest → MainActivity → rename as you understand
# 3. Use string constants to identify purpose
# 4. Cross-reference: who calls this method?

# Common ProGuard patterns:
# a.a.a.a → namespace.class.method → trace through
# Classes with <clinit> initializing long byte arrays → likely encrypted strings
```

### String Decryption
```javascript
// Frida: hook the decryption method and log results
Java.perform(() => {
    // Find the obfuscated decryptor (usually called from static initializer)
    // Look for: class with static method taking int/string returning string
    const Obf = Java.use("a.b.c");  // obfuscated class name
    Obf["a"].implementation = function(idx) {
        const result = this["a"](idx);
        console.log(`decrypt(${idx}) → "${result}"`);
        return result;
    };
});
```

---

## 8. Repackaging & Signing {#repack}

```bash
# 1. Decompile
apktool d app.apk -o app_mod/

# 2. Make changes (patch smali, add permissions, etc.)

# 3. Recompile
apktool b app_mod/ -o app_modded.apk

# 4. Generate keystore (first time)
keytool -genkey -v -keystore my.keystore \
  -alias mykey -keyalg RSA -keysize 2048 \
  -validity 10000

# 5. Sign
# Method A: apksigner (recommended)
apksigner sign --ks my.keystore --ks-key-alias mykey \
  --ks-pass pass:mypassword app_modded.apk

# Method B: jarsigner + zipalign
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
  -keystore my.keystore app_modded.apk mykey
zipalign -v 4 app_modded.apk app_final.apk

# 6. Verify
apksigner verify app_final.apk

# 7. Install
adb install app_final.apk
```
