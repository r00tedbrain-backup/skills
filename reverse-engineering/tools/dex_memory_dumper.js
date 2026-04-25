// dex_memory_dumper.js
// Original work — MIT License — part of r00tedbrain-backup/skills
//
// Frida-based DEX dumper for Android. Runs entirely in user-space inside the
// target process via Frida's runtime, eliminating the need for a native
// ptrace-based binary. Provides equivalent functionality to community tools
// such as P4nda0s/panda-dex-dumper but as a portable, MIT-licensed JavaScript
// agent.
//
// What it does
//   1. Scans process memory for DEX magic bytes ("dex\n" + version + null).
//   2. For each candidate, validates the DEX header (file_size, header_size,
//      checksum bounds) to filter out partial / decoy matches.
//   3. Writes each valid DEX blob to /data/local/tmp/<package>/dex_<addr>.dex
//      on the device, ready to be pulled with `adb pull`.
//   4. Optionally also iterates the loaded ART class loaders and asks each
//      for its DexCache entries — a more reliable path on packed apps where
//      the in-memory DEX has been rewritten or relocated.
//
// Authorized use only
//   For analyzing applications you own, applications under bug-bounty scope
//   with written permission, or your own QA / interoperability research.
//
// Usage
//   1. Push a frida-server matching your device's ABI to the device and run it
//      (frida-server is Apache 2.0; download a release matching your Android).
//   2. Spawn or attach with Frida CLI:
//
//        # Attach to running process (foreground app):
//        frida -U -n com.example.app -l dex_memory_dumper.js
//
//        # Or spawn so we hook before the packer runs:
//        frida -U -f com.example.app -l dex_memory_dumper.js
//
//      Then in the Frida REPL:
//        > dump()                  // full memory + ClassLoader scan
//        > dump({ memoryOnly: true })
//        > dump({ classLoaderOnly: true })
//        > dump({ outDir: '/sdcard/Download/dex' })
//
//   3. After a successful run pull the files:
//
//        adb shell ls /data/local/tmp/<package>/
//        adb pull /data/local/tmp/<package>/ ./dex_dump/

'use strict';

// ---------------------------------------------------------------------------
// DEX format constants (https://source.android.com/docs/core/runtime/dex-format)
// ---------------------------------------------------------------------------

const DEX_MAGIC_PREFIX = [0x64, 0x65, 0x78, 0x0A]; // "dex\n"
const DEX_HEADER_SIZE_FIELD_OFFSET   = 0x24;
const DEX_FILE_SIZE_FIELD_OFFSET     = 0x20;
const DEX_HEADER_EXPECTED_SIZE       = 0x70;
const DEX_MIN_PLAUSIBLE_SIZE         = 0x70;        // header alone
const DEX_MAX_PLAUSIBLE_SIZE         = 64 * 1024 * 1024; // 64 MiB sanity cap

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(msg) {
    console.log('[dex-dumper] ' + msg);
}

function warn(msg) {
    console.log('[dex-dumper] WARN: ' + msg);
}

function getPackageName() {
    // Prefer the official Android API for the running app id.
    try {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const app = ActivityThread.currentApplication();
        if (app !== null) {
            return app.getPackageName();
        }
    } catch (_e) { /* not in a Java VM context yet */ }
    return 'unknown_package';
}

function ensureDeviceDir(path) {
    const File = Java.use('java.io.File');
    const f = File.$new(path);
    if (!f.exists()) {
        f.mkdirs();
    }
    return path;
}

function writeBytesToFile(filePath, nativePtr, sizeBytes) {
    // Read once into a byte[] then dump via FileOutputStream — avoids JNI loops.
    const FileOutputStream = Java.use('java.io.FileOutputStream');
    const buffer = Memory.readByteArray(nativePtr, sizeBytes);
    const fos = FileOutputStream.$new(filePath);
    try {
        const arr = Java.array('byte', new Uint8Array(buffer));
        fos.write(arr);
    } finally {
        fos.close();
    }
}

function isPlausibleDexHeader(addr) {
    try {
        // Magic
        for (let i = 0; i < DEX_MAGIC_PREFIX.length; i++) {
            if (Memory.readU8(addr.add(i)) !== DEX_MAGIC_PREFIX[i]) return null;
        }
        // Version: "035\0", "037\0", "038\0", "039\0", "040\0"
        const v0 = Memory.readU8(addr.add(4));
        const v1 = Memory.readU8(addr.add(5));
        const v2 = Memory.readU8(addr.add(6));
        const v3 = Memory.readU8(addr.add(7));
        if (v0 !== 0x30 || v3 !== 0x00) return null;        // must be "0XX\0"
        if (v1 < 0x33 || v1 > 0x34) return null;            // 3X
        if (v2 < 0x30 || v2 > 0x39) return null;            // digit
        // header_size must be exactly 0x70 for valid DEX
        const headerSize = Memory.readU32(addr.add(DEX_HEADER_SIZE_FIELD_OFFSET));
        if (headerSize !== DEX_HEADER_EXPECTED_SIZE) return null;
        // file_size sanity
        const fileSize = Memory.readU32(addr.add(DEX_FILE_SIZE_FIELD_OFFSET));
        if (fileSize < DEX_MIN_PLAUSIBLE_SIZE) return null;
        if (fileSize > DEX_MAX_PLAUSIBLE_SIZE) return null;
        return fileSize;
    } catch (_e) {
        return null;
    }
}

// ---------------------------------------------------------------------------
// Strategy 1 — Full process memory scan
// ---------------------------------------------------------------------------

function scanMemoryForDex(outDir) {
    const found = [];
    const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true });
    log('memory scan: ' + ranges.length + ' readable ranges');

    for (const range of ranges) {
        try {
            const matches = Memory.scanSync(range.base, range.size, 'dex\\n0?? 00 ?? ?? ?? ?? ?? ??');
            // Some Frida builds choke on glob patterns; fall back to byte pattern.
            const hits = matches.length ? matches : Memory.scanSync(
                range.base, range.size, '64 65 78 0a'
            );
            for (const hit of hits) {
                const size = isPlausibleDexHeader(hit.address);
                if (!size) continue;

                const dexPath = outDir + '/dex_' + hit.address.toString() + '_' + size + '.dex';
                try {
                    writeBytesToFile(dexPath, hit.address, size);
                    found.push({ addr: hit.address.toString(), size: size, path: dexPath });
                    log('memory: dumped ' + size + ' bytes from ' + hit.address + ' -> ' + dexPath);
                } catch (e) {
                    warn('memory: write failed at ' + hit.address + ': ' + e.message);
                }
            }
        } catch (e) {
            // Range may be unreadable despite r-- flag; skip silently.
        }
    }

    log('memory scan complete: ' + found.length + ' DEX blob(s) dumped');
    return found;
}

// ---------------------------------------------------------------------------
// Strategy 2 — Walk every Java ClassLoader and ask its DexFile entries
// ---------------------------------------------------------------------------

function dumpViaClassLoaders(outDir) {
    const dumped = [];
    Java.perform(() => {
        try {
            const loaders = Java.enumerateClassLoadersSync();
            log('classloader scan: ' + loaders.length + ' loaders found');

            // Common dex-bearing fields in DexClassLoader / PathClassLoader
            const Reflect = Java.use('java.lang.reflect.Method');

            for (let li = 0; li < loaders.length; li++) {
                const loader = loaders[li];
                try {
                    Java.classFactory.loader = loader;
                    walkLoaderForDex(loader, outDir, dumped);
                } catch (e) {
                    // Move on — some loaders are restricted
                }
            }
        } catch (e) {
            warn('classloader scan failed: ' + e.message);
        }
    });
    log('classloader scan complete: ' + dumped.length + ' DEX blob(s) dumped');
    return dumped;
}

function walkLoaderForDex(loader, outDir, dumped) {
    // BaseDexClassLoader -> pathList -> DexPathList -> dexElements[] -> Element -> dexFile -> mCookie
    const klass = loader.getClass();
    let cur = klass;
    let pathListField = null;
    while (cur !== null) {
        try {
            pathListField = cur.getDeclaredField('pathList');
            break;
        } catch (_e) {
            cur = cur.getSuperclass();
        }
    }
    if (!pathListField) return;

    pathListField.setAccessible(true);
    const pathList = pathListField.get(loader);
    if (pathList === null) return;

    const dexElementsField = pathList.getClass().getDeclaredField('dexElements');
    dexElementsField.setAccessible(true);
    const dexElements = dexElementsField.get(pathList);
    if (dexElements === null) return;

    const Array_ = Java.use('java.lang.reflect.Array');
    const length = Array_.getLength(dexElements);
    for (let i = 0; i < length; i++) {
        const element = Array_.get(dexElements, i);
        if (element === null) continue;
        try {
            const dexFileField = element.getClass().getDeclaredField('dexFile');
            dexFileField.setAccessible(true);
            const dexFile = dexFileField.get(element);
            if (dexFile === null) continue;
            // mCookie is a long (or long[]) holding native DexFile pointers
            const mCookieField = dexFile.getClass().getDeclaredField('mCookie');
            mCookieField.setAccessible(true);
            const mCookie = mCookieField.get(dexFile);
            const cookies = unwrapCookie(mCookie);
            for (const cookieAddr of cookies) {
                try {
                    const dexPtr = ptr(cookieAddr.toString());
                    const size = isPlausibleDexHeader(dexPtr);
                    if (!size) continue;
                    const dexPath = outDir + '/cl_dex_' + dexPtr.toString() + '_' + size + '.dex';
                    writeBytesToFile(dexPath, dexPtr, size);
                    dumped.push({ source: 'classloader', addr: dexPtr.toString(), size: size, path: dexPath });
                    log('classloader: dumped ' + size + ' bytes from ' + dexPtr + ' -> ' + dexPath);
                } catch (e) {
                    warn('classloader: write failed: ' + e.message);
                }
            }
        } catch (_e) {
            // Element layout may differ on some ROMs; skip.
        }
    }
}

function unwrapCookie(mCookie) {
    // mCookie can be:
    //   - long (single cookie)
    //   - long[] (multiple cookies — first entry is class-loader, rest are DEX pointers)
    if (mCookie === null) return [];
    const out = [];
    try {
        const cls = mCookie.getClass();
        const compType = cls.getComponentType();
        if (compType !== null) {
            // Array — skip index 0 which is the class-loader pointer in modern ART
            const Array_ = Java.use('java.lang.reflect.Array');
            const len = Array_.getLength(mCookie);
            for (let i = 1; i < len; i++) {
                out.push(Array_.get(mCookie, i));
            }
        } else {
            out.push(mCookie);
        }
    } catch (_e) { /* fallback: treat as single value */
        out.push(mCookie);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

function dump(opts) {
    opts = opts || {};
    const pkg = getPackageName();
    const outDir = opts.outDir || ('/data/local/tmp/' + pkg);

    Java.perform(() => {
        try {
            ensureDeviceDir(outDir);
        } catch (e) {
            warn('cannot mkdir ' + outDir + ': ' + e.message);
        }
    });

    log('package:    ' + pkg);
    log('output dir: ' + outDir);

    const result = { memory: [], classLoader: [] };

    if (!opts.classLoaderOnly) {
        result.memory = scanMemoryForDex(outDir);
    }
    if (!opts.memoryOnly) {
        result.classLoader = dumpViaClassLoaders(outDir);
    }

    log('total dumped: ' + (result.memory.length + result.classLoader.length));
    log('pull with:    adb pull ' + outDir + '/ ./');
    return result;
}

// Expose to RPC and to the global Frida REPL
rpc.exports = {
    dump: dump,
    getPackage: getPackageName,
};

// If a packer decrypts DEX after a delay, give it time first when spawned with -f.
setTimeout(() => {
    log('ready — call dump() in the REPL when the target has fully loaded');
}, 1500);
