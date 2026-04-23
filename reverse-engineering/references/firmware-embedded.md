# Firmware & Embedded Systems RE Reference

> **Authorized use only.** For analyzing firmware of devices you own or have
> explicit permission to inspect. All commands shown operate on local files
> (firmware images placed in the working directory by the user) or on local
> hardware. The skill does NOT instruct network download or data exfiltration.

## Table of Contents
1. [Firmware Extraction](#extraction)
2. [Binwalk](#binwalk)
3. [Filesystem Analysis](#filesystem)
4. [QEMU Emulation](#qemu)
5. [JTAG / UART / SWD](#hardware)
6. [U-Boot & Bootloaders](#uboot)
7. [ARM / MIPS / RISC-V Bare Metal](#bare)
8. [IoT Attack Surface](#iot)
9. [Firmware Diffing](#diffing)

---

## 1. Firmware Extraction {#extraction}

```bash
# From vendor website (place firmware file locally before analysis)
# Obtain firmware.bin from official vendor support page and place in working dir

# From physical device - hardware methods:
# 1. UART shell (if available)
# 2. JTAG/SWD debug interface
# 3. Flash chip reading (SPI, NAND, NOR)
# 4. JTAG boundary scan

# Read SPI flash (hardware)
# Clip onto SPI flash chip in-circuit or desolder
flashrom -p ch341a_spi -r firmware.bin     # CH341A programmer
flashrom -p linux_spi:dev=/dev/spidev0.0 -r fw.bin  # Raspberry Pi SPI

# NAND flash (on-device, shell required)
nandread -f /dev/mtd0 -o nand_dump.bin
nanddump /dev/mtd0 > nand_dump.bin

# eMMC dump (requires opening device + soldering)
# If OS accessible on device, dump to local file:
dd if=/dev/mmcblk0 of=emmc_dump.bin bs=512

# From running device with local shell — save to local file, then transfer:
cat /dev/mtdblock0 > /tmp/fw.bin
# Transfer via SSH/SCP:  scp /tmp/fw.bin user@workstation:./
```

---

## 2. Binwalk {#binwalk}

```bash
# Install
pip install binwalk
# or: apt install binwalk

# Scan firmware
binwalk firmware.bin                       # signature scan
binwalk -e firmware.bin                   # extract everything
binwalk -Me firmware.bin                  # recursive matryoshka extract
binwalk --dd='.*' firmware.bin            # extract ALL signatures

# Entropy analysis (find encrypted/compressed regions)
binwalk -E firmware.bin                   # entropy graph
binwalk -E -J firmware.bin               # JSON output

# File carving
binwalk --carve firmware.bin             # carve without full extract

# Specific searches
binwalk -y "filesystem" firmware.bin     # only filesystems
binwalk -y "certificate" firmware.bin    # TLS certs
binwalk -y "private key" firmware.bin    # private keys!
binwalk -y "password" firmware.bin

# After extraction
ls _firmware.bin.extracted/
# Common finds: squashfs, cramfs, jffs2, ext2/3/4, tar, gzip, cpio

# Mount squashfs
unsquashfs squashfs-root.bin
# or binwalk already extracted it to squashfs-root/

# Mount jffs2
modprobe mtdram total_size=65536 erase_size=256
modprobe mtdblock
dd if=jffs2.bin of=/dev/mtd0
mount -t jffs2 /dev/mtdblock0 /mnt/jffs2
```

---

## 3. Filesystem Analysis {#filesystem}

```bash
# After extraction, treat it like a Linux rootfs
ls _firmware.bin.extracted/squashfs-root/

# Key directories to audit:
# /etc/passwd, /etc/shadow    → default credentials
# /etc/config/                → config files
# /usr/sbin/, /bin/           → executables
# /lib/, /usr/lib/            → shared libraries
# /etc/ssl/                   → certificates
# /var/www/                   → web interface
# /tmp/                       → runtime data

# Find hardcoded credentials
grep -r "password\|passwd\|secret\|apikey\|token" . --include="*.conf" --include="*.json" --include="*.xml" -l
grep -rE "password\s*=\s*[\"'][^\"']{3,}" . -l

# Find SUID binaries (potential privesc)
find . -perm -4000 -type f 2>/dev/null

# Find executables
find . -type f -executable 2>/dev/null
find . -name "*.sh" -type f

# Strings all binaries
for f in $(find . -type f -executable); do
    strings "$f" | grep -qE "http://|secret|password|token" && echo "$f"
done

# Web interface analysis
find . -name "*.cgi" -o -name "*.php" -o -name "*.lua" | head -20
# Look for command injection: system(), exec(), popen()
grep -r "system\|exec\|popen\|passthru" . --include="*.cgi" --include="*.sh"
```

---

## 4. QEMU Emulation {#qemu}

```bash
# Install QEMU + cross-toolchain
apt install qemu-user-static qemu-system-arm qemu-system-mips
apt install gcc-arm-linux-gnueabihf gcc-mipsel-linux-gnu

# User-mode emulation (single binary, fast)
# ARM
qemu-arm-static -L ./squashfs-root ./squashfs-root/bin/busybox ls /

# MIPS little-endian
qemu-mipsel-static -L ./squashfs-root ./squashfs-root/usr/sbin/httpd

# With fake environment
chroot ./squashfs-root /bin/sh           # full chroot
# If missing libs:
cp /usr/bin/qemu-arm-static ./squashfs-root/usr/bin/
chroot ./squashfs-root qemu-arm-static /bin/sh

# Fix missing kernel interfaces
# Create fake /proc, /sys, /dev
mount -t proc none ./squashfs-root/proc
mount -t sysfs none ./squashfs-root/sys
mount -o bind /dev ./squashfs-root/dev

# Full system emulation (for complete firmware)
# ARM (e.g., router)
qemu-system-arm -M virt \
  -kernel zImage \
  -dtb device.dtb \
  -nographic \
  -append "root=/dev/vda console=ttyAMA0" \
  -drive file=rootfs.ext4,format=raw,id=hd \
  -device virtio-blk-device,drive=hd \
  -netdev user,id=net0,hostfwd=tcp::8080-:80 \
  -device virtio-net-device,netdev=net0

# FirmAE (automated firmware emulation)
# FirmAE — github.com/pr0v3rbs/FirmAE
git clone <FIRMAE_REPO_URL>
./run.sh -r brand firmware.bin   # emulate + check web interface

# Firmwalker (automated filesystem audit)
./firmwalker.sh ./squashfs-root/
```

---

## 5. JTAG / UART / SWD {#hardware}

### UART Discovery
```bash
# Common UART parameters: 115200 8N1
# Finding UART pads: look for 4-pin headers (VCC/TX/RX/GND)
# Use multimeter: measure voltage — TX line will show ~3.3V or 5V idle

# Connect USB-UART adapter (CP2102, CH340, PL2303)
# GND → GND, RX → TX, TX → RX (cross!)

# Connect and monitor
screen /dev/ttyUSB0 115200
minicom -D /dev/ttyUSB0 -b 115200
picocom -b 115200 /dev/ttyUSB0

# If you see garbled output: try common bauds
for baud in 9600 19200 38400 57600 115200 230400 460800 921600; do
    echo "Trying $baud..."
    timeout 3 minicom -D /dev/ttyUSB0 -b $baud | xxd | head -5
done
# Look for recognizable ASCII output

# Autodetect baud (sigrok/PulseView with logic analyzer)
```

### JTAG
```bash
# OpenOCD — universal JTAG tool
# Find JTAG pinout: use JTAGulator or UART tool + continuity testing

# OpenOCD config example (ARM Cortex-M)
cat > openocd.cfg << 'EOF'
interface ftdi
ftdi_vid_pid 0x0403 0x6010
transport select jtag
source [find target/stm32f4x.cfg]
EOF

openocd -f openocd.cfg

# In telnet session (port 4444):
telnet localhost 4444
> halt
> reg            # dump registers
> mdw 0x08000000 64   # read flash (64 words from addr)
> dump_image firmware.bin 0x08000000 0x100000  # dump 1MB flash

# GDB over OpenOCD (port 3333)
arm-none-eabi-gdb firmware.elf
(gdb) target remote :3333
(gdb) monitor reset halt
(gdb) load    # flash firmware
(gdb) continue

# SWD (simpler 2-wire version of JTAG, common on ARM Cortex)
# Same OpenOCD setup, just change transport:
transport select swd
```

---

## 6. U-Boot & Bootloaders {#uboot}

```bash
# U-Boot shell (via UART, interrupt autoboot)
# Press any key during "Hit any key to stop autoboot" message

# U-Boot commands
printenv          # all environment variables
printenv bootcmd  # what runs on boot
help              # all commands

# Dump flash via U-Boot
# Copy to RAM first, then send via TFTP or XMODEM
md 0x9F000000 0x400000    # memory display (flash base + size)
# TFTP dump:
setenv serverip 192.168.1.100
setenv ipaddr 192.168.1.200
tftpput 0x80000000 0x400000 dump.bin   # some versions

# Write TFTP-served firmware
tftpboot 0x80000000 firmware.bin
sf probe 0          # init SPI flash
sf erase 0x0 0x800000
sf write 0x80000000 0x0 0x800000

# Bypass U-Boot password (if set)
# setenv bootdelay -1 disables interrupt
# Hardware: short NAND/NOR flash DATA line to GND briefly during boot → corrupts env → default
```

---

## 7. ARM / MIPS / RISC-V Bare Metal {#bare}

### ARM Specifics
```bash
# Calling convention (ARM32 AAPCS):
# r0-r3: arguments + return value
# r4-r11: saved registers
# r12: intra-procedure scratch
# r13 (sp): stack pointer
# r14 (lr): link register (return address!)
# r15 (pc): program counter

# Thumb vs ARM mode:
# LSB of address = 1 → Thumb mode (16-bit instructions)
# LSB of address = 0 → ARM mode (32-bit)
# BX/BLX switches modes

# ARM64 (AArch64) calling convention:
# x0-x7: arguments + return values
# x8: indirect result register
# x19-x28: callee-saved
# x29 (fp): frame pointer
# x30 (lr): link register
# sp: stack pointer
# pc: program counter (not directly addressable)

# Disassemble ARM binary
arm-linux-gnueabihf-objdump -d binary
aarch64-linux-gnu-objdump -d binary

# GDB for ARM
qemu-arm-static -g 1234 ./binary &
arm-linux-gnueabihf-gdb binary
(gdb) target remote :1234
```

### MIPS Specifics
```bash
# MIPS calling convention:
# $a0-$a3: arguments
# $v0-$v1: return values
# $t0-$t9: temporaries
# $s0-$s7: saved
# $ra: return address
# $sp: stack pointer
# $gp: global pointer (important for PIC code!)
# $fp: frame pointer

# MIPS delay slots: instruction after branch ALWAYS executes
# j target → next instruction executes → THEN jumps

# Disassemble MIPS
mipsel-linux-gnu-objdump -d binary       # little-endian
mips-linux-gnu-objdump -d binary         # big-endian

# Emulate
qemu-mipsel-static ./binary
qemu-mips-static ./binary
```

---

## 8. IoT Attack Surface {#iot}

```bash
# Network service discovery
nmap -sV -p- 192.168.1.1    # scan device
nmap -sV --script=default 192.168.1.1

# Web interface
# Common: 80, 443, 8080, 8443, 8888
# Check for:
# - Command injection in ping/traceroute/diagnostics
# - Default credentials (admin:admin, admin:password, admin:1234)
# - Path traversal in file operations
# - CSRF on config changes
# - Telnet/SSH with default creds

# MQTT (IoT protocol) - port 1883
mosquitto_sub -h 192.168.1.1 -t "#" -v  # subscribe to ALL topics
mosquitto_pub -h 192.168.1.1 -t "cmd/device" -m "reboot"

# CoAP (Constrained Application Protocol) - UDP 5683
coap-client -m get coap://192.168.1.1/.well-known/core  # discover resources
coap-client -m get coap://192.168.1.1/config

# Shodan for IoT
# shodan search "port:23 router" country:ES
# Default creds DB: search "default router passwords" online

# CVE scanning
searchsploit "D-Link DIR-615"
nuclei -target <TARGET_IP> -t cves/ -t default-logins/
```

---

## 9. Firmware Diffing {#diffing}

```bash
# BinDiff (binary-level diffing, Ghidra plugin)
# Install: search "BinDiff download" — Zynamics/Google product
# Use: Ghidra → File → Export → BinExport → compare two versions

# bindiff CLI
java -jar bindiff.jar --primary old.BinExport --secondary new.BinExport --output diff.BinDiff

# Radare2 diffing
radiff2 old_firmware new_firmware        # binary diff
radiff2 -g sym.func old new              # graphical diff of function
radiff2 -C old new                       # count differences

# Diaphora (IDA/Ghidra plugin for function matching across versions)
# Great for finding patched vulnerabilities:
# Export both versions → Diaphora → shows modified functions

# Quick filesystem diff (after extraction)
diff -rq old_rootfs/ new_rootfs/ 2>/dev/null | grep -v ".pyc"

# Find patched functions (likely vuln fixes)
# Focus on: buffer handling, auth checks, network parsing
```
