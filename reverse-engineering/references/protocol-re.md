# Network Protocol Reverse Engineering Reference

## Table of Contents
1. [Traffic Capture](#capture)
2. [Protocol Inspection](#inspection)
3. [Protocol Analysis & Identification](#analysis)
4. [Binary Protocol Parsing](#binary)
5. [Encryption & TLS Analysis](#encryption)
6. [WebSocket / gRPC](#websocket)
7. [Mobile Traffic Analysis](#mobile)
8. [Custom Wireshark Dissectors](#dissector)
9. [Protocol Documentation Template](#template)
10. [Protocol Fuzzing & Validation](#fuzzing)
11. [Analysis Workflow & Best Practices](#workflow)

---

## 1. Traffic Capture {#capture}

### Wireshark / tshark
```bash
# Capture on specific interface
wireshark -i eth0 -k
wireshark -i eth0 -k -f "port 443"           # with capture filter

# tshark CLI capture
tshark -i eth0 -w capture.pcap                # basic capture
tshark -i eth0 -s 0 -w capture.pcap           # full packet (no truncation)

# Ring buffer (rotate files — ideal for continuous monitoring)
tshark -i eth0 -b filesize:100000 -b files:10 -w capture.pcap

# tshark export & field extraction
tshark -r capture.pcap -Y "http" -V                            # verbose HTTP
tshark -r capture.pcap -T json > capture.json                  # JSON export
tshark -r capture.pcap -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dport \
  -e _ws.col.Info                                              # summary fields

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0               # stream index 0

# Extract files from HTTP
tshark -r capture.pcap --export-objects http,./http_objects/

# Statistics
tshark -r capture.pcap -q -z conv,tcp                          # conversations
tshark -r capture.pcap -q -z endpoints,ip                      # endpoints
tshark -r capture.pcap -q -z io,phs                            # protocol hierarchy
```

### tcpdump
```bash
# Basic capture
tcpdump -i eth0 -w capture.pcap
tcpdump -i eth0 port 8080 -w capture.pcap     # with filter
tcpdump -i eth0 -s 0 -w capture.pcap          # full packet

# Real-time display (hex + ASCII)
tcpdump -i eth0 -X port 80
```

---

## 2. Protocol Inspection {#inspection}

### mitmproxy (HTTP/HTTPS analysis)
```bash
# Install
pip install mitmproxy

# Start proxy (port 8080)
mitmproxy                              # interactive TUI
mitmweb                                # browser-based UI
mitmdump -w traffic.mitm               # save traffic
mitmdump -r traffic.mitm               # replay/view saved

# Intercept + modify with script
mitmdump -s intercept_script.py

# Configure test device:
# HTTP proxy → your machine:8080
# Install mitmproxy CA cert on test device
```

```python
# mitmproxy intercept script — log and inspect API traffic
from mitmproxy import http

def request(flow: http.HTTPFlow):
    if "api.example.com" in flow.request.host:
        print(f"[REQ] {flow.request.method} {flow.request.url}")
        print(f"[BODY] {flow.request.content[:200]}")

def response(flow: http.HTTPFlow):
    if "api.example.com" in flow.request.host:
        print(f"[RESP] {flow.response.status_code}")
        print(f"[SIZE] {len(flow.response.content)} bytes")
```

### Burp Suite
```bash
# Start Burp → Proxy → Options → 127.0.0.1:8080
# Configure browser/device proxy
# Install PortSwigger CA cert on test device

# Key features for protocol analysis:
# Repeater: manually replay + modify requests
# Comparer: diff two responses (find changing fields)
# Decoder: base64, URL, hex decode/encode
# Logger: passive traffic log
```

---

## 3. Protocol Analysis & Identification {#analysis}

### Common Protocol Signatures
```text
Protocol    Magic / Indicator                          Detection
─────────────────────────────────────────────────────────────────
HTTP        "HTTP/1." or "GET " or "POST " at start    Plaintext
TLS/SSL     0x16 0x03 (record layer)                   First bytes
DNS         UDP port 53, specific header format         Port + structure
SMB         0xFF 0x53 0x4D 0x42 ("SMB")                Magic bytes
SSH         "SSH-2.0" banner                           Plaintext banner
FTP         "220 " response, "USER " command           Plaintext
SMTP        "220 " banner, "EHLO" command              Plaintext
MySQL       0x00 length prefix, protocol version        Structure
PostgreSQL  0x00 0x00 0x00 startup length               Structure
Redis       "*" RESP array prefix                      First byte
MongoDB     BSON documents with specific header         Structure
```

### Identify Protocol in Wireshark
```bash
# Wireshark: Analyze → Decode As → set port to known protocol
# Or: right-click packet → Decode As

# Shannon entropy of payload (detect encryption/compression)
python3 -c "
import math
data = bytes.fromhex('your_hex_payload')
freq = [0]*256
for b in data: freq[b]+=1
n=len(data)
e=-sum((f/n)*math.log2(f/n) for f in freq if f)
print(f'Entropy: {e:.2f} — ', end='')
print('Likely encrypted/compressed' if e > 7.0 else 'Plaintext/structured')
"

# Entropy thresholds:
# < 6.0  → Likely plaintext or structured data
# 6.0-7.5 → Possibly compressed
# > 7.5  → Likely encrypted or random
```

### Protocol Fingerprinting
```bash
# p0f — passive OS/app fingerprinting
p0f -i eth0

# JA3/JA3S — TLS client/server fingerprinting
tshark -r capture.pcap -Y "ssl.handshake.type == 1" \
    -T fields -e ssl.handshake.ja3                     # client fingerprint
tshark -r capture.pcap -Y "ssl.handshake.type == 2" \
    -T fields -e ssl.handshake.ja3s                    # server fingerprint

# HASSH — SSH fingerprinting
# Tool: github.com/salesforce/hassh
```

---

## 4. Binary Protocol Parsing {#binary}

### Protocol Header Patterns
```text
+--------+--------+--------+--------+
|  Magic number / Signature         |
+--------+--------+--------+--------+
|  Version       |  Flags          |
+--------+--------+--------+--------+
|  Length        |  Message Type   |
+--------+--------+--------+--------+
|  Sequence Number / Session ID     |
+--------+--------+--------+--------+
|  Payload...                       |
+--------+--------+--------+--------+

Common binary patterns:
  Length-prefixed: [4B length][payload]
  TLV:            [1B type][2B length][value]
  Fixed header:   [magic][version][type][length][checksum][payload]
```

### Python Protocol Parser (modern dataclass approach)
```python
import struct
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class MessageHeader:
    magic: bytes
    version: int
    msg_type: int
    length: int

    HEADER_SIZE = 12   # 4 + 2 + 2 + 4

    @classmethod
    def from_bytes(cls, data: bytes) -> "MessageHeader":
        magic, version, msg_type, length = struct.unpack(
            ">4sHHI", data[:cls.HEADER_SIZE]
        )
        return cls(magic, version, msg_type, length)

def parse_messages(data: bytes) -> List[Tuple[MessageHeader, bytes]]:
    """Parse a stream of length-prefixed messages."""
    offset = 0
    messages = []

    while offset + MessageHeader.HEADER_SIZE <= len(data):
        header = MessageHeader.from_bytes(data[offset:])
        payload_start = offset + MessageHeader.HEADER_SIZE
        payload = data[payload_start:payload_start + header.length]
        messages.append((header, payload))
        offset = payload_start + header.length

    return messages

# Parse TLV (Type-Length-Value) structure
def parse_tlv(data: bytes) -> List[Tuple[int, bytes]]:
    """Parse TLV-encoded fields."""
    fields = []
    offset = 0

    while offset + 3 <= len(data):
        field_type = data[offset]
        length = struct.unpack(">H", data[offset+1:offset+3])[0]
        value = data[offset+3:offset+3+length]
        fields.append((field_type, value))
        offset += 3 + length

    return fields
```

### Hex Dump Analysis
```python
def hexdump(data: bytes, width: int = 16) -> str:
    """Format binary data as hex dump for analysis."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(
            chr(b) if 32 <= b < 127 else '.'
            for b in chunk
        )
        lines.append(f'{i:08x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(lines)

# Example output:
# 00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  HTTP/1.1 200 OK.
# 00000010  0a 43 6f 6e 74 65 6e 74  2d 54 79 70 65 3a 20 74  .Content-Type: t
```

### Structure Discovery (basic struct parser)
```python
import struct

def parse_packet(data):
    """Parse a binary protocol packet with magic/type/length/payload."""
    offset = 0

    # Magic (2 bytes)
    magic = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    print(f"magic: {magic:#06x}")

    # Type (1 byte)
    msg_type = struct.unpack_from("B", data, offset)[0]
    offset += 1
    print(f"type: {msg_type}")

    # Length (4 bytes big-endian)
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    print(f"length: {length}")

    # Payload
    payload = data[offset:offset+length]
    print(f"payload ({len(payload)}): {payload.hex()}")

    return {"magic": magic, "type": msg_type, "payload": payload}

# Usage
raw = bytes.fromhex("deadbeef0100000005 68656c6c6f")
parse_packet(raw)
```

### Protocol Diffing
```python
# Compare two packets to find fields that changed between actions
p1 = bytes.fromhex("...")
p2 = bytes.fromhex("...")

for i, (a, b) in enumerate(zip(p1, p2)):
    if a != b:
        print(f"offset {i:#04x}: {a:#04x} → {b:#04x}")
```

### Protobuf Decoding (common in mobile/cloud apps)
```bash
# Detect: payload starts with 0A, 12, 1A, 22 (protobuf field tags)
# Decode without .proto file
pip install blackboxprotobuf
python3 -c "
import blackboxprotobuf
data = bytes.fromhex('your_payload')
msg, typedef = blackboxprotobuf.decode_message(data)
import json; print(json.dumps(msg, indent=2))
"

# Or: protoc --decode_raw < payload.bin
```

### Scapy for Custom Analysis
```python
from scapy.all import *

# Read pcap
packets = rdpcap("capture.pcap")

# Analyze packets
for pkt in packets:
    if pkt.haslayer(TCP):
        print(f"Src: {pkt[IP].src}:{pkt[TCP].sport}")
        print(f"Dst: {pkt[IP].dst}:{pkt[TCP].dport}")
        if pkt.haslayer(Raw):
            print(f"Data: {pkt[Raw].load[:50]}")

# Filter packets
http_packets = [p for p in packets if p.haslayer(TCP)
                and (p[TCP].sport == 80 or p[TCP].dport == 80)]
```

---

## 5. Encryption & TLS Analysis {#encryption}

### Identifying Encryption in Payloads
```python
import math
from collections import Counter

def entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0
    counter = Counter(data)
    probs = [count / len(data) for count in counter.values()]
    return -sum(p * math.log2(p) for p in probs)

# Entropy thresholds:
# < 6.0  → Likely plaintext or structured data
# 6.0-7.5 → Possibly compressed
# > 7.5  → Likely encrypted or random

# Common encryption indicators:
# - High, uniform entropy across payload
# - No obvious structure or repeating patterns
# - Length often multiple of block size (16 for AES)
# - Possible IV at start (16 bytes for AES-CBC)
```

### TLS Metadata Extraction
```bash
# Extract TLS handshake metadata
tshark -r capture.pcap -Y "ssl.handshake" \
    -T fields -e ip.src -e ssl.handshake.ciphersuite

# Certificate extraction
tshark -r capture.pcap -Y "ssl.handshake.certificate" \
    -T fields -e x509sat.printableString
```

### TLS Decryption (for authorized testing)
```bash
# Pre-master secret log (set in browser environment)
# export SSLKEYLOGFILE=/tmp/keys.log

# Configure Wireshark:
# Edit → Preferences → Protocols → TLS
# Set (Pre)-Master-Secret log filename to the key log file
# This allows decrypting captured TLS sessions for analysis
```

---

## 6. WebSocket / gRPC {#websocket}

### WebSocket
```python
# Capture: Wireshark filter → websocket
# Burp Suite: intercepts WS automatically in "WebSockets history" tab

# Python WS proxy / inspector
import asyncio, websockets, json

async def proxy(websocket, path):
    target_uri = "wss://api.example.com/ws"
    async with websockets.connect(target_uri) as target:
        async def forward_to_target():
            async for msg in websocket:
                print(f"CLIENT->SERVER: {msg[:200]}")
                await target.send(msg)
        async def forward_to_client():
            async for msg in target:
                print(f"SERVER->CLIENT: {msg[:200]}")
                await websocket.send(msg)
        await asyncio.gather(forward_to_target(), forward_to_client())

asyncio.run(websockets.serve(proxy, "127.0.0.1", 8765))
```

### gRPC
```bash
# gRPC uses HTTP/2 + Protobuf
# Capture with Wireshark: filter http2
# Decode: need .proto file or use grpc_reflection

# grpcurl — CLI gRPC client
grpcurl -plaintext localhost:50051 list              # list services
grpcurl -plaintext localhost:50051 describe          # describe all
grpcurl -plaintext -d '{"name":"test"}' localhost:50051 pkg.Service/Method

# Intercept with mitmproxy (gRPC addon)
# mitmdump --mode reverse:<local_endpoint> -p 50052 -s grpc_addon.py
```

---

## 7. Mobile Traffic Analysis {#mobile}

### Android
```bash
# Method 1: Global proxy (HTTP only)
adb shell settings put global http_proxy <YOUR_IP>:8080

# Method 2: Install CA cert for user-trusted certs
# Export DER cert from Burp/mitmproxy
adb push cert.der /sdcard/cert.cer
# Device → Settings → Security → Install cert

# Method 3: For apps targeting API 24+ (Android 7+)
# Apps must explicitly trust user CAs
# Edit network_security_config.xml to trust user CAs:
# <certificates src="user" />
# Then repack APK (see references/android-re.md)

# Method 4: Runtime certificate analysis
# See references/frida.md for runtime inspection techniques
```

### iOS
```bash
# Configure proxy: Settings → Wi-Fi → (i) → HTTP Proxy → Manual
# Host: your machine IP, Port: 8080

# Install CA: navigate to proxy CA page on test device → install profile
# Settings → General → Profile → install

# For apps with cert pinning: see references/ios-re.md for analysis techniques
```

### VPN-based (catches all traffic, including non-HTTP)
```bash
# Use VPN + transparent proxy
# Tools: ProxyDroid (Android), HTTP Catcher (iOS)

# Linux: iptables redirect (on gateway machine)
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
mitmproxy --mode transparent
```

---

## 8. Custom Wireshark Dissectors {#dissector}

### Lua Dissector (for unknown/custom protocols)
```lua
-- custom_protocol.lua
-- Usage: wireshark -X lua_script:custom_protocol.lua
local proto = Proto("custom", "Custom Protocol")

-- Define protocol fields
local f_magic   = ProtoField.string("custom.magic",   "Magic")
local f_version = ProtoField.uint16("custom.version", "Version", base.DEC)
local f_type    = ProtoField.uint16("custom.type",    "Type",    base.HEX)
local f_length  = ProtoField.uint32("custom.length",  "Length",  base.DEC)
local f_payload = ProtoField.bytes("custom.payload",  "Payload")

proto.fields = { f_magic, f_version, f_type, f_length, f_payload }

-- Message type names (customize per protocol)
local msg_types = {
    [0x0001] = "HELLO",
    [0x0002] = "HELLO_ACK",
    [0x0003] = "DATA",
    [0x0004] = "CLOSE",
    [0x0005] = "KEEPALIVE",
}

function proto.dissector(buffer, pinfo, tree)
    -- Check minimum header size (12 bytes)
    if buffer:len() < 12 then return end

    pinfo.cols.protocol = "CUSTOM"

    local subtree = tree:add(proto, buffer(), "Custom Protocol")

    -- Parse header fields
    subtree:add(f_magic,   buffer(0, 4))
    subtree:add(f_version, buffer(4, 2))

    local msg_type = buffer(6, 2):uint()
    local type_node = subtree:add(f_type, buffer(6, 2))
    local type_name = msg_types[msg_type] or "UNKNOWN"
    type_node:append_text(" (" .. type_name .. ")")

    local length = buffer(8, 4):uint()
    subtree:add(f_length, buffer(8, 4))

    -- Info column
    pinfo.cols.info = type_name .. " len=" .. length

    -- Parse payload if present
    if length > 0 and buffer:len() >= 12 + length then
        subtree:add(f_payload, buffer(12, length))
    end
end

-- Register for TCP port (customize per protocol)
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8888, proto)
```

### Heuristic Dissector (auto-detect by magic bytes)
```lua
-- Heuristic: register without specific port
local function heuristic_checker(buffer, pinfo, tree)
    -- Check magic bytes
    if buffer:len() < 4 then return false end
    if buffer(0, 4):string() ~= "PROT" then return false end

    -- Matches — call main dissector
    proto.dissector(buffer, pinfo, tree)
    return true
end

proto:register_heuristic("tcp", heuristic_checker)
```

---

## 9. Protocol Documentation Template {#template}

Use this template when documenting a reverse-engineered protocol:

```markdown
# Protocol: <NAME> Specification

## Overview
Brief description of protocol purpose, typical use case, and discovery context.

## Transport
- Layer: TCP / UDP / WebSocket
- Default Port: XXXX
- Encryption: None / TLS 1.2+ / Custom
- Byte Order: Big-endian / Little-endian

## Message Format

### Header (N bytes)
| Offset | Size | Field      | Type   | Description               |
|--------|------|------------|--------|---------------------------|
| 0      | 4    | Magic      | bytes  | 0x50524F54 ("PROT")       |
| 4      | 2    | Version    | uint16 | Protocol version (1)      |
| 6      | 2    | Type       | uint16 | Message type identifier   |
| 8      | 4    | Length     | uint32 | Payload length in bytes   |

### Message Types
| Type   | Name       | Direction       | Description              |
|--------|------------|-----------------|--------------------------|
| 0x0001 | HELLO      | Client → Server | Connection initiation    |
| 0x0002 | HELLO_ACK  | Server → Client | Connection accepted      |
| 0x0003 | DATA       | Bidirectional   | Application data         |
| 0x0004 | CLOSE      | Bidirectional   | Connection termination   |

### Type 0x0001: HELLO
| Offset | Size | Field      | Description                |
|--------|------|------------|----------------------------|
| 0      | 4    | ClientID   | Unique client identifier   |
| 4      | 2    | Flags      | Connection flags           |
| 6      | var  | Extensions | TLV-encoded extensions     |

## State Machine
    [INIT] --HELLO--> [WAIT_ACK] --HELLO_ACK--> [CONNECTED]
                                                    |
                                                DATA / DATA
                                                    |
    [CLOSED] <--CLOSE--+----------------------------+

## Example Exchange
    Client → Server: HELLO     (ClientID=0x12345678, Flags=0x00)
    Server → Client: HELLO_ACK (Status=OK, SessionID=0xABCD)
    Client → Server: DATA      (payload: "request data")
    Server → Client: DATA      (payload: "response data")
    Client → Server: CLOSE     (reason=0x00)

## Observations
- Note any quirks, undocumented fields, or version differences
- Note encryption/compression applied to payloads
- Note any timing requirements or keepalive intervals
```

---

## 10. Protocol Fuzzing & Validation {#fuzzing}

### Fuzzing with Boofuzz
```python
from boofuzz import Session, Target, TCPSocketConnection
from boofuzz import s_initialize, s_static, s_word, s_dword
from boofuzz import s_size, s_block_start, s_block_end, s_string

def fuzz_protocol():
    """Fuzz a custom protocol to validate parser robustness."""
    session = Session(
        target=Target(
            connection=TCPSocketConnection("<TARGET_IP>", 8888)
        )
    )

    # Define message structure matching protocol spec
    s_initialize("HELLO")
    s_static(b"\x50\x52\x4f\x54")       # Magic — fixed
    s_word(1, name="version", fuzzable=True)
    s_word(0x01, name="type", fuzzable=False)
    s_size("payload", length=4)          # Length field auto-calculated
    s_block_start("payload")
    s_dword(0x12345678, name="client_id")
    s_word(0, name="flags")
    s_block_end()

    # Define DATA message
    s_initialize("DATA")
    s_static(b"\x50\x52\x4f\x54")
    s_word(1, name="version")
    s_word(0x03, name="type")
    s_size("payload", length=4)
    s_block_start("payload")
    s_string("test_data", name="data", max_len=4096)
    s_block_end()

    session.connect(s_get("HELLO"))
    session.connect(s_get("HELLO"), s_get("DATA"))
    session.fuzz()

if __name__ == "__main__":
    fuzz_protocol()
```

### Replay and Modification with Scapy
```python
from scapy.all import rdpcap, send, IP, TCP, Raw

# Replay captured traffic
packets = rdpcap("capture.pcap")
for pkt in packets:
    if pkt.haslayer(TCP) and pkt[TCP].dport == 8888:
        send(pkt)

# Modify and replay (for testing protocol handling)
for pkt in packets:
    if pkt.haslayer(Raw):
        original = pkt[Raw].load
        modified = original.replace(b"v1", b"v2")     # change version string
        pkt[Raw].load = modified
        del pkt[IP].chksum                             # recalculate
        del pkt[TCP].chksum
        send(pkt)
```

### Manual Packet Crafting
```python
import socket, struct

def send_hello(host: str, port: int, client_id: int = 0x12345678):
    """Send a HELLO message to test protocol implementation."""
    # Build header
    magic = b"PROT"
    version = struct.pack(">H", 1)
    msg_type = struct.pack(">H", 0x0001)

    # Build payload
    payload = struct.pack(">I", client_id)   # ClientID
    payload += struct.pack(">H", 0x0000)     # Flags

    # Length field
    length = struct.pack(">I", len(payload))

    # Assemble and send
    packet = magic + version + msg_type + length + payload

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send(packet)
    response = sock.recv(4096)
    sock.close()

    print(f"Sent: {packet.hex()}")
    print(f"Recv: {response.hex()}")
    return response
```

---

## 11. Analysis Workflow & Best Practices {#workflow}

### Recommended Analysis Steps
```text
1. Capture traffic         → Multiple sessions, different scenarios
2. Identify boundaries     → Message start/end markers, delimiters
3. Map structure           → Fixed header vs. variable payload
4. Identify fields         → Compare multiple samples, diff changes
5. Determine encoding      → Entropy check, compression, encryption
6. Document format         → Create specification (use template above)
7. Build parser            → Python struct/dataclass implementation
8. Create dissector        → Wireshark Lua plugin for team use
9. Validate understanding  → Replay crafted packets, confirm behavior
10. Fuzz edge cases        → Boofuzz / Scapy for robustness testing
```

### Common Patterns to Look For
```text
- Magic numbers / signatures at message start
- Version fields for compatibility
- Length fields (often immediately before variable data)
- Type / opcode fields for message identification
- Sequence numbers for ordering / deduplication
- Checksums / CRCs for integrity verification
- Timestamps (unix epoch, Windows FILETIME)
- Session / connection identifiers
- Flags bitfields (usually 1-2 bytes)
- Padding / alignment bytes (often 0x00)
```

### Field Discovery Techniques
```text
Method                    What It Reveals
──────────────────────────────────────────────────────
Same action, repeated     → Fixed fields (magic, version, type)
Different actions         → Type/opcode field changes
Longer/shorter payload    → Length field correlates with size
Sequential requests       → Sequence number increments
Different sessions        → Session ID field changes
Binary diff               → Exact offset of changing fields
Entropy per field         → Encrypted vs. plaintext sections
```
