# Network Protocol Reverse Engineering Reference

## Table of Contents
1. [Traffic Capture](#capture)
2. [HTTPS MITM](#mitm)
3. [Protocol Analysis](#protocol)
4. [Binary Protocol Decoding](#binary)
5. [WebSocket / gRPC](#websocket)
6. [Mobile Traffic Interception](#mobile)

---

## 1. Traffic Capture {#capture}

```bash
# Wireshark filters
ip.addr == 1.2.3.4                    # traffic to/from IP
tcp.port == 8080                       # specific port
http.request.method == "POST"          # POST requests
tcp contains "password"                # TCP with string
ssl.handshake.type == 1                # TLS Client Hello (SNI visible)
dns.qry.name contains "target"         # DNS queries

# tshark CLI
tshark -i eth0 -w capture.pcap                    # capture
tshark -r capture.pcap -Y "http" -V               # verbose HTTP
tshark -r capture.pcap -T json > capture.json     # JSON export
tshark -r capture.pcap -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport \
  -e _ws.col.Info                                 # summary fields

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0  # stream 0

# Extract files from HTTP
tshark -r capture.pcap --export-objects http,./http_objects/
```

---

## 2. HTTPS MITM {#mitm}

### mitmproxy
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

# Configure device:
# HTTP proxy → your machine:8080
# Install mitmproxy CA cert → http://mitm.it on device
```

```python
# mitmproxy intercept script
from mitmproxy import http

def request(flow: http.HTTPFlow):
    if "api.target.com" in flow.request.host:
        print(f"[REQ] {flow.request.method} {flow.request.url}")
        print(f"[BODY] {flow.request.content[:200]}")
        
        # Modify request
        # flow.request.headers["X-Custom"] = "injected"
        # flow.request.content = b'{"modified": true}'

def response(flow: http.HTTPFlow):
    if "api.target.com" in flow.request.host:
        print(f"[RESP] {flow.response.status_code}")
        # Modify response
        # flow.response.content = b'{"success": true}'
```

### Burp Suite
```bash
# Start Burp → Proxy → Options → 127.0.0.1:8080
# Configure browser/device proxy
# Install PortSwigger CA cert

# Useful Burp features:
# Repeater: manually replay + modify requests
# Intruder: fuzzing / parameter brute force
# Decoder: base64, URL, hex decode/encode
# Comparer: diff two responses
# Logger: passive traffic log
```

---

## 3. Protocol Analysis {#protocol}

### Identify Protocol
```bash
# Wireshark: Analyze → Decode As → set port to known protocol
# Or: right-click packet → Decode As

# Shannon entropy of payload
python3 -c "
import math
data = bytes.fromhex('your_hex_payload')
freq = [0]*256
for b in data: freq[b]+=1
n=len(data)
e=-sum((f/n)*math.log2(f/n) for f in freq if f)
print(f'Entropy: {e:.2f} — ', end='')
print('Encrypted/Compressed' if e > 7.0 else 'Plaintext/Structured')
"
```

### Protocol Fingerprinting
```bash
# p0f — passive OS/app fingerprinting
p0f -i eth0

# Ja3/Ja3s — TLS fingerprinting
tshark -r capture.pcap -T fields -e tls.handshake.ja3
# ja3.zone for lookup

# HASSH — SSH fingerprinting
# https://github.com/salesforce/hassh
```

---

## 4. Binary Protocol Decoding {#binary}

### Structure Discovery
```python
# Step 1: Collect multiple samples of the same message type
# Step 2: Find fixed bytes (magic, type fields)
# Step 3: Find length fields (correlate field value with payload size)
# Step 4: Map fields

# Example: analyze binary protocol packet
import struct

def parse_packet(data):
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
# Feed two packets that differ by one action → find the field that changed
p1 = bytes.fromhex("...")
p2 = bytes.fromhex("...")

for i, (a, b) in enumerate(zip(p1, p2)):
    if a != b:
        print(f"offset {i:#04x}: {a:#04x} → {b:#04x}")
```

### Protobuf (common in mobile apps)
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

---

## 5. WebSocket / gRPC {#websocket}

### WebSocket
```python
# Capture: Wireshark filter → websocket
# Burp Suite: intercepts WS automatically in "WebSockets history" tab

# Python WS proxy / inspector
import asyncio, websockets, json

async def proxy(websocket, path):
    target_uri = "wss://api.target.com/ws"
    async with websockets.connect(target_uri) as target:
        async def forward_to_target():
            async for msg in websocket:
                print(f"CLIENT→SERVER: {msg[:200]}")
                await target.send(msg)
        async def forward_to_client():
            async for msg in target:
                print(f"SERVER→CLIENT: {msg[:200]}")
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
mitmdump --mode reverse:http://localhost:50051 -p 50052 -s grpc_addon.py
```

---

## 6. Mobile Traffic Interception {#mobile}

### Android
```bash
# Method 1: Global proxy (HTTP only, no SSL)
adb shell settings put global http_proxy 192.168.1.100:8080

# Method 2: Install CA cert for user-trusted certs
# Burp/mitmproxy: export DER cert
adb push cert.der /sdcard/cert.cer
# Device → Settings → Security → Install cert

# Method 3: For apps with network_security_config (Android 7+)
# Apps must explicitly trust user CAs after API 24
# Bypass: edit network_security_config.xml to trust user CAs:
# <certificates src="user" />
# Then repack APK (see references/android-re.md)

# Method 4: Frida SSL unpin (no repack needed)
# See references/frida.md → SSL Unpinning
```

### iOS
```bash
# Configure proxy: Settings → Wi-Fi → (i) → HTTP Proxy → Manual
# Host: your machine IP, Port: 8080

# Install CA: navigate to http://mitm.it on device → install profile
# Settings → General → Profile → install

# For apps with cert pinning: Frida or SSL Kill Switch 2 (see references/ios-re.md)
```

### VPN-based (no proxy settings needed)
```bash
# Use VPN + transparent proxy (catches all traffic, including non-HTTP)
# Tools: ProxyDroid (Android), HTTP Catcher (iOS)

# Linux: iptables redirect
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
mitmproxy --mode transparent
```
