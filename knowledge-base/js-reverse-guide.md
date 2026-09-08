# JS Reverse Engineering + API Discovery Guide

> Mandatory engagement step, see `../rules/engagement-guide.md` §4.1: **do not only extract `/api/` paths**. Add salts, ciphertext-id public keys, hidden/admin routes, and hardcoded demo accounts to the checklist when present; write "none" when absent. Demo accounts are keys, not a dictionary for the login form.

## Use Cases

- Page endpoints carry encrypted parameters that cannot be replayed directly with curl
- Need to discover hidden API endpoints from front-end JS
- Need to understand the signature/token generation logic in order to craft arbitrary requests
- Route tables contain hidden/admin, webpack async chunks, hardcoded demo accounts / test tenants

---

## Workflow One: API Discovery

### 1. Inspect Network Requests

With the js-reverse MCP tool (once the target page is open in the browser):

```
Action: list_network_requests()
Filter: resourceTypes=["xhr", "fetch"]
Watch for: endpoints carrying user data (/user/, /api/, /order/, /account/)
```

### 2. Batch-Extract Endpoints From JS Sources

```javascript
// Run inside evaluate_script; extracts every XHR path on the page
() => {
  const scripts = Array.from(document.querySelectorAll('script[src]'))
    .map(s => s.src);
  return scripts;
}
```

```bash
# Download all JS files, then grep endpoint paths
for url in $(cat js_files.txt); do
  curl -s "$url" | grep -oP '"(/api/[^"]+)"' | tr -d '"'
done | sort -u > discovered_apis.txt

# Keyword search
grep -E "(userId|uid|token|sign|order|payment)" discovered_apis.txt
```

### 3. Search With search_in_sources

```
search_in_sources("userId")          // find user-ID related endpoints
search_in_sources("/api/")           // find all API paths
search_in_sources("Authorization")   // find where the token is set
search_in_sources("signature")       // find signature parameters
```

---

## Workflow Two: Encrypted Parameter Analysis

Applies when requests carry encrypted parameters such as `sign` / `_token` / `x-sign`.

### Step 1: Break on XHR

```
1. break_on_xhr("/api/target-endpoint")
2. Trigger the corresponding action on the page
3. Once execution pauses: get_paused_info()
4. Inspect the call stack to locate the function that sets the encrypted parameter
```

### Step 2: Analyze the Call Stack

```
get_paused_info() example output:
  Frame 0: setRequestHeader (XMLHttpRequest)
  Frame 1: signRequest (utils.js:342)     <- look here
  Frame 2: sendApiRequest (api.js:89)
  Frame 3: onClick (page.js:234)
```

Frame 1 located, read the source:

```
get_script_source(url="utils.js", startLine=335, endLine=355)
```

### Step 3: Extract the Signing Logic

Common signature algorithm patterns:

```javascript
// Pattern 1: sort parameters + MD5
function signRequest(params) {
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  return md5(sorted + SECRET_KEY);
}

// Pattern 2: timestamp + nonce + HMAC
function sign(data) {
  const ts = Date.now();
  const nonce = Math.random().toString(36).substr(2);
  return hmacSha256(ts + nonce + JSON.stringify(data), APP_SECRET);
}

// Pattern 3: fixed salt concatenation
const sign = md5(userId + ':' + timestamp + ':' + SALT);
```

### Step 4: Execute the Signing Function in the Browser

```javascript
// Call the in-page signing function directly via evaluate_script
() => {
  // if the function lives in the global scope
  return window.signRequest({userId: "victim_id", action: "getInfo"});
}
```

### Step 5: Reimplement the Signature in Python

```python
import hashlib
import hmac
import time
import random
import string

# MD5 signature reimplementation
def sign_request(params: dict, secret_key: str) -> str:
    sorted_str = '&'.join(f"{k}={params[k]}" for k in sorted(params.keys()))
    return hashlib.md5((sorted_str + secret_key).encode()).hexdigest()

# HMAC-SHA256 signature reimplementation
def sign_hmac(data: str, app_secret: str) -> str:
    ts = str(int(time.time() * 1000))
    nonce = ''.join(random.choices(string.ascii_lowercase, k=8))
    msg = ts + nonce + data
    return hmac.new(app_secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

# Verify: the Python output should match the browser JS result
```

---

## Workflow Three: Hidden Endpoint Discovery

### Extract From Webpack Chunks

```bash
# Find chunk files
curl -s "https://target.com" | grep -oP 'chunk\.[a-z0-9]+\.js'

# Download all chunks
for chunk in $(curl -s "https://target.com" | grep -oP '"/static/js/[^"]+\.js"' | tr -d '"'); do
  curl -s "https://target.com$chunk" >> all_js.txt
done

# Extract paths
grep -oP '"(/[a-z]+){1,5}"' all_js.txt | sort -u | grep -v node_modules
```

### Extract From Route Configurations

```bash
# Vue/React route config
grep -oP 'path:\s*["\x27][^"'\'']+' all_js.txt
grep -oP '"route":\s*["\x27][^"'\'']+' all_js.txt

# Axios base URL
grep -oP 'baseURL:\s*["\x27][^"'\'']+' all_js.txt
grep -oP 'BASE_API\s*=\s*["\x27][^"'\'']+' all_js.txt
```

---

## Workflow Four: API Parameter Enumeration

Once endpoints are discovered, enumerate parameters to hunt for IDOR/injection points:

```python
import requests

# Test each discovered endpoint one by one
discovered_apis = [
    "/api/v1/user/info",
    "/api/v1/order/list",
    "/api/v2/account/profile",
]

session = requests.Session()
session.headers.update({"Authorization": "Bearer YOUR_TOKEN"})

for api in discovered_apis:
    r = session.get(f"https://target.com{api}")
    print(f"[{r.status_code}] {api} - {len(r.text)} bytes")
    if r.status_code == 200:
        # Record ID fields in the response for later IDOR tests
        data = r.json()
        print(f"  response fields: {list(data.keys()) if isinstance(data, dict) else 'array'}")
```
