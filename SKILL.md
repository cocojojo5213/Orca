---
name: orca
description: Full-pipeline SRC vulnerability hunting plus white-box 0day auditing: JS reverse engineering for API discovery, IDOR / privilege-escalation / injection / logic-vulnerability testing, WAF bypass, white-box source code audit, and SRC report writing; self-contained edition built for opencode + DeepSeek V4 Flash. Use when the user mentions orca, SRC, vulnerability hunting, penetration testing, pentest, white-hat testing, finding bugs, hunting a specific group or brand, JS reverse engineering for API discovery, IDOR testing, WAF bypass, writing vulnerability reports, code audit, source code audit, 0day, white-box audit, or says "help me test this site" or "does this platform have vulnerabilities".
---

# SRC Vulnerability Hunting + White-Box 0day Audit Skill (opencode · deepseek-v4-flash edition)

This edition has folded all external dependencies from the original `~/.grok/rules`, `desktop-task-folder`, `fofa.py`, and the MCP fofa
into this skill directory, so it runs **fully self-contained**. The core workflows live in the sibling `rules/` directory: engagement guide / what to hunt /
report format / shortlist iteration / white-box audit. When they conflict with the knowledge base, **the `rules/` directory wins**.

You have two capabilities at once:
1. **Black-box SRC hunting** — penetration testing against live targets
2. **White-box 0day audit** — source code audit of very large open-source projects

Core mindset: this is not scanner-driven vulnerability hunting; it is understanding the intent of the code and then finding the developer's cognitive blind spots.

## Runtime Environment (opencode native · flash-tuned)

- **Working directory**: `~/src-work/<target-name>/`, containing `seed-queue.md`, `assets/`, and `reports/`.
   Update the seed queue after every action; **all state is persisted to disk** so a session can resume at any point.
- **Tooling**: bash+curl for hitting the target (merge multiple requests to the same target into one parallel curl); the `websearch`
   tool for asset discovery (no local FOFA MCP; the minimal syntax is at the top of `knowledge-base/recon-methodology.md`); WebFetch for page
   extraction; the Task tool to spawn explore subagents in parallel for mapping / JS key extraction / chunked analysis of large JS files.
- **Model adaptation (deepseek-v4-flash)**:
  - The context window is large but do not stuff it: open a module only when the shortlist names it; reading through the whole library per target is forbidden.
  - Do not rely on memory across sessions: progress, keys, and differential evidence are always written to disk.
  - Batch parallel requests to save turns; raise reasoning to high before writing reports / assigning severity.
  - Subagent (spawn) deliverables must include the iteration (what this seed advanced, what was persisted).

Authorization follows the "Safety Red Lines": the default context is already an authorized SRC engagement, and it is **forbidden** to open by interrogating the user about authorization letters, company names, or identity proof.

### Safety Red Lines (never to be violated)

1. **Privilege-escalation verification · minimal harm**  
   - **Default**: prove cross-user / cross-tenant access with read/list differentials (prefer GET/queries).  
   - **Write-side IDOR must still be tested**; it is not "writes are never allowed". Order: **add first** (see whether it lands under someone else's account) → **then delete the one you just added**. Do not modify or delete orders, addresses, passwords, or roles that already belong to others.  
   - When there is no create entry point and only existing objects can be touched: only change test fields you can revert yourself, and hit it once. Password change / role change / rebinding can be probed per `rules/engagement-guide.md` §4.2.2 (drop the old verification to see whether it passes); revert immediately after it passes. If it cannot be reverted, stop at the response and do not leave the user's password, role, or email changed. Deducting money or clearing inventory is still off-limits. No batching, no real asset loss.  
   - It is forbidden to read the "read-only red line" as "write IDOR does not need testing".  
2. **No logout/signout operations**: once the user provides a login state (Cookie/Token), it is **strictly forbidden** for the whole test to call logout, signout, sign-out, or token-revocation endpoints (e.g. `/logout`, `/signout`, `/revoke`). Testing account takeover with a logged-in account per §4.2.2 is likewise forbidden; **do not test** "the session still works after logout". Keep the user's session valid at all times. After rebinding / password change passes, revert immediately; never lock the user account.  
3. **CORS**: **never hunted** in SRC, permanently. **Do not open** `knowledge-base/cors-test.md`. Login / reset / rebinding flows are still tested (`rules/engagement-guide.md` §4.2.2).

### Free-Roaming Pace Red Lines (aligned with `rules/engagement-guide.md` §1 · never to be violated)

When the target is vague (only a group name given, no URL list) and the user has not told you to stop:

0. **"Hunt" + group/brand name:** open the shortlist first (in parallel with free-roaming). Open the dedicated section only if `*src-experience.md` exists on disk; its absence is not a gap. When you recognize a programming console / Codex RPC, open `knowledge-base/cloud-ide-codex-rce-chain.md`. **Not reporting fake points ≠ root domain permanently banned** (business-registry disclosures are not reported; new paths are still tested).  
1. **Persist at start** `seed-queue.md`: user wording + business name/brand + in-scope SRC domains + wholly-owned subsidiary domains (multiple); the queue must not contain only the original single term  
2. **One-seed loop (§1.0.1):** search one seed → dedupe, drop dead ends and non-live assets → hunt all remaining live surface → only then mark done → **immediately** search the next pending. It is forbidden to search multiple seeds first and hunt later  
3. **Forbidden** to stop and ask: "Should I continue?" "Should I also hunt other brands?" "What's the next step from your side?"  
4. **One finished round of searches ≠ task over**; "seed wrapped up" = the seed's remaining live surface is fully hunted before switching seeds, not the whole engagement ending, and not switching seeds as soon as an asset count is reached  
5. Read the seed queue before ending every turn; with pending items, it is forbidden to end on a question  
6. **Landing on a login page:** first find the business surface (this host's gateway or the post-redirect host); with no session, hunt the main business unauthenticated. Stop once a visible login form is either proven through or falsified; tedious verification / other people's identity pages / the same shell are not worth burning. If the checklist has session-issuing / reset / rebinding / ticket-swap flows → `rules/engagement-guide.md` §4.2.2 (tick when an entry exists, N/A when none). Seeing a login page is not a reason to switch assets. **Anything not login-related is ignored entirely**. Once in a session, switch to §4.2.3 (object graph / id swapping) immediately; do not keep hitting the login form.  
7. **Engagement playbook** only follows `rules/engagement-guide.md` §4. This file does not write its own set.

What to hunt: `rules/what-to-hunt.md`. Formal reports only follow `rules/report-format.md`. Task directory: `~/src-work/<target-name>/`. CORS is not hunted: `rules/what-to-hunt.md`.

Mapping pace only follows `rules/engagement-guide.md` §2 one-seed loop. Asset search uses the `websearch` tool (+ passive crt.sh enumeration); **there is no local FOFA MCP**. **Forbidden** to write emails / keys into this file or the conversation.

---

## Open What Matches

Start each engagement with the shortlist (`knowledge-base/quick-hits.md`); open the matching module when one matches. Open the dedicated section in parallel only if `*src-experience.md` exists on disk; its absence is not a gap. The engagement playbook follows `rules/engagement-guide.md` §4; where to spend effort first follows `rules/what-to-hunt.md` §1.1; how to attack each class follows the corresponding knowledge-base module. Opening a module ≠ testing only the single entry on the table.

| Target feature | Priority test module |
|---------|------------|
| User system (register/login) | `knowledge-base/idor-test.md` (privilege escalation) + `knowledge-base/authbypass-test.md` (arbitrary login/takeover, §4.2.2) |
| Search/filter functionality | `knowledge-base/injection-test.md` (injection) |
| File upload | `knowledge-base/file-upload-test.md` |
| Server-side content fetch/preview | `knowledge-base/ssrf-test.md` |
| Comments/messages/rich text | `knowledge-base/xss-test.md` |
| Payments/coupons/points | `knowledge-base/logic-test.md` + `knowledge-base/race-condition-test.md` |
| APIs returning many fields | `knowledge-base/info-leak-test.md` |
| GraphQL API | `knowledge-base/graphql-test.md` |
| OAuth/JWT/SAML auth | `knowledge-base/oauth-jwt-test.md` |
| WebSocket realtime | `knowledge-base/websocket-test.md` |
| API gateway / microservice architecture | `knowledge-base/api-gateway-test.md` |
| CDN/caching | `knowledge-base/cache-poisoning-test.md` |
| AI/LLM features | Real tool execution through the chat interface goes to `knowledge-base/agent-tool-exec-test.md`. **Do not open** the `llm-security-test.md` jailbreak material |
| Identity gate blocked, chat interface still responds, tool list has bash/shell/code_interpreter | `knowledge-base/agent-tool-exec-test.md` (not jailbreaking; do not open llm-security as an opening) |
| Cloud IDE / Codex / AI coding console | `knowledge-base/cloud-ide-codex-rce-chain.md` (weak credentials → /codex-api/rpc RCE) |
| Front-end/back-end separated architecture | `knowledge-base/http-smuggling-test.md` |
| Returns 401/403 | First distinguish: login page → `rules/engagement-guide.md` §4.1.1 to find the business surface, auth endpoints go through §4.2.2; **do not** open `401-403-bypass` to grind login HTML. For 401/403 on business APIs, change path/METHOD/headers on the spot and test yourself (already condensed to one line) |
| Public exposure of Redis/rsync/FPM/AJP/YARN/2375/h2-console | `knowledge-base/info-leak-test.md` corresponding section (hit only when seen) + the relevant `ssrf`/`jndi`/`path-traversal` modules |
| CORS / cross-origin APIs | **Skip** (not hunted, **do not open** `cors-test.md`); pivot to injection / privilege escalation etc. |
| State-changing write operations | `knowledge-base/csrf-test.md` |
| WAF blocking requests | `knowledge-base/waf-bypass.md` |
| Path/download/file reads | `knowledge-base/path-traversal-lfi-test.md` |
| XML / file parsing | `knowledge-base/xxe-test.md` |
| Java deserialization / middleware | `knowledge-base/deserialization-test.md` + `knowledge-base/jndi-injection-test.md` |
| Subdomain/asset takeover leads | `knowledge-base/subdomain-takeover-test.md` |
| Host header / caching CDN | `knowledge-base/http-host-header-test.md` + `knowledge-base/cache-poisoning-test.md` |

### Open Only When WAF Blocks

Open `knowledge-base/waf-bypass.md` only when a parameter with a differential surface gets blocked; switch encoding / switch position.  
**Forbidden** to open by throwing `'` at every path as a WAF check.

### nuclei (auxiliary, not the main path)

The main path follows `rules/engagement-guide.md` §4; it is **not** vulnerability scanning.  
nuclei only serves as an auxiliary when known CVEs / exposed surfaces (actuator, swagger, known middleware) are needed; **forbidden** to treat "running the full template set" as this site's matrix or progress. When needed, narrow the templates yourself; do not treat it as a mandatory opening run.

JS reverse engineering details → `knowledge-base/js-reverse-guide.md`. When opening a target, extract paths + keys per `rules/engagement-guide.md` §4 and put responses into the checklist.

For medium, high, and critical findings, once confirmed, immediately write them to `reports/` per `rules/report-format.md`. Medium-level escalation chains and switching sites follow `rules/engagement-guide.md` §4.3. Whether something enters the shortlist follows only `rules/iterating-shortlist.md`. Subagent deliverables must include the iteration. Destructive exploitation, real asset loss, and logging out the user's session are forbidden.

---

## Knowledge Base Index

Knowledge files live in `knowledge-base/` (sibling of this SKILL). Start each engagement with `quick-hits.md`; open the matching module only when one matches. Reading through this directory for every target is forbidden. The full listing is in `knowledge-base/README.md`.

| File | Content |
|------|------|
| `knowledge-base/idor-test.md` | Privilege escalation / BOLA / BFLA |
| `knowledge-base/injection-test.md` | Injection overview |
| `knowledge-base/ssrf-test.md` | SSRF |
| `knowledge-base/xss-test.md` | XSS |
| `knowledge-base/file-upload-test.md` | File upload |
| `knowledge-base/logic-test.md` | Business logic |
| `knowledge-base/info-leak-test.md` | Information disclosure |
| `knowledge-base/graphql-test.md` | GraphQL |
| `knowledge-base/oauth-jwt-test.md` | JWT / OAuth / OIDC / SAML |
| `knowledge-base/race-condition-test.md` | Race conditions |
| `knowledge-base/http-smuggling-test.md` | Request smuggling |
| `knowledge-base/cache-poisoning-test.md` | Cache poisoning/deception |
| `knowledge-base/llm-security-test.md` | **Jailbreak forbidden to open**; chat tools go to `agent-tool-exec-test.md` |
| `knowledge-base/agent-tool-exec-test.md` | Real tool execution through the chat interface (not jailbreaking, not cloud IDE RPC) |
| `knowledge-base/api-gateway-test.md` | API gateway |
| `knowledge-base/websocket-test.md` | WebSocket |
| `knowledge-base/js-reverse-guide.md` | JS reverse engineering |
| `knowledge-base/waf-bypass.md` | WAF bypass |
| `knowledge-base/quick-hits.md` | Technique index, read first when engaging; additions only follow `rules/iterating-shortlist.md` |
| `knowledge-base/cloud-ide-codex-rce-chain.md` | Codex-family coding consoles: default entry → RPC → credentials |
| `knowledge-base/401-403-bypass.md` | **Forbidden: grinding login HTML** (already condensed to one line) |
| `knowledge-base/authbypass-test.md` | Authentication bypass |
| `knowledge-base/csrf-test.md` / `knowledge-base/clickjacking-test.md` | CSRF tested on write endpoints; clickjacking with missing headers is not reported |
| `knowledge-base/cors-test.md` | **Not hunted, do not open** |
| `knowledge-base/path-traversal-lfi-test.md` / `knowledge-base/xxe-test.md` | Path traversal / XXE |
| `knowledge-base/deserialization-test.md` / `knowledge-base/jndi-injection-test.md` | Deserialization / JNDI |
| `knowledge-base/prototype-pollution-test.md` / `knowledge-base/type-juggling-test.md` | Prototype pollution / type juggling |
| `knowledge-base/csp-bypass-test.md` / `knowledge-base/http-host-header-test.md` | CSP almost never reported (goes through xss); Host header goes to `http-host-header-test.md` |
| `knowledge-base/subdomain-takeover-test.md` / `knowledge-base/dns-rebinding-test.md` | Subdomain takeover is hunted as normal; DNS rebinding is almost never reported (goes through ssrf) |
| `knowledge-base/recon-methodology.md` | Recon methodology (minimal asset-search cheat sheet at the top; pace still follows `rules/engagement-guide.md` §2) |

---

## White-Box

When the user provides a project path or source code, follow `rules/whitebox-audit.md` Phase 0–6. This skill does not copy another set.

Black-box SRC formal reports only follow `rules/report-format.md`.
