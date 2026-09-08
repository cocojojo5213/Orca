# Knowledge Base Index

Field-tested methodology / test checklists / scenario matrix. Use together with the `SKILL.md` workflows.

## Usage Conventions

- Read `quick-hits.md` first when engaging; open the matching module for details only when one matches. Open a short file in full; for very long files, open the named section first and continue if needed. Reading through this directory for every target is forbidden
- Open the dedicated section only if `*src-experience.md` exists on disk; its absence is not a gap. Opening `SKILL.md` no longer carries the group diary
- Neither the shortlist nor "injection/SSRF/XSS/RCE" is an upper bound. Run the full type matrix on the site; the four-pack is applied where a differential surface exists (to avoid empty days), it is not only these four classes, nor is it spraying `'` on every path. With a session, privilege escalation / logic are as hard-mandatory as the four-pack (`../rules/engagement-guide.md` §4.2.3)
- Convenience and capability come first; saving tokens is a side benefit and must not block opening modules
- Search by heading for techniques named in the shortlist. Fat sections that have pointers keep only the field-tested text + the pointer section; forbidden-to-open / almost-never-reported sections are already condensed to one line. Technique rows are not deleted, and success criteria are not watered down.
- In-page links already point to real files in this directory (like `idor-test.md`); do not follow `../xxx/SKILL.md` anymore
- When conflicting with `../rules/`, **the rules win** (what to hunt `../rules/what-to-hunt.md`; CORS is not hunted; report writing follows `../rules/report-format.md`)
- **`cors-test.md` / `llm-security-test.md`: not hunted / jailbreak forbidden to open.** `401-403-bypass.md` does not grind login HTML.
- Formal SRC reports: `../rules/report-format.md`

## File Listing

| File | Description |
|------|------|
| `quick-hits.md` | Hunting technique index (one line / pointer; the full text stays in each module) |
| `401-403-bypass.md` | **Forbidden: grinding login HTML** (already condensed to one line); business API 401s are tested on the spot by yourself |
| `api-gateway-test.md` | API gateway |
| `agent-tool-exec-test.md` | Real tool execution through the chat interface (not jailbreaking, not cloud IDE RPC) |
| `authbypass-test.md` | Authentication bypass (password change while logged out / IDaaS + shortlist pointers; the English dictionary has been cut) |
| `cache-poisoning-test.md` | Cache poisoning/deception (original + additions) |
| `clickjacking-test.md` | Missing headers not reported (already condensed to one line) |
| `cloud-ide-codex-rce-chain.md` | Cloud IDE/Codex family: weak credentials → RPC RCE → cluster/API key chain (the shortlist has pointers) |
| `cors-test.md` | **Not hunted, do not open** (already condensed to one line) |
| `crlf-injection-test.md` | Almost never reported (already condensed to one line) |
| `csp-bypass-test.md` | Almost never reported (already condensed to one line); XSS goes to `xss-test.md` |
| `csrf-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `csv-formula-injection-test.md` | Almost never reported (already condensed to one line) |
| `dangling-markup-test.md` | Almost never reported (already condensed to one line) |
| `dependency-confusion-test.md` | Almost never reported (already condensed to one line) |
| `deserialization-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `dns-rebinding-test.md` | Almost never reported (already condensed to one line); SSRF goes to `ssrf-test.md` |
| `el-injection-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `email-header-injection-test.md` | Almost never reported (already condensed to one line) |
| `file-upload-test.md` | File upload (pointers: STS / bucket listing / share auth, etc.) |
| `ghost-bits-cast-test.md` | Ghost Bits principle + common characters + formula; the two byte-by-byte tables have been cut |
| `graphql-test.md` | GraphQL (original + additions) |
| `hpp-test.md` | Almost never reported (already condensed to one line) |
| `http-host-header-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `http-smuggling-test.md` | Request smuggling (original + additions) |
| `http2-attacks-test.md` | Almost never reported (already condensed to one line); smuggling goes to `http-smuggling-test.md` |
| `idor-test.md` | Privilege escalation (Chinese main-line text + shortlist pointers) |
| `info-leak-test.md` | Information disclosure |
| `injection-test.md` | Injection (OR+total / email-subscription iframe / SSTI probing; the English encyclopedia has been cut) |
| `insecure-scm-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `jndi-injection-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `js-reverse-guide.md` | JS reverse engineering |
| `llm-security-test.md` | **Jailbreak material forbidden to open** (already condensed to one line); chat tools go to `agent-tool-exec-test.md` |
| `logic-test.md` | Business logic (payment/flow + merchant promo binding) |
| `oauth-jwt-test.md` | OAuth/JWT/SAML/OIDC (original + multi-source additions) |
| `open-redirect-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `path-traversal-lfi-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `prototype-pollution-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `race-condition-test.md` | Race conditions (original + additions) |
| `recon-methodology.md` | Recon methodology |
| `ssrf-test.md` | SSRF (IMDS path differentials / GOPROXY / object-storage origin fetch) |
| `subdomain-takeover-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `type-juggling-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |
| `waf-bypass.md` | WAF bypass |
| `websocket-test.md` | WebSocket (original + additions) |
| `xslt-injection-test.md` | Almost never reported (already condensed to one line) |
| `xss-test.md` | XSS (Chinese intro + obscure events + XSS→RCE / custom protocols) |
| `xxe-test.md` | Special-topic knowledge (imported from or merged with hack-skills) |

**Total: 48 knowledge files** (excluding this README). The SRC report layout is not in this library: see `../rules/report-format.md`. Severity follows only the format file; this library does not assign severity.
