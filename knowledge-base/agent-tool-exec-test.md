# Real tool execution at the chat endpoint

> Quick-hits pointer. Recognized when: the identity endpoint is blocked, the chat endpoint still accepts, and the tool list contains a tool that runs commands.  
> **Not** jailbreak / prompt injection (don't open `llm-security-test.md` as the opener).  
> **Not** cloud-IDE weak password + `command/exec` RPC (that chain is in `cloud-ide-codex-rce-chain.md`).  
> Unauthorized history reads see `idor-test.md` "Unauthorized read of another user's assistant history" (the body lives only in that doc).  
> Reporting follows `../rules/report-format.md`. Commands run only harmless markers / `id`.

## Recognize

Any of these setups:

1. Identity / whoami / profile endpoints return unauthenticated, 401, `unauthenticated` — while the same frontend's **chat endpoint** (`/chat` / `createTask` style) still accepts without a Cookie
2. **No whoami baseline, still fire**: the public page can POST-create a session with only a `message` (or similar) body

Plus: the JS or tool list contains a tool that runs commands (common names `bash` / `shell` / `code_interpreter` / `python` / `execute` — **the name list is not closed**, what counts is that it executes).

Common frontends: helix-assistant, cloud-h5, cloud assistants with a tool stream. Recognized by behavior across reskins, not pinned to a product name.

## Fire (unauthenticated)

1. If an identity endpoint exists, it must block as the baseline; no identity endpoint does not mean no bug
2. POST the chat endpoint, have the model run `id` **with that tool** (or `echo marker && id`), or compute an md5 string you can reproduce locally. Don't just ask "please execute" without naming the tool. `id` only proves a command ran — **keep following**
3. Watch the event stream / tool responses. **SSE with only deltas and no `toolName`: don't stop** — match 32-hex strings in the stream against local hashlib; or have it list the working directory and look for an `AGENT.md` / `IDENTITY.md` / `SOUL.md` never mentioned in the prompt
4. If there are `fileUrls` / attachment-URL params: fill in an external site and see whether the server pulls title/ICP back into the conversation
5. Once a command runs, follow these three (fire if there's an entry point, write down why if not): SRC's internal verification-stand flag; cloud metadata / temporary keys; other-subject business content in the sandbox (conversation history, tickets, key files). A public homepage does not count as reaching internal networks

With a session, the same shot still fires: identity passes — does the chat endpoint's tool still accept commands you craft?

## Counts as

stdout / SSE contains any of:

- SRC verification-stand flag (`ssrf-` style)
- Cloud key (temporary ticket / permanent AK/SK that can identify the account)
- Other-subject business content (not the marker you just injected)

Sandbox `uid=`, local md5, sandbox filenames never mentioned in the prompt only prove a command ran — **do not count**.

## False positives

- The model only claims it executed; numbers don't match local; sandbox filenames appear in the prompt
- Sandbox rejects commands, empty tool list
- Chat endpoint requires login too — same gate as the identity endpoint
- Only prompt jailbreak, no tool execution (that's not this shot)
- Only curls a public site (Baidu homepage / ICP number) counted as reaching internal

## Stop

No such endpoint → this shot is N/A; go back to ID-swap / password change / the other four classes.  
Endpoint exists but only yields sandbox `uid=`, nothing beyond flag / cloud key / other-subject content → disproven, stop; don't grind toward root.  
Recognized → fire **only the current site**; no all-net same-skin rescan for this.