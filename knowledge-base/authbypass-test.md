# authbypass-authentication-flaws

Landing page is a login / SSO → the form shell follows `../rules/engagement-guide.md` §4.1.1: find the business surface; don't run this doc from the top with dictionaries / captchas / unlimited password attempts.  
Session-issuing, reset, rebinding, ticket-swap, and 2FA are fired per this doc + `../rules/engagement-guide.md` §4.2.2; don't skip the whole stance because of §4.1.1. The table is the per-site floor, not the only shots allowed.  
Middleware bare default ports get one glance. Slider / code-send / password attempts that don't enter an account → pivot to the auth chain, don't stop halfway. Reporting follows `../rules/report-format.md`.  
English dictionaries / 20 captcha tricks / reset matrices were cut; quick-hits pointers — search by heading. Host-poisoned reset see `http-host-header-test.md`. QR-login CSRF see `csrf-test.md` §18.

# Authentication Bypass

### Unauthenticated password-change endpoint

Recognize: password change / first-set / final reset step reachable unauthenticated. Body commonly has an old-password or verification-code field (`old_pwd` / `sms_code` style) + new password + identity id. The official page says SMS/old-password required — the API may still accept an empty string.

Fire: unauthenticated. Empty or omit the old-password/verification field, new password passes complexity. Baseline: a wrong verification code must block; a nonexistent identity id must query empty. Firing the same password again and getting "duplicate of historical password" = already written to DB, not a hollow success. Revert immediately after it passes; if it cannot be reverted, stop — don't switch to other users, don't log in.

Counts: unauthenticated Success, changed someone else's password.

False positives: only returns 0 without writing; real old password / real SMS required; Success but login goes through a different IdP and the password didn't carry over.

### IDaaS unoccupied security-question slot

Recognize: IDaaS forgot-password. Anonymous username submission issues a JWT with `scope` `_` (not reset). Security-question ids are enumerable; writing an id already bound to the account returns 409. Common IDaaS skin path: `forget_password/v2/sq`; reskins of the same shape still fire.

Fire:

1. Unauthenticated POST sq, body `{"username":"admin"}` (or an account confirmed via an existence endpoint).
2. With the token GET question, note the already-bound ids.
3. POST `update_question` writing the answer to an **unoccupied** id (don't force-write a bound id).
4. `verifyquestions?type=RESET_PASSWORD` with three self-written questions, swap to `self.password.expired.reset`.
5. `set_password`: revert immediately after it passes; if it can't be reverted, stop at the response — don't leave the admin password changed. Policy rejects and the security question didn't write → half-result, doesn't count as a break-through row in quick-hits.

Counts: security-question answer written onto someone else's account (rebinding), or the token really changed someone else's password.

False positives: sq token directly set_password returns `scope is not expected`; only occupied ids writeable → 409; verify wrong answer; policy rejects and the question didn't write. Missing on one site doesn't delete the quick-hits row.

### Unauthenticated training binding endpoint (quick-hits has a pointer)

Recognize: training / academy H5 gateway puts account-binding and query RPCs under an unauthenticated client prefix (`/spapi/v2/client/` style). Body eats C-side uid (`mtUserId`) + merchant number (`bAccountId`), no Cookie.

Fire (unauthenticated):

1. POST bind: uid swapped to someone else, merchant number self-invented
2. POST querybind: uid only or merchant number only

Counts: returns the other party's phone, or binding succeeded = rebinding.

False positives: only unauthenticated/param-error responses; uid never bound to a phone and won't write. Missing on one site doesn't delete the quick-hits row. Key values and one-off phone numbers don't go into the library.

### Federated login eats only uin (quick-hits has a pointer)

Recognize: cloud activity / hackathon / partner portal signing endpoint whose body is only `provider` + cloud-account `uin` (or similar uid), no OAuth `code` / `ticket` / `id_token` validation. A public roster or by-code can reveal other people's UINs.

Fire (unauthenticated):

1. Copy a `uin` from the public partner/user roster, or hit by-code first
2. `POST` the signing endpoint with only `provider` + the other party's `uin`
3. Use the JWT against `me` / user info

Counts: me is the **other party's** UIN — usable as that account. Only guest empty accounts → not achieved.

False positives: real OAuth code required; unregistered uin rejected outright; ticket issued but me is still yourself. Missing on one site doesn't delete the quick-hits row. Key values and one-off JWTs don't go into the library.

### Activity-lab login doesn't validate the interconnect ticket (quick-hits has a pointer)

Recognize: activity page login eats interconnect `openid`+`acctype`+`access_token`, and the server **doesn't go validate** the ticket against the interconnect. Baseline gate: same params with `acctype=wx` or an empty `access_token` fail login; `acctype=qq`/`qc`/`pt` with a fake token still issues. Not the empty-password/omit generic shot, not the cloud-activity-eats-uin shot. Frontend `fx_act_helper.js` / Milo login helper is a common shell; no such name — still fire.

Fire (unauthenticated):

1. POST `/api/login` (activity prefix follows the page, don't pin one path), `access_token` = fake value, `acctype` = qq (one shot each for qc/pt), `openid` = enumerable value
2. Use the JWT against getRoles (per server) / bindRole-style role endpoints. Baseline: no header → should require login; wx/empty ticket → should fail
3. Empty role list isn't no-bug — switch server, switch neighbor ids; follow the bind endpoint until it binds. Revert what can be reverted after it passes

Counts: ticket contains the other party's openid, role list shows their character names/`charac_no`, or you can bind on.

False positives: only issues empty accounts with an empty role list that can't bind a game character; real interconnect ticket required. Key values and one-off JWTs don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Session ticket in ops-config deep link (quick-hits has a pointer)

Recognize: homepage / ops-config JSON reachable unauthenticated, whose banner jump URLs (skipPath / jumpUrl / schema) carry a `token` / `apptoken` / `access_token` string usable as a session. Baseline gate: hitting me without this string should be login-expired.

Fire (unauthenticated):

1. Copy the whole jump URL from config, put the query ticket into the Token / Authorization header
2. Hit me / user info / wallet
3. Baseline: same endpoint without the string → expired

Counts: me is someone else's phone/role — the session works as that account.

False positives: ticket expired or a placeholder that can't log in; config only carries ops copy without a ticket. Key values don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Sign-verification failure 302 leaks the computed signature (quick-hits has a pointer)

Recognize: payment/open gateway envelope has `sign_data`/`sign` + merchant number. With a fake signature, **GET / DELETE / OPTIONS / HEAD may all 302**, with the Location or `msg` carrying the server-computed valid signature (`calculateSign is:` style). Some gateways only return HTML/ILLEGAL_SIGN on GET and leak on a different METHOD; some **GET itself 302-leaks the signature** — don't only check DELETE/OPTIONS.

Fire (unauthenticated):

1. Fake-signed call to the sign/order endpoint — **GET first, look at Location** for `calculateSign`
2. If GET carries nothing, switch to DELETE/OPTIONS/HEAD, decode the signature from the Location URL
3. Put it back into `sign_data` and hit query/orders. Baseline: fake signature still fails, real signature returns the other merchant's orders

Counts: signed queries reveal **another merchant's** unpublished orders/account content (amount, close reason, card type).

False positives: every METHOD only reports verification failure with no computed signature; copying it back still rejects. Key values don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Identity-provider proxying error echo leaks token (quick-hits has a pointer)

Recognize: a business endpoint proxies calls to the identity provider for the frontend. Three common skins: ① mini-program code / jump-code endpoint where you control `path`/`page`/`pagepath`, and on an illegal page the message **echoes back** `access_token=` verbatim; ② QQ/OAuth ticket-swap endpoint splices `client_secret` into the upstream URL — change `redirect_uri` to an external domain so the downstream 5xx's, and the error URL throws `client_secret=` to the frontend; ③ an unauthenticated business endpoint `GET /api/business/access-token` (or similar ticket path) directly 200-issues, no need to wait for an error echo. A fake code against the local-domain callback usually only returns a business error code without the key — **don't stop**. If the checklist has a ticket endpoint, don't only hit the code-issuing one.

Fire (unauthenticated):

1. If the checklist has a ticket endpoint, GET it first — a 200 with `data` = `access_token` is already the copy, no need for the illegal-pagepath route
2. No ticket endpoint: fill path with an external site or an obviously illegal page; for the swap endpoint first do fake-code + local-domain `redirect_uri` as baseline
3. For the swap endpoint, change `redirect_uri` to an external domain, copy `access_token=` or `client_secret=` from the error URL/message
4. Identity ticket → `identity-provider API/cgi-bin/account/getaccountbasicinfo`, then `/wxa/generatescheme`; QQ AppSecret → exchange an authorization code for that app's access_token / hit this site's swap endpoint

Counts: can query the official account subject/appid, or issue an official jump code; or a full AppSecret that exchanges into that app's access_token.

False positives: error only has ErrCode without token/secret; fake code against local-domain callback doesn't carry the key; token fails against the identity API; secret can't swap a ticket. Key values don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Activation-page RPC hands out signKey (quick-hits has a pointer)

Recognize: payment UISDK / activation page. Unauthenticated hit on a config or thrift endpoint with body containing only enumerable `appId`. Dead app → `APP_NOT_FOUND` with no key; live app returns full `signKey`/`signMethod`. Not the doc/webpack hardcoded shot (that's the next section).

Fire (unauthenticated):

1. Swap `appId`. Baseline: dead id should have no key
2. Copy the live `signKey`, sign on the spot per the returned `signMethod` (commonly MD5, params joined dictionary-order with `&key=`)
3. Hit payment query. Baseline: fake key → `SIGN_ERROR`, real key passes
4. Passing the signature isn't the end: hit settlement-card change `change/card` — bank-branch-number differential yields `changeId`, original value reporting "no change" is proof of write. SUCCESS with `changeId=null` / unchanged rate doesn't count. Revert immediately after it passes

Counts: full AppSecret with the real key passing production verification; or reads another merchant's ID card/card/pending orders; or creates a virtual-store poiId; or changes another merchant's settlement card / bank (with `changeId` valued).

False positives: returned placeholder key fails verification; dead or alive both `APP_NOT_FOUND` with no key. Key values don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Debug docs with hardcoded AppSecret (quick-hits has a pointer)

Recognize: docs / Demo / official packages / integration HTML / historical npm packages hardcode the **full** AppSecret (appId+appSecret, signKey, merchant pfx, SDK keys) — not `your-secret` / `YOUR_ACCESS_KEY` placeholders. **Wiki masks the key with asterisks but the same official zip / Demo / HTML sample is still plaintext — don't stop. Old npm versions aren't "taken down".** Common skins: debug guide `config.js`, FAQ-linked GitHub `properties`, docs-operation screenshot PNGs, `prod/config.properties` / Demo Java `baseInfo` inside SDK zips, `MSDKConfig.json` in integration HTML, public npm `index.js`. Nearby there's a ticket-swap endpoint or a production endpoint that signs per the docs. The algorithm is in the fire section below; not pinned to one product.

Fire (unauthenticated):

1. Copy appId/accessKey, appSecret/secretKey from docs, FAQ-linked GitHub, **or the operation screenshots in the docs pages** (real values go into the report only, not this library). OCR/look at the screenshot — don't stop at config.js
1b. Enterprise IM / open address-book: after ticket swap, `user/get` or `user/list` mobile being an empty string **isn't a stop** — hit `linkedcorp/user/get` (body `userid`). Baseline: address-book endpoint has no phone, interconnect-enterprise endpoint returns an 11-digit phone — that's the escalation
2. Ticket-swap endpoint: fill code with a fake string. Baseline: replacing the secret with an equal-length fake gives "business param illegal"; the real secret gives "authorization code expired / invalid code". If this site has no `/proxy` and the swap endpoint on another business domain isn't in scope, same-product standalone oauth `/oauth/v2/token` directly POSTs `grant_type=client_credentials` (fake key → `invalid_client`)
3. Distribution/open query endpoint: HMAC per the docs (keys lowercased, dictionary-ordered concat; include integration params like `test=test` if present). Baseline: fake secret fails signing, real key returns the supply roster under that app
4. Official CLI debug/formal package endpoints (`package/changeDebugVersion`, `changeVersion` style). Baseline: fake key → "key error"; real key passing auth to "game package resource not found" also proves the key is alive — don't stop at not having uploaded a real package. **The package-change endpoint isn't only upload/version-swap** — WASM subpackage `packageBind` / `build` / `queryBuildResult` also fire; fake key → key error, real key binding under that app's name is a write
5. Gateway with a server-side IP whitelist: try `X-Forwarded-For: 127.0.0.1`. Without the header → no access; with it, the real key returns the supply
6. After supply queries pass the signature, don't stop at the roster: hit the pre-order check, get the real sell/settle price, then booking. Baseline: fake key → signature failure. Cancel the order number immediately after placing it; if it can't be reverted, stop at the response. No batch real orders
7. GitHub/SDK public demo RSA+3DES: if the production XML pay-gate still accepts it, sign `POST /service/query` on the spot and decrypt the returned ciphertext. Baseline: fake key fails verification. Neighbor ids sharing the same demo RSA returning a business error (wrong order number) is not a verification failure — the key is still alive. No real orders/refunds
8. Open-docs object storage with a pre-signed oversized SDK zip: unpack `prod/config.properties` (and the state-secret config) + pfx, open the cert with the config password, copy merchant number/signKey to hit **production order query**. Baseline: fake key → SIGN_ERROR. Query only, no real transfers
9. Game MSDK: with wiki encode=2, `sig=md5(msdkKey+timestamp)` (no path/body binding, no time window) signs production/test `/auth/*` on the spot. Baseline: fake sig → `sig error`; a real sig passing the gate into identity-provider `access_token expired` / hand-Q `0x711`-style business errors also proves the key alive — don't treat it as no bug. V3 `/auth/guest_register`: a plaintext-uuid `reqid` returns `decrypt faild`; use the **first 16 ASCII bytes** of msdkKey as the QQ TEA key (16 rounds, big-endian `oi_symmetry_encrypt2`), hex it; with the opened guestid hit `/auth/guest_check_token`. No valid player social token → stop; no grinding logins to enter accounts
10. Official integration HTML sample `MSDKConfig.json` with plaintext `MSDK_SDK_KEY`: with `source=0`, `sig=md5(path+"?"+dictionary-order query excluding sig+body+key)`; decrypt uses `md5(ts+ciphertext+key)` (the doc-sample ts/ciphertext/sign matching is what you take to production). Baseline: fake sig → `invalid sig`; real sig past the gate → guest login where `channel_info` only carries a self-invented uuid still issues openid/token/jwt = user ticket. No grinding channel codes to enter other people's accounts
11. Historical npm package with hardcoded `developerId`+`signKey`: cooperative-center gateway with a fake signature returns "signature error" on live accounts and "developer data abnormal" on dead ones — live accounts enumerable. Real sig `sign=SHA1(signKey+key-sorted key+value)`. The privacy-number bulk-pull endpoint also returns `OP_SUCCESS` without the store `appAuthToken`; ticket-swap with a real sig passing into "onboarding status incorrect" also proves the key alive. Empty array is not a false positive (no current downgrade orders). **Don't stop**: a newer npm version of the same suite hardcoding `appAuthToken` isn't an integration leftover — take the token, sign `queryPoiInfo` on the spot, swap `ePoiId` to get another merchant's store name + 11-digit phone. No real orders / no grinding auth codes
12. Recharge / enterprise-payment Demo HTML (`enterprise_client` style) with AppId+AppKey hardcoded in input boxes: don't treat as integration placeholders. Copy them unauthenticated; HMAC-SHA1 source string `GET&urlencode(path)&urlencode(key-sorted kv)`, key = `AppKey+'&'`, Base64 → sig. Baseline: fake sig → `sig error`. Real sig against production `/v1/r/{appid}/open_order` returns `token_id`. Only unpaid orders, no cashier payment / refunds. Real values only go into the report
13. Login-page JS writing DingTalk ISV `suiteKey`+`suiteSecret` as `clientId`/`clientSecret` (values starting `suited`): don't treat as OAuth placeholders. Unauthenticated POST `https://oapi.dingtalk.com/service/get_suite_token` with a fake `suite_ticket`. Baseline: fake secret → "illegal suite key or secret". Real key returns `suite_access_token`. Real values only go into the report
14. Console webpack/Vuex default map keys: don't treat as placeholders. After the fake-key baseline, don't only do reverse-geocoding: hit location-cloud / layer `table/list`, then `data/list` if tables exist. Only reverse-geocoding works with empty tables → false positive. Real values only go into the report
15. Official docs / integration HTML sample curl with hardcoded Gamekey: don't treat as a placeholder. Copy AppID+Gamekey unauthenticated, `sign=md5(mod,func,appid,time,postdata,key)` signs the production queueing gateway `getZoneListCount` on the spot. Baseline: fake key → `req sign error`. Real sig → `ret=0` with server/zone online counts. Query online/queue only; no queue insertion, no kicking players. Real values only go into the report

Counts: the key is alive — exchanges into that app's user ticket, or the business query returns the supply roster under that app, or binds a WASM subpackage version to that app, or booking yields an order number under that app, or decrypts **another merchant's** unpublished payment-order cardholder; or fake sig fails verification while real sig passes the production gate into a downstream identity-provider business error (production still recognizes the full key); or production `open_order` yields an unpaid `token_id`; or DingTalk `get_suite_token` yields `suite_access_token`; or production queueing `getZoneListCount` `ret=0` with server/zone online.

False positives: docs are placeholders; real and fake keys give the same error; key expired/unreachable; integration key only works against test, production rejects; wiki masking treated as "zip/Demo also masked". Key values don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Portal CMS with hardcoded site keys (quick-hits has a pointer)

Recognize: portal / open-platform frontend (not debug-doc zips) hardcodes portal CMS `accessKey`+`secretKey`. There's `GET /api/v1/cms/login` returning a JWT, common header name `cms-token`. The homepage may just be a CMS welcome page — the keys live in another portal JS.

Fire (unauthenticated):

1. Copy AK/SK, hit login (real values only go into the report)
2. With the ticket hit `channel/list`, `content/list|detail|search`, `attachment/list`
3. Don't stop at the official carousel channel. Follow developer/test/backend channels, GET `attachments.url`

Counts: internal test reports / article bodies in channels not shown publicly (xlsx sheet fields also count).

False positives: only public operation banners / client download links. Key values don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Signing nonce is a private key (quick-hits has a pointer)

Recognize: enterprise IM / business **unlogin** signing endpoint (`queryAppSignature` / `queryCorpSignature` style). Other business endpoints require login — this one takes no Cookie. Response `nonceStr`/`nonce` starts with `MIIE` or `-----BEGIN` and loads as a PKCS8 private key. Commonly preceded by an unauthenticated channel/live-code endpoint leaking `corpId`.

Fire (unauthenticated):

1. Copy `corpId` from the unauthenticated channel/live-code leak
2. POST the signing endpoint with url + corpId
3. Load `nonceStr` as the private key (Python `load_der_private_key` / openssl). Baseline: fake corpId → business error, no PEM

Counts: loads as an RSA private key.

False positives: nonce is just a short random string; fake corpId keeps returning business errors. Key values don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Unauthenticated IM/trial ticket issuance (quick-hits has a pointer)

Recognize: unauthenticated `im/getConfig` issuing a TIM `userSig` with `identifier=null`; or cloud-product trial center / apaas signing endpoint issuing tickets per the **existing userId** in the request (baseline: guest `none_auth` opens a new account); or the same backend's other business endpoints require login while the signing endpoint issues an IM/RTC userSig with only a custom trace header + client-supplied userId; or a self-built IM gateway signing endpoint only eats appkey, the ticket has no userId and the entry body's uId is the identity; or the JS-written v2 inner signing endpoint is IP-whitelisted; or an official audio/video/IM web Demo hardcodes the signing endpoint and fixed pwd, identifier follows the request, and empty-password still issues tickets for existing users.

Fire (unauthenticated): use that sig against the **IM integration domain**: `openim/login`, `getmsg`, `friend_get`, `get_joined_group_list`, group profiles/messages. Trial pages then hit login_token for `data.phone`. Baseline gates: other business endpoints should require login; the signing endpoint with only a trace header and userId swapped to interviewer_/candidate_ style; take authorization/signature to group history / room entry. After an anonymous appkey issues a ticket, access/get with uId swapped to interviewer_/admin, watch the userID in the response. v2 `by_app_name` returning "IP not allowed" **isn't a stop** — hit v3 same path, needs only `appName`. Official Demo: copy the UserSigService URL and pwd from JS, identifier = an existing user number; fire once more with empty pwd. Use the userSig against friend_get, baseline against the guest empty account.

Counts: pulls **other people's** sessions / group members / friends, or plaintext phones.

False positives: can only log into guest `null` with empty sessions and self-created empty groups; swapping to another user's UserID=70013; `none_auth` only opens empty accounts; demo accounts with no bound phone don't count. Missing on one site doesn't delete the quick-hits row.

### Hardcoded product number issuing shared JWT (quick-hits has a pointer)

Recognize: AIGC / mini-tool H5 or landing page hardcodes the product number / `qbid` in scripts. The signing endpoint (`account/qb` style) issues a **shared-product-number** JWT unauthenticated, ticket name is the product name, not a guest. JS often only has create / GET-by-id, no list.

Fire (unauthenticated):

1. Copy the hardcoded product number, hit the signing endpoint
2. With the ticket POST same-origin `.../task/list` (or workflow/history style lists JS never wrote). Baseline: without the ticket → unauthenticated; empty-packet list still yields total
3. Follow `userImages` / original-image CDN, confirm real face/ID photos

Counts: list total is huge and carries **other people's** original images / ID photos.

False positives: ticket can only create empty tasks; list total=0 or only your own recent uploads. Key values and one-off JWTs don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Official customer-service chain signs an external site (quick-hits has a pointer)

Recognize: enterprise customer-service H5 signing chain; inlined `getXcxLink`/`get_wx_open_link`. Not a generic redirect page.

Fire (unauthenticated): POST `queryStr=caUrl=external-site&urlType=2`. Open the returned customer-service landing link.

Counts: landing page's official name is the official service account, and the `base64Decode`d query contains the URL you filled.

False positives: only signs this site's `/ca/`; landing page carries no query; login required. Missing on one site doesn't delete the quick-hits row.

### Demo account collecting cloud keys (quick-hits has a pointer)

Recognize: cloud-vendor product Demo / trial page / console proxy / vendor backend; STS acquisition, federated identity, and task creation need only a business id or an empty body, no Cookie. The STS endpoint's missing-param response is field validation, not a login gate, and a demo account may not exist. Not the object-storage STS wildcard-overwrite shot (that's in `file-upload-test.md`).

Fire (unauthenticated): with a demo account copy the customer number, then hit key-acquisition / task-creation / federated identity. Without a demo account, still hit the key endpoint: missing-param field-validation isn't a login gate. Empty body reporting missing `AppId`/`Uin` isn't no-endpoint either — a parseable numeric Uin may issue federated STS; bucket+file_name still fire. The key endpoint may live on a separate demo CDN `/openapi/` (follow it from the page JS). After the share-domain frontend HMAC passes the gateway, baseline against other endpoints' "token invalid / Token verification failed" — STS endpoints like `/share/token/info` still fire without the share-page token. Probe live buckets with PUT/NoSuchBucket. Take the key to GetCallerIdentity against the main account; with launch/search-style Actions sign further (insufficient quota isn't a stop — see if it can identify the account or produce a bill). Epaas after HMAC `SC-SIGN`: roster still UserNotLogin — specifically hunt GetUploadURL/FileName that don't validate token (passing the signature ≠ returning data).

Counts: temporary key identifies AccountId/role name; the roster under the same identity shows just-created tasks; or search-console output yields bills/instances/other-subject business fields; or live bucket PUT 200.

False positives: key against business APIs all Unauthorized; key endpoint requires login/401; create 200 but no roster entry. No demo account/customer number is not a false positive. Missing on one site doesn't delete the quick-hits row. Key values don't go into the library.

### Unauthenticated partner login-chain issuance (quick-hits has a pointer)

Recognize: e-contract / supplier portal landing page is a login page whose box only takes an enumerable partner numeric id (partnerId / supplierId style), no password. Unauthenticated `getUrl` (or similar login-chain issuing) directly returns `partnerId`+`generate`+`code`. Nearby there's a `setCookies` / ticket-swap endpoint that turns those three into a session.

Fire (unauthenticated):

1. Copy the issuing endpoint from login-page JS, partner id = the number hinted on the page or a neighbor
2. POST the returned three items to setCookies / ticket-swap, copy Set-Cookie
3. With the session hit contract lists / payment onboarding / identity endpoints. Baseline: no Cookie → unauthenticated; nonexistent partner id → empty

Counts: identity endpoint logs in successfully, or can read unpublished contracts as that account.

False positives: issuing endpoint requires login; code must be opened from email; setCookies doesn't produce a session; only public recruitment pages. Missing on one site doesn't delete the quick-hits row. Key values and one-off cookies don't go into the library.

### Unauthenticated partner direct-connect config query (quick-hits has a pointer)

Recognize: ops console / supply-chain frontend hangs the supplier direct-connect config query unauthenticated. Body only has an enumerable partner numeric id (partnerId style), no Cookie. Response `partnerInfos` (or similar) carries clientId+clientSecret.

Fire (unauthenticated):

1. Copy the query endpoint from ops-console JS (getV2 / tech/partner style)
2. partnerId = neighbor id. Baseline: unconfigured id → empty/unconfigured, not a login gate
3. Confirm it's a full clientSecret, not an empty success code

Counts: response carries full clientId+clientSecret — usable as that direct-connect key.

False positives: endpoint decommissioned; clientSecret empty or placeholder; login required; only company names without keys. Missing on one site doesn't delete the quick-hits row. Key values don't go into the library.

### Unauthenticated sign-and-redirect to an external domain (quick-hits has a pointer)

Recognize: unauthenticated SSO / redirect signing; callback only checks whether the string contains the official host, or doesn't validate at all and signs any external domain.

Fire (unauthenticated): fill callback/redirect with an external domain — both **with** the official host embedded (query/subdomain/userinfo) and **without** it. Any ticket/sign in the response goes to your own SSO. Watch the passpage for `location.replace(redirect+"?"+tokenname+"="+session)`. Baseline: without the official string → emptied or blocked. Only issues a ticket after a real device login AND the frontend never splices the token into the redirect → half-result, stop at sign-off, not a break-through.

Counts: SSO succeeds and the redirect stays external; or after login the pass appears in an external-domain query.

False positives: callback emptied; SSO missing the callback param. Missing on one site doesn't delete the quick-hits row.

### Missing-param field moved to headers for ticket swap (quick-hits has a pointer)

Recognize: unauthenticated business endpoint JSON reports "missing xxx"; even with it in query/body it still reports missing. Or Spring 400 HTML/`message` writes `Required String parameter 'os' is not present` — naming a **Cookie name**, not a query param.

Fire: move that field into an **HTTP header** and hit SSO / ticket-swap / login. Header not eaten isn't a stop — try Cookie (self-invent device `uuid`/`os`/`platform` style). Unauthenticated write endpoints (store-binding / status-change) get the same treatment, not only ticket-swap. Baseline: with it only in query → still "missing".

Counts: returns someone else's login ticket/name; or writes onto another's store/object.

False positives: query has the field yet still "missing" (neither header nor Cookie eaten) doesn't count; only your own ticket. Missing on one site doesn't delete the quick-hits row.

### Password-login API behind an SSO shell (quick-hits has a pointer)

Recognize: management backend only redirects to SSO / unified auth — the page has no username/password box; the backend still exposes a username/password login API. Don't treat the SSO shell as "no login endpoint at all". Common backend skeleton `/admin-api/system/auth/login` is a common skin; no such name — still fire.

Fire (unauthenticated):

1. POST `/admin-api/system/auth/login`, body `{"username":"admin","password":"123456"}` (don't grind SSO captchas)
2. Put `data.accessToken` into `Authorization: Bearer`, hit `/admin-api/system/tenant/page` or `/system/user/page`
3. Baseline: wrong password fails; the default credential yields a platform ticket like `userId=1`

Counts: entered the platform admin account, and tenant/user rosters show other people's phones/names.

False positives: login endpoint 404 or default credential changed; ticket only enters an empty tenant with no contacts. Key values and one-off tokens don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Empty-packet refresh issuing an admin ticket (quick-hits has a pointer)

Recognize: JSON gateway has a refresh-ticket endpoint (`/api/auth/refresh` style). Unauthenticated empty `{}` issues a ticket whose identity is `admin` (not a guest). Management backend and frontend share the same cloud-dev/gateway.

Fire (unauthenticated): POST the refresh endpoint; put `data.token` into `Authorization: Bearer`, hit `/api/admin/me/permissions` and the application/user rosters. Baseline: without this ticket → unauthenticated.

Counts: me is super admin (permission `*`), or rosters show **other people's** phones/names.

False positives: only guest/expired tickets; refresh requires the old refresh token; me is still yourself. Key values don't go into the library. Missing on one site doesn't delete the quick-hits row.

### Empty openId entering an existing account (quick-hits has a pointer)

Recognize: mini-program / H5 GET login endpoint eats `openId` (`loginByOpenId` style). Missing param reports a missing field, fake openId fails login, but the **empty string** still 200-returns an **existing merchant account** and phone — not a guest empty account.

Fire (unauthenticated):

1. One shot missing-param, confirm it's a login endpoint
2. One shot fake value, should fail
3. Fire `openId=` empty string; if GET query doesn't eat it, try POST JSON `{"openId":""}`
4. Baseline: the store name/login phone from the empty string, versus the fake-value failure and missing-param report, aren't the same guest account

Counts: entered an existing merchant account and got the phone (usable as that account).

False positives: empty string only yields a guest empty account. Key values and one-off cookies don't go into the library. Missing on one site doesn't delete the quick-hits row.