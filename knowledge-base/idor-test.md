> What is written is governed only by `../rules/report-format.md`. With a session, the minimum probes for engagement are in `../rules/engagement-guide.md` §4.2.3 (object graph, id swapping, sentinel values); for a single account, use other people's ids from lists/responses, don't grind a registration for a second account. Default to proving cross-user / cross-tenant via read/list differentials. Write IDOR still has to be tested, but **not** against other people's existing data for modify/delete. The order is below in "How to Test Write IDOR". Batch modify/delete is forbidden, real asset loss is forbidden.
> Shortlist pointers are found by searching headings. The English BOLA encyclopedia has been cut; how to test write IDOR stays in the top half.

## Part I: Original Knowledge Base

# Privilege Escalation (IDOR / Authorization Bypass) Testing Handbook

> **Minimum harm:** default to read/list differentials. Write IDOR still gets tested, following "add your own first -> then delete what you added". Do not read "read-only" as "write IDOR is not tested or reported".

### How to Test Write IDOR (Add First, Then Clean Up)

If the read differential is already a closed loop, don't write. When the read is not enough and you need to prove "you can modify someone else's things":

1. **Test adding first.** With your own account (or unauthenticated), call the create endpoint and see whether it lands under someone else's name / someone else's store / someone else's tenant. Success = write IDOR is already proven.  
2. **Then delete the very row you just added.** Clean it up through the same endpoint or the matching delete endpoint; don't leave dirty data behind.  
3. **Do not** modify other people's existing orders, change other people's passwords/roles, or delete other people's original addresses/coupons/products. Those cannot be cleaned up cleanly and are not the minimal falsification.  
4. If there is no create endpoint on site and only modify/delete on existing objects: change a test field **you can change back yourself**, hit it once, and stop. Password change / role change / rebinding can be probed per `../rules/engagement-guide.md` §4.2.2 and `authbypass-test.md` (drop the old verification and see whether it passes); revert immediately after it passes; if it cannot be reverted, stop at the response — don't leave someone else's password, role, or email behind.  
5. To prove asset loss: only touch test amounts/statuses **you can revert yourself**, hit once and revert immediately. Don't actually move production funds, don't clear someone else's stock, don't turn someone else's existing order into something unrecoverable. **Not** that payment / write IDOR goes untested. Batching is forbidden, trying deletes against production master data is forbidden. This paragraph is minimum harm, **not** "write IDOR / takeover / field-adding is untested".

## Concept Distinctions

- **Horizontal privilege escalation**: same privilege level, accessing another user's resources (A accesses B's order)
- **Vertical privilege escalation**: a low-privilege account calling high-privilege endpoints (a normal user calling the admin API)
- **Unauthenticated access**: hitting an endpoint that requires auth without logging in

---

## Test Flow

### Step 1: Find the User Identifier Parameters

Look for user/resource identifiers in:

```
URL path:    /api/user/12345/info
URL query:   ?userId=12345&orderId=ABC
Request body:      {"uid": 12345, "target_id": "user_abc"}
Response body:    {"id": 12345, "created_by": 67890}  <- collect these IDs
```

**High-value endpoint traits**:
- Paths containing `user`, `account`, `profile`, `order`, `bill`, `message`
- Responses containing other people's phone numbers, emails, real names, ID numbers
- State-changing endpoints: `update`, `edit`, `delete`, `change`

### Step 2: Object ID (a Second Account Helps; If Not, Don't Grind Registration)

```
With a comparison account: log in with account A to get a token, and use account B's resource IDs as the comparison target.
Single account / no account: use lists, responses, neighbor IDs, or `0` / `-1` / empty as other people's IDs (`../rules/engagement-guide.md` §4.2.3). Do not grind a registration just to get a second account.
```

### Step 3: Swap Identifier Test

```python
# Horizontal privilege escalation test example
# Use A's token to access B's resource

import requests

token_a = "Bearer eyJ..."
victim_user_id = "B's user ID"

# Original request (access own data)
r1 = requests.get(
    "https://target.com/api/user/info",
    params={"userId": "A's ID"},
    headers={"Authorization": token_a}
)

# Escalation request (access B)
r2 = requests.get(
    "https://target.com/api/user/info",
    params={"userId": victim_user_id},
    headers={"Authorization": token_a}
)

# Compare the responses
print("Own:", r1.json())
print("Other user:", r2.json())
# If r2 successfully returns B's data -> horizontal privilege escalation
```

### Step 4: Vertical Privilege Escalation Test

```bash
# Call an admin endpoint with a normal user's token
# First capture an admin endpoint under an admin account
ADMIN_ENDPOINT="https://target.com/api/admin/users/list"
USER_TOKEN="regular user's token"

curl -X GET "$ADMIN_ENDPOINT" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json"

# 200 success -> vertical privilege escalation
# 403 Forbidden -> access control in place
```

### Step 5: Unauthenticated Access Test

```bash
# Drop the Authorization header and request directly
curl -X GET "https://target.com/api/user/info?userId=12345"

# Or replace it with an invalid token
curl -X GET "https://target.com/api/user/info?userId=12345" \
  -H "Authorization: Bearer invalid_token_123"
```

---

## Common Bypass Techniques

### ID Guessing
```
Integer ID: try ±1, ±10, 0, -1, 999999
Tenant/app fields in lists: if swapping in another user's real ID gets blocked, try 0 / -1 / empty / omitted (see "Sentinel Tenant" below)
UUID: other users' UUIDs may be obtainable from responses or JS
Phone number: some endpoints use the phone number directly as the identifier
```

### Parameter Pollution
```
# Submit the same parameter multiple times
POST /api/user/info?userId=A_ID&userId=B_ID
POST body: userId=A_ID   + URL: ?userId=B_ID
```

### Path Traversal
```
/api/user/A_ID/orders  ->  /api/user/B_ID/orders
/api/order/123         ->  /api/order/124, 125...
```

### Encoding Bypass
```
userId=12345         -> userId=0x3039 (hex)
userId=12345         -> userId=%31%32%33%34%35 (URL-encoded)
```

---

## PoC Evidence Collection

```
Must save:
1. Full request content (including token, headers)
2. Full response content (including the victim's data)
3. Comparison screenshots (A's normal response vs the escalation response)
4. Proof of the mapping between the victim account ID and the data
```

---

### Ciphertext ID (Shortlist Pointer)

Recognize: the id of update/query requests for addresses, orders, or profile data is a long ciphertext blob; the response or list shows a small plaintext number; JS has `RSAUtils` / `JSEncrypt` / `security.js`, or hardcodes `modulus` + `exponent`.

Attack: ciphertext is not a wall — the public key is usable by anyone.

1. First test your own record and correlate the plaintext id in the response  
2. Encrypt neighboring numbers yourself (plaintext ±1, then keep stepping outward) with the same front-end encryption  
3. Swap only the ciphertext id; leave the session untouched

Counts as: swapping it over reveals **someone else's** name/phone/address. Proving only that your own ciphertext decrypts back to your own plaintext -> does not count.

False positives: the server filters by session, so even correct encryption returns only your own data; that key is for signature verification and random encryption gets rejected outright. A miss on this site does not remove the shortlist row. Real key values and a site's `security.js` URL never enter the library; copy them from the live site's JS during the engagement.

### Sentinel Tenant (Shortlist Pointer)

Recognize: tickets / qualifications / session lists carry `appId`, `tenantId`, `orgId`; the response has attachment URLs (`sign` + `file_name` + yet another tenant field).

Attack (swapping in a real other-person ID would already be plain horizontal privilege escalation; this is one more shot):

1. Try `0`, `-1`, empty string, omitted on the tenant field — backends often treat sentinel values as "no filtering"  
2. `total` / row count surging relative to your own tenant baseline is what counts as a break-through; raising `pageSize` or flipping `page` merely pulls the full volume, **not a bug**  
3. Type fields (like `serviceType`) get the same `0` / `-1` treatment — may switch to another set of business tickets  
4. Signed downloads in lists: opening as-is is usually 403; **leave `sign` / `file_name` alone and only change the tenant in the URL to your own** (the signature does not cover this field). Full text in the presigned section of `file-upload-test.md`

Counts as: the list shows another tenant's ticket bodies / customer-service conversations, or the attachment really downloads the counterpart's certificates. Core is a cross-tenant business read.

False positives: `0` still returns only your own; cross-tenant download is 403; only a file channel with no business list. Sentinel value missing -> don't delete this row; keep trying list filtering on the next site anyway.

### Artifact Registry catalog Doesn't Filter Tenant (Shortlist Pointer)

Recognize: there are containers / cloud functions / mini-program cloud; you can `docker login` or see a Registry / Harbor / `/v2/`.

Attack: this is list-scope privilege escalation, not downloading files unauthenticated.

1. Log into the artifact registry with **your own** account  
2. `GET /v2/_catalog` (Harbor also has a project-list type endpoint, same shot)  
3. If the repo names in the response match **another tenant** -> `/v2/<repo>/tags/list`, then `docker pull` one of them

Counts as: the catalog shows another tenant's private repos and the image can actually be pulled (the layers contain the other party's app/config). Proving only that you can log in yourself, or that you can only pull official public images -> does not count.

False positives: the catalog returns only your own; names are listed but pull is 403; it was a public registry all along. A miss on this site does not remove the shortlist row.

And anonymous fileId download, and an OSS bucket policy wide open are not this entry: this one is **logged-in catalog handing out all of the site's private repos**.

### Login-Prefix Twin (Shortlist Pointer)

Recognize: the business H5 puts the login RPC under `/fapi/d/` (or a similar login-required prefix); the same gateway also has an unauthenticated prefix `/fapi/n/` (or n / unlogin / guest). Hitting only the `d` endpoint in JS makes the whole flow look like "please log in".

Attack (no login):

1. Control: the `d` endpoint should demand login / a ticket  
2. Change the `d` in the path to `n`, same RPC, same object id, hit again  
3. Swap in a neighbor ID; open the ID-photo URL returned in the response

Counts as: someone else's ID card / ID photo / phone without login.

False positives: `n` still demands login; `n` only has public config; only the supplement docs you just submitted. A miss on this site does not remove the shortlist row.

### Numeric RPC Neighbor cmd (Shortlist Pointer)

Recognize: the business page JS calls a numeric RPC gateway (`/data/{number}/forward` and the like). The page usually hardcodes a single cmd (invoices / ads and the like). Neighbor numbers may be another set of internal list/write endpoints — don't stop at the hardcoded one. `Numeric RPC gateway` is a common façade; run the test even when that exact name is absent.

Attack (no login):

1. Copy the forward address from JS and change the number in the path to a neighbor  
2. First send an empty `{"req":{}}` to see the list; the control hardcoded cmd should be another set of business  
3. Once internal records show up in the list, take the id and hit neighbor write endpoints (fake id first / already-empty id). If it passes and can be reverted, revert

Counts as: internal publish/operator bodies, or fields getting changed.

False positives: the neighbor number is still the same set of public endpoints; only a public software catalog comes out. Real key values never enter the library. A miss on this site does not remove the shortlist row.

### Identity-Domain Account CRUD (Shortlist Pointer)

Recognize: the account CRUD endpoint of the same product's business front end returns a login gate (`AuthFailure.NoLogin`); there is a separate `*-ids` identity subdomain where the same `/api/ms-account/` needs no Cookie. `GET` list may 404; only `POST` returns data.

Attack (no login):

1. Control: the same list through the business front end should demand login  
2. Hit the ids subdomain `POST /api/ms-account/user/list` instead, try both empty body and `Offset+Limit`  
3. If that works, go `generate` -> `reset-pwd` carrying only the Id (no Id should give a parameter error) -> `delete` to clean up the probe account

Counts as: the roster contains phones / corporate emails; you can create accounts, change passwords without the old password being verified, delete by Ids.

False positives: only hitting the business front end and treating it as no bug; the list returns data but Mail/Phone are all empty and the write endpoints are gated too. A miss on this site does not remove the shortlist row.

### Lists Skip the Detail Access Gate (Shortlist Pointer)

Recognize: a public list only returns published/public items; details, hidden, tabs, preview/export all use the same business id. Or the list has a visibility query parameter that filters hidden items out by default. Or the list requires login / empty body while the detail only needs a numeric id + business key (like workid). Or the public-facing detail blanks the contact/phone, while the audit/approval detail uses the same business id. Or a docs CMS front end hardcodes a public `area` / `endpoint` / `channel` while the API does not authenticate. Or a public search endpoint has a material-type parameter (`materialType` / `tab`) defaulting to a public value. Or an onboarding/audit query only carries a business id and returns an empty shell by default. Or a same-product full-list endpoint has no visibility parameter and the rows carry unpublished/offline detail bodies, while public search and showcase details stay gated. Or a browse/catalog page tells visitors to log in while the same site's search API still returns internal/proprietary document bodies unauthenticated.

Attack (no login):

1. Note the public list's ids; throw ids absent from the list at detail / hidden / tab; if detail 403s, keep going to preview / export  
2. Add `status=hidden` / `all` / `private` (or a similar visibility parameter) to the list endpoint yourself. Control: without the parameter the list is empty or public-only; the same id on detail still saying "no permission" is no reason to stop either — the gate may be wrapped only around the detail  
3. **This list endpoint 401 / demands login / empty body — don't stop.** Switch to another guest query in the same product and watch the response's `hidden` / `is_public` / `isHidden`. If public contents 404, hit hidden/contents with the same id. If detail only needs a numeric id + business key, still hit it. `is_secret=1` still returning full text — don't stop at the title.  
4. **Detail returns 200 and the JSON already says unpublished / requires login / `canAnswer=false` — don't stop.** Check the same payload for `savedConfigDraft` / a similar draft field with unpublished body. The blocked-copy text and the draft can live in the same JSON.  
5. **Public-facing detail blanks contact / mobile / email — don't stop.** Hit the audit / approval / review detail with the same id; the gate may only be wrapped around the public-facing endpoint.  
6. **Works/items with `period=edit|publish` (or a similar status param) — don't stop at publish.** Hit the content endpoint with `period=edit` without login. Control: the same id's publish says it doesn't exist / is deleted, and info blocks "no permission to read others' ". Only edit returning the body counts.  
7. **JSON list filter items null / missing field reporting Unknown / parameter error — don't stop.** Change that field to an empty array `[]` and hit again. Backends often treat an empty array as "no filter" and hand out unpublished / full tables anonymously; a missing param or null is what gets blocked instead. Control: `null` or removing the key should error or return empty; `[]` is what surfaces unpublished bodies.
8. **Docs CMS front end hardcodes a public `area` / `endpoint` / `channel` — don't stop at the default.** Unauthenticated, change the param to an internal zone (commonly 1 vs 2, oa vs public). Control: bodies for integrations/hardening/internal-network algorithms absent from the default public list; only when the list or detail surfaces them after the change does it count.  
9. **Public search endpoint has `materialType` (or a similar material type) — don't stop at the front-end default public value.** Against the public specs/showcase types, switch to internal-market materials, marketing specs and the like. If the path missing `/v2/` returns `auth failed`, don't stop — patch it back per the front-end replacement rule and hit again. Counts as: internal material rosters / direct file links behind the SSO wall, `isLimitAuth=1`.  
10. **Self-service onboarding / audit query with only a store number / business id returning an empty shell — don't stop.** Add audit status = approved (like `baseInfoStatus`) and hit again. The `uid` in the response leads straight to the email/contact endpoint. Control: without the status it should be an empty shell or have no phone.  

11. **License-image JSON has no idNo — don't stop.** When the detail returns a trademark-registration certificate / license scan, actually open it: the registrant line often appends the ID-card number right after the name. If the number in the image matches the person it counts; don't only scan JSON fields.  
12. **Export-task list empty at `pageNum=0` — don't take it as no data.** Retry with `pageNum=1`; it often lists other users' exports across the whole site. Grab `fileName` / key and hit download.
13. **Detail telephone / mobile fields masked — don't stop.** Unpublished detail's `requirement` / remarks / free text often contains the full 11-digit mobile number; the API only stripped the structured fields.
14. **Hit the full-list endpoint even without a visibility parameter.** Read unpublished / offline / rejected detail bodies straight from the rows. Control: public search shows total=0 for that id and the showcase detail a person opens says it doesn't exist. Testing only the public search and detail page is not a clean miss.
15. **Browse/catalog page says visitors must log in — don't stop.** The same site's search API (Keyword+Page+PageSize) may still return internal/proprietary document bodies and detail URLs unauthenticated. Detail-page JSON with `isLogined=false` that still returns full text — don't stop. Control: the catalog page a person opens says visitors must log in to view.
16. **Detail endpoint patched / item not found — don't stop.** The same site's visit-log / tracking / doc-add-visit-log endpoints may still return OA/internal full text when given a numeric doc number. Control: the original detail endpoint with the same business id should already be blocked.
17. **Catalog says visitors must log in to view/download — don't stop.** The same site's file-list endpoint (like `getHomeCosFileList`, `solution_id`+`version_id`+`folder_id=0`) may still list training videos / whitepapers / manuals unauthenticated. Throw the list `file_id` at the permission endpoint (`getFilePrivilege`) and look at `PreviewUrl` / signed download. Control: the catalog page a person opens says visitors must log in to view and download.
18. **Content SPA picks the Color/gateway domain by a `location.host` regex — don't hit the wrong TLD.** JS commonly shows `.*\.jd\.hk` -> the content gateway domain; hitting the wrong content gateway domain makes it look like there is no endpoint. Same attack: unauthenticated floor queryContents + previewContentDetail. Control: the public detail should be absent / 1414.
19. **Docs-site public itemList / catalog only lists external products — don't stop.** Unauthenticated, change `item` (or the same project number) to a plain auto-incremented number and hit detail/page. The body may be compressed markdown — unpack it with the same scheme the front end uses. Control: only knowledge bases absent from the public itemList ("internal / not released / not external") count.
20. **Form/survey detail JSON has a relative / linked table carrying an answers sheet — don't stop.** What a person opens is the fill-in page; the answers sheet may have a different id. Hit the answers-sheet detail/opendoc unauthenticated. Control: the fill-in page is only questions; the answers sheet is what exposes ID-card/phone cells.
21. **Content-preview endpoint only takes a numeric contentId; the response says `isDelete=1` / deleted / unpublished — don't stop.** Control: the public showcase should not have this piece. Only a full H5 page or editor JSON counts; don't settle for the title.

Counts as: unpublished business bodies surfacing from a list (not public-showcase titles); or the target subject's phone / certificates; or a license image whose registrant line prints the ID-card number; or source bodies of unpublished / delisted works.

False positives: even with the visibility parameter only public drafts come out; only titles with no body; treating list 401 as no bug; edit and publish returning the same already-live body; empty array and missing parameter returning the same live draft; `materialType` still only returns the public showcase; only a business id giving an empty shell treated as no bug without adding the audit status; only testing public search / showcase details treated as no bug; browse page saying "please log in" treated as no bug; numeric item still being those few public docs. Hitting the wrong Color domain and taking it for no endpoint is not a false positive. A miss on this site does not remove the shortlist row.

### Gateway Proxy With Hardcoded No-Auth Header (Shortlist Pointer)

Recognize: logistics / open gateway (`lop-proxy` and the like) front-end JS hardcodes `Auth-Control: no-auth` + `LOP-DN` (business domain). Other business endpoints demand login; with this header set, roster / waybill endpoints still return data.

Attack (no login):

1. Copy `LOP-DN` and `Auth-Control: no-auth` from JS (or a similar gateway-auth-skip header)  
2. Empty-page through the site/roster endpoint; then swap an enumerable `siteId` into waybill/detail  
3. Control: without the header it should demand login or "Host not registered"

Counts as: other people's phones / addresses / site contacts, not public tracking.

False positives: the header passes the gateway but business still demands login; only public tracking with no PII. A miss on this site does not remove the shortlist row.

### Anonymous Session Reads the Signup Table (Shortlist Pointer)

Recognize: BaaS anonymous session; the list endpoint does not verify admin. The page hardcodes a few admin IDs, and the backend bounces to login. Appwrite / Weavefox / TablesDB are common façades — run the test even when that exact name is absent. Front end commonly shows `Client().setEndpoint`, `X-Appwrite-Project`, `POST /v1/account/sessions/anonymous`; signup/activity tables go through `tablesDB.listRows`.

Attack (no login, no admin account):

1. With no Cookie, first hit `GET /v1/tablesdb/{db}/tables/{table}/rows` — the baseline should be `total=0` / empty rows (the system actually blocks guests)  
2. `POST /v1/account/sessions/anonymous` body `{}`, headers carrying the same `X-Appwrite-Project`, take the `Set-Cookie: a_session_...`  
3. Hit the same listRows again with this anonymous session

Counts as: after the anonymous session, `total` surges relative to the empty session, and the rows contain **other people's** phones / emails / signup bodies. The admin whitelist lives only in the browser and was never enforced on the list endpoint.

False positives: no-session is already the full table (that is fully unauthenticated, a separate entry); the anonymous session is still empty or only your own just-submitted row; DELETE of someone else's row 401 only means writes aren't open — the read still counts; a public operations display roster. A miss on this site does not remove the shortlist row.

And "no Project key, CRUD works without even an anonymous session" is not the same shot: the key of this entry is **the anonymous session is treated as logged-in, and admin is not verified**.

### Cloud-Dev Anonymous User Table (Shortlist Pointer)

Recognize: cloud development has anonymous login enabled; there is a low-code datasource function. The console or front end lets you copy an environment id. Not the already-listed proxy `targetUrl`, and not the BaaS `sessions/anonymous`.

Attack (no login):

1. `POST https://{envId}.api.<cloud-dev gateway>/auth/v1/signin/anonymously`, header `x-device-id`, body `{}`, take the JWT  
2. `POST /v1/functions/lowcode-datasource`, `Authorization: Bearer` that ticket, body `dataSourceName=sys_user`, `methodName=wedaGetRecords` (`getRecords` is equivalent)  
3. Control: the same gateway `GET /auth/v1/user/query` should block anonymous; the datasource name `users` often fails row permission, **don't stop** — `sys_user` is the system user table  
4. HTTP gateway (commonly `/web?env=`) returning `LOGIN_TYPE_DISABLED` **don't stop**: switch to `POST /web?env=`, `auth.signInAnonymously` -> `auth.getUserInfo` to take `jwt;expire` (**don't strip the semicolon suffix**) -> `functions.invokeFunction`, hit `sys_user` / `wedaGetRecords` the same way  
5. An old HS256 ticket dropped on `/v1/functions` returning `KID_INVALID` -> this shot failed; switch to the step-4 gateway ticket instead of treating it as "datasource does not exist"  
6. `sys_user` row permission failing **don't stop**: with the same `/web` anonymous ticket switch to `database.countDocument` / `database.queryDocument`, `collectionName=users` (the user table persisted by connected login, not the datasource name `users`)

Counts as: the records contain **other people's** phones / emails / uin / super-admin flags, not the empty account you just created anonymously.

False positives: row permission rejects anonymous and the `/web` users collection is empty too; the datasource doesn't exist; only demo todo/sales come out; treating the old HS256 ticket's `KID_INVALID` as no bug. HTTP gateway `LOGIN_TYPE_DISABLED` is not a false positive. Datasource name `users` failing is not a false positive. A miss on this site does not remove the shortlist row. Real key values and a one-off JWT never enter the library.

### Grab openid From Detail, Then Hit the Mailbox (Shortlist Pointer)

Recognize: recruiting / designated-user detail carries `specifyUsers` or openid; H5 hardcodes a SHA256 request signature; or the invite-page URL already has `?openid=`.

Attack (no login):

1. Call the detail and copy the openid  
2. Compute the Signature with the key, then hit `/msg/message/list/`  
3. If the URL already has an openid, hit the unsigned `get_invite_code` / `count` / `detail` too; the roster's `uid` can be filled back in

Counts as: swapping openid changes the mailbox or the invite code / roster, surfacing the other party's points-expiry notification or masked phone nickname.

False positives: the list is identical for everyone, just a site-wide broadcast; the endpoint really requires login/signature; a fake openid has no invite code; a public operations roster. A miss on this site does not remove the shortlist row.

### Knowledge-Base nodeId Unauthenticated Full-Text Read (Shortlist Pointer)

Recognize: the publish page's conversation-data artifactMap has a knowledge-base `nodeId`; the main site `/space/d/` requires login.

Attack (no login): hit the publish domain `POST /space/api/page/share/query/pagechunk` (body=`pageId=nodeId`). Control: the share page's own pageId should be "not shareable".

Counts as: pulling someone else's document full text (title / character card / outline, `role=editor`).

False positives: only reading the published HTML snapshot; pagechunk also returns 12607 for the knowledge base; the body is already in the conversation snapshot. A miss on this site does not remove the shortlist row.

### Anonymous CSRF Header Reads Detail (Shortlist Pointer)

Recognize: an anonymous CSRF / temporary-token endpoint directly returns a token; the business detail only validates this header, not login; the numeric id in the query and the response's `data.id` can be different numbers. Not the assistant `GetHistoryList` optional login header (that shot is "Assistant History Reads Other Users' Tasks Unauthenticated").

Attack (no login):

1. Hit the csrf/token endpoint to take the header  
2. Swap numeric ids on the detail (1, 2, 13); **query id not matching the response id — don't stop**  
3. Control: without the header it should fail; a nonexistent id should be "not found"

Counts as: unpublished / test training scripts or internal session bodies (cardMap / dialogue full text, not titles).

False positives: only a public plaza; token passes but still empty. A miss on this site does not remove the shortlist row.

### Custom Identity Header Used as Session (Shortlist Pointer)

Recognize: the admin SPA request interceptor treats a custom header (`User-Id` / `employeeId` / `X-User-Id` and the like) as the login identity, no Cookie needed. Unauthenticated roster endpoints often only return numeric employee/BD numbers, no phones.

Attack (no login):

1. Copy the header name from the JS interceptor  
2. Unauthenticated, hit the roster (empty params / HQ filter). Only numeric numbers — **don't stop**  
3. Put that number in the header and hit the current-person info endpoint. Control: no header, or `1`, should query empty

Counts as: other people's name + 11-digit phone.

False positives: header passes but still empty; the roster already leaks phones (that's another entry). A miss on this site does not remove the shortlist row.

And "Anonymous CSRF Header Reads Detail" is not this entry: that one is a temporary-token header; this one is **an identity number riding in the header**. And "Onboarding H5 Empty Params Leak the BD Directory" is not this entry either: that one leaks phones with an empty category; here the roster has no phone and you still need to use the header as identity for another shot.

### Customer Detail Endpoint Also Eats phone (Shortlist Pointer)

Recognize: the CRM / enterprise-IM customer detail endpoint's front end only sends an external contact id (`externalUserId` / `contactId`). Only that id returns an empty shell. The backend also eats `phone`, and often needs `tagShow` / `udfShow` to surface internal fields.

Attack (no login):

1. Control: only the external contact id should return an empty shell  
2. Add an 11-digit `phone` to the body and turn on `tagShow` / `udfShow` (or similar expansion fields)  
3. Empty / garbage numbers should return an empty shell; changing the number must change the person

Counts as: other people's name / company / internal UDF, and the exact full number was what was queried.

False positives: phone always empty or only returns the same test number. An empty ID-card slot is not a false positive. A miss on this site does not remove the shortlist row.

### Assistant History Reads Other Users' Tasks Unauthenticated (Shortlist Pointer)

Recognize: the assistant/Agent front end has `GetHistoryList`; the login state only lives in an optional header. Not tool execution on the chat endpoint (that shot is in `agent-tool-exec-test.md`).

Attack (no login): call the list, swap the guid and check whether it's the same batch; then throw `session_id` at `GetHistory`. Page with `last_ts`+`direct=back`.

Counts as: the list/detail surfaces **other people's** task bodies (downloads, subscriptions, conversation cards), not the public plaza.

False positives: only the plaza `GetSquareTasks`/`share_id`; swapping guid empties the list or leaves only your own. A miss on this site does not remove the shortlist row.

### Hardcoded appKey Hits Business Tables (Shortlist Pointer)

Recognize: front-end `AV.init` / LeanCloud hardcodes `appId`+`appKey` (or `X-LC-Id`/`X-LC-Key`); or a nocode/supabase landing page hardcodes a `role=anon` JWT.

Attack (no login): with those two headers, hit `/1.1/classes/*`: first `_User` should 403 as control, then sweep business-table count/limit; if writable, change a probe field and delete it back. For supabase, carry `apikey`+`Authorization: Bearer` and hit the tables listed in the `/rest/v1/` swagger. **rest table 403 / only public operations config — don't stop**: switch to `POST /storage/v1/object/{bucket}/{official-prefix}`, header `x-upsert:true` (see `file-upload-test.md` STS step 9).

Counts as: business-table `count` is huge or contains **other people's** drafts/emails/phones; PUT modifying someone else's `objectId` succeeds.

False positives: `_User` and business tables both 403; can only read what you just created; can only LIST public operations config. A miss on this site does not remove the shortlist row. Real key values never enter the library.

### Form Model Ships With Standard Answers (Shortlist Pointer)

Recognize: survey/quiz fill-in model endpoints; front end hardcodes a business id or whitelist (`FORM_WHITE_LISTS` / demo encryptFormId and the like); the response schema carries the `answer` standard answers or internal audit questions/sample images. Not public signup-form titles, and not the already-submitted answer list.

Attack (no login):

1. Hit getModel / schema / getFormModel from the JS whitelist / demo id; don't stop at the form title  
2. Open the sample image preview/imgUrl in the schema  
3. Also hit the admin list/export/fillList; don't fabricate answers when there are no fill records

Counts as: internal quiz body + standard answers, or the certificate/license sample image really downloading.

False positives: only public signup-form titles; schema has no answer; only the answer sheet you just filled. A miss on this site does not remove the shortlist row.

### Unauthenticated Internal Script Content (Shortlist Pointer)

Recognize: the customer-service / dev-support console umi has `getKnowledgeList.json` + `getKnowledgeInfo.json`; or the lobby/help HTML detail endpoint eats a numeric doc number; or the public announcement JSON (bulletin / getbulletin and the like) uses `callname` + `callcontent` as an RPC and the page only calls the public menu (`getKnowledgeByMenuId`); or an unauthenticated CMS `siteList` / `contentList` / `content` can list non-official sites and the channel name carries "internal knowledge base"; or the customer-service/IT chatbot unauthenticated search endpoint (menu id + fuzzy searchText) has the body in `buttonList`/`searchList`'s `behavior.value`, not in the title `content`. Don't only recognize the umi JSON set.

Attack (no login): control `queryUserInfo`/`queryFeedbackList` should deny. Try `categoryId` from 1 on the list, then throw `id` at Info. **With no JSON list, still hit the HTML detail** (`showKnowledgeInfo.htm?knowledgeId=` / `help_detail.htm?help_id=`), using a modern UA (IE can trigger netd). Announcement endpoint: when the page's public menu control has very few entries, swap `callname` to `getKnowledgeList` (`callcontent` carries pagination), then `getKnowledge` at the detail id. CMS: first `siteList` to copy a non-official siteId, then `contentList` to see channel names, swap siteId and hit `content` detail; the default official-site Banner is not this shot. Gateway returning `loginMode is null` — don't stop, add header `loginMode: 0`; if siteList still fails for lack of siteId, directly hit contentList with an internal siteId. `content` must also carry siteId, otherwise it looks like there is no body. Chatbot: `chat_dir_id`-type directory endpoint 401 — don't stop, switch to the search endpoint (`search_recommend` and the like), `searchText` filled with common words, `id` filled with the menu number; read the body from `behavior.value`.

Counts as: list `pager.items` in the thousands or count huge, and Info/HTML/detail/`behavior.value` surfaces **internal** scripts / joint-investigation notices / SMS / operations knowledge-base bodies, not public FAQ / external agreements.

False positives: only public help drafts / error codes / external agreements / official Banner; Info only returns titles; the ticket endpoint also passes (that's another entry); only hitting the default official site; stopping at a dir node 401; the search endpoint only returning the title content. A miss on this site does not remove the shortlist row.

### Open-Payment Fake Signature Enumerates appId (Shortlist Pointer)

Recognize: the open-payment / merchant onboarding gateway body has `appId`+`sign` (can also add `random`/`merchantId`). With a fake signature, live apps return `MERCHANT_NOT_EXIST` or `SUCCESS`, dead apps return `SIGN_ERROR` / `APP_NOT_FOUND`. Not the "JS hardcodes the salt and computes it yourself" row, and not copying a real AppSecret out of docs.

Attack (no login):

1. Fill `sign` with a fake value (32 `a`s and the like), sweep `appId`, watch the response codes  
2. For live ones, hit the merchant query (`query` / `query/v2`) swapping `merchantId` (docs sample numbers, neighbor numbers)  
3. With the same fake signature, hit signing/agreement endpoints and only watch whether the response accepts; no batch signing, no changing settlement cards  

4. **ST / demo cashier pre-order** — when a fake signature or node-proxied signature can also reach the production gateway: unauthenticated `POST /api/precreate` or `/demoapi/precreate`, sign filled with a fake value + live appId + someone else's merchantId. Site-local query returning 404 — don't stop, hit production `/api/pay/query`.

Counts as: other merchants' ID cards / bank cards / phones; or production order query `ORDER_NEW` with another merchant's transaction number.

False positives: fake signature always `SIGN_ERROR`; `SUCCESS` but cert/card numbers all empty; docs sample appId dead; only `channelPayerNo` comes back and the production query doesn't exist; can only hang on the demo store. A miss on this site does not remove the shortlist row. Real key values never enter the library.

### Short Link 302 Carries Phone in Query (Shortlist Pointer)

Recognize: SMS/operations short-link resolver site; a guessed short code 302s to a landing page with plaintext `phone` / `name` / amount in the query. The homepage may be an OpenResty welcome page, a 302 to the brand site, or an `index.html` with only Hello — **don't read `/` alone as falsifying the whole site**.

Attack (no login):

1. Add short-code dictionaries (`aaaaa`, `1`, `1234`) onto `/open` `/app` `/s/` `/www`  
2. Only look at the 302 target's query; don't follow into the landing business domain  
3. Control: unmatched codes should be a dead page with no phone number

Counts as: **someone else's** phone/name in the redirect address.

False positives: dead page; public marketing without PII; short codes only resolve on a real SMS. A miss on this site does not remove the shortlist row. Homepage Welcome / 302 official site / Hello shell are not false positives.

### Privacy-Number Failure Falls Back to Real Number (Shortlist Pointer)

Recognize: order/store/logistics H5 calls a privacy-number or virtual-number (AXB) endpoint; unauthenticated it only needs a business appid + an enumerable object number. On failure the response hands out the real 11-digit mobile as the number, and the text even says "failed to get a privacy number, will call the real number". Don't just discard it as a virtual-number endpoint.

Attack (no login):

1. Copy functionId / privacy-number path from the front end; hit object numbers from 0, 2, neighbor values  
2. Control: non-numeric object numbers should be a parameter error with no phone  
3. Only changing the number changing the number counts as batch  
4. Gateway returning `cross-origin 403` on empty Origin or same-site Origin **don't stop**: switch Origin to a business domain (order / cart / H5 domain, not pinned to one host) and hit again

Counts as: the response is **someone else's** real mobile.

False positives: only virtual/intermediate numbers; login required; changing the number doesn't change it; empty-Origin 403 treated as no endpoint. A miss on this site does not remove the shortlist row.

### Onboarding H5 Empty Params Leak the BD Directory (Shortlist Pointer)

Recognize: the onboarding H5 has a BD-contact phone page; other settle endpoints in the same set 302 unauthenticated. The JS has an RPC that looks up BD by category (queryBd / bdInfo and the like); when industry/category is empty the body is empty. The page may only display a 400 hotline.

Attack (no login):

1. Copy the gateway `/api` and functionId from the BD-contact page JS  
2. Hit with the category field empty (`body={}`). Control: filling in a fixed numeric category usually returns an empty array  
3. Other settle endpoints in the same set 302 — don't treat the whole site as having no endpoint

Counts as: the full table of internal BD names + 11-digit phones + corporate emails.

False positives: a fixed numeric category returning an empty array treated as no endpoint; taking the page's public 400 hotline as this shot. A miss on this site does not remove the shortlist row.

### Onboarding H5 Hardcoded Token Swaps pin (Shortlist Pointer)

Recognize: the onboarding H5 / mini-program bundled JS hardcodes the token of the OCR / corporate-info endpoint. The JSON endpoint only needs a pin (or similar account) + a non-empty token, no Cookie. Control: token empty or omitted returns only empty data.

Attack (no login):

1. Copy the hardcoded token and the corporate-info path from the onboarding chunk  
2. Control: empty token should return empty data  
3. With the hardcoded token, try pin `admin` / `test` / `0` / short accounts  
4. Once the hardcoded string passes, fill an arbitrary non-empty string as control (passing means the token content is not validated)

Counts as: swapping pin returns the corresponding real phone.

False positives: empty token also returns data (fully unauthenticated, another entry); token passes but still only returns your just-onboarded account. A miss on this site does not remove the shortlist row. Real key values never enter the library.

### Company-Name / Invoice-Title Autocomplete (Shortlist Pointer)

Recognize: signup / onboarding / invoice-title autocomplete; the dropdown only shows company names; the endpoint goes through a business-registry / D&B Match or a title suggest. The front end may mark the endpoint `auth:true` while the server still does not verify login.

Attack (no login):

1. POST name + country code, or the title endpoint. The suggest field may be `prefix` (filling `title` will error "keyword cannot be empty" as if there were no entry point)  
2. suggest reporting empty keyword — don't stop: the same product also has a special-invoice / registry-completion endpoint whose field is exactly `title`, front end marked `auth:true`, still hit it  
3. Compare the page dropdown: the page only has company names; only when the response adds phone/card/address does it count

Counts as: the response shows the responsible party or the invoicing phone/address/bank account, and it matches the person.

False positives: dropdown and endpoint both only have company names; login required; public corporate directory with no phones; front end marked auth treated as no bug. A miss on this site does not remove the shortlist row.


### Mass Assignment / Hidden Writable Fields (Shortlist Pointer)

Recognize: the register / edit-profile / create-user JSON has more fields than the page controls; Swagger, admin "create user", or front-end comments add `role` / `isAdmin` / `verified` / `tenantId` / `balance` / `permissions`.

Attack:

1. Control: diff admin-create-user vs your own register/edit-profile; only stuff the fields that differ. Without a control, copy from Swagger / JS.
2. Stuff each field only on your own account once; revert immediately after it passes. Don't change roles on other people's existing accounts.
3. `__proto__` / nested `user.role` also try; this is not the same as the PP template RCE (PP is in `prototype-pollution-test.md`).

Counts as: your own account becomes high-privilege, or balance/auth state really changes. Field accepted but privilege unchanged -> not a success.

False positives: can only change the display name; a public operations switch; server whitelist swallowing extra keys. A miss on this site does not remove the shortlist row. Don't invent fields when there is no register/edit-profile endpoint.

## 12. QUICK IDOR CHECKLIST

```
□ A comparison account helps; single account uses lists/responses/neighbor IDs, never grind registration for a second
□ Map all API calls that contain object IDs (Burp History export filter)
□ Test all HTTP verbs on each endpoint (write: first POST-add, then delete the row you added; never delete others' existing objects)
□ Test ID in all locations: path, body, header, query, cookie
□ Try sequential IDs (−1, +1 from your own)
□ Ciphertext id: if JS has a public key, encrypt neighboring numbers yourself (see "Ciphertext ID")
□ List tenant fields: try 0 / -1 / empty (even when swapping a real other ID fails; see "Sentinel Tenant")
□ Has a Registry/`/v2/`: with your own account hit `_catalog`, can you list and pull another tenant's image (see "Artifact Registry catalog")
□ BaaS anonymous session then listRows, against the empty no-Cookie table (see "Anonymous Session Reads the Signup Table")
□ Cloud-dev anonymous login then hit `lowcode-datasource`'s `sys_user`/`wedaGetRecords`; HTTP gateway `LOGIN_TYPE_DISABLED` — don't stop (see "Cloud-Dev Anonymous User Table")
□ Detail carries specifyUsers/openid: copy the openid and hit the mailbox (see "Grab openid From Detail, Then Hit the Mailbox")
□ Publish-page artifactMap's nodeId hits pagechunk (see "Knowledge-Base nodeId Unauthenticated Full-Text Read")
□ Assistant GetHistoryList optional header: hit list/detail unauthenticated (see "Assistant History Reads Other Users' Tasks Unauthenticated")
□ Front end hardcodes LeanCloud/supabase anon: hit business tables (see "Hardcoded appKey Hits Business Tables")
□ Knowledge list + detail unauth reads internal scripts (see "Unauthenticated Internal Script Content")
□ Open-payment onboarding gateway fake-signature enumerates appId, then swap merchantId on live apps (see "Open-Payment Fake Signature Enumerates appId")
□ SMS short-link homepage Welcome / 302 official site / Hello shell — don't stop; guess /open /app /s/ /www and watch the 302 query phone (see "Short Link 302 Carries Phone in Query")
□ Unauthenticated privacy/virtual-number endpoint: on failure see whether a real mobile is handed out; object numbers enumerable (see "Privacy-Number Failure Falls Back to Real Number")
□ Signup/onboarding/invoice-title autocomplete: hit suggest (prefix) and special-invoice/registry-completion (title) unauthenticated; front-end auth mark still hit (see "Company-Name / Invoice-Title Autocomplete")
□ Onboarding H5 BD-contact page: hit the JS BD-lookup endpoint with category empty, don't fill fixed numbers (see "Onboarding H5 Empty Params Leak the BD Directory")
□ Admin SPA treats header User-Id as identity: roster only numeric — don't stop, put that number in the header and hit the current-person endpoint (see "Custom Identity Header Used as Session")
□ Browse/catalog page says visitors must log in — don't stop; same-site search (Keyword+Page) unauthenticated too, follow the detail URL (see "Lists Skip the Detail Access Gate" step 15)
□ Catalog says login needed to download — don't stop; same-site file-list endpoint + permission endpoint PreviewUrl unauthenticated too (see "Lists Skip the Detail Access Gate" step 17)
□ Public search endpoint `materialType`/`tab` switched to internal types; path missing v2 returns auth failed — don't stop (see "Lists Skip the Detail Access Gate" step 9)
□ Onboarding/audit query only business id gives empty shell: add audit status = approved, the response uid leads to the email endpoint (see "Lists Skip the Detail Access Gate" step 10)
□ Docs-site public itemList only external products — don't stop; plain numeric item hits detail/page (see "Lists Skip the Detail Access Gate" step 19)
□ Form/survey fill detail's relative hangs an answers sheet — don't stop; hit the answers sheet unauthenticated (see "Lists Skip the Detail Access Gate" step 20)
□ supabase anon JWT: beyond rest tables, hit Storage REST + x-upsert over official prefixes (see file-upload STS step 9)
□ Try UUIDs/GUIDs collected from your own account data
□ Test sub-resources (attachments, comments, transactions)
□ Test admin endpoints directly (BFLA)
□ Test POST/PUT body for extra fields (mass assignment)
□ Compare JSON response field count vs documented fields (hidden fields)
□ Test state/status: only your own order / test fields you can revert
□ Merchant binds promo/coupon: change productId onto someone else's goods, C-side price must drop to count (see logic-test.md §1.4)
```

---


Merchant binds promo/coupon to an SKU: only coupon ownership is validated, not goods ownership -> your coupon + someone else's productId; the C-side price must actually drop to count. Full text in logic-test.md §1.4.
