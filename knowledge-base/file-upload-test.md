> What is written is governed only by `../rules/report-format.md`. This module is test methods: don't stop at "can upload / can download"; follow executable / path / SSRF / cross-user business objects.
> Shortlist pointers are found by searching headings. PHP webshells / GIFAR / ImageTragick / English attachments have been cut; without object storage, don't blindly test cross-bucket.

# File Upload Vulnerability Testing Handbook

## Test Flow (Opening)

Find upload points (avatar / attachment / import / rich text) -> upload a benign file first: check the returned path, whether it gets renamed, whether it lands on CDN/OSS or the local machine, and whether it can be opened directly. Don't stop at "can upload / can download": follow object overwrite of other users, signed reads, and executable / path / SSRF angles. Adapt the suffix / Content-Type / parsing bypasses on the spot according to the stack.

### STS / Object-Key Wildcard Overwrite (Shortlist Pointer)

Recognize: object storage (BOS / OSS / S3 / TOS and the like) issues STS / presigned credentials before upload; the object key is often the file md5; the bucket name increments by date or batch. Or a key-issuing endpoint like assumerole where the `filename` / `Action` in the request gets glued into the Policy. Below, xluser / AES / `1.jpg` are common façades — **run the wildcard even when those exact words are absent**.

Attack:

1. When the credential request's `identifier` / `key` / `object` / `prefix` / `filename` **is not length-validated**, try `*`, `**`, then try **empty** and `/` (some implementations treat an empty prefix as the whole bucket)  
2. One `*` may land on an empty bucket; **two or more** may hit the current business bucket, turning the credential `key` into a wildcard over the current bucket  
3. On path / `actionName` / the path param glued into the Policy, try `../../../`、`../../../&/../../` and see whether the signed scope expands to the root  
4. Other people's object keys are often md5: open the docs page and search JS/endpoints for `md5sum` / `md5` — no download, no payment needed  
5. With the freshly issued STS, set the upload path to that md5 and overwrite the object  
6. assumerole gets one more shot: `filename=*-*` (or `*`), `Action=*`. Some implementations have the **latter Policy section overriding the earlier one**, turning the key into the whole bucket. If it works, `list_objects` first, then delete/overwrite the listed keys. **List/Delete 403 — don't stop**: GET/PUT against arbitrary keys. The key-issuing XHR without a login header gets hit too. **A sibling drive's anonymous ticket saying `illegal user id` does not mean this gateway rejects it either**: keep hitting the STS endpoint that lets an anonymous xluser ticket pass. When `upload_dir`/`dir` in the query goes verbatim into the OSS Policy, fill `*`. When the page is served via CDN, force-refresh or wait for the cache to expire before accepting  
7. On PUT, try `x-cos-acl: public-read` and `x-cos-grant-full-control: id="your UIN"` in the headers (OSS/S3 equivalent headers likewise). **Only when the object really becomes public-read, or control moves to your UIN**, does it count; a bare 200 is not takeover
8. Even with no "file already exists" oracle, still guess short original filenames (`1.jpg`/`2.png`/`5.jpg`) and GET the CDN anonymously. If the token endpoint's front end hardcodes AES/salt, compute the sign yourself unauthenticated; `filename=*` often directly hands out appId+bucket, and once the CDN prefix is assembled you can download **other people's ID photos**  
9. **Landing page hardcodes a supabase / nocode `role=anon` JWT — the rest-table CRUD is not the finish line.** With `apikey` + `Authorization: Bearer`, hit `POST /storage/v1/object/{bucket}/{official-prefix/probe-key}`. Official covers/case images often live under `use-cases/`, `covers/` and the like. First POST your own probe file; POST the same object name again with header `x-upsert: true`, body changed to another marker string. Control the two bodies via public `GET /storage/v1/object/public/{bucket}/{key}`. **Don't actually overwrite official operations images**: being able to overwrite your own just-uploaded file under the same prefix proves the official same-prefix objects are equally overwritable. DELETE the probe file when done. rest `/rest/v1/` 403 — don't stop, Storage REST is often separately open.

Counts as: reopening/downloading **that counterpart's** doc/image now shows the content you uploaded; or listing other people's keys and being able to delete/overwrite them; or `x-upsert` on an official prefix turning your probe file into the second marker string (official objects under the same prefix share the same key). Proving only that you can upload to your own key -> false positive.

False positives: `*` only signs a dead bucket; wildcard works but overwrite is 403; you're changing your own object; the Policy is server-side hardcoded and cannot be overwritten; only your own prefix wildcards; CDN never refreshes so it looks like nothing was overwritten. A miss on this site does not remove the shortlist row.

And S3 presigned "change your own Content-Type", and "signed URL tenant swap reads his files", and the below "bucket policy wide open to anonymous", "signature not bound to Host", "signature overwriting Content-Type" are all not this entry: this one is **the credential scope wildcarded to the whole bucket, overwriting or wiping other people's objects**.

### Signature Not Bound to Host (Shortlist Pointer)

Recognize: COS / OSS / S3 signed URLs; `q-header-list`, `SignedHeaders`, `X-Amz-SignedHeaders` in the query **do not include host**. Only hit when there is object storage with signed URLs; without it don't blindly switch domains.

Attack:

1. Look at which headers the signature parameters cover. No `host` -> continue.  
2. Swap the URL host to the domain of **another bucket in the same account** (copy from cert SAN, errors, console, JS); leave the path and signature query untouched for now.  
3. Then add `?uploads` (or `&uploads` after the existing query) to hit ListMultipartUploads; GET an object if it works too.

Counts as: listing or reading objects **in another bucket**. Swapping domains but staying in your own bucket -> not a success.

False positives: signature covers Host; domain swap 403; only your own bucket exists. A miss on this site does not remove the shortlist row.

And STS `*` (credential scope wildcarded) and signed URL changing only a tenant field **are not this entry**: this one is **Host left out of the signature, the same signature reaching another bucket**.

### Signature Overwrites Content-Type (Shortlist Pointer)

Recognize: you control the object content (your own upload, or STS can overwrite); the object's Content-Type is locked (`image/jpeg` and the like); you hold a temporary key or can mint a new presigned URL.

Attack:

1. The upload-time CT swap shot still runs (`text/HtMl`, `text/html,image/png`). That's "CT wasn't signed at signing time".  
2. **Sign again afterwards**: with the temporary key, mint a GET for the **existing object** carrying `response-content-type=text/html` (COS/OSS support signature-overriding response headers).  
3. Open this newly signed URL in the browser; don't only look at curl's Content-Type.

Counts as: the browser executes it as HTML (stored XSS). Download still as attachment / original CT -> not a success.

False positives: the signing endpoint rejects this parameter; can only change objects you cannot reach; `X-Content-Type-Options: nosniff` and CT stays image. A miss on this site does not remove the shortlist row. Without object storage and a temporary key, don't blindly sign.

And "changing Content-Type at upload PUT" is not this entry: that one changes the type **at write time**; this one is **overriding the response header to HTML with a signature at read time**.

### webpack Plaintext Object-Storage Permanent Keys (Shortlist Pointer)

Recognize: the admin / operations console webpack bakes production `accessKeyId`+`secretAccessKey` (MSS / S3 and the like permanent keys) into the JS. Or Weblogic `/console/login/LoginForm.jsp` inlines an `SRV_` key like `_reportCfg`. The upload sign `getUploadSign` is the front end computing an HMAC-SHA1 policy, not going through a logged-in STS endpoint. The `starts-with $key` in the policy is often an empty string.

Attack (no login):

1. Copy the online/prod AK/SK (real values go only into the report)  
2. Compute the POST policy yourself, stretch the expiration, and keep `starts-with $key` as the JS does (empty stays empty)  
3. POST the bucket: control with a fake signature `SignatureDoesNotMatch`, no signature `conditions has no signature`  
4. PUT an arbitrary key then GET via CDN; DELETE what you just uploaded to prove the key can write. Try overwriting objects already referenced by the official pages  
5. List/PUT 403 — don't stop: first `GetBucketLocation`. Control with a fake AK `InvalidAccessKeyId`. If the page's bucket name is misspelled (staic/static), try neighbors

Counts as: a complete permanent cloud key that can sign (real-sign PUT 200, or GetBucketLocation returning a region). Overwriting existing official objects is even more solid.

False positives: InvalidAccessKeyId; can only upload to a fixed prefix; getUploadSign is actually an SSO endpoint with no local key; the key expired. Real key values never enter the library. A miss on this site does not remove the shortlist row.

And STS wildcard (mint a temporary ticket first), and bucket policy wide open to anonymous (no key needed), and viewer XOR hiding a COS permanent key (must decrypt then ask for AccountId) are all not this entry: this one is **webpack plaintext permanent key + the front end computing the signature itself**.

### Bucket Policy Wide Open to Anonymous (Shortlist Pointer)

Recognize: the official site / console's images, usage guides, and agreements are served directly from an OSS / cloudrun-style bucket domain; the bucket root or `?policy` / GetBucketPolicy / an equivalent policy endpoint opens, and the statements are all Allow.

Attack:

1. Read the policy if readable; then LIST the bucket (no AK)  
2. Try PUT / overwrite on objects **already referenced on the official site** (don't go modify the bucket policy itself)  
3. Prioritize guides, agreements, site maps; verify by opening the original official URL after overwriting

Counts as: the official guide / agreement / image content becomes what you uploaded. Proving only that anonymous LIST works, or only being able to upload to a new unreferenced key -> false positive.

False positives: policy is read-only, cannot write; PUT only lands on your own prefix; what you downloaded was public static pages all along. A miss on this site does not remove the shortlist row.

And STS `*` (apply for credentials first, key wildcarded), and filename `../` crossing tenant directories, and Azure container-level SAS are all not this entry: this one is **bucket policy open to anonymous, no credentials needed**.

### Storage Proxy sign key=/ (Shortlist Pointer)

Recognize: the business gateway proxies object storage behind `/api/storage/sign` (or a similar sign); the query only eats `key`. `key=/` or `key=.` returns S3 `ListBucketResult` XML, not an STS application.

Attack (no login):

1. GET `?key=/` (then try `.`). Control: a garbage key should be `NoSuchKey` / 400  
2. Copy business prefixes from the list (`images/` `editor-` and the like) and GET the same endpoint  
3. Check whether the objects are unpublished material; don't stop at the official Banner

Counts as: listing and reading other people's unpublished object content.

False positives: only app-static public static files; `filename=` 400 treated as no endpoint. A miss on this site does not remove the shortlist row. And STS wildcard (mint a key first), bucket policy anonymous-wide (hit the bucket domain directly) are not this entry: this one is **the business gateway acting as its own List/Get proxy**.


### Artifact Download Detail Treats uin Presence as Login Gate (Shortlist Pointer)

Recognize: software / proprietary-cloud / material download center; the detail JSON has `DownloadURL`; the front end copies `uin`/`skey` from the Cookie into the query. With no identity the URL is an empty string and the page bounces to login.

Attack: GET the detail unauthenticated, fill the identity field with a non-empty fake value (`uin=1`), no skey. Control with empty uin. On the returned signed URL, Range-GET the first tens of bytes to look for ELF/PK.

Counts as: the real proprietary-cloud installer / internal-deployment doc file. Empty uin also returning a URL -> fully unauthenticated (another entry). Signed 403 / only a public manual -> not a success.

### Onboarding JS Hardcodes fileKey (Shortlist Pointer)

Recognize: the onboarding / qualification SPA bundled JS has a mock or demo formData hardcoding a long ciphertext `fileKey`. The site root 301s to a new domain, **the old host's download endpoint may still be alive**. Don't discard the mock as a placeholder, and don't treat the 301 as the whole site being dead.

Attack (no login):

1. Copy `fileKey` from the new-domain chunk  
2. Hit the old host `/json/view/file/downloadFile?fileKey=` (or equivalent)  
3. Control: a garbage fileKey should be empty/error; the real key returns the image

Counts as: the private-bucket license/certificate original image really downloading.

False positives: treating the 301 new domain as the whole site dead; treating the mock fileKey as a placeholder and garbage also returning the same image. A miss on this site does not remove the shortlist row. Real key values and complete JS stay out of this module.

### Share Auth false Still Downloads Media (Shortlist Pointer)

Recognize: cloud-recording share; the auth endpoint has `download_enable`/`view_minutes_enable`. Or the meeting JSON gateway has no `permission/auth` at all (404 — don't stop).

Attack (no login):

1. Hit both `download-multi-record-file` **and** `sign-multi-record-file` (need `auth_share_id`+`resource_type`). The international JSON gateway lacking `sharing_id` only returns `2710500 invalid params`; only carrying `auth_share_id` and `sharing_id` together mints the MP4; missing it makes it look like no bug. **POST JSON reporting "recording id cannot be empty" — don't stop, switch to GET query with record_id / auth_share_id in the URL.**  
2. No auth endpoint — don't treat it as no entry point: hit `public/record-detail/download-multi-record-file` directly.  
3. Summary/timeline `get-full-summary` / `query-timeline` with only `record_id` also try; don't assume a share must be carried.  
4. COS 403 with no Referer **is not the end**: GET again with the share-page Referer.  
5. `permission/get-cfg` — see whether it leaks other records of the same meeting.  
6. Only getting the url without GETting the MP4 counts as half; keep following.

Counts as: auth written false still pulling the real MP4 (ftypisom + size); or just record_id yielding the full minutes body (not the title).

False positives: auth genuinely blocks and the file can't be downloaded; only a public manual; minutes only return the title with no body. A miss on this site does not remove the shortlist row.

### Password-Protected Share Response Carries Plaintext Extraction Code (Shortlist Pointer)

Recognize: the share-detail JSON has one side `need_pwd` / `auth_level` (or similar) saying an extraction code is required, and an auth object stuffing the plaintext extraction code into `pass_word` (or similar). Or the landing HTML / `syncData` inlines the same plaintext code.

Attack (no login):

1. First hit the view endpoint with the extraction code empty. Control: the file list should be empty and the gate field should demand a code.  
2. Copy the plaintext code from the same response and fill it back into the view endpoint. Control: empty code gives an empty list; only with the code does `file_id` appear.  
3. **If the landing HTML / `syncData` already has the plaintext `pass_word`, copy it directly** — no need to hit the View CGI first.  
4. Take `file_id` and this code to the download endpoint, follow to a real file header (PDF/ZIP and the like body); don't stop at the JSON having a code.

Counts as: obtaining the extraction code and downloading the password-protected share body — not an empty-code share that directly returns the file list.

False positives: `pass_word` is a hash that won't log in when copied; empty-code View already returns files (that's an extraction-code-free share, not this shot). A miss on this site does not remove the shortlist row.
Real key values and complete JS stay out of this module.

