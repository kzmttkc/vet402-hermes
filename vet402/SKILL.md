---
name: vet402
description: Check a seller in vet402 before paying, buying, or calling a paid API. Use this when asked whether to pay, whether the seller delivered, or to look up a paid URL before paying.
version: 0.2.0
---

# vet402

## When to use

The user says any of:

- "Should I pay this API?"
- "Has this seller delivered after I paid?"
- "Look up this paid URL before paying"

## Before an approval

Call `vet402_check` before a payment. Write all of the following into the approval body before asking a person to approve:

- the URL, with the query string and any userinfo removed
- the HTTP method
- the verdict (ALLOW, WARN, BLOCK, unknown, unavailable, or rejected)
- the reason codes
- the evidence link

Do not pay, buy, or call the paid API until the record for that method is ALLOW, or a person has approved that exact body. A refusal pays nothing. `mpp_fetch` does not run.
