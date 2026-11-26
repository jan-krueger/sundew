---
hide:
  - toc
---

# How a request is checked

Sundew runs in nginx's `PREACCESS` phase: after `realip` has set the client
address, before `limit_req` counts the request. Denied clients never use a
`limit_req` slot.

--8<-- "outcomes.html"

## The verdict

| Lists in the location | Client | Result |
| --- | --- | --- |
| Denylist | In any of its sets | Deny |
| Denylist | In none | Allow |
| Allowlist (with or without a denylist) | In any allowlist set | Allow; the denylist is not consulted |
| Allowlist | In none | Deny |

## A lookup that is not cached

The worker does not block while it waits: it sends one 48-byte question and
goes on serving other connections. Requests for the same address that arrive
while a question is on its way wait for the same answer: 40 concurrent requests
for one address make one lookup per worker.

--8<-- "request-path.html"


## What it costs

| Case | Cost |
| --- | --- |
| Cache hit | Under a microsecond; no measurable change in throughput in our tests |
| Cache miss | One round trip to the helper; the kernel lookup itself takes about 3 µs |
| Kernel busy | Up to `sundew_lookup_timeout`; the worker keeps serving others |

After an internal redirect (`index`, `try_files`) the request is checked
again, which is a cache hit. Subrequests are not checked.

!!! warning "`return` runs first"
    `return` answers in the `REWRITE` phase, before `PREACCESS`. A location
    that only does `return` is never checked.
