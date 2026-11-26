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

Measured with the release image serving a small static file, the case where
Sundew's share of the work is largest:

| Case | Requests/s | Compared with no check |
| --- | --- | --- |
| No check (`ipset_denylist off`) | 158,400 | — |
| Cache hit, allowed | 148,500 | −6% |
| Cache hit, denied (403) | 256,600 | a 403 is cheaper to send than the page |
| A new address on every request: every request asks the helper | 100,900 | −36% |
| The same against a set of 1,000,000 entries | 111,600 | set size does not matter |

nginx 1.30.8, `worker_processes auto` on 12 CPUs (Intel i7-9750H), `wrk -t 4 -c 64`
for 10 s, median of 3 runs. Reproduce with `make bench`.

- A cache hit is answered inside the worker; misses share one helper, which
  handles roughly 100,000 lookups a second.
- Most traffic comes from addresses seen within the last
  [`ipset_cache_ttl`](../reference/directives.md#ipset_cache_ttl), so real
  workloads sit close to the cache-hit row.
- While the kernel is busy (another process lists or restores a large set), a
  miss waits up to [`sundew_lookup_timeout`](../reference/directives.md#sundew_lookup_timeout);
  the worker keeps serving other requests.

After an internal redirect (`index`, `try_files`) the request is checked
again, which is a cache hit. Subrequests are not checked.

!!! warning "`return` runs first"
    `return` answers in the `REWRITE` phase, before `PREACCESS`. A location
    that only does `return` is never checked.
