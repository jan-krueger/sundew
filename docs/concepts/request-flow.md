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
while a question is on its way wait for the same answer.

--8<-- "request-path.html"


## What it costs

| Case | Work |
| --- | --- |
| Cache hit | A lookup in shared memory, inside the worker |
| Cache miss | One message to the helper and one kernel lookup per set; the worker serves other requests meanwhile |
| Kernel busy (another process lists or restores a large set) | The request waits up to [`sundew_lookup_timeout`](../reference/directives.md#sundew_lookup_timeout), then [`ipset_fail_open`](../reference/directives.md#ipset_fail_open) applies |
| `ipset_ratelimit` | One update of a counter in shared memory |

Most traffic comes from addresses seen within the last
[`ipset_cache_ttl`](../reference/directives.md#ipset_cache_ttl), so most
requests are cache hits. The size of a set does not change the cost of a
lookup.

After an internal redirect (`index`, `try_files`) the request is checked
again, which is a cache hit. Subrequests are not checked.

!!! warning "`return` runs first"
    `return` answers in the `REWRITE` phase, before `PREACCESS`. A location
    that only does `return` is never checked.
