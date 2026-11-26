---
hide:
  - toc
---

# Caching

Every worker reads and writes one cache in shared memory, `sundew_cache`. It
keeps answers across reloads, so a reload does not send a burst of lookups to
the kernel.

## What is cached

| Answer | Cached | Reused for |
| --- | --- | --- |
| In the set | Yes | [`ipset_cache_ttl`](../reference/directives.md#ipset_cache_ttl), then up to 10 more minutes while no fresh answer can be had |
| Not in the set | Yes: most traffic matches nothing | `ipset_cache_ttl` |
| Error, timeout | No | — |

An answer belongs to one address and one set. The set is identified by its
name, family, type and revision, so a set that is destroyed and recreated with
another type starts fresh.

## How fresh

The kernel does not announce changes to sets, so a change made by fail2ban or
an admin reaches nginx:

--8<-- "timeline.html"

- An address not looked up within the last `ipset_cache_ttl`: on its next
  request.
- An address looked up recently: when its cached answer expires, at most
  `ipset_cache_ttl` later.

`ipset_cache_ttl 0` asks the kernel on every request.

## How big

| `sundew_cache_size` | Answers |
| --- | --- |
| `1m` | about 25,000 |
| `16m` (default) | about 450,000 |
| `64m` | about 1,800,000 |

One answer is one address for one set: an address checked against three sets
takes three. A full cache costs extra lookups, not errors: the oldest answer in
a bucket makes room.

## Why attackers cannot flood it

Positions in the cache come from SipHash with a random key chosen at start, so
an attacker cannot pick IPv6 addresses that all land in one bucket. Readers
take no lock; a worker that dies while writing leaves a bucket the next writer
repairs.
