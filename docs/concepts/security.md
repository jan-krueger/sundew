---
hide:
  - toc
---

# Security model

nginx's workers parse whatever the internet sends. Sundew gives them nothing
worth taking: the one privilege it needs, `CAP_NET_ADMIN`, lives in a separate,
small helper.

--8<-- "architecture.html"

## Who can do what

| Process | Account | Capabilities | Can |
| --- | --- | --- | --- |
| nginx master | root | as started | Start workers and the helper |
| nginx worker | your `user` | none, checked at start | Ask the helper about an address and a list of set numbers, or to apply an add rule to an address |
| sundew-keeper | `sundew` | `CAP_NET_ADMIN` | Restart the engine; reads nothing from workers |
| sundew-engine | `sundew` | `CAP_NET_ADMIN` | Look up the configured sets, and add to the sets in `sundew_writable_sets` through the configured rules |

## If an attacker takes over a worker

| They can | They cannot |
| --- | --- |
| Ask whether an address is in one of the configured sets | Name any other set: requests carry set and rule numbers the master assigned |
| Add addresses to the writable sets, through the configured rules | Choose the set, the timeout or the prefix: those come from the rule. Never longer than the rule's timeout |
| Add up to 20 addresses a second per rule (bursts of 100) | Add more: the helper refuses, and pauses a rule after 1,000 adds in a minute |
| | Add protected addresses (private, loopback, your `sundew_protect` prefixes), or a prefix that overlaps them |
| | Remove an address, change a firewall rule, a route or an interface: the helper has no code to delete or to build any other netlink message |
| | Extend an existing ban: an address already in the set keeps its timeout |
| Get their own channel closed by sending garbage | Signal, trace or read the helper: another account, not dumpable |
| | Use the helper's privileges through an inherited file descriptor: the kernel checks the caller too |

## How the helper is confined

<div class="grid two" markdown>

!!! abstract "Fresh process"
    A separate binary started with `execveat()`, not a fork of nginx: none of
    nginx's memory, TLS keys, shared memory or sockets. Empty environment, only
    its own file descriptors.

!!! abstract "Minimal identity"
    Runs as `sundew` with `CAP_NET_ADMIN` alone, locked securebits,
    `no_new_privs`, not dumpable, no core files, cannot create processes.

!!! abstract "seccomp"
    Killed on any system call outside a short list: socket and netlink I/O,
    epoll, memory, clock.

!!! abstract "Landlock"
    Where the kernel supports it: no file access, no TCP, no abstract unix
    sockets, no signals.

</div>

Before it starts, nginx checks that the helper binary and every directory
above it belong to root and are writable only by root. The helper checks that
it is not setuid, setgid or carrying file capabilities, and that its control
socket's peer is root.

## Limits

- **seccomp cannot read netlink messages.** A compromised engine controls
  netfilter in its network namespace. That is why the engine is small, written
  in Rust, and its decoders are fuzzed.
- **Answers are cached.** A change to a set can take
  [`ipset_cache_ttl`](../reference/directives.md#ipset_cache_ttl) to apply.
- **Bans follow the address nginx sees.** A client who can choose its apparent
  address, through a wrongly trusted proxy header, can get others banned by a
  honeypot or a rate limit. The protected list stops the worst case (your own
  proxies and private networks), and browser requests never trigger a
  honeypot; see the [honeypot guide](../guides/honeypot.md).
- **`ipset_fail_open on` is a choice.** Whoever can slow the kernel's ipset
  lock down, for example by making someone list a huge set, gets unknown
  addresses through. Cached bans still apply.
- **realip decides the address.** Trusting the wrong proxies lets clients pick
  the address Sundew checks; see
  [Behind a CDN](../guides/behind-a-proxy.md).

Found a hole? Report it privately: see
[SECURITY.md](https://github.com/jan-krueger/sundew/blob/main/SECURITY.md).
