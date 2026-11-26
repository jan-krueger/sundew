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
| nginx worker | your `user` | none, checked at start | Ask the helper about an address and a list of set numbers |
| sundew-keeper | `sundew` | `CAP_NET_ADMIN` | Restart the engine; reads nothing from workers |
| sundew-engine | `sundew` | `CAP_NET_ADMIN` | Look up the configured sets, nothing else |

## If an attacker takes over a worker

| They can | They cannot |
| --- | --- |
| Ask whether an address is in one of the configured sets | Name any other set: questions carry set numbers the master assigned |
| Get their own channel closed by sending garbage | Change a set, a firewall rule, a route or an interface: version 0.1 has no code that writes to the kernel |
| | Signal, trace or read the helper: another account, not dumpable |
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
- **`ipset_fail_open on` is a choice.** Whoever can slow the kernel's ipset
  lock down, for example by making someone list a huge set, gets unknown
  addresses through. Cached bans still apply.
- **realip decides the address.** Trusting the wrong proxies lets clients pick
  the address Sundew checks; see
  [Behind a CDN](../guides/behind-a-proxy.md).

Found a hole? Report it privately: see
[SECURITY.md](https://github.com/jan-krueger/sundew/blob/main/SECURITY.md).
