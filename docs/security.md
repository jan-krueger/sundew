# Security model

nginx workers parse untrusted traffic, so Sundew gives them nothing worth
stealing. The one privilege it needs, `CAP_NET_ADMIN`, lives in a separate,
small helper process.

## What each process holds

| Process | Account | Capabilities | Can |
| --- | --- | --- | --- |
| nginx master | root | as started | Start workers and the helper; not changed by Sundew |
| nginx worker | your `user` | none, checked at start; `no_new_privs` set | Ask the helper about an address and a list of set numbers |
| `sundew-keeper` | `sundew` | `CAP_NET_ADMIN` only | Restart the engine; reads nothing from workers |
| `sundew-engine` | `sundew` | `CAP_NET_ADMIN` only | Query the sets in the configuration, nothing else |

A worker whose threads hold any capability refuses to start.

## What a compromised worker can do

- Ask whether an address is in one of the configured sets. It cannot name any
  other set; requests carry set numbers that the master assigned.
- Not change any set, firewall rule, route or interface: v0.1 contains no code
  that writes to the kernel.
- Not signal, trace or read the helper: it runs as another account and is not
  dumpable.

A malformed request closes that worker's channel; the helper and the other
workers carry on.

## How the helper is confined

The helper is a separate binary started with `execveat()`, not a fork of nginx,
so it holds none of nginx's memory: no TLS keys, no shared memory, no listening
sockets.

Before it reads any request, it:

- runs as `sundew` with only `CAP_NET_ADMIN`, locked securebits and
  `no_new_privs`;
- has an empty environment and only its own file descriptors;
- is not dumpable and writes no core files; `RLIMIT_NPROC` 0 stops it creating
  processes;
- applies Landlock where the kernel supports it: no file access, no TCP
  connect or bind, no abstract unix sockets, no signals;
- installs a seccomp filter that kills it on any system call outside a short
  list (netlink and socket I/O, epoll, memory, clock);
- checks it is not setuid, setgid or carrying file capabilities, and that its
  control socket's peer is root.

nginx refuses to start a helper binary, or one under a directory, that is not
owned by root or is group- or world-writable.

## Limits

- seccomp cannot inspect what the engine sends over netlink. A compromised
  engine controls netfilter in its network namespace. This is why the engine is
  small, written in Rust, and its decoders are fuzzed.
- Cached answers can be up to `ipset_cache_ttl` old. Lower it, or set `0`, if a
  ban must apply within a second.
- With `ipset_fail_open on`, an attacker who can slow the helper down (for
  example by filling a set the kernel scans under one global lock) gets
  unknown addresses through. Cached bans still apply.

Report vulnerabilities privately, see
[SECURITY.md](https://github.com/jan-krueger/sundew/blob/main/SECURITY.md).
