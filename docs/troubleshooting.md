# Troubleshooting

Startup problems stop nginx with a message in its error log or on stderr. On a
reload the old configuration keeps running.

## `set "X": set does not exist`

Create the set before starting nginx, for example
`ipset create X hash:ip`. Sets live in a network namespace: nginx in a
container sees the container's sets, not the host's (use `--network host` for
those).

## `set "X": unsupported set type`

Sundew checks `hash:ip`, `hash:net` and `bitmap:ip` sets. Other types, such as
`hash:ip,port` or `list:set`, are refused.

## `helper user "sundew" does not exist`

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin sundew
```

Or name another dedicated account with `sundew_helper_user`.

## `helper "…" must be a regular file owned by root …`

The helper and every directory above it must be owned by root and writable only
by root. Fix the ownership, or point `sundew_helper_path` at a copy that is.

## `sundew requires the nginx master to run as root`

Start nginx as root and set `user`; the workers drop to that account and keep
nothing. nginx started without root, rootless containers and `master_process
off` are not supported.

## `netlink unavailable (is the ip_set kernel module loaded?)`

```bash
modprobe ip_set ip_set_hash_ip ip_set_hash_net ip_set_bitmap_ip
```

In a container the host must have the modules loaded, since containers share
the host kernel.

## `helper startup failed: capability setup failed`

The helper could not keep `CAP_NET_ADMIN`. In Docker, add
`--cap-add NET_ADMIN`; under systemd, `CapabilityBoundingSet=` must include
`CAP_NET_ADMIN`.

## `worker task … has CapEff=…; workers must hold no capabilities`

Something gives the workers capabilities, such as `setcap` on the nginx binary
or `AmbientCapabilities=` in the systemd unit. Remove it: workers need none.

## Requests are denied after a timeout

`sundew: deny … (lookup timeout, …)` at `info` level: the helper did not answer
within `sundew_lookup_timeout`. Most often another process is listing or
restoring a large set, which holds the kernel's ipset lock.

- Raise `sundew_lookup_timeout` if a few hundred milliseconds of delay is
  acceptable.
- Raise `ipset_cache_ttl` so fewer requests need the helper.
- `ipset_fail_open on` lets unknown clients through; cached bans still apply.

## `helper channel closed; lookups now follow the fail policy`

The helper exited, for example because it was killed. Cached bans keep
applying; a reload starts a new helper. The helper restarts its engine by
itself after a crash; this message means the whole helper is gone.

## A location is not protected

A location that only uses `return` answers before the check runs. Serve a file,
proxy, or move `return` into a named location reached through `error_page`.
