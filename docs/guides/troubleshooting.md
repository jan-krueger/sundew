# Troubleshooting

By symptom. For a message from the error log, look it up in
[Log messages](../reference/messages.md).

## nginx does not start, or a reload is ignored

Look at the error log, or the output of `systemctl status nginx`. Sundew always
says why, and on a reload the old configuration keeps running. The usual
causes:

| Message starts with | Fix |
| --- | --- |
| `set "X": set does not exist` | Create the set before nginx starts, see [fail2ban](fail2ban.md#1-create-the-set-at-boot) |
| `helper user "sundew" does not exist` | `useradd --system --no-create-home --shell /usr/sbin/nologin sundew` |
| `helper "…" must be a regular file owned by root` | `chown root:root` and `chmod 0755` the helper and its directories |
| `helper startup failed: netlink unavailable` | `modprobe ip_set`; in a container, on the host |
| `helper startup failed: capability setup failed` | Docker: `--cap-add NET_ADMIN`. systemd: allow `CAP_NET_ADMIN` in `CapabilityBoundingSet=` |

## Every request gets 403

Most likely the helper cannot answer and `ipset_fail_open` is `off`.

1. Look for `lookup timed out` or `helper channel closed` in the error log at
   `info` and above.
2. Is the helper running? `ps -eo user,comm | grep sundew` should list
   `sundew-keeper` and `sundew-engine`.
3. A reload starts a fresh helper.

If the log shows `deny … (not in allowlist, …)`, an allowlist applies to that
location and the client is not in it.

## A banned address still gets through

- **The answer is cached.** Changes reach addresses nginx has seen within
  [`ipset_cache_ttl`](../reference/directives.md#ipset_cache_ttl), 60 s by
  default.
- **nginx sees another address.** Behind a proxy, configure realip; log
  `$remote_addr` to see what Sundew checks. See
  [Behind a CDN](behind-a-proxy.md).
- **The location only uses `return`.** `return` answers before Sundew runs.
  Serve a file, proxy, or send the request through `error_page` to a named
  location.
- **Wrong family.** An IPv6 client is checked against IPv6 sets only.
- **Dry run.** `ipset_dryrun on` logs instead of denying.

## Requests are slow

A request waits for the helper only when its answer is not cached, at most
[`sundew_lookup_timeout`](../reference/directives.md#sundew_lookup_timeout).
Timeouts mean the kernel's ipset lock is busy, most often because another
process lists or restores a large set (`ipset list`, `ipset save`). Raise
`ipset_cache_ttl` so fewer requests need the kernel, and avoid listing large
sets on busy servers.
