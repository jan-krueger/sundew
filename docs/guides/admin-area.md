# Restrict an admin area

Let only addresses in a set into a location, and keep the list in an ipset your
VPN or office tooling maintains.

```bash
sudo ipset create office hash:net
sudo ipset add office 198.51.100.0/24
sudo ipset create vpn hash:ip
sudo ipset add vpn 203.0.113.5
```

```nginx
server {
    ipset_denylist bad_guys;

    location /admin/ {
        ipset_allowlist office vpn;
        ipset_status    404;
        proxy_pass      http://backend;
    }
}
```

| Client | `/admin/` | Elsewhere |
| --- | --- | --- |
| In `office` or `vpn` | Allowed, even if also in `bad_guys` | Denied if in `bad_guys` |
| In neither | 404 | Allowed unless in `bad_guys` |

- An allowlist lets **only** its members in, and members skip the denylist.
- `ipset_status 404` hides that the area exists. Any 4xx or 5xx works, or `444`
  to close the connection.
- A client is checked against the sets of its own address family. With only
  IPv4 sets in the allowlist, every IPv6 client gets the 404; add a
  `family inet6` set if staff connect over IPv6.

!!! warning "When the helper cannot answer"
    With the default `ipset_fail_open off`, an allowlisted location denies
    everyone whose answer is not cached while the helper is unavailable.
    Allowlist members seen within the last
    [`ipset_cache_ttl`](../reference/directives.md#ipset_cache_ttl) plus 10
    minutes still get in.
