# Rate-limit and ban abusers

Allow each client a number of requests per time window. Clients that go over
get 429; with `autoban=`, they are also added to a set and denied everywhere
for a while.

## 1. Create the ban set

```bash
sudo ipset create abusers hash:ip timeout 3600
sudo ipset create abusers6 hash:ip family inet6 timeout 3600
```

## 2. Configure

```nginx
sundew_writable_sets abusers abusers6;          # top level of nginx.conf

http {
    ipset_denylist abusers abusers6;

    server {
        location /login {
            ipset_ratelimit rate=10 window=1m autoban=abusers,abusers6 ban_time=30m;
            proxy_pass http://backend;
        }

        location /api/ {
            ipset_ratelimit rate=600 window=1m;     # 429 only, no ban
            proxy_pass http://backend;
        }
    }
}
```

| Request | Result |
| --- | --- |
| 1st–10th within a minute | Passes |
| 11th | 429, and the client is added to `abusers` for 30 minutes |
| Any request while in `abusers` | 403, on every location that denies `abusers` |

## How it counts

- A sliding window: the count of the previous window is weighted by how much of
  it still overlaps, so a burst at a window boundary does not get twice the
  rate.
- Each `ipset_ratelimit` line has its own counters.
- IPv6 clients are counted per /64 (`key6=`), since one host often has many
  addresses.
- Clients in an `ipset_allowlist` are not counted.
- Counters live in shared memory, `sundew_ratelimit_zone_size` (8 MB for about
  180,000 clients). When it is full, the client not seen for longest is
  forgotten.

## Ban safely

- Requests with `Sec-Fetch-Site: cross-site` get 429 but never a ban: another
  site could make your visitors' browsers send them.
- Private and loopback addresses, and anything in
  [`sundew_protect`](../reference/directives.md#sundew_protect), are never
  banned. Put your CDN and monitoring there.
- Many users can share one address (offices, mobile carriers): keep
  `ban_time` short and the rate generous on pages everyone uses.

With `ipset_dryrun on`, Sundew logs `would rate-limit` instead of sending 429
and banning.
