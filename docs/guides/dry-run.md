# Roll out a new list safely

Before a new blocklist blocks anyone, find out whom it would block.

## 1. Deny in dry-run mode

```nginx
location / {
    ipset_denylist new_feed;
    ipset_dryrun   on;
}
```

Requests from addresses in `new_feed` go through; each one logs at `notice`:

```text
sundew: dryrun, would deny 198.51.100.7 (in denylist, set new_feed), client: 198.51.100.7, …
```

## 2. Count what would happen

Put the result in the access log:

```nginx
log_format sundew '$remote_addr $status $ipset_result $ipset_matched_set "$request_uri"';
access_log /var/log/nginx/sundew.log sundew;
```

```bash
# addresses that would be denied, most requests first
awk '$3 == "dryrun" { print $1 }' /var/log/nginx/sundew.log | sort | uniq -c | sort -rn | head

# paths they asked for
awk '$3 == "dryrun" { print $5 }' /var/log/nginx/sundew.log | sort | uniq -c | sort -rn | head
```

Look for paths your users need, such as your login page or health checks, and
for addresses of partners and monitoring.

## 3. Enforce

Remove `ipset_dryrun on;` and reload. `$ipset_result` now reads `deny` for the
same requests, and they get [`ipset_status`](../reference/directives.md#ipset_status).

!!! tip
    `ipset_dryrun` works per location: enforce on `/login` first, keep
    observing everywhere else.
