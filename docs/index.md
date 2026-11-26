# Sundew

Sundew blocks or allows nginx clients by checking their address against Linux
kernel ipsets. A set changed by fail2ban, CrowdSec, a cron job or an admin
applies to the next request; nginx does not reload.

```nginx
load_module modules/ngx_http_sundew_module.so;

http {
    ipset_denylist bad_guys;
}
```

nginx workers keep **no privileges at all**. A small helper process, started
and supervised by nginx, is the only process with `CAP_NET_ADMIN`, and it only
answers "is this address in set X?" for the sets your configuration names.

!!! note
    Sundew is pre-release (0.1.0-dev). The
    [changelog](https://github.com/jan-krueger/sundew/blob/main/CHANGELOG.md)
    says what exists.

## Why check sets in nginx

| Firewall-only blocking | Sundew |
| --- | --- |
| Sees the TCP peer: your CDN or load balancer | Sees the client address after nginx's `realip` module |
| Blocks every port and path | Per server and per location rules |
| No dry run | `ipset_dryrun on` logs what would be blocked |
| Drops packets silently | Returns a status (403, 503, 444, …) and sets `$ipset_result` for logs |

## Where to start

| You want to… | Read |
| --- | --- |
| Install it and block a set | [Getting started](getting-started.md) |
| Look up a directive or variable | [Configuration](configuration.md) |
| Know what each process may do | [Security model](security.md) |
| Scrape counters | [Monitoring](monitoring.md) |
| Fix a startup error | [Troubleshooting](troubleshooting.md) |
| Understand the request path and reloads | [How it works](internals/how-it-works.md) |
| Check versions and the commercial module's directives | [Compatibility](internals/compatibility.md) |
