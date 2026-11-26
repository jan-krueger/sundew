# Sundew

Kernel ipset access control for nginx, without giving your web server root.

Sundew blocks or allows clients by checking their address against Linux
ipsets. A set changed by fail2ban, CrowdSec or an admin applies to the next
request, with no reload. It works behind CDNs and load balancers through
nginx's `realip` module, for IPv4 and IPv6, over HTTP/1.1, HTTP/2 and HTTP/3.

```nginx
load_module modules/ngx_http_sundew_module.so;

http {
    ipset_blacklist bad_guys;
}
```

nginx workers keep no privileges. A small helper that nginx starts and
supervises is the only process with `CAP_NET_ADMIN`; it runs under seccomp and
Landlock and answers only for the sets your configuration names. See the
[security model](docs/security.md).

Directive names match the commercial `ipset_*` module, so configurations can
move over; see [Compatibility](docs/internals/compatibility.md).

**Status:** pre-release, `0.1.0-dev`. Lookups only: `ipset_autoadd` and
`ipset_ratelimit` are planned for 0.2.

## Documentation

| | |
| --- | --- |
| [Getting started](docs/getting-started.md) | Build, install, block a set |
| [Configuration](docs/configuration.md) | Directives and variables |
| [Security model](docs/security.md) | What each process may do |
| [Monitoring](docs/monitoring.md) | JSON and Prometheus counters |
| [Troubleshooting](docs/troubleshooting.md) | Startup errors and their fixes |
| [How it works](docs/internals/how-it-works.md) | Processes, cache, reloads |

## License

BSD 2-Clause; see [LICENSE](LICENSE). Not affiliated with nginx, F5 or
GetPageSpeed.
