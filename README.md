# Sundew

Kernel ipset access control for nginx, without giving your web server root.

Sundew blocks or allows clients by checking their address against Linux
ipsets. A set changed by fail2ban, CrowdSec or an admin applies to the next
request, with no reload. It works behind CDNs and load balancers through
nginx's `realip` module, for IPv4 and IPv6, over HTTP/1.1, HTTP/2 and HTTP/3.

```bash
echo 'ipset_denylist bad_guys;' > sundew.conf
docker run -d --cap-add NET_ADMIN --network host \
    -v "$PWD/sundew.conf:/etc/nginx/conf.d/sundew.conf:ro" ghcr.io/jan-krueger/sundew:latest
```

Prebuilt modules exist for the nginx.org packages, Debian 13 and Ubuntu 24.04;
any other nginx 1.24+ builds from source. See
[Get started](docs/get-started.md).

nginx workers keep no privileges. A small helper that nginx starts and
supervises is the only process with `CAP_NET_ADMIN`; it runs under seccomp and
Landlock and answers only for the sets your configuration names. See the
[security model](docs/concepts/security.md).

Configurations written for the commercial `ipset_*` module work as they are,
including `ipset_blacklist` and `ipset_whitelist`; Sundew's own names are
`ipset_denylist` and `ipset_allowlist`. See
[migration guide](docs/guides/migrate.md).

**Status:** pre-release, `0.1.0-dev`. Lookups only: `ipset_autoadd` and
`ipset_ratelimit` are planned for 0.2.

## Documentation

The documentation is published at <https://jan-krueger.github.io/sundew/>.

| | |
| --- | --- |
| [Get started](docs/get-started.md) | Install with Docker, a prebuilt module or from source; block your first address |
| [Guides](docs/guides/index.md) | fail2ban, CDNs, admin areas, dry runs, Docker and Kubernetes, Prometheus, migration |
| [Directives](docs/reference/directives.md) | Every directive, with syntax, default and context |
| [Log messages](docs/reference/messages.md) | What each message means and how to fix it |
| [Security model](docs/concepts/security.md) | What each process may do |
| [How a request is checked](docs/concepts/request-flow.md) | The request path, the cache and what it costs |

## License

BSD 2-Clause; see [LICENSE](LICENSE). Not affiliated with nginx, F5 or
GetPageSpeed.
