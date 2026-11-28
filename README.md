# Sundew

Kernel ipset and nftables access control for nginx, without giving your web
server root.

Sundew blocks or allows clients by checking their address against Linux
ipsets or nftables sets. A set changed by fail2ban, CrowdSec or an admin
applies to the next request, with no reload. It works behind CDNs and load balancers through
nginx's `realip` module, for IPv4 and IPv6, over HTTP/1.1, HTTP/2 and HTTP/3.

```bash
echo 'ipset_denylist bad_guys;' > sundew.conf
docker run -d --cap-add NET_ADMIN --network host \
    -v "$PWD/sundew.conf:/etc/nginx/conf.d/sundew.conf:ro" ghcr.io/jan-krueger/sundew:latest
```

Prebuilt modules exist for the nginx.org packages, Debian 12 and 13, and
Ubuntu 22.04 and 24.04; any other nginx 1.18+ builds from source. See
[Get started](https://jan-krueger.github.io/sundew/get-started/).

nginx workers keep no privileges. A small helper that nginx starts and
supervises is the only process with `CAP_NET_ADMIN`; it runs under seccomp and
Landlock and answers only for the sets your configuration names. See the
[security model](https://jan-krueger.github.io/sundew/concepts/security/).

Configurations written for the commercial `ipset_*` module work as they are,
including `ipset_blacklist` and `ipset_whitelist`; Sundew's own names are
`ipset_denylist` and `ipset_allowlist`. See the
[migration guide](https://jan-krueger.github.io/sundew/guides/migrate/).

**Status:** 0.3. Denylists and allowlists in ipsets and nftables sets,
honeypots (`ipset_autoadd`) and rate limiting with bans (`ipset_ratelimit`).

## Documentation

The documentation is published at <https://jan-krueger.github.io/sundew/>.

| | |
| --- | --- |
| [Get started](https://jan-krueger.github.io/sundew/get-started/) | Install with Docker, a prebuilt module or from source; block your first address |
| [Guides](https://jan-krueger.github.io/sundew/guides/) | Honeypots, rate limits, fail2ban, nftables, CDNs, admin areas, dry runs, Docker and Kubernetes, Prometheus, migration |
| [Directives](https://jan-krueger.github.io/sundew/reference/directives/) | Every directive, with syntax, default and context |
| [Log messages](https://jan-krueger.github.io/sundew/reference/messages/) | What each message means and how to fix it |
| [Security model](https://jan-krueger.github.io/sundew/concepts/security/) | What each process may do |
| [How a request is checked](https://jan-krueger.github.io/sundew/concepts/request-flow/) | The request path, the cache and what it costs |

## License

BSD 2-Clause; see [LICENSE](LICENSE). Not affiliated with nginx, F5 or
GetPageSpeed.
