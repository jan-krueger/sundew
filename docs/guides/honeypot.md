# Catch scanners with a honeypot

Scanners request paths your site does not have: `/wp-login.php`, `/.env`,
`/phpmyadmin/`. Turn those paths into traps. The first request adds the
scanner to a set; every later request from it is denied, on every location
that denies the set.

## 1. Create the set

```bash
sudo ipset create scanners hash:ip timeout 86400
sudo ipset create scanners6 hash:ip family inet6 timeout 86400
```

The set needs the `timeout` option: Sundew refuses to add to a set whose
entries would never expire.

## 2. Configure

```nginx
sundew_writable_sets scanners scanners6;        # top level of nginx.conf

http {
    ipset_denylist scanners scanners6;

    server {
        location = /wp-login.php    { ipset_autoadd scanners scanners6; }
        location = /.env            { ipset_autoadd scanners scanners6; }
        location ^~ /phpmyadmin/    { ipset_autoadd scanners scanners6; }
    }
}
```

- A trap answers 404 by default, like any missing page; `status=` changes it.
- Each client goes to the set of its address family: IPv4 to `scanners`, IPv6
  to `scanners6`.
- `timeout=1h` overrides the set's default timeout for this trap.

## 3. Check

```console
$ curl -s -o /dev/null -w '%{http_code}\n' https://example.com/wp-login.php
404
$ sudo ipset test scanners 198.51.100.7
198.51.100.7 is in set scanners.
$ curl -s -o /dev/null -w '%{http_code}\n' https://example.com/
403
```

The ban applies from the next request, in every worker: Sundew writes it into
its cache as soon as the kernel confirms it.

## What keeps a honeypot from banning the wrong people

| Risk | Protection |
| --- | --- |
| A page makes visitors' browsers load the trap (`<img src="/wp-login.php">`) | Requests with `Sec-Fetch-*` headers, and prefetches, are answered but not added. Scanners do not send these headers |
| Your load balancer, CDN or monitoring hits the trap | Private, loopback and link-local addresses are never added. Add your CDN's ranges with [`sundew_protect`](../reference/directives.md#sundew_protect) |
| Behind a proxy, every client looks like the proxy | Configure [realip](behind-a-proxy.md); a protected proxy address is refused, and logged |
| Someone floods the trap from many addresses to fill the set | At most 20 adds a second per rule, and a pause after 1,000 in a minute, logged at `alert` |
| A crawler you want follows a link to the trap | Disallow the trap paths in `robots.txt` |

Try it first: with `ipset_dryrun on` in the trap locations, Sundew logs
`dry run, not adding …` instead.
