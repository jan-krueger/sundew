# Variables

| Variable | Value |
| --- | --- |
| `$ipset_result` | `allow`, `deny` or `dryrun`. Empty when the request was not checked: no list applies, or it is a subrequest |
| `$ipset_matched_set` | The set that decided: the denylist set the client is in, or the allowlist set that let it in. Empty otherwise |

Both describe the main request and can be used in any phase after the check,
for example in logs and headers.

```nginx
log_format sundew '$remote_addr $status $ipset_result $ipset_matched_set "$request"';
access_log /var/log/nginx/access.log sundew;
```

```text
198.51.100.7 403 deny f2b-web "GET /wp-login.php HTTP/1.1"
203.0.113.5 200 allow office "GET /admin/ HTTP/2.0"
192.0.2.10 200 allow - "GET / HTTP/2.0"
```

!!! warning
    Do not send `$ipset_matched_set` to clients, for example in a response
    header: it tells an attacker which list caught them.
