# Configuration

## Access rules

Context: `http`, `server`, `location`. A level that sets a directive replaces
what it inherits; it does not add to it.

| Directive | Default | Effect |
| --- | --- | --- |
| `ipset_blacklist set ... \| off` | — | Deny clients in any of the sets. `off` cancels an inherited list |
| `ipset_whitelist set ... \| off` | — | Allow only clients in at least one of the sets; members skip the blacklist |
| `ipset_status code` | `403` | Status for denied clients: 400–599, or 444 to close the connection (on HTTP/2 and HTTP/3, the stream) |
| `ipset_fail_open on \| off` | `off` | What happens when no answer is available, see [below](#when-there-is-no-answer) |
| `ipset_dryrun on \| off` | `off` | Log `sundew: dryrun, would deny …` at `notice` and let the request through |
| `ipset_cache_ttl time` | `60s` | How long an answer is reused. `0` asks the kernel on every request |
| `sundew_lookup_timeout time` | `100ms` | How long a request waits for the helper |

- Sets: up to 64 per configuration, names of 1–31 characters from
  `A-Za-z0-9_.:-`, types `hash:ip`, `hash:net` and `bitmap:ip`. nginx refuses to
  start, or keeps its old configuration on reload, if a set is missing or of
  another type.
- A client is checked against the sets of its own address family. An IPv4
  client mapped into IPv6 (`::ffff:192.0.2.1`) is checked as IPv4. With
  `ipset_whitelist`, a client whose family has no whitelist set is denied.
- The check runs in nginx's `PREACCESS` phase, after `realip` and before
  `limit_req`. Denied clients never use a `limit_req` slot.
- Subrequests are not checked. After an internal redirect (for example `index`
  or `try_files`) the request is checked again, which is a cache hit.

!!! warning "`return` answers before the check"
    `return` runs in the `REWRITE` phase, before `PREACCESS`. A location that
    only does `return` is not protected.

## When there is no answer

A lookup has no answer when the helper does not reply within
`sundew_lookup_timeout`, reports an error, or is not running.

1. A ban cached within `ipset_cache_ttl` plus 10 minutes still denies, so
   overloading the helper does not unban anyone.
2. Otherwise `ipset_fail_open off` denies with `ipset_status`, and
   `ipset_fail_open on` allows.

## Helper

Context: `main`.

| Directive | Default | Effect |
| --- | --- | --- |
| `sundew_cache_size size` | `16m` | Shared memory for cached answers; at least `1m`. 16 MB holds about 450,000 answers |
| `sundew_helper_path path` | next to the module | The helper binary. It and every parent directory must be owned by root and not group- or world-writable |
| `sundew_helper_user name` | `sundew` | Account the helper runs as. Must exist, and must be neither root nor the worker `user` |
| `sundew_handshake_timeout time` | `5s` | How long nginx waits for a new helper to check the sets at start and on reload |
| `sundew_helper_drain_timeout time` | `1h` | How long a helper from before a reload keeps answering old workers. `worker_shutdown_timeout` plus 60 s when that is set |

## Endpoints

Context: `location`. See [Monitoring](monitoring.md).

| Directive | Serves |
| --- | --- |
| `ipset_stats` | Counters as JSON |
| `ipset_metrics` | Counters in the Prometheus text format |

## Variables

| Variable | Value |
| --- | --- |
| `$ipset_result` | `allow`, `deny` or `dryrun`; empty when the request was not checked |
| `$ipset_matched_set` | The set that decided: the blacklist set the client is in, or the whitelist set that let it in. Empty otherwise |

```nginx
log_format sundew '$remote_addr $status $ipset_result $ipset_matched_set "$request"';
```

## Examples

### Behind a CDN

```nginx
http {
    set_real_ip_from 203.0.113.0/24;      # your CDN's ranges
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;

    ipset_blacklist bad_guys bad_nets;
}
```

### An admin area for listed addresses only

```nginx
location /admin/ {
    ipset_whitelist office vpn;
    ipset_status 404;
}
```

### Try a set before enforcing it

```nginx
location / {
    ipset_blacklist new_feed;
    ipset_dryrun on;
}
```

Then look for `would deny` in the error log, or count `$ipset_result` values
in the access log.
