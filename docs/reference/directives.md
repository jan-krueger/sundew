# Directives

Directives in `http`, `server` and `location` are inherited by inner blocks. A
block that sets one replaces what it inherits; lists are not merged.

| Directive | Default | Context |
| --- | --- | --- |
| [`ipset_denylist`](#ipset_denylist) | — | http, server, location |
| [`ipset_allowlist`](#ipset_allowlist) | — | http, server, location |
| [`ipset_status`](#ipset_status) | `403` | http, server, location |
| [`ipset_fail_open`](#ipset_fail_open) | `off` | http, server, location |
| [`ipset_dryrun`](#ipset_dryrun) | `off` | http, server, location |
| [`ipset_cache_ttl`](#ipset_cache_ttl) | `60s` | http, server, location |
| [`sundew_lookup_timeout`](#sundew_lookup_timeout) | `100ms` | http, server, location |
| [`ipset_autoadd`](#ipset_autoadd) | — | server, location |
| [`ipset_ratelimit`](#ipset_ratelimit) | — | http, server, location |
| [`ipset_stats`](#ipset_stats) | — | location |
| [`ipset_metrics`](#ipset_metrics) | — | location |
| [`sundew_writable_sets`](#sundew_writable_sets) | — | main |
| [`sundew_protect`](#sundew_protect) | built-in list | main |
| [`sundew_cache_size`](#sundew_cache_size) | `16m` | main |
| [`sundew_ratelimit_zone_size`](#sundew_ratelimit_zone_size) | `8m` | main |
| [`sundew_helper_path`](#sundew_helper_path) | next to the module | main |
| [`sundew_helper_user`](#sundew_helper_user) | `sundew` | main |
| [`sundew_handshake_timeout`](#sundew_handshake_timeout) | `5s` | main |
| [`sundew_helper_drain_timeout`](#sundew_helper_drain_timeout) | `1h` | main |

## Access

### ipset_denylist

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_denylist set ...;</code> <br> <code>ipset_denylist off;</code></td></tr>
<tr><th>Default</th><td>—</td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
<tr><th>Alias</th><td><code>ipset_blacklist</code></td></tr>
</table>

Denies clients whose address is in any of the sets, with
[`ipset_status`](#ipset_status). `off` cancels an inherited list.

```nginx
ipset_denylist f2b-web abuse-nets nft:inet/filter/blocklist;
```

- A set is an ipset name, or an nftables set written
  `nft:FAMILY/TABLE/SET` ([set names](#set-names)). Both kinds can be mixed
  in one list. Up to 64 sets per configuration.
- A client is checked against the sets of its own family. `::ffff:192.0.2.1`
  is checked as `192.0.2.1`.
- Every set must exist when nginx starts or reloads, or the reload is rejected.

#### Set names

| Kind | Written | Supported |
| --- | --- | --- |
| ipset | `NAME`, 1–31 characters from `A-Z a-z 0-9 _ . : -` | `hash:ip`, `hash:net`, `bitmap:ip` |
| nftables | `nft:FAMILY/TABLE/SET`; `FAMILY` is `ip`, `ip6` or `inet`; `TABLE` and `SET` 1–63 characters from `A-Z a-z 0-9 _ . -`, and `SET` may contain `/` | Sets of `type ipv4_addr` or `type ipv6_addr` (or `typeof ip saddr`, `typeof ip6 saddr`), with or without `flags interval`. Not maps or concatenations |

The same string names the set everywhere: in
[`sundew_writable_sets`](#sundew_writable_sets), in
[`$ipset_matched_set`](variables.md) and in metrics labels.

### ipset_allowlist

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_allowlist set ...;</code> <br> <code>ipset_allowlist off;</code></td></tr>
<tr><th>Default</th><td>—</td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
<tr><th>Alias</th><td><code>ipset_whitelist</code></td></tr>
</table>

Allows only clients whose address is in at least one of the sets; all others
are denied with [`ipset_status`](#ipset_status). Members skip
[`ipset_denylist`](#ipset_denylist).

```nginx
location /admin/ {
    ipset_allowlist office vpn;
}
```

A client whose family has no set in the list is denied: with only IPv4 sets,
every IPv6 client is.

### ipset_status

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_status code;</code></td></tr>
<tr><th>Default</th><td><code>ipset_status 403;</code></td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
</table>

The response for denied clients: a code from 400 to 599, or `444` to close the
connection without a response (on HTTP/2 and HTTP/3, the stream).

### ipset_fail_open

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_fail_open on &#124; off;</code></td></tr>
<tr><th>Default</th><td><code>ipset_fail_open off;</code></td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
</table>

What to do when there is no answer: the helper did not reply within
[`sundew_lookup_timeout`](#sundew_lookup_timeout), reported an error, or is not
running.

1. An address found in a set within [`ipset_cache_ttl`](#ipset_cache_ttl) plus
   10 minutes is treated as still in it.
2. Otherwise `off` denies and `on` allows.

### ipset_dryrun

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_dryrun on &#124; off;</code></td></tr>
<tr><th>Default</th><td><code>ipset_dryrun off;</code></td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
</table>

Allows requests that would be denied, logs
`sundew: dryrun, would deny <address> (<reason>, set <set>)` at `notice`, and
sets [`$ipset_result`](variables.md) to `dryrun`.

## Freshness

### ipset_cache_ttl

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_cache_ttl time;</code></td></tr>
<tr><th>Default</th><td><code>ipset_cache_ttl 60s;</code></td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
</table>

How long an answer from the kernel is reused, for addresses in a set and for
addresses not in it. A change to an ipset reaches an address that was looked
up within this time once it expires. Changes to nftables sets reach nginx at
once; for those this is the limit for elements that expire by their own
timeout, which the kernel does not announce. `0` asks the kernel on every
request.

### sundew_lookup_timeout

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_lookup_timeout time;</code></td></tr>
<tr><th>Default</th><td><code>sundew_lookup_timeout 100ms;</code></td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
</table>

How long a request waits for the helper when its answer is not cached. The
worker serves other requests meanwhile. Past the timeout,
[`ipset_fail_open`](#ipset_fail_open) applies.

## Writing to sets

Every set Sundew adds to must be listed in
[`sundew_writable_sets`](#sundew_writable_sets), have the ipset `timeout`
option, and must not be used by `ipset_allowlist`. The helper never adds an
address in the [protected list](#sundew_protect), adds at most 20 addresses a
second per rule (bursts of 100), and pauses a rule for 10 minutes after more
than 1,000 adds in a minute. An address already in the set keeps its timeout.

### ipset_autoadd

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_autoadd set ... [timeout=time] [status=code] [prefix4=N] [prefix6=N] [if=value];</code> <br> <code>ipset_autoadd off;</code></td></tr>
<tr><th>Default</th><td>—</td></tr>
<tr><th>Context</th><td>server, location</td></tr>
</table>

Adds the client's address to the set of its address family and answers with
`status`: a honeypot. List an IPv4 and an IPv6 set to catch both; a client
whose family has no set listed is answered but not added. On HTTP/1.1 the
connection is closed after the response.

| Parameter | Default | Effect |
| --- | --- | --- |
| `timeout=` | the set's default timeout | How long the address stays in the set, 1 s to 24 days. Required when the set's default is 0 |
| `status=` | `404` | The response: 400–599, or 444 to close the connection |
| `prefix4=`, `prefix6=` | `32`, `128` | Add the whole prefix instead of the address. ipset `hash:net` sets only |
| `if=` | — | Add only when this value is neither empty nor `0`; variables allowed |

The address is not added, but the response is still sent, for:

- requests with any `Sec-Fetch-*` header, or `Sec-Purpose`/`Purpose` asking
  for a prefetch: browsers, which a page could trick into requesting the trap;
- TLS early data, which can be replayed;
- `ipset_dryrun on`, and clients in an `ipset_allowlist`.

```nginx
location = /wp-login.php {
    ipset_autoadd scanners scanners6 timeout=1d;
}
```

### ipset_ratelimit

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_ratelimit rate=N [window=time] [autoban=set[,set]] [ban_time=time] [key6=N];</code> <br> <code>ipset_ratelimit off;</code></td></tr>
<tr><th>Default</th><td>—</td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
</table>

Allows each client `rate` requests per `window`, counted over a sliding window,
and answers further requests with 429. Clients in an `ipset_allowlist` are not
counted.

| Parameter | Default | Effect |
| --- | --- | --- |
| `rate=` | — | Requests allowed per window, 1–65535 |
| `window=` | `60s` | 1 s to 1 day |
| `autoban=` | — | Add the client to this set the first time it goes over the rate. A comma-separated IPv4 and IPv6 set: each client goes to the one of its family |
| `ban_time=` | `3600s` | How long it stays in the `autoban` set |
| `key6=` | `64` | IPv6 clients are counted per prefix of this length |

Each `ipset_ratelimit` line keeps its own counters. Requests with
`Sec-Fetch-Site: cross-site` still get 429 but never cause a ban.

```nginx
location /api/ {
    ipset_ratelimit rate=100 window=1m autoban=abusers,abusers6 ban_time=1h;
    proxy_pass http://backend;
}
```

## Endpoints

### ipset_stats

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_stats;</code></td></tr>
<tr><th>Context</th><td>location</td></tr>
</table>

Serves the [counters](metrics.md) as JSON.

### ipset_metrics

<table class="sw-directive">
<tr><th>Syntax</th><td><code>ipset_metrics;</code></td></tr>
<tr><th>Context</th><td>location</td></tr>
</table>

Serves the [counters](metrics.md) in the Prometheus text format.

```nginx
location = /metrics {
    ipset_denylist off;
    ipset_metrics;
    allow 10.0.0.0/8;
    deny all;
}
```

## Helper

### sundew_writable_sets

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_writable_sets set ...;</code></td></tr>
<tr><th>Default</th><td>—</td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

The sets that `ipset_autoadd` and `ipset_ratelimit autoban=` may add to. Any
other set named there stops nginx with an error. An ipset needs `timeout`
support; an nftables set needs `flags timeout`, and must not have
`flags interval` or `flags constant`. On a shared server, an
included virtual host cannot make nginx write to a set the main configuration
did not allow.

### sundew_protect

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_protect prefix ... ;</code></td></tr>
<tr><th>Default</th><td>built-in list</td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

Addresses the helper never adds to a set. A prefix overlapping a protected one
is refused too. `!prefix` removes a built-in entry.

Built in: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
`169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `224.0.0.0/4`,
`240.0.0.0/4`, `::/128`, `::1/128`, `::ffff:0:0/96`, `fc00::/7`, `fe80::/10`,
`ff00::/8`.

```nginx
sundew_protect 203.0.113.0/24;      # your CDN or monitoring
sundew_protect !10.0.0.0/8;         # clients really do come from 10/8
```

### sundew_cache_size

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_cache_size size;</code></td></tr>
<tr><th>Default</th><td><code>sundew_cache_size 16m;</code></td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

Shared memory for cached answers, at least `1m`. 16 MB holds about 400,000
answers; one answer is one address for one set.

### sundew_ratelimit_zone_size

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_ratelimit_zone_size size;</code></td></tr>
<tr><th>Default</th><td><code>sundew_ratelimit_zone_size 8m;</code></td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

Shared memory for rate-limit counters, at least `1m`. 8 MB holds about 180,000
clients; when it is full, the client not seen for longest is forgotten.

### sundew_helper_path

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_helper_path path;</code></td></tr>
<tr><th>Default</th><td><code>sundew-helper</code> in the module's directory</td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

The helper binary. It, and every directory above it, must be owned by root and
not writable by group or others, and it must not be setuid, setgid or carry
file capabilities.

### sundew_helper_user

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_helper_user name;</code></td></tr>
<tr><th>Default</th><td><code>sundew_helper_user sundew;</code></td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

The account the helper runs as. It must exist and be neither root nor nginx's
`user`.

### sundew_handshake_timeout

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_handshake_timeout time;</code></td></tr>
<tr><th>Default</th><td><code>sundew_handshake_timeout 5s;</code></td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

How long nginx waits for a new helper to confirm the sets, at start and on
every reload.

### sundew_helper_drain_timeout

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_helper_drain_timeout time;</code></td></tr>
<tr><th>Default</th><td><code>sundew_helper_drain_timeout 1h;</code></td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

After a reload, how long the previous helper keeps answering workers of the old
configuration. With `worker_shutdown_timeout` set, that plus 60 seconds is used
instead.
