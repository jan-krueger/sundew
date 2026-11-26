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
| [`ipset_stats`](#ipset_stats) | — | location |
| [`ipset_metrics`](#ipset_metrics) | — | location |
| [`sundew_cache_size`](#sundew_cache_size) | `16m` | main |
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
ipset_denylist f2b-web abuse-nets;
```

- Set types: `hash:ip`, `hash:net`, `bitmap:ip`. Up to 64 sets per
  configuration; names of 1–31 characters from `A-Z a-z 0-9 _ . : -`.
- A client is checked against the sets of its own family. `::ffff:192.0.2.1`
  is checked as `192.0.2.1`.
- Every set must exist when nginx starts or reloads, or the reload is rejected.

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
addresses not in it. A change to a set reaches an address that was looked up
within this time once it expires. `0` asks the kernel on every request.

### sundew_lookup_timeout

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_lookup_timeout time;</code></td></tr>
<tr><th>Default</th><td><code>sundew_lookup_timeout 100ms;</code></td></tr>
<tr><th>Context</th><td>http, server, location</td></tr>
</table>

How long a request waits for the helper when its answer is not cached. The
worker serves other requests meanwhile. Past the timeout,
[`ipset_fail_open`](#ipset_fail_open) applies.

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

### sundew_cache_size

<table class="sw-directive">
<tr><th>Syntax</th><td><code>sundew_cache_size size;</code></td></tr>
<tr><th>Default</th><td><code>sundew_cache_size 16m;</code></td></tr>
<tr><th>Context</th><td>main</td></tr>
</table>

Shared memory for cached answers, at least `1m`. 16 MB holds about 400,000
answers; one answer is one address for one set.

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
