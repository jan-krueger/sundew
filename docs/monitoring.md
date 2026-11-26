# Monitoring

Counters live in shared memory: every worker adds to them, and they survive
reloads. A restart of nginx resets them.

```nginx
location = /sundew/stats {
    ipset_blacklist off;
    ipset_stats;
    allow 127.0.0.1;
    deny all;
}

location = /sundew/metrics {
    ipset_blacklist off;
    ipset_metrics;
    allow 10.0.0.0/8;
    deny all;
}
```

Turn the blacklist off on these locations: otherwise a helper outage, with
`ipset_fail_open off`, also blocks your monitoring.

## Counters

| Name | Counts |
| --- | --- |
| `checked` | Requests checked |
| `allowed`, `denied`, `dryrun` | Outcomes |
| `fail_open`, `fail_closed` | Requests decided by `ipset_fail_open` because no answer was available |
| `stale_served` | Requests denied by a ban older than `ipset_cache_ttl` while no answer was available |
| `cache_hit`, `cache_miss` | Requests answered from the cache, and requests that needed the helper |
| `lookups` | Questions sent to the helper |
| `coalesced` | Requests that waited for a question already on its way for the same address |
| `timeouts`, `helper_errors`, `helper_down`, `busy` | Lookups without an answer, by reason |
| `late_replies` | Answers that arrived after `sundew_lookup_timeout` |

Per set: `matched`, the requests that set decided.

## JSON

```json
{"version":"0.1.0-dev","counters":{"checked":1200,"allowed":1180,"denied":20,…},"sets":{"bad_guys":{"matched":20}}}
```

## Prometheus

Each counter is `sundew_<name>_total`; sets are `sundew_set_matched_total{set="…"}`.

```text
sundew_info{version="0.1.0-dev"} 1
sundew_denied_total 20
sundew_set_matched_total{set="bad_guys"} 20
```

## Worth alerting on

| Expression | Means |
| --- | --- |
| `rate(sundew_helper_down_total[5m]) > 0` | A worker lost its helper; lookups follow the fail policy until the next reload |
| `rate(sundew_timeouts_total[5m]) > 0` | The helper or the kernel is slow; see [Troubleshooting](troubleshooting.md#requests-are-denied-after-a-timeout) |
| `rate(sundew_fail_open_total[5m]) > 0` | Unknown clients are being let through |
