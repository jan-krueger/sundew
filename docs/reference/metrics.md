# Metrics

[`ipset_stats`](directives.md#ipset_stats) serves these counters as JSON and
[`ipset_metrics`](directives.md#ipset_metrics) in the Prometheus text format.
They are shared by all workers and survive reloads; restarting nginx resets
them.

## Requests

| Prometheus | JSON | Counts |
| --- | --- | --- |
| `sundew_checked_total` | `checked` | Requests checked |
| `sundew_allowed_total` | `allowed` | Requests let through |
| `sundew_denied_total` | `denied` | Requests denied |
| `sundew_dryrun_total` | `dryrun` | Requests that would have been denied, under `ipset_dryrun` |
| `sundew_fail_open_total` | `fail_open` | Requests let through because no answer was available |
| `sundew_fail_closed_total` | `fail_closed` | Requests denied because no answer was available |
| `sundew_stale_served_total` | `stale_served` | Requests decided by an expired cached answer while no answer was available |
| `sundew_ratelimited_total` | `ratelimited` | Requests over an `ipset_ratelimit` rate |
| `sundew_trapped_total` | `trapped` | Requests to an `ipset_autoadd` location |
| `sundew_set_matched_total{set="…"}` | `sets.<name>.matched` | Requests decided by this set |

## Adds

| Prometheus | JSON | Counts |
| --- | --- | --- |
| `sundew_adds_total` | `adds` | Addresses added to a set, or already in it |
| `sundew_adds_refused_total` | `adds_refused` | Adds the helper refused: protected address, over budget, circuit breaker open |
| `sundew_adds_failed_total` | `adds_failed` | Adds that failed: kernel error, set full or missing, helper unavailable |
| `sundew_adds_skipped_total` | `adds_skipped` | Adds not attempted: dry run, browser request, prefetch, TLS early data, `if=`, cross-site rate-limit ban |

## Cache and helper

| Prometheus | JSON | Counts |
| --- | --- | --- |
| `sundew_cache_hit_total` | `cache_hit` | Requests answered from the cache |
| `sundew_cache_miss_total` | `cache_miss` | Requests that needed the helper |
| `sundew_lookups_total` | `lookups` | Questions sent to the helper |
| `sundew_coalesced_total` | `coalesced` | Requests that joined a question already on its way for the same address |
| `sundew_timeouts_total` | `timeouts` | Questions not answered within `sundew_lookup_timeout` |
| `sundew_late_replies_total` | `late_replies` | Answers that arrived after their timeout, up to 5 s late; they are still cached |
| `sundew_helper_errors_total` | `helper_errors` | Questions the helper answered with an error |
| `sundew_helper_down_total` | `helper_down` | Questions that could not be sent: the helper is gone |
| `sundew_busy_total` | `busy` | Questions not sent: too many in flight in one worker |

`sundew_info{version="…"}` is always 1.

## Examples

=== "Prometheus"

    ```text
    # TYPE sundew_denied_total counter
    sundew_denied_total 1204
    # TYPE sundew_cache_hit_total counter
    sundew_cache_hit_total 982113
    sundew_set_matched_total{set="f2b-web"} 1188
    sundew_set_matched_total{set="office"} 16
    ```

=== "JSON"

    ```json
    {
      "version": "0.3.0",
      "counters": { "checked": 990240, "allowed": 989036, "denied": 1204, "cache_hit": 982113, "…": 0 },
      "sets": { "f2b-web": { "matched": 1188 }, "office": { "matched": 16 } }
    }
    ```
