# Monitor with Prometheus

## 1. Expose the metrics

```nginx
server {
    listen 127.0.0.1:9113;

    location = /metrics {
        ipset_denylist off;
        ipset_metrics;
    }
}
```

Keep the endpoint off the public listener, and turn the denylist off on it:
otherwise a helper outage, with `ipset_fail_open off`, blocks your monitoring
too.

## 2. Scrape

```yaml title="prometheus.yml"
scrape_configs:
  - job_name: sundew
    static_configs:
      - targets: ["web1:9113", "web2:9113"]
```

## 3. Alert

```yaml title="sundew-rules.yml"
groups:
  - name: sundew
    rules:
      - alert: SundewHelperDown
        expr: rate(sundew_helper_down_total[5m]) > 0
        for: 2m
        annotations:
          summary: "nginx lost its Sundew helper; lookups follow ipset_fail_open until a reload"

      - alert: SundewLookupTimeouts
        expr: rate(sundew_timeouts_total[5m]) > 0.1
        for: 10m
        annotations:
          summary: "the helper or the kernel answers slowly"

      - alert: SundewFailingOpen
        expr: rate(sundew_fail_open_total[5m]) > 0
        annotations:
          summary: "clients are let through without an answer"
```

## Useful queries

| Question | PromQL |
| --- | --- |
| Denials per second, by set | `rate(sundew_set_matched_total[5m])` |
| Share of requests denied | `rate(sundew_denied_total[5m]) / rate(sundew_checked_total[5m])` |
| Cache hit ratio | `rate(sundew_cache_hit_total[5m]) / (rate(sundew_cache_hit_total[5m]) + rate(sundew_cache_miss_total[5m]))` |
| Lookups per second | `rate(sundew_lookups_total[5m])` |

All metrics: [Metrics reference](../reference/metrics.md). For JSON instead,
use [`ipset_stats`](../reference/directives.md#ipset_stats).
