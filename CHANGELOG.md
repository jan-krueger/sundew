# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ipset_denylist` and `ipset_allowlist` check clients against kernel ipsets
  of type `hash:ip`, `hash:net` and `bitmap:ip`, IPv4 and IPv6, in `http`,
  `server` and `location`. Allowlist members skip the denylist. `ipset_blacklist`
  and `ipset_whitelist` work too, for configurations from the commercial module.
- `ipset_status`, `ipset_fail_open` and `ipset_dryrun`, and the variables
  `$ipset_result` and `$ipset_matched_set`.
- A cache shared by all workers (`ipset_cache_ttl`, default 60 s;
  `sundew_cache_size`, default 16 MB for about 450,000 answers). It survives
  reloads. A cache hit costs no measurable throughput on a 2-worker test
  machine.
- While the helper cannot answer, cached bans keep applying for 10 minutes
  beyond `ipset_cache_ttl`.
- Requests wait for the helper without blocking the worker, up to
  `sundew_lookup_timeout` (default 100 ms). Concurrent requests for the same
  address share one lookup: 40 concurrent requests made 2 lookups, one per
  worker.
- `ipset_stats` (JSON) and `ipset_metrics` (Prometheus) endpoints, with
  counters that survive reloads.
- The helper: a separate binary started by nginx that alone holds
  `CAP_NET_ADMIN`, runs as its own account under seccomp and Landlock, restarts
  its engine after a crash, and only answers for the configured sets. Workers
  start only without capabilities.
- nginx refuses to start, or keeps its old configuration on reload, when a set
  is missing or of an unsupported type.
- Errors inside the helper reach nginx's error log through the workers: a set
  destroyed while nginx runs, kernel errors, engine crashes and malformed
  requests, each at most once a second.
- Docker images on GHCR: the official nginx image, stable and mainline, Debian
  and Alpine, amd64 and arm64, with Sundew installed and loaded.
- Prebuilt modules and a static helper for nginx.org 1.30.8 and 1.31.10
  (Debian and Alpine), Debian 13's nginx 1.26.3 and Ubuntu 24.04's nginx
  1.24.0, for amd64 and arm64, with checksums and build provenance.
- Tested on nginx 1.24.0, 1.30.8 and 1.31.10, including builds with AddressSanitizer
  and UndefinedBehaviorSanitizer, across reloads, binary upgrades, worker and
  helper crashes, client aborts and HTTP/2 and HTTP/3 stream resets.
