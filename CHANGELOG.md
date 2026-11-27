# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ipset_autoadd set ... [timeout=] [status=] [prefix4=] [prefix6=] [if=]`: a
  honeypot location adds the client to the set of its address family and
  answers 404. The ban applies from the next request in every worker.
- `ipset_ratelimit rate=N [window=] [autoban=set[,set]] [ban_time=] [key6=]`:
  a sliding-window limit per client (per /64 for IPv6) that answers 429 and can
  ban the client the first time it goes over.
- `sundew_writable_sets`: the only sets nginx may add to; anything else stops
  `nginx -t`.
- `sundew_protect`: addresses never added, on top of a built-in list of
  private, loopback, link-local and reserved ranges. Prefixes overlapping a
  protected one are refused too.
- The helper adds at most 20 addresses a second per rule (bursts of 100) and
  pauses a rule for 10 minutes after 1,000 adds in a minute.
- No add for browser requests (`Sec-Fetch-*`, prefetch), TLS early data,
  `ipset_dryrun`, allowlisted clients, or when `if=` is empty or `0`. A
  cross-site request gets 429 but no ban.
- `$ipset_result` value `ratelimited`; counters `ratelimited`, `trapped`,
  `adds`, `adds_refused`, `adds_failed` and `adds_skipped`.
- `sundew_ratelimit_zone_size`, 8 MB by default for about 180,000 clients.

### Changed
- An address already in a set keeps its timeout when added again.
- Adding to a set without the ipset `timeout` option, or without any timeout,
  stops nginx with an error instead of creating permanent entries.
- Module and helper speak protocol 2: install both from the same release.

## [0.1.0] - 2026-11-26

The first release.

### Added
- `ipset_denylist` and `ipset_allowlist` check clients against kernel ipsets
  of type `hash:ip`, `hash:net` and `bitmap:ip`, IPv4 and IPv6, in `http`,
  `server` and `location`. Allowlist members skip the denylist. `ipset_blacklist`
  and `ipset_whitelist` work too, for configurations from the commercial module.
- `ipset_status`, `ipset_fail_open` and `ipset_dryrun`, and the variables
  `$ipset_result` and `$ipset_matched_set`.
- A cache shared by all workers (`ipset_cache_ttl`, default 60 s;
  `sundew_cache_size`, default 16 MB for about 400,000 answers). It survives
  reloads.
- While the helper cannot answer, cached bans keep applying for 10 minutes
  beyond `ipset_cache_ttl`.
- Requests wait for the helper without blocking the worker, up to
  `sundew_lookup_timeout` (default 100 ms). Concurrent requests for the same
  address share one lookup. An answer arriving up to 5 s after the timeout still fills the cache,
  so a slow kernel is not asked again for the same address.
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

[Unreleased]: https://github.com/jan-krueger/sundew/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jan-krueger/sundew/releases/tag/v0.1.0
