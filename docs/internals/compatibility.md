# Compatibility

## Tested

| | Versions |
| --- | --- |
| nginx | 1.24.0, 1.30.8 |
| Linux | 7.2 |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 (nginx with `http_v3_module`) |
| Set types | `hash:ip`, `hash:net`, `bitmap:ip`; IPv4 and IPv6 |

Every test also runs nginx built with AddressSanitizer and
UndefinedBehaviorSanitizer.

- The module needs nginx built with `--with-compat` and the same version it was
  built against.
- Older kernels are untested. Ambient capabilities need Linux 4.3. Without
  `pidfd_open` (5.3) nginx tracks the helper by process ID; without Landlock
  (5.13) the helper runs with seccomp only.
- SELinux has not been tested. On RHEL-like systems in enforcing mode, the
  helper may need a policy.

## The commercial `ipset_*` directives

Sundew accepts the directive names of the commercial
`ngx_http_ipset_access_module`, so configurations can move over. It shares no
code with it.

| Directive | Sundew 0.1 |
| --- | --- |
| `ipset_blacklist`, `ipset_whitelist` | Yes, also in `location` |
| `ipset_status`, `ipset_fail_open`, `ipset_dryrun`, `ipset_cache_ttl` | Yes, also in `location` |
| `ipset_stats`, `ipset_metrics` | Yes; metric names start with `sundew_` |
| `$ipset_result`, `$ipset_matched_set` | Yes; `$ipset_result` is `allow`, `deny` or `dryrun` |
| `ipset_autoadd` | Not yet |
| `ipset_ratelimit` | Not yet |
| `ipset_challenge`, `ipset_challenge_difficulty` | Not planned |

| Difference | Sundew |
| --- | --- |
| Privileges | Workers hold none; a separate helper holds `CAP_NET_ADMIN` |
| Missing or wrong set | nginx refuses to start or reload, instead of failing requests |
| Helper unavailable | Cached bans keep applying for 10 minutes beyond `ipset_cache_ttl` |
