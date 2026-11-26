# Migrate from ngx_http_ipset_access_module

Configurations for GetPageSpeed's commercial module work with Sundew. What
changes is how it is installed and a few features it does not have yet.

## 1. Swap the module

=== "Before"

    ```nginx
    load_module modules/ngx_http_ipset_access_module.so;
    ```

=== "After"

    ```nginx
    load_module modules/ngx_http_sundew_module.so;
    ```

Install Sundew as in [Get started](../get-started.md), including the `sundew`
account. Remove any systemd drop-in or `setcap` that gave nginx
`CAP_NET_ADMIN`: Sundew's workers refuse to start with capabilities.

## 2. Check the directives

| Directive | With Sundew |
| --- | --- |
| `ipset_blacklist`, `ipset_whitelist` | Work as before. Sundew's own names are `ipset_denylist` and `ipset_allowlist` |
| `ipset_status`, `ipset_fail_open`, `ipset_dryrun`, `ipset_cache_ttl` | Work as before; also allowed in `location` |
| `ipset_stats`, `ipset_metrics` | Work; the [counters](../reference/metrics.md) have other names (`sundew_…`) |
| `$ipset_result`, `$ipset_matched_set` | Work; `$ipset_result` is `allow`, `deny` or `dryrun` |
| `ipset_autoadd` | Not yet: remove it, or keep the trap location and add addresses some other way |
| `ipset_ratelimit` | Not yet: use nginx's `limit_req`, which runs after Sundew |
| `ipset_challenge`, `ipset_challenge_difficulty` | Not planned: remove them |

## 3. Test and reload

```bash
sudo nginx -t
sudo systemctl reload nginx
```

`nginx -t` checks syntax only. The reload checks every set: if one is missing
or of a type Sundew does not support, nginx logs why and keeps the old
configuration.

## What behaves differently

| | Commercial module | Sundew |
| --- | --- | --- |
| Privileges | nginx's workers need `CAP_NET_ADMIN` | Workers hold nothing; a sandboxed helper does |
| Missing set | Lookups fail per request; `ipset_fail_open` decides | The reload is rejected and the old configuration keeps running |
| While lookups fail | `ipset_fail_open` decides | Cached bans keep applying; others follow `ipset_fail_open` |
