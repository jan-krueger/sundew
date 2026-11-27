# Guides

Recipes for one task each. They assume Sundew is installed
([Get started](../get-started.md)).

| I want to… | Guide |
| --- | --- |
| Ban scanners that probe for `/wp-login.php` and friends | [Catch scanners with a honeypot](honeypot.md) |
| Answer 429 to fast clients, and ban the worst | [Rate-limit and ban abusers](rate-limit.md) |
| Ban addresses fail2ban finds | [Feed a set from fail2ban](fail2ban.md) |
| Use nftables sets instead of ipset | [Use nftables sets](nftables.md) |
| Block real clients behind Cloudflare, a load balancer or ingress | [Behind a CDN or load balancer](behind-a-proxy.md) |
| Let only the office and VPN into `/admin` | [Restrict an admin area](admin-area.md) |
| Try a new blocklist without blocking anyone yet | [Roll out a new list safely](dry-run.md) |
| Run it in Docker or Kubernetes | [Docker and Kubernetes](containers.md) |
| Graph and alert on it | [Monitor with Prometheus](prometheus.md) |
| Replace `ngx_http_ipset_access_module` | [Migrate](migrate.md) |
| Fix something | [Troubleshooting](troubleshooting.md) |
