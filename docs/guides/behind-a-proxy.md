# Behind a CDN or load balancer

Behind a proxy, every connection comes from the proxy. Sundew checks the address
nginx's [realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
produces, so tell realip which proxies to trust and which header holds the
client.

--8<-- "proxy.html"

=== "Cloudflare"

    ```nginx
    http {
        include       /etc/nginx/cloudflare-ips.conf;   # set_real_ip_from lines
        real_ip_header CF-Connecting-IP;

        ipset_denylist bad_guys;
    }
    ```

    Generate `cloudflare-ips.conf` from <https://www.cloudflare.com/ips/>, one
    `set_real_ip_from <range>;` per line, and refresh it when the list changes.

=== "Load balancer"

    ```nginx
    http {
        set_real_ip_from  10.0.0.0/8;          # your load balancers
        real_ip_header    X-Forwarded-For;
        real_ip_recursive on;

        ipset_denylist bad_guys;
    }
    ```

=== "PROXY protocol"

    ```nginx
    http {
        set_real_ip_from 10.0.0.0/8;
        real_ip_header   proxy_protocol;

        server {
            listen 443 ssl proxy_protocol;
            ipset_denylist bad_guys;
        }
    }
    ```

!!! danger "Trust only your proxies"
    `set_real_ip_from` must list only addresses you control or your CDN's
    published ranges. Trust everyone, and any client picks the address Sundew
    checks: a banned client sends a clean one.

## Check

Send a request through the proxy from an address in the set, or test the
header from a trusted address:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 192.0.2.1' https://example.com/
```

Log what Sundew saw:

```nginx
log_format sundew '$remote_addr $status $ipset_result $ipset_matched_set "$request"';
access_log /var/log/nginx/access.log sundew;
```

`$remote_addr` is the address after realip, the one Sundew checked.
