# Getting started

There are no packages yet: build the module against your nginx and build the
helper with Cargo.

## Requirements

- Linux with the `ip_set` kernel module.
- nginx 1.24 or newer, started as root (workers switch to the `user` you set).
- The nginx source of the exact version you run, a C compiler, and Rust 1.85 or
  newer.

## 1. Build

```bash
nginx -V                          # note the version and configure arguments
curl -O https://nginx.org/download/nginx-1.30.8.tar.gz
tar xzf nginx-1.30.8.tar.gz && cd nginx-1.30.8
./configure --with-compat <the arguments from nginx -V> --add-dynamic-module=/path/to/sundew
make modules                      # objs/ngx_http_sundew_module.so

cd /path/to/sundew/helper
cargo build --release --locked    # target/release/sundew-helper
```

## 2. Install

Both files go into nginx's modules directory. The helper must be owned by root
and not writable by anyone else, and so must every directory above it; nginx
refuses to start it otherwise.

```bash
install -o root -g root -m 0644 objs/ngx_http_sundew_module.so /usr/lib/nginx/modules/
install -o root -g root -m 0755 target/release/sundew-helper   /usr/lib/nginx/modules/
useradd --system --no-create-home --shell /usr/sbin/nologin sundew
```

The `sundew` account runs the helper. It must not be the account the workers
run as.

## 3. Create a set

```bash
modprobe ip_set ip_set_hash_ip ip_set_hash_net
ipset create bad_guys hash:ip timeout 86400
ipset add bad_guys 192.0.2.1
```

## 4. Configure nginx

```nginx
load_module modules/ngx_http_sundew_module.so;

user www-data;

http {
    ipset_blacklist bad_guys;

    server {
        listen 80;

        location = /sundew/metrics {
            ipset_blacklist off;
            ipset_metrics;
            allow 127.0.0.1;
            deny all;
        }
    }
}
```

## 5. Start and check

```bash
nginx -t && systemctl reload nginx
ps -eo pid,user,comm | grep sundew      # sundew-keeper and sundew-engine, user sundew
curl -i -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1/   # 403 once realip trusts 127.0.0.1
```

Behind a CDN or load balancer, configure nginx's
[realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html):
Sundew checks the address realip produces.

Next: [Configuration](configuration.md).
