# Getting started

Three ways to install, easiest first. Images and downloads are published from
the first release, 0.1.0, on.

## Option A: Docker image

The image is the official nginx image with Sundew installed and loaded.

| Tag | nginx |
| --- | --- |
| `ghcr.io/jan-krueger/sundew:<version>-nginx1.30.8` | 1.30.8 stable, Debian |
| `ghcr.io/jan-krueger/sundew:<version>-nginx1.30.8-alpine` | 1.30.8 stable, Alpine |
| `ghcr.io/jan-krueger/sundew:<version>-nginx1.31.10` | 1.31.10 mainline, Debian |
| `ghcr.io/jan-krueger/sundew:<version>-nginx1.31.10-alpine` | 1.31.10 mainline, Alpine |

`latest` is the newest release on stable nginx, for amd64 and arm64.

```bash
cat > sundew.conf <<'CONF'
ipset_denylist bad_guys;
CONF

docker run -d --name web --cap-add NET_ADMIN --network host \
    -v "$PWD/sundew.conf:/etc/nginx/conf.d/sundew.conf:ro" \
    ghcr.io/jan-krueger/sundew:latest
```

- `--cap-add NET_ADMIN` is for the helper; the workers drop it.
- Sets belong to a network namespace. `--network host` uses the host's sets,
  where fail2ban and friends put them. Without it, the container needs its own
  sets, created before nginx starts.
- Files in `/etc/nginx/conf.d/` are read inside `http {}`.

## Option B: prebuilt module

Each release has a tarball per nginx build and architecture, holding
`ngx_http_sundew_module.so` and `sundew-helper`:

| Your nginx | Tarball |
| --- | --- |
| nginx.org packages or images, 1.30.8 | `sundew-<version>-nginx.org-1.30.8-<arch>.tar.gz` |
| nginx.org Alpine images, 1.30.8 | `sundew-<version>-nginx.org-1.30.8-alpine-<arch>.tar.gz` |
| nginx.org mainline, 1.31.10 | `sundew-<version>-nginx.org-1.31.10[-alpine]-<arch>.tar.gz` |
| Debian 13 `nginx` package (1.26.3) | `sundew-<version>-debian13-<arch>.tar.gz` |
| Ubuntu 24.04 `nginx` package (1.24.0) | `sundew-<version>-ubuntu24.04-<arch>.tar.gz` |

`<arch>` is `amd64` or `arm64`. The module loads only into the nginx version it
was built for; `nginx -v` tells you which you have. `SHA256SUMS` and build
provenance come with each release (`gh attestation verify <file> --repo
jan-krueger/sundew`).

```bash
tar xzf sundew-0.1.0-debian13-amd64.tar.gz && cd sundew-0.1.0-debian13-amd64
install -o root -g root -m 0644 ngx_http_sundew_module.so /usr/lib/nginx/modules/
install -o root -g root -m 0755 sundew-helper             /usr/lib/nginx/modules/
useradd --system --no-create-home --shell /usr/sbin/nologin sundew
```

The helper must be owned by root and not writable by anyone else, and so must
every directory above it; nginx refuses to start it otherwise. The `sundew`
account runs the helper and must not be the account the workers run as.

Then continue with [Create a set](#create-a-set).

## Option C: build from source

For any other nginx 1.24 or newer. Needs the nginx source of the exact version
you run, a C compiler, and Rust 1.85 or newer.

```bash
nginx -V                          # note the version
curl -O https://nginx.org/download/nginx-1.30.8.tar.gz
tar xzf nginx-1.30.8.tar.gz && cd nginx-1.30.8
./configure --with-compat --add-dynamic-module=/path/to/sundew
make modules                      # objs/ngx_http_sundew_module.so, nginx itself is not rebuilt

cd /path/to/sundew/helper
cargo build --release --locked    # target/release/sundew-helper
```

Install both files and the `sundew` account as in option B.

## Requirements

- Linux with the `ip_set` kernel module.
- nginx started as root (workers switch to the `user` you set).

## Create a set

```bash
modprobe ip_set ip_set_hash_ip ip_set_hash_net
ipset create bad_guys hash:ip timeout 86400
ipset add bad_guys 192.0.2.1
```

## Configure nginx

```nginx
load_module modules/ngx_http_sundew_module.so;

user www-data;

http {
    ipset_denylist bad_guys;

    server {
        listen 80;

        location = /sundew/metrics {
            ipset_denylist off;
            ipset_metrics;
            allow 127.0.0.1;
            deny all;
        }
    }
}
```

## Start and check

```bash
nginx -t && systemctl reload nginx
ps -eo pid,user,comm | grep sundew      # sundew-keeper and sundew-engine, user sundew
curl -i -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1/   # 403 once realip trusts 127.0.0.1
```

Behind a CDN or load balancer, configure nginx's
[realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html):
Sundew checks the address realip produces.

Next: [Configuration](configuration.md).
