# Get started

By the end of this page nginx returns 403 to an address you put in a set, and
200 to everyone else.

!!! info "You need"
    - Linux with the `ip_set` kernel module (`sudo modprobe ip_set`), and the
      `ipset` tool.
    - Root on the machine. nginx's master runs as root; its workers and Sundew's
      helper do not.

## 1. Install

=== "Docker"

    The image is the official nginx image with Sundew installed and loaded.

    ```bash
    docker pull ghcr.io/jan-krueger/sundew:latest
    ```

    | Tag | nginx |
    | --- | --- |
    | `latest`, `<version>-nginx1.30.8` | 1.30.8 stable, Debian |
    | `<version>-nginx1.30.8-alpine` | 1.30.8 stable, Alpine |
    | `<version>-nginx1.31.10`, `…-alpine` | 1.31.10 mainline |

    All tags are for amd64 and arm64. You start the container in
    [step 3](#3-turn-it-on).

=== "Prebuilt module"

    For nginx from nginx.org's packages and images, Debian 12 and 13, and
    Ubuntu 22.04 and 24.04. Pick the tarball for your nginx from the
    [latest release](https://github.com/jan-krueger/sundew/releases/latest):

    | Where nginx came from | Tarball |
    | --- | --- |
    | nginx.org packages or Debian-based images | `sundew-<version>-nginx.org-<nginx>-<arch>.tar.gz` |
    | nginx.org Alpine images | `sundew-<version>-nginx.org-<nginx>-alpine-<arch>.tar.gz` |
    | Debian 12 `nginx` package | `sundew-<version>-debian12-nginx<nginx>-<arch>.tar.gz` |
    | Debian 13 `nginx` package | `sundew-<version>-debian13-nginx<nginx>-<arch>.tar.gz` |
    | Ubuntu 22.04 `nginx` package | `sundew-<version>-ubuntu22.04-nginx<nginx>-<arch>.tar.gz` |
    | Ubuntu 24.04 `nginx` package | `sundew-<version>-ubuntu24.04-nginx<nginx>-<arch>.tar.gz` |

    `<nginx>` is the version `nginx -v` prints; the module loads only into that
    version. `<arch>` is `amd64` or `arm64`. The nginx.org tarballs need glibc
    2.34 or later, which Debian 12, Ubuntu 22.04 and RHEL 9 have. The latest
    release covers the two
    newest nginx.org stable and mainline versions and the distributions'
    current packages. Builds for a new nginx version are added to it once they
    pass the tests; files already published are never replaced.

    Check that the tarball was built by Sundew's release workflow, from this
    repository, before you install it:

    ```bash
    gh attestation verify sundew-*.tar.gz --repo jan-krueger/sundew
    ```

    ```bash
    tar xzf sundew-*.tar.gz && cd sundew-*/
    sudo install -o root -g root -m 0644 ngx_http_sundew_module.so /usr/lib/nginx/modules/
    sudo install -o root -g root -m 0755 sundew-helper             /usr/lib/nginx/modules/
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin sundew
    ```

    Then load the module at the top of `/etc/nginx/nginx.conf`, outside any
    block:

    ```nginx
    load_module modules/ngx_http_sundew_module.so;
    ```

=== "From source"

    For any other nginx 1.18 or newer. You need the source of the exact nginx
    version you run, a C compiler and Rust 1.85 or newer. Only the module is
    compiled; your nginx stays as it is.

    ```bash
    v=$(nginx -v 2>&1 | sed 's|.*nginx/\([0-9.]*\).*|\1|')
    curl -fsSL "https://nginx.org/download/nginx-$v.tar.gz" | tar xz
    git clone https://github.com/jan-krueger/sundew

    (cd "nginx-$v" && ./configure --with-compat --add-dynamic-module=../sundew && make modules)
    (cd sundew/helper && cargo build --release --locked)

    sudo install -o root -g root -m 0644 "nginx-$v/objs/ngx_http_sundew_module.so" /usr/lib/nginx/modules/
    sudo install -o root -g root -m 0755 sundew/helper/target/release/sundew-helper /usr/lib/nginx/modules/
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin sundew
    ```

    Then load the module at the top of `/etc/nginx/nginx.conf`:

    ```nginx
    load_module modules/ngx_http_sundew_module.so;
    ```

!!! warning "Ownership matters"
    nginx refuses to start a helper that is not owned by root, is writable by
    anyone else, or sits in such a directory. The `sundew` account must not be
    the one nginx's workers run as.

## 2. Create a set

```bash
sudo ipset create bad_guys hash:ip timeout 86400
sudo ipset add bad_guys 192.0.2.1
```

`timeout 86400` lets entries expire after a day; leave it out for permanent
entries. The set must exist before nginx starts.

## 3. Turn it on

The test below sends `X-Forwarded-For` from localhost, so nginx is told to
trust that header from `127.0.0.1`. Behind a real proxy, see
[Behind a CDN or load balancer](guides/behind-a-proxy.md).

=== "Docker"

    ```bash
    cat > sundew.conf <<'CONF'
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    ipset_denylist   bad_guys;
    CONF

    docker run -d --name web --cap-add NET_ADMIN --network host \
        -v "$PWD/sundew.conf:/etc/nginx/conf.d/sundew.conf:ro" \
        ghcr.io/jan-krueger/sundew:latest
    ```

    - `--network host` lets the container see the host's sets.
    - `--cap-add NET_ADMIN` is for the helper. nginx's workers drop it.

=== "Prebuilt module or source"

    Add to the `http` block, for example as `/etc/nginx/conf.d/sundew.conf`:

    ```nginx
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    ipset_denylist   bad_guys;
    ```

    ```bash
    sudo nginx -t && sudo systemctl reload nginx
    ```

## 4. Check it

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1/
403
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 192.0.2.2' http://127.0.0.1/
200
```

Change the set and ask again; within a minute, the cache's default lifetime,
nginx follows:

```console
$ sudo ipset add bad_guys 192.0.2.2
$ sleep 61; curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 192.0.2.2' http://127.0.0.1/
403
```

The helper runs next to nginx's workers, as its own account:

```console
$ ps -eo user,comm | grep -E 'nginx|sundew'
root     nginx
www-data nginx
sundew   sundew-keeper
sundew   sundew-engine
```

## Next

<div class="grid cards" markdown>

- [:octicons-arrow-right-24: Feed the set from fail2ban](guides/fail2ban.md)
- [:octicons-arrow-right-24: Put it behind a CDN](guides/behind-a-proxy.md)
- [:octicons-arrow-right-24: All directives](reference/directives.md)
- [:octicons-arrow-right-24: How a request is checked](concepts/request-flow.md)

</div>
