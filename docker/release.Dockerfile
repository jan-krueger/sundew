# syntax=docker/dockerfile:1
#
# Release builds. Targets:
#   artifacts  ngx_http_sundew_module.so and sundew-helper (docker build --output)
#   image      nginx with Sundew installed and loaded
#
# BASE is an official nginx image (nginx:1.30.8, nginx:1.30.8-alpine) or a
# distribution image whose own nginx package to build for (DISTRO_NGINX=1).

ARG BASE=nginx:1.30.8
ARG RUST_IMAGE=rust:1.99-alpine


FROM ${RUST_IMAGE} AS helper

RUN apk add --no-cache musl-dev
WORKDIR /src/helper
COPY helper/ ./
RUN cargo build --release --locked \
 && install -m 0755 target/release/sundew-helper /sundew-helper


FROM ${BASE} AS module

ARG NGINX_VERSION
ARG NGINX_SHA256
ARG DISTRO_NGINX=

RUN set -eu; \
    if command -v apk >/dev/null; then \
        apk add --no-cache build-base curl linux-headers openssl-dev pcre2-dev zlib-dev; \
    else \
        apt-get update; \
        apt-get install -y --no-install-recommends build-essential ca-certificates curl \
            libpcre2-dev libssl-dev zlib1g-dev; \
        if [ -n "$DISTRO_NGINX" ]; then apt-get install -y --no-install-recommends nginx; fi; \
        rm -rf /var/lib/apt/lists/*; \
    fi; \
    have=$(nginx -v 2>&1 | sed -n 's|^nginx version: nginx/\([0-9.]*\).*|\1|p'); \
    [ "$have" = "$NGINX_VERSION" ] || { echo "base has nginx $have, expected $NGINX_VERSION" >&2; exit 1; }

COPY config /src/sundew/config
COPY src /src/sundew/src

RUN set -eu; \
    curl -fsSLo /tmp/nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"; \
    echo "${NGINX_SHA256}  /tmp/nginx.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/nginx.tar.gz -C /tmp; \
    cd /tmp/nginx-${NGINX_VERSION}; \
    ./configure --with-compat --with-cc-opt='-O2 -g' --add-dynamic-module=/src/sundew >/tmp/configure.log 2>&1 \
        || { tail -30 /tmp/configure.log; exit 1; }; \
    make -j"$(nproc)" modules; \
    install -m 0644 objs/ngx_http_sundew_module.so /ngx_http_sundew_module.so; \
    printf '%s\n' 'load_module /ngx_http_sundew_module.so;' 'pid /tmp/smoke.pid;' \
        'error_log stderr;' 'events {}' 'http { ipset_blacklist smoke; }' > /tmp/smoke.conf; \
    nginx -t -c /tmp/smoke.conf


FROM scratch AS artifacts

COPY --from=module /ngx_http_sundew_module.so /
COPY --from=helper /sundew-helper /


FROM ${BASE} AS image

COPY --from=module --chown=root:root /ngx_http_sundew_module.so /usr/lib/nginx/modules/
COPY --from=helper --chown=root:root /sundew-helper /usr/lib/nginx/modules/

RUN set -eu; \
    if command -v adduser >/dev/null && ! command -v useradd >/dev/null; then \
        addgroup -S -g 998 sundew; adduser -S -D -H -u 998 -G sundew -s /sbin/nologin sundew; \
    else \
        groupadd -r -g 998 sundew; useradd -r -u 998 -g sundew -M -s /usr/sbin/nologin sundew; \
    fi; \
    chmod 0644 /usr/lib/nginx/modules/ngx_http_sundew_module.so; \
    chmod 0755 /usr/lib/nginx/modules/sundew-helper; \
    sed -i '1i load_module modules/ngx_http_sundew_module.so;' /etc/nginx/nginx.conf

LABEL org.opencontainers.image.source="https://github.com/jan-krueger/sundew" \
      org.opencontainers.image.licenses="BSD-2-Clause" \
      org.opencontainers.image.description="nginx with Sundew: kernel ipset access control"
