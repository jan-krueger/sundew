# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-slim-trixie AS toolchain

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl gdb iproute2 ipset libcap2-bin \
        libpcre2-dev libssl-dev procps python3 strace zlib1g-dev \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add clippy rustfmt \
 && groupadd -r -g 101 nginx && useradd -r -u 101 -g nginx -M -s /usr/sbin/nologin nginx \
 && groupadd -r -g 998 sundew && useradd -r -u 998 -g sundew -M -s /usr/sbin/nologin sundew


FROM toolchain AS dev

ARG NGINX_VERSION
ARG NGINX_SHA256

ENV NGINX_VERSION=${NGINX_VERSION} \
    NGINX_CONFIGURE_ARGS="--prefix=/opt/nginx --with-compat --with-debug --with-threads --with-http_realip_module --with-http_ssl_module --with-http_v2_module"

RUN curl -fsSLo /tmp/nginx.tar.gz https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
 && echo "${NGINX_SHA256}  /tmp/nginx.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/src \
 && tar -xzf /tmp/nginx.tar.gz -C /opt/src \
 && mv /opt/src/nginx-${NGINX_VERSION} /opt/src/nginx \
 && rm /tmp/nginx.tar.gz \
 && cd /opt/src/nginx \
 && ./configure ${NGINX_CONFIGURE_ARGS} \
 && make -j"$(nproc)" \
 && make install \
 && mkdir -p /opt/nginx/modules

ENV CARGO_HOME=/work/cargo \
    CARGO_TARGET_DIR=/work/target

WORKDIR /src
