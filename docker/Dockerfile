# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-slim-trixie AS toolchain

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl gdb iproute2 ipset libcap2-bin nftables \
        libpcre2-dev libssl-dev nghttp2-client openssl procps python3 strace \
        wrk zlib1g-dev \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add clippy rustfmt \
 && groupadd -r -g 101 nginx && useradd -r -u 101 -g nginx -M -s /usr/sbin/nologin nginx \
 && groupadd -r -g 998 sundew && useradd -r -u 998 -g sundew -M -s /usr/sbin/nologin sundew


FROM toolchain AS dev

ARG NGINX_VERSION
ARG NGINX_SHA256
ARG NGINX_CC_OPT="-O1 -g"
ARG NGINX_LD_OPT=""

ENV NGINX_VERSION=${NGINX_VERSION} \
    NGINX_CC_OPT="${NGINX_CC_OPT}" \
    NGINX_LD_OPT="${NGINX_LD_OPT}" \
    NGINX_CONFIGURE_ARGS="--prefix=/opt/nginx --with-compat --with-debug --with-threads --with-http_realip_module --with-http_ssl_module --with-http_v2_module"

RUN curl -fsSLo /tmp/nginx.tar.gz https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
 && echo "${NGINX_SHA256}  /tmp/nginx.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/src \
 && tar -xzf /tmp/nginx.tar.gz -C /opt/src \
 && mv /opt/src/nginx-${NGINX_VERSION} /opt/src/nginx \
 && rm /tmp/nginx.tar.gz \
 && cd /opt/src/nginx \
 && : > /opt/src/extra && : > /opt/src/ccopt \
 && if [ -f src/http/v3/ngx_http_v3.h ]; then echo " --with-http_v3_module" >> /opt/src/extra; fi \
 && if ! grep -q pcre2 auto/lib/pcre/conf; then \
        echo " --without-http_rewrite_module --without-pcre" >> /opt/src/extra; \
        echo " -Wno-deprecated-declarations" > /opt/src/ccopt; \
    fi \
 && ./configure ${NGINX_CONFIGURE_ARGS} $(cat /opt/src/extra) \
        --with-cc-opt="${NGINX_CC_OPT}$(cat /opt/src/ccopt)" --with-ld-opt="${NGINX_LD_OPT}" \
 && make -j"$(nproc)" \
 && make install \
 && mkdir -p /opt/nginx/modules

ENV CARGO_HOME=/work/cargo \
    CARGO_TARGET_DIR=/work/target

WORKDIR /src
