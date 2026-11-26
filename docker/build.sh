#!/bin/sh
set -eu

OBJS=/work/objs
STAMP="$OBJS/.configure-stamp"
SUM=$(cat /src/config | sha256sum | cut -d' ' -f1)-$(echo "$NGINX_CONFIGURE_ARGS" | sha256sum | cut -d' ' -f1)

cd /opt/src/nginx

if [ ! -f "$STAMP" ] || [ "$(cat "$STAMP")" != "$SUM" ]; then
    # shellcheck disable=SC2086
    ./configure $NGINX_CONFIGURE_ARGS --builddir="$OBJS" --add-dynamic-module=/src >/work/configure.log 2>&1 \
        || { tail -30 /work/configure.log; exit 1; }
    echo "$SUM" > "$STAMP"
fi

make -s -f "$OBJS/Makefile" modules
install -o root -g root -m 0644 "$OBJS/ngx_http_sundew_module.so" /opt/nginx/modules/

cd /src/helper
cargo build --release --locked -q
install -o root -g root -m 0755 "$CARGO_TARGET_DIR/release/sundew-helper" /opt/nginx/modules/

echo "build: ok (nginx $NGINX_VERSION)"
