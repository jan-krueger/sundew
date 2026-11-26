# shellcheck shell=bash
# Shared helpers for the container test suites.

NGINX=/opt/nginx/sbin/nginx
RUN=/tmp/sundew
CONF=$RUN/nginx.conf
NET_ADMIN=0000000000001000

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

conf() {
    mkdir -p $RUN/www $RUN/san
    chmod 1777 $RUN/san
    [ -f $RUN/cert.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout $RUN/key.pem -out $RUN/cert.pem -days 2 -subj /CN=localhost >/dev/null 2>&1
    echo ok > $RUN/www/index.html
    sed -e "s|@RUN@|$RUN|g" -e "s|@SETS@|${1:-ipset_blacklist sw_bad4 sw_bad6;}|" \
        -e "s|@MAIN@|${MAIN:-}|" -e "s|@HTTP@|${HTTP:-}|" -e "s|@LOC@|${LOC:-}|" \
        -e "s|@H3@|$(h3_listen)|" \
        /src/tests/nginx.conf.in > $CONF
}

has_h3() { $NGINX -V 2>&1 | grep -q http_v3_module; }
h3_listen() { has_h3 && echo 'listen 127.0.0.1:8443 quic reuseport; listen 127.0.0.1:8443 ssl; http3 on;'; }

master()  { cat $RUN/nginx.pid 2>/dev/null; }
workers() { pgrep -P "$(master)" -f 'nginx: worker' | sort; }
keepers() { pgrep -x sundew-keeper | sort; }
engines() { pgrep -x sundew-engine | sort; }
count()   { "$@" | grep -c . ; }
status()  { awk -v k="$2:" '$1 == k { print $2 }' /proc/"$1"/status; }

wait_for() {
    local i
    for i in $(seq 1 100); do
        if eval "$1"; then return 0; fi
        sleep 0.1
    done
    return 1
}

# HTTP status for a client address (via X-Forwarded-For)
code() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "http://127.0.0.1:8080/"; }
is() { [ "$(code "$1")" = "$2" ]; }

# a never-seen address: 200 proves the helper answered (fail closed is 403)
FRESH=0
alive() { FRESH=$((FRESH + 1)); is "10.250.$((FRESH / 250)).$((FRESH % 250 + 1))" 200; }

stop_all() {
    [ -f $RUN/nginx.pid ] && $NGINX -c $CONF -s stop 2>/dev/null
    wait_for '[ -z "$(pgrep -x nginx)" ] && [ -z "$(keepers)" ]' || pkill -9 -x nginx
    pkill -9 -x sundew-keeper 2>/dev/null
    pkill -9 -x sundew-engine 2>/dev/null
    mkdir -p /tmp/san-keep
    cp -a $RUN/san/. /tmp/san-keep/ 2>/dev/null
    rm -rf $RUN
}

# sanitizer reports (SAN=1 images)
# ASan: every report; UBSan: reports that involve our sources (/src/src/)
san_files() { ls -d $RUN/san/* /tmp/san-keep/* 2>/dev/null; }
san_reports() {
    local f n=0
    for f in $(san_files); do
        case ${f##*/} in
            asan*) n=$((n + 1)) ;;
            ubsan*) grep -q '/src/src/' "$f" && n=$((n + 1)) ;;
        esac
    done
    echo $n
}
san_show() { for f in $(san_files); do echo "-- $f"; head -30 "$f"; done; }
san_core() { cat $(san_files) 2>/dev/null | grep -o 'src/[a-z0-9_/]*\.c:[0-9]*:[0-9]*: runtime error: [^,]*' | sort | uniq -c; }

summary() {
    echo
    echo "passed: $PASS  failed: $FAIL"
    [ "$FAIL" = 0 ]
}

setup_sets() {
    ipset destroy 2>/dev/null
    ipset create sw_bad4 hash:ip
    ipset create sw_bad6 hash:ip family inet6
    ipset create sw_net4 hash:net
    ipset add sw_bad4 192.0.2.1
    ipset add sw_bad6 2001:db8::1
    ipset add sw_net4 198.51.100.0/24
}

start() {
    $NGINX -c $CONF 2>$RUN/start.err
    wait_for '[ -n "$(master)" ] && [ "$(count workers)" = 2 ] && [ "$(count engines)" -ge 1 ]'
}
