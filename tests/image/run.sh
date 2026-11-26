#!/bin/bash
# The release image, used the way a user would. Runs on the host.
# Usage: run.sh <image> <dev-image>
set -u
IMAGE=$1
DEV=$2
NS=sundew-ns-$$
C=sundew-img-$$
CONF=$(mktemp -d)
fail=0

cleanup() { docker rm -f $C $NS >/dev/null 2>&1; rm -rf "$CONF"; }
trap cleanup EXIT

ok()   { echo "  ok   $*"; }
bad()  { echo "  FAIL $*"; fail=1; }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
x()    { docker exec $NS bash -c "$1"; }
img()  { docker exec $C sh -c "$1"; }
code() { x "curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: $1' http://127.0.0.1/"; }
pid_of() { img "for p in /proc/[0-9]*; do [ \"\$(cat \$p/comm 2>/dev/null)\" = $1 ] && echo \${p#/proc/}; done" | head -1; }
status() { img "awk '\$1 == \"$2:\" { print \$2 }' /proc/$1/status"; }
wait_for() { for _ in $(seq 1 100); do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }

cat > "$CONF/sundew.conf" <<'CONF'
set_real_ip_from 127.0.0.1;
real_ip_header X-Forwarded-For;
ipset_blacklist bad4 bad6;
CONF

echo "== $IMAGE"
docker run -d --name $NS --cap-add NET_ADMIN "$DEV" sleep infinity >/dev/null
x "ipset create bad4 hash:ip && ipset add bad4 192.0.2.1 && ipset create bad6 hash:ip family inet6 && ipset add bad6 2001:db8::1"
docker run -d --name $C --cap-add NET_ADMIN --network container:$NS \
    -v "$CONF/sundew.conf:/etc/nginx/conf.d/sundew.conf:ro" "$IMAGE" >/dev/null

check "nginx serves" wait_for '[ "$(code 192.0.2.2)" = 200 ]'
check "banned v4 -> 403" [ "$(code 192.0.2.1)" = 403 ]
check "banned v6 -> 403" [ "$(code 2001:db8::1)" = 403 ]
E=$(pid_of sundew-engine)
check "engine running" [ -n "$E" ]
check "engine Seccomp=2" [ "$(status "$E" Seccomp)" = 2 ]
check "engine CapEff=NET_ADMIN" [ "$(status "$E" CapEff)" = 0000000000001000 ]
for i in $(seq 1 30); do code 10.1.0.$i >/dev/null; done
check "engine survived 30 lookups under seccomp (musl)" [ "$(pid_of sundew-engine)" = "$E" ]
W=$(pid_of nginx | head -1)
img "nginx -s reload"
check "lookups after reload" wait_for '[ "$(code 10.2.0.1)" = 200 ] && [ "$(code 192.0.2.1)" = 403 ]'
check "one helper after reload" wait_for '[ "$(img "grep -l sundew-keeper /proc/[0-9]*/comm 2>/dev/null" | wc -l)" = 1 ]'
check "no alerts in the log" bash -c "! docker logs $C 2>&1 | grep -E '\[(alert|crit|emerg)\]'"
docker logs $C 2>&1 | grep -E '\[(alert|crit|emerg)\]' | head -5 | sed 's/^/  log: /'
exit $fail
