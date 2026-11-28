#!/bin/bash
# Async suspension (P0b). Runs inside the dev container.
set -u

. /src/tests/lib.sh

URL1=http://127.0.0.1:8080/
URL2=http://127.0.0.1:8081/
URL3=https://127.0.0.1:8443/

h1() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" $URL1; }
h2() { curl -s --http2-prior-knowledge -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" $URL2; }
h3() { curl -sk --http3-only -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" $URL3; }

dbg() { grep -ac "$1" $RUN/error.log; }

restart() {
    stop_all
    MAIN=${1:-} HTTP=${2:-} conf
    start
}

# every section ends here: no crashes, no unexpected alerts, no sanitizer reports
clean() {
    local w
    w=$(grep -a 'exited on signal' $RUN/error.log | head -3)
    check "$1: no worker crash" [ -z "$w" ]
    w=$(grep -aE '\[(alert|crit|emerg)\]' $RUN/error.log | head -3)
    [ -n "$w" ] && echo "$w" | sed 's/^/  log: /'
    check "$1: no alert/crit/emerg" [ -z "$w" ]
    check "$1: no sanitizer reports" [ "$(san_reports)" = 0 ]
    [ "$(san_reports)" = 0 ] || san_show
}

ips() { local i; for i in $(seq 1 "$1"); do echo "10.$2.$((i / 250)).$((i % 250 + 1))"; done; }

setup_sets
rm -rf /tmp/san-keep

echo "== protocols"
restart
for p in h1 h2 $(has_h3 && echo h3); do
    check "$p: hit -> 403" [ "$($p 192.0.2.1)" = 403 ]
    check "$p: miss -> 200" [ "$($p 192.0.2.2)" = 200 ]
    check "$p: v6 hit -> 403" [ "$($p 2001:db8::1)" = 403 ]
done
clean protocols

echo "== coalescing (delay 1s)"
restart "sundew_debug_delay 1s;" "sundew_lookup_timeout 2s;"
s0=$(dbg 'sundew submit'); c0=$(dbg 'sundew coalesce')
n403=$(curl -s -Z --parallel-immediate --parallel-max 40 -H 'X-Forwarded-For: 192.0.2.1' -w 'CODE:%{http_code}\n' \
    $(for i in $(seq 1 40); do printf '%s?%d ' $URL1 "$i"; done) | grep -o 'CODE:403' | wc -l)
s1=$(dbg 'sundew submit'); c1=$(dbg 'sundew coalesce')
check "40 concurrent requests all 403 ($n403)" [ "$n403" = 40 ]
check "at most one lookup per worker ($((s1 - s0)))" [ $((s1 - s0)) -le 2 ]
check "the rest coalesced ($((c1 - c0)))" [ $((s1 - s0 + c1 - c0)) = 40 ]
clean coalescing

echo "== deadline (delay 300ms, timeout 100ms)"
restart "sundew_debug_delay 300ms;" "sundew_lookup_timeout 100ms;"
t=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H 'X-Forwarded-For: 192.0.2.2' $URL1)
check "fail closed on timeout ($t)" [ "${t% *}" = 403 ]
check "answered at the deadline" awk -v t="${t#* }" 'BEGIN { exit !(t >= 0.09 && t < 0.29) }'
check "timeout logged" wait_for "[ \$(dbg 'lookup timed out') -ge 1 ]"
check "late reply cached" wait_for "[ \$(dbg 'sundew late reply') -ge 1 ]"
t=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H 'X-Forwarded-For: 192.0.2.2' $URL1)
[ "${t% *}" = 200 ] && awk -v t="${t#* }" 'BEGIN { exit !(t < 0.05) }'
check "next request served from the cache ($t)" [ $? = 0 ]
clean deadline
restart "sundew_debug_delay 300ms;" "sundew_lookup_timeout 100ms; ipset_fail_open on;"
check "fail open on timeout" [ "$(h1 192.0.2.1)" = 200 ]
clean "fail open"

echo "== client aborts (delay 300ms)"
restart "sundew_debug_delay 300ms;" "sundew_lookup_timeout 1s;"
before=$(workers | tr '\n' ' ')
for ip in $(ips 200 1); do
    curl -s -o /dev/null --max-time 0.05 -H "X-Forwarded-For: $ip" $URL1 &
done
wait
for ip in $(ips 100 2); do
    curl -s -o /dev/null --http2-prior-knowledge --max-time 0.05 -H "X-Forwarded-For: $ip" $URL2 &
done
wait
sleep 0.5
check "h1/h2 aborts: workers unchanged" [ "$(workers | tr '\n' ' ')" = "$before" ]
check "still serving" [ "$(h1 192.0.2.1)" = 403 ] && [ "$(h1 192.0.2.2)" = 200 ]
clean aborts

echo "== HTTP/2 stream resets and connection drops (delay 200ms)"
restart "sundew_debug_delay 200ms;" "sundew_lookup_timeout 1s;"
before=$(workers | tr '\n' ' ')
for r in 1 2 3; do
    curl -s -Z --parallel-immediate --parallel-max 100 --http2-prior-knowledge --max-time 0.05 \
        -H "X-Forwarded-For: 10.9.0.$r" $(for i in $(seq 1 100); do printf '%s?%d ' $URL2 "$i"; done) >/dev/null
done
for r in 1 2 3 4 5; do
    timeout -s KILL 0.3 h2load -n 5000 -c 4 -m 100 -H "X-Forwarded-For: 10.8.0.$r" $URL2 >/dev/null 2>&1
done
sleep 0.5
check "h2 resets: workers unchanged" [ "$(workers | tr '\n' ' ')" = "$before" ]
check "h2 still serving" [ "$(h2 192.0.2.1)" = 403 ]
clean "h2 resets"

if has_h3; then
    echo "== HTTP/3 stream resets and connection drops (delay 200ms)"
    restart "sundew_debug_delay 200ms;" "sundew_lookup_timeout 1s;"
    before=$(workers | tr '\n' ' ')
    for r in 1 2 3; do
        curl -sk -Z --parallel-immediate --parallel-max 50 --http3-only --max-time 0.05 \
            -H "X-Forwarded-For: 10.7.0.$r" $(for i in $(seq 1 50); do printf '%s?%d ' $URL3 "$i"; done) >/dev/null
    done
    for r in 1 2 3; do
        timeout -s KILL 0.3 h2load --alpn-list=h3 -n 2000 -c 4 -m 50 -H "X-Forwarded-For: 10.6.0.$r" $URL3 >/dev/null 2>&1
    done
    sleep 0.5
    check "h3 resets: workers unchanged" [ "$(workers | tr '\n' ' ')" = "$before" ]
    check "h3 still serving" [ "$(h3 192.0.2.1)" = 403 ]
    clean "h3 resets"
fi

echo "== graceful shutdown with pending lookups (delay 300ms)"
restart "sundew_debug_delay 300ms;" "sundew_lookup_timeout 1s;"
rm -f /tmp/codes.*
for ip in $(ips 20 3); do
    (curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $ip" $URL1 > /tmp/codes.$ip) &
done
sleep 0.1
$NGINX -c $CONF -s quit
wait
check "all pending requests completed (200)" [ "$(cat /tmp/codes.* | grep -o 200 | wc -l)" = 20 ]
check "nginx exited" wait_for '[ -z "$(pgrep -x nginx)" ]'
check "helper exited" wait_for '[ -z "$(keepers)" ]'
clean shutdown

echo "== reload with pending lookups (delay 300ms)"
restart "sundew_debug_delay 300ms;" "sundew_lookup_timeout 1s;"
rm -f /tmp/codes.*
for ip in $(ips 20 4); do
    (curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $ip" $URL1 > /tmp/codes.$ip) &
done
sleep 0.1
kill -HUP "$(master)"
wait
check "all pending requests completed across reload" [ "$(cat /tmp/codes.* | grep -o 200 | wc -l)" = 20 ]
check "old helper drained" wait_for '[ "$(count keepers)" = 1 ]'
clean reload

echo "== engine killed with pending lookups (delay 300ms, timeout 1s)"
restart "sundew_debug_delay 300ms;" "sundew_lookup_timeout 1s;"
rm -f /tmp/codes.*
for ip in $(ips 10 5); do
    (curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $ip" $URL1 > /tmp/codes.$ip) &
done
# all ten lookups sent; no new engine may answer them before they time out
wait_for '[ "$(curl -s http://127.0.0.1:8080/stats | python3 -I -c "import json,sys; print(json.load(sys.stdin)[\"counters\"][\"lookups\"])")" -ge 10 ]'
kill -STOP "$(keepers)"
kill -9 "$(engines)"
wait
kill -CONT "$(keepers)"
check "lost replies fail closed (403) ($(cat /tmp/codes.* | fold -w3 | sort | uniq -c | tr -s " " | tr "\n" ","))" [ "$(cat /tmp/codes.* | grep -o 403 | wc -l)" = 10 ]
check "engine restarted" wait_for '[ "$(count engines)" = 1 ]'
check "serving after restart" wait_for '[ "$(h1 192.0.2.2)" = 200 ]'
grep -a 'engine killed by signal 9' $RUN/error.log >/dev/null || true
clean "engine kill"

echo "== engine stalled: more requests than the channel holds"
stop_all
MAIN="worker_rlimit_nofile 8192;" HTTP="sundew_lookup_timeout 500ms;" conf
sed -i 's/worker_connections 1024/worker_connections 4096/' $CONF
start
kill -STOP "$(engines)"
out=$(python3 -I /src/tests/async/burst.py 1400 3)
kill -CONT "$(engines)"
check "every request answered, fail closed ($out)" [ "$out" = "403:1400 none:0" ]
busy=$(curl -s http://127.0.0.1:8080/stats | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["counters"]["busy"])')
check "the overflow counted as busy ($busy)" [ "$busy" -gt 0 ]
check "logged" grep -aq 'send to helper failed' $RUN/error.log
check "serving after the stall" wait_for '[ "$(h1 10.78.0.1)" = 200 ]'
clean "engine stall"

echo "== load"
# before 1.19.7, HTTP/2 had its own per-connection limit
h2max=""
[ "$(printf '%s\n' "$NGINX_VERSION" 1.19.7 | sort -V | head -1)" = 1.19.7 ] || h2max="http2_max_requests 100000;"
restart "" "keepalive_requests 100000; $h2max"
out=$(h2load --h1 -n 20000 -c 50 -H 'X-Forwarded-For: 192.0.2.1' $URL1 2>&1 | grep 'status codes')
check "h1 20000 banned -> 403 ($out)" grep -q '0 2xx, 0 3xx, 20000 4xx, 0 5xx' <<<"$out"
out=$(h2load -n 20000 -c 10 -m 20 -H 'X-Forwarded-For: 10.20.0.1' $URL2 2>&1 | grep 'status codes')
check "h2 20000 allowed -> 200 ($out)" grep -q '20000 2xx, 0 3xx, 0 4xx, 0 5xx' <<<"$out"
clean load

stop_all
check "no sanitizer reports overall" [ "$(san_reports)" = 0 ]
san_core | sed 's/^/  nginx core ubsan (not ours): /'
summary
