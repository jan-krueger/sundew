#!/bin/bash
# v0.1 features: cache, whitelist, dryrun, status, stats. Runs inside the dev container.
set -u

. /src/tests/lib.sh

restart() {
    stop_all
    SETS=${1:-ipset_blacklist sw_bad4 sw_bad6;} MAIN=${2:-} HTTP=${3:-} LOC=${4:-} conf_sets
    start
}
conf_sets() { conf "$SETS"; }

timed() { curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "X-Forwarded-For: $1" "http://127.0.0.1:8080${2:-/}"; }
fast() { awk -v t="${1#* }" 'BEGIN { exit !(t < 0.15) }'; }
slow() { awk -v t="${1#* }" 'BEGIN { exit !(t >= 0.25) }'; }
hdr() { curl -s -D - -o /dev/null -H "X-Forwarded-For: $1" "http://127.0.0.1:8080${2:-/}" | tr -d '\r' | awk -F': ' 'tolower($1) == "x-sundew" { print $2 }'; }
stat() { curl -s http://127.0.0.1:8080/stats | python3 -I -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

setup_sets
ipset create sw_allow4 hash:ip
ipset add sw_allow4 192.0.2.50
ipset add sw_bad4 192.0.2.50
ipset create sw_bm bitmap:ip range 192.0.2.0/24
ipset add sw_bm 192.0.2.77
ipset create sw_port hash:ip,port

echo "== cache (delay 300ms)"
restart "" "sundew_debug_delay 300ms;" "sundew_lookup_timeout 1s;"
t1=$(timed 192.0.2.1); t2=$(timed 192.0.2.1)
check "first lookup goes to the helper ($t1)" bash -c "[ '${t1% *}' = 403 ] && $(declare -f slow); slow '$t1'"
check "second is a cache hit ($t2)" bash -c "[ '${t2% *}' = 403 ] && $(declare -f fast); fast '$t2'"
n=0; for i in 1 2 3 4 5 6; do t=$(timed 192.0.2.1); fast "$t" && [ "${t% *}" = 403 ] && n=$((n + 1)); done
check "hits in every worker (shared zone)" [ "$n" = 6 ]
t1=$(timed 192.0.2.9); t2=$(timed 192.0.2.9)
check "negative results are cached too ($t2)" bash -c "[ '${t2% *}' = 200 ] && $(declare -f fast); fast '$t2'"
check "stats: cache_hit counted" [ "$(stat "d['counters']['cache_hit']")" -ge 8 ]
kill -HUP "$(master)"; wait_for '[ "$(count keepers)" = 1 ]'
t=$(timed 192.0.2.1)
check "cache survives reload ($t)" bash -c "[ '${t% *}' = 403 ] && $(declare -f fast); fast '$t'"
check "stats survive reload" [ "$(stat "d['counters']['cache_hit']")" -ge 9 ]

echo "== cache TTL and external changes"
restart "" "" "ipset_cache_ttl 1s;"
check "allowed before ban" is 192.0.2.30 200
ipset add sw_bad4 192.0.2.30
check "still cached as allowed" is 192.0.2.30 200
sleep 1.2
check "external ban visible after TTL" is 192.0.2.30 403
ipset del sw_bad4 192.0.2.30
sleep 1.2
check "external unban visible after TTL" is 192.0.2.30 200
restart "" "" "ipset_cache_ttl 0;"
check "ttl 0: allowed" is 192.0.2.31 200
ipset add sw_bad4 192.0.2.31
check "ttl 0: ban visible at once" is 192.0.2.31 403
ipset del sw_bad4 192.0.2.31

echo "== serve stale bans while the helper is down"
restart "" "" "ipset_cache_ttl 1s;"
check "banned" is 192.0.2.1 403
check "allowed" is 192.0.2.40 200
kill -9 "$(keepers)" "$(engines)"
sleep 1.2
check "stale ban still served" is 192.0.2.1 403
check "stale allow not served (fail closed)" is 192.0.2.40 403
check "unknown address fails closed" is 192.0.2.41 403
check "stats: stale_served" [ "$(stat "d['counters']['stale_served']")" -ge 1 ]
check "stats: helper_down" [ "$(stat "d['counters']['helper_down']")" -ge 1 ]
restart "" "" "ipset_cache_ttl 1s; ipset_fail_open on;"
check "banned (fail open config)" is 192.0.2.1 403
kill -9 "$(keepers)" "$(engines)"
sleep 1.2
check "fail open: stale ban still served" is 192.0.2.1 403
check "fail open: unknown address allowed" is 192.0.2.42 200

echo "== whitelist"
restart "ipset_whitelist sw_allow4; ipset_blacklist sw_bad4;"
check "member allowed, even if blacklisted" is 192.0.2.50 200
check "non-member denied" is 192.0.2.51 403
check "v6 client, v4-only whitelist: denied" is 2001:db8::5 403
check "\$ipset_matched_set = sw_allow4" [ "$(hdr 192.0.2.50)" = "allow sw_allow4" ]

echo "== dryrun, status, per-location off"
restart "" "" "" "location /dry { ipset_dryrun on; alias $RUN/www/index.html; } location /s503 { ipset_status 503; alias $RUN/www/index.html; } location /s444 { ipset_status 444; alias $RUN/www/index.html; } location /open { ipset_blacklist off; alias $RUN/www/index.html; }"
c=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1:8080/dry)
check "dryrun: banned client gets 200 ($c)" [ "$c" = 200 ]
check "dryrun: \$ipset_result = dryrun" [ "$(hdr 192.0.2.1 /dry)" = "dryrun sw_bad4" ]
check "dryrun logged" grep -aq 'would deny 192.0.2.1' $RUN/error.log
c=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1:8080/s503)
check "ipset_status 503 ($c)" [ "$c" = 503 ]
c=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1:8080/s444)
check "ipset_status 444 closes the connection ($c)" [ "$c" = 000 ]
c=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1:8080/open)
check "ipset_blacklist off in a location ($c)" [ "$c" = 200 ]

echo "== set types"
restart "ipset_blacklist sw_bm sw_net4;"
check "bitmap:ip hit" is 192.0.2.77 403
check "bitmap:ip miss" is 192.0.2.78 200
check "hash:net hit" is 198.51.100.200 403
stop_all
conf "ipset_blacklist sw_port;"
$NGINX -c $CONF 2>$RUN/start.err
check "hash:ip,port rejected at startup" grep -q 'set "sw_port": unsupported set type' $RUN/start.err

echo "== stats and metrics"
restart
for i in 1 2 3; do is 192.0.2.1 403; done
j=$(curl -s http://127.0.0.1:8080/stats)
check "stats is JSON" python3 -I -c "import json,sys; json.loads(sys.argv[1])" "$j"
check "stats: denied >= 3" [ "$(stat "d['counters']['denied']")" -ge 3 ]
check "stats: sw_bad4 matched >= 3" [ "$(stat "d['sets']['sw_bad4']['matched']")" -ge 3 ]
m=$(curl -s -D - http://127.0.0.1:8080/metrics | tr -d '\r')
check "metrics content type" grep -q '^Content-Type: text/plain; version=0.0.4' <<<"$m"
check "metrics: set counter" grep -qE '^sundew_set_matched_total\{set="sw_bad4"\} [0-9]+$' <<<"$m"
check "metrics: denied counter" grep -qE '^sundew_denied_total [0-9]+$' <<<"$m"
check "metrics: every sample line is well formed" bash -c "! grep -vE '^(# (HELP|TYPE) .*|[a-z_]+(\{[a-z_]+=\"[^\"]*\"\})? [0-9]+)$' <<<\"\$1\" | grep -v '^Content\|^HTTP\|^Server\|^Date\|^Connection\|^X-Sundew\|^$' | grep -q ." _ "$m"

stop_all
check "no sanitizer reports" [ "$(san_reports)" = 0 ]
[ "$(san_reports)" = 0 ] || san_show
summary
