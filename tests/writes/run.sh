#!/bin/bash
# v0.2 writes: ipset_autoadd, ipset_ratelimit. Runs inside the dev container.
set -u

. /src/tests/lib.sh

IDX=$RUN/www/index.html
WRITABLE="sundew_writable_sets sw_trap sw_trap6 sw_ban sw_net;"

LOCS="location = /wp-login.php { ipset_autoadd sw_trap timeout=120; } \
location = /trap403 { ipset_autoadd sw_trap status=403; } \
location = /trap6 { ipset_autoadd sw_trap6; } \
location = /trapif { ipset_autoadd sw_trap if=\$arg_go; } \
location = /dry { ipset_dryrun on; ipset_autoadd sw_trap; alias $IDX; } \
location = /short { ipset_autoadd sw_trap timeout=2; } \
location = /net { ipset_autoadd sw_net timeout=60 prefix4=24; } \
location = /api { ipset_ratelimit rate=5 window=10s autoban=sw_ban ban_time=600; alias $IDX; } \
location = /rl6 { ipset_ratelimit rate=3 window=10s key6=64; alias $IDX; } \
location = /rl2 { ipset_ratelimit rate=2 window=2s; alias $IDX; }"

restart() {   # extra main, extra http
    stop_all
    MAIN="$WRITABLE ${1:-}" HTTP="${2:-}" LOC="$LOCS" conf "ipset_denylist sw_bad4 sw_trap sw_trap6 sw_ban;"
    start
}

get() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "${@:3}" "http://127.0.0.1:8080$2"; }
in_set() { ipset test "$1" "$2" 2>/dev/null; }
timeout_of() { ipset list "$1" | awk -v a="$2" '$1 == a { print $3 }'; }
stat() { curl -s http://127.0.0.1:8080/stats | python3 -I -c "import json,sys; print(json.load(sys.stdin)['counters'][sys.argv[1]])" "$1"; }

setup_sets
ipset create sw_trap hash:ip timeout 300
ipset create sw_trap6 hash:ip family inet6 timeout 300
ipset create sw_ban hash:ip timeout 300
ipset create sw_net hash:net timeout 300
ipset create sw_allow4 hash:ip
ipset add sw_allow4 192.0.2.50
ipset create sw_notimeout hash:ip
ipset create sw_t0 hash:ip timeout 0

echo "== honeypot"
restart
check "trap answers 404" [ "$(get 192.0.2.10 /wp-login.php)" = 404 ]
check "address added" wait_for "in_set sw_trap 192.0.2.10"
t=$(timeout_of sw_trap 192.0.2.10)
check "with the trap's timeout ($t s)" [ -n "$t" ] && [ "$t" -le 120 ] && [ "$t" -ge 100 ]
check "denied at once on the next request (written through)" [ "$(get 192.0.2.10 /)" = 403 ]
check "status=403" [ "$(get 192.0.2.11 /trap403)" = 403 ]
check "IPv6, set's default timeout" wait_for "[ \$(get 2001:db8::10 /trap6) = 404 ] && in_set sw_trap6 2001:db8::10"
t=$(timeout_of sw_trap6 2001:db8::10)
check "default timeout used ($t s)" [ -n "$t" ] && [ "$t" -gt 250 ]
check "logged" grep -aq 'adding 192.0.2.10 to set "sw_trap" for 120s' $RUN/error.log
check "stats: trapped and adds" [ "$(stat trapped)" -ge 3 ] && [ "$(stat adds)" -ge 3 ]

echo "== a short ban does not outlive the kernel's timeout in the cache"
get 192.0.2.12 / >/dev/null
check "trap with timeout=2" [ "$(get 192.0.2.12 /short)" = 404 ]
check "denied while banned" wait_for "[ \$(get 192.0.2.12 /) = 403 ]"
sleep 3.2
check "allowed again after 2 s although ipset_cache_ttl is 60 s" [ "$(get 192.0.2.12 /)" = 200 ]

echo "== never-ban list"
check "trap from 10.1.2.3 still answers 404" [ "$(get 10.1.2.3 /wp-login.php)" = 404 ]
sleep 0.3
check "private address not added" not in_set sw_trap 10.1.2.3
check "refusal logged" grep -aq 'refused to add a protected address to set "sw_trap"' $RUN/error.log
check "stats: adds_refused" [ "$(stat adds_refused)" -ge 1 ]
restart "sundew_protect 192.0.2.128/25 !10.0.0.0/8;"
get 192.0.2.200 /wp-login.php >/dev/null; get 10.1.2.4 /wp-login.php >/dev/null; sleep 0.3
check "sundew_protect adds a prefix" not in_set sw_trap 192.0.2.200
check "!prefix removes a built-in one" in_set sw_trap 10.1.2.4

echo "== guards"
restart
get 192.0.2.20 /wp-login.php -H 'Sec-Fetch-Mode: no-cors' >/dev/null
get 192.0.2.21 /wp-login.php -H 'Purpose: prefetch' >/dev/null
get 192.0.2.22 /trapif >/dev/null
get 192.0.2.23 '/trapif?go=1' >/dev/null
sleep 0.3
check "browser request not added" not in_set sw_trap 192.0.2.20
check "prefetch not added" not in_set sw_trap 192.0.2.21
check "if= empty: not added" not in_set sw_trap 192.0.2.22
check "if= set: added" in_set sw_trap 192.0.2.23
check "browser skip logged" grep -aq 'browser request (Sec-Fetch-\*), not adding 192.0.2.20' $RUN/error.log
check "dry run: 200" [ "$(get 192.0.2.24 /dry)" = 200 ]
sleep 0.3
check "dry run: not added" not in_set sw_trap 192.0.2.24
check "stats: adds_skipped" [ "$(stat adds_skipped)" -ge 4 ]

echo "== hash:net prefix"
check "trap" [ "$(get 198.51.100.77 /net)" = 404 ]
check "the /24 was added" wait_for "ipset list sw_net | grep -q '^198.51.100.0/24 '"

echo "== rate limit"
codes=$(for i in 1 2 3 4 5 6 7; do get 192.0.2.30 /api; echo; done | tr '\n' ' ')
check "5 allowed, then 429, then banned ($codes)" [ "$codes" = "200 200 200 200 200 429 403 " ]
check "autobanned" wait_for "in_set sw_ban 192.0.2.30"
t=$(timeout_of sw_ban 192.0.2.30)
check "for ban_time ($t s)" [ -n "$t" ] && [ "$t" -gt 550 ]
check "banned everywhere now" [ "$(get 192.0.2.30 /)" = 403 ]
check "\$ipset_result = ratelimited" bash -c "for i in 1 2; do curl -s -o /dev/null -H 'X-Forwarded-For: 192.0.2.31' http://127.0.0.1:8080/rl2; done; curl -sI -H 'X-Forwarded-For: 192.0.2.31' http://127.0.0.1:8080/rl2 | grep -qi 'X-Sundew: ratelimited'"
for i in 1 2 3 4 5 6 7; do get 192.0.2.32 /api -H 'Sec-Fetch-Site: cross-site' >/dev/null; done
sleep 0.3
check "cross-site: 429 but no ban" not in_set sw_ban 192.0.2.32
codes=$(for a in 2001:db8:1::1 2001:db8:1::2 2001:db8:1::3 2001:db8:1::4; do get $a /rl6; echo; done | tr '\n' ' ')
check "IPv6 /64 shares one counter ($codes)" [ "$codes" = "200 200 200 429 " ]
codes=$(for i in 1 2 3; do get 192.0.2.33 /rl2; echo; done | tr '\n' ' ')
check "rate 2 per 2 s ($codes)" [ "$codes" = "200 200 429 " ]
sleep 4.2
check "allowed again after the window" [ "$(get 192.0.2.33 /rl2)" = 200 ]
check "stats: ratelimited" [ "$(stat ratelimited)" -ge 4 ]

echo "== add budget (20/s, burst 100)"
restart
for i in $(seq 1 130); do get "203.0.113.$i" /wp-login.php >/dev/null & done; wait
sleep 0.5
n=$(ipset list sw_trap | grep -c '^203\.0\.113\.')
check "at most ~100 added in a burst ($n)" [ "$n" -ge 95 ] && [ "$n" -le 110 ]
check "budget logged" grep -aq 'refused adds to set "sw_trap": over 20 per second' $RUN/error.log

echo "== configuration errors"
stop_all
MAIN="" LOC="location = /t { ipset_autoadd sw_trap; }" conf "ipset_denylist sw_bad4;"
check "set not in sundew_writable_sets" bash -c "$NGINX -t -c $CONF 2>&1 | grep -q 'which is not listed in \"sundew_writable_sets\"'"
MAIN="sundew_writable_sets sw_allow4;" LOC="location = /t { ipset_autoadd sw_allow4; }" conf "ipset_allowlist sw_allow4;"
check "allowlist set as add target" bash -c "$NGINX -t -c $CONF 2>&1 | grep -q 'is used by ipset_allowlist and is also added to'"
MAIN="sundew_writable_sets sw_notimeout;" LOC="location = /t { ipset_autoadd sw_notimeout; }" conf "ipset_denylist sw_bad4;"
$NGINX -c $CONF 2>$RUN/e1; check "set without timeout support" grep -q 'has no timeout support' $RUN/e1
MAIN="sundew_writable_sets sw_t0;" LOC="location = /t { ipset_autoadd sw_t0; }" conf "ipset_denylist sw_bad4;"
$NGINX -c $CONF 2>$RUN/e2; check "no timeout and set default 0" grep -q "default timeout is 0" $RUN/e2
MAIN="sundew_writable_sets sw_trap;" LOC="location = /t { ipset_autoadd sw_trap prefix4=24; }" conf "ipset_denylist sw_bad4;"
$NGINX -c $CONF 2>$RUN/e3; check "prefix4= on hash:ip" grep -q 'need a hash:net set' $RUN/e3
check "nothing started" [ -z "$(pgrep -x nginx)" ] && [ -z "$(keepers)" ]

stop_all
check "no sanitizer reports" [ "$(san_reports)" = 0 ]
[ "$(san_reports)" = 0 ] || san_show
summary
