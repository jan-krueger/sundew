#!/bin/bash
# nftables sets: lookups, writes, startup checks. Runs inside the dev container.
set -u

. /src/tests/lib.sh

IDX=$RUN/www/index.html
S=nft:inet/sw

restart() {   # sets, extra main, locations
    stop_all
    MAIN="${2:-}" HTTP="ipset_cache_ttl 0;" LOC="${3:-}" conf "$1"
    start
}
hdr() { curl -s -D - -o /dev/null -H "X-Forwarded-For: $1" "http://127.0.0.1:8080${2:-/}" | tr -d '\r' | awk -F': ' 'tolower($1) == "x-sundew" { print $2 }'; }
get() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "http://127.0.0.1:8080$2"; }
elem() { nft list set inet sw "$1" | tr -d '\n' | grep -o "$2 [^,}]*"; }
fails() { $NGINX -c $CONF 2>$RUN/e; grep -q "$1" $RUN/e; }

setup_sets
nft flush ruleset
nft -f - <<'N'
table inet sw {
    set bad4 { type ipv4_addr; elements = { 192.0.2.3 } }
    set bad6 { typeof ip6 saddr; elements = { 2001:db8::3 } }
    set nets { type ipv4_addr; flags interval; elements = { 198.51.100.0/24 } }
    set allow { type ipv4_addr; elements = { 192.0.2.50 } }
    set trap { type ipv4_addr; flags timeout; timeout 5m; }
    set trap6 { type ipv6_addr; flags timeout; }
    set ban { type ipv4_addr; flags timeout; }
    set notimeout { type ipv4_addr; }
    set fixed { type ipv4_addr; flags constant; elements = { 192.0.2.99 } }
    set cc { type ipv4_addr . inet_service; }
    map m { type ipv4_addr : verdict; }
}
table ip sw4 {
    set bad { type ipv4_addr; elements = { 192.0.2.7 } }
}
N
nft add element inet sw bad4 '{ 192.0.2.50 }'

echo "== lookups"
restart "ipset_denylist $S/bad4 $S/bad6 $S/nets nft:ip/sw4/bad;"
check "member" is 192.0.2.3 403
check "not a member" is 192.0.2.4 200
check "IPv6 member (typeof)" is 2001:db8::3 403
check "IPv6 not a member" is 2001:db8::4 200
check "interval set: inside the range" is 198.51.100.77 403
check "interval set: outside" is 198.51.101.1 200
check "table of family ip" is 192.0.2.7 403
h=$(hdr 198.51.100.77)
check "\$ipset_matched_set ($h)" [ "$h" = "deny $S/nets" ]
check "metrics label" bash -c "curl -s http://127.0.0.1:8080/metrics | grep -q 'set=\"$S/nets\"'"

echo "== live changes"
nft add element inet sw bad4 '{ 192.0.2.30 }'
check "added element denied at once" is 192.0.2.30 403
nft delete element inet sw bad4 '{ 192.0.2.30 }'
check "deleted element allowed again" is 192.0.2.30 200

echo "== ipset and nftables together"
restart "ipset_denylist sw_bad4 $S/bad4; ipset_allowlist $S/allow;"
check "ipset member" is 192.0.2.1 403
check "nft member" is 192.0.2.3 403
check "allowlisted in nft wins over the denylist" is 192.0.2.50 200
check "not allowlisted: denied" is 192.0.2.4 403

echo "== a set deleted while running"
nft add set inet sw tmp '{ type ipv4_addr; }'
restart "ipset_denylist $S/bad4 $S/tmp;"
check "before: allowed" is 192.0.2.60 200
nft delete set inet sw tmp
sleep 10.5
check "after: lookups fail closed" is 192.0.2.61 403
check "logged" wait_for "grep -aq 'set \"$S/tmp\" no longer exists' $RUN/error.log"
nft add set inet sw tmp '{ type ipv4_addr; }'
check "recreated: lookups work again" wait_for "is 192.0.2.62 200"

echo "== writes"
LOCS="location = /trap { ipset_autoadd $S/trap; } \
location = /trap2m { ipset_autoadd $S/trap timeout=120; } \
location = /trap6 { ipset_autoadd $S/trap6 timeout=60; } \
location = /api { ipset_ratelimit rate=3 window=10s autoban=$S/ban ban_time=600; alias $IDX; }"
restart "ipset_denylist $S/trap $S/trap6 $S/ban;" "sundew_writable_sets $S/trap $S/trap6 $S/ban;" "$LOCS"
check "honeypot answers 404" [ "$(get 192.0.2.70 /trap)" = 404 ]
check "added with the set's default timeout ($(elem trap 192.0.2.70))" bash -c "nft list set inet sw trap | grep -q '192.0.2.70 expires'"
check "then denied everywhere" is 192.0.2.70 403
get 192.0.2.71 /trap2m >/dev/null
check "timeout= ($(elem trap 192.0.2.71))" bash -c "nft list set inet sw trap | grep -q '192.0.2.71 timeout 2m'"
get 2001:db8::71 /trap6 >/dev/null
check "IPv6 add ($(nft list set inet sw trap6 | grep -o '2001:db8::71 [^,}]*'))" bash -c "nft list set inet sw trap6 | grep -q '2001:db8::71 timeout 1m'"
get 192.0.2.71 /trap2m >/dev/null
check "existing element keeps its timeout" bash -c "nft list set inet sw trap | grep -c '192.0.2.71' | grep -qx 1"
get 10.1.2.3 /trap >/dev/null
check "never-ban list: private address not added" not bash -c "nft list set inet sw trap | grep -q 10.1.2.3"
codes=""; for i in 1 2 3 4; do codes="$codes $(get 192.0.2.80 /api)"; done
check "rate limit, then autoban ($codes)" [ "$codes" = " 200 200 200 429" ]
check "banned for ban_time ($(elem ban 192.0.2.80))" bash -c "nft list set inet sw ban | grep -q '192.0.2.80 timeout 10m'"
check "banned everywhere now" is 192.0.2.80 403

echo "== configuration errors"
stop_all
for ref in nft:inet/sw nft:arp/sw/bad4 "nft:inet/s w/x" nft:inet//bad4; do
    conf "ipset_denylist \"$ref\";"
    check "invalid reference \"$ref\"" bash -c "$NGINX -t -c $CONF 2>&1 | grep -q 'invalid nftables set'"
done
conf "ipset_denylist $S/nosuch;"
check "missing set" fails 'table or set does not exist; create it, e.g. "nft add set inet sw nosuch'
conf "ipset_denylist nft:inet/nosuch/bad4;"
check "missing table" fails 'table or set does not exist'
conf "ipset_denylist nft:ip/sw/bad4;"
check "table in another family" fails 'table or set does not exist'
conf "ipset_denylist $S/m;"
check "map refused" fails 'is not supported'
conf "ipset_denylist $S/cc;"
check "concatenation refused" fails 'is not supported'
MAIN="sundew_writable_sets $S/notimeout;" LOC="location = /t { ipset_autoadd $S/notimeout timeout=60; }" conf "ipset_denylist sw_bad4;"
check "add target without flags timeout" fails 'has no "flags timeout"'
MAIN="sundew_writable_sets $S/nets;" LOC="location = /t { ipset_autoadd $S/nets timeout=60; }" conf "ipset_denylist sw_bad4;"
check "interval set as add target" fails 'has "flags interval"'
MAIN="sundew_writable_sets $S/fixed;" LOC="location = /t { ipset_autoadd $S/fixed timeout=60; }" conf "ipset_denylist sw_bad4;"
check "constant set as add target" fails 'has "flags constant"'
MAIN="sundew_writable_sets $S/ban;" LOC="location = /t { ipset_autoadd $S/ban timeout=60 prefix4=24; }" conf "ipset_denylist sw_bad4;"
check "prefix4= on an nft set" fails 'need a hash:net set'
MAIN="sundew_writable_sets $S/ban;" LOC="location = /t { ipset_autoadd $S/ban; }" conf "ipset_denylist sw_bad4;"
check "no timeout and no set default" fails "default timeout is 0"
check "nothing started" [ -z "$(pgrep -x nginx)" ] && [ -z "$(keepers)" ]

stop_all
nft flush ruleset
check "no sanitizer reports" [ "$(san_reports)" = 0 ]
[ "$(san_reports)" = 0 ] || san_show
summary
