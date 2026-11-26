#!/bin/bash
# Lifecycle and privilege matrix (P0a). Runs inside the dev container.
set -u

NGINX=/opt/nginx/sbin/nginx
RUN=/tmp/sundew
CONF=$RUN/nginx.conf
RELOADS=${RELOADS:-100}
NET_ADMIN=0000000000001000

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

conf() {
    mkdir -p $RUN
    sed -e "s|@RUN@|$RUN|g" -e "s|@SETS@|${1:-ipset_blacklist sw_bad4 sw_bad6;}|" \
        /src/tests/lifecycle/nginx.conf.in > $CONF
}

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

lookup() { curl -s "http://127.0.0.1:8080/t?ip=$1"; }

stop_all() {
    [ -f $RUN/nginx.pid ] && $NGINX -c $CONF -s stop 2>/dev/null
    wait_for '[ -z "$(pgrep -x nginx)" ] && [ -z "$(keepers)" ]' || pkill -9 -x nginx
    pkill -9 -x sundew-keeper 2>/dev/null
    pkill -9 -x sundew-engine 2>/dev/null
    rm -rf $RUN
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

echo "== startup failures"
stop_all; setup_sets
conf "ipset_blacklist sw_missing;"
$NGINX -c $CONF 2>$RUN/start.err
check "missing set refuses to start" [ -z "$(pgrep -x nginx)" ]
check "missing set message" grep -q 'set "sw_missing": set does not exist' $RUN/start.err
check "no helper left behind" wait_for '[ -z "$(keepers)" ] && [ -z "$(engines)" ]'
stop_all

echo "== nginx -t spawns nothing"
conf
$NGINX -t -c $CONF >/dev/null 2>&1
check "nginx -t ok" [ $? = 0 ]
check "no helper after -t" [ -z "$(keepers)" ]

echo "== start"
conf
check "started" start
check "one keeper" [ "$(count keepers)" = 1 ]
check "one engine" [ "$(count engines)" = 1 ]

echo "== credentials"
for w in $(workers); do
    check "worker $w CapEff=0" [ "$(status "$w" CapEff)" = 0000000000000000 ]
    check "worker $w CapPrm=0" [ "$(status "$w" CapPrm)" = 0000000000000000 ]
    check "worker $w CapAmb=0" [ "$(status "$w" CapAmb)" = 0000000000000000 ]
    check "worker $w NoNewPrivs" [ "$(status "$w" NoNewPrivs)" = 1 ]
done
E=$(engines); K=$(keepers)
check "engine CapEff=NET_ADMIN" [ "$(status "$E" CapEff)" = $NET_ADMIN ]
check "engine CapPrm=NET_ADMIN" [ "$(status "$E" CapPrm)" = $NET_ADMIN ]
check "engine CapBnd=NET_ADMIN" [ "$(status "$E" CapBnd)" = $NET_ADMIN ]
check "engine CapAmb=0" [ "$(status "$E" CapAmb)" = 0000000000000000 ]
check "engine CapInh=0" [ "$(status "$E" CapInh)" = 0000000000000000 ]
check "engine NoNewPrivs" [ "$(status "$E" NoNewPrivs)" = 1 ]
check "engine Seccomp=2" [ "$(status "$E" Seccomp)" = 2 ]
check "engine uid sundew" [ "$(status "$E" Uid | cut -f1)" = "$(id -u sundew)" ]
check "engine non-dumpable" [ "$(stat -c %U /proc/"$E"/fd 2>/dev/null)" = root ]
check "engine empty environ" [ ! -s /proc/"$E"/environ ]
check "keeper CapAmb=NET_ADMIN" [ "$(status "$K" CapAmb)" = $NET_ADMIN ]
check "keeper CapBnd=NET_ADMIN" [ "$(status "$K" CapBnd)" = $NET_ADMIN ]
check "keeper uid sundew" [ "$(status "$K" Uid | cut -f1)" = "$(id -u sundew)" ]
check "keeper not nginx's child" [ "$(status "$K" PPid)" != "$(master)" ]

echo "== fds"
efds=$(ls /proc/"$E"/fd | wc -l)
check "engine fds = 0-2, policy, ctl, 2 slots, netlink, epoll ($efds)" [ "$efds" = 9 ]
listen_inode=$(awk '$2 ~ /:1F90$/ && $4 == "0A" { print $10 }' /proc/net/tcp)
no_listener() { local l; l=$(ls -l /proc/"$1"/fd) || return 1; ! grep -q "socket:\[$listen_inode\]" <<<"$l"; }
check "listening socket found" [ -n "$listen_inode" ]
check "master holds the listening socket" bash -c "ls -l /proc/$(master)/fd | grep -q 'socket:\[$listen_inode\]'"
check "engine has no listening socket" no_listener "$E"
check "keeper has no listening socket" no_listener "$K"

echo "== lookups"
check "v4 hit"  bash -c "lookup() { curl -s \"http://127.0.0.1:8080/t?ip=\$1\"; }; lookup 192.0.2.1 | grep -q 'sw_bad4=in'"
check "v4 miss" bash -c "curl -s 'http://127.0.0.1:8080/t?ip=192.0.2.2' | grep -q 'sw_bad4=not-in'"
check "v6 hit"  bash -c "curl -s 'http://127.0.0.1:8080/t?ip=2001:db8::1' | grep -q 'sw_bad6=in'"
check "v6 miss" bash -c "curl -s 'http://127.0.0.1:8080/t?ip=2001:db8::2' | grep -q 'sw_bad6=not-in'"
check "v4 does not query v6 sets" bash -c "! curl -s 'http://127.0.0.1:8080/t?ip=192.0.2.1' | grep -q sw_bad6"

echo "== PREACCESS order: realip -> sundew -> limit_req"
echo order > $RUN/order.txt
curl -s -H 'X-Forwarded-For: 203.0.113.9' http://127.0.0.1:8080/order >/dev/null
order=$(grep -aoE 'sundew preaccess handler: [0-9.]+|limit_req\[0\]' $RUN/error.log | tail -2 | tr '\n' '|')
check "order ($order)" [ "$order" = "sundew preaccess handler: 203.0.113.9|limit_req[0]|" ]

echo "== engine crash -> keeper re-execs"
old=$E
kill -9 "$E"
check "new engine" wait_for '[ -n "$(engines)" ] && [ "$(engines)" != "'"$old"'" ]'
E=$(engines)
check "same keeper" [ "$(keepers)" = "$K" ]
check "re-exec'd engine CapEff=NET_ADMIN (ambient survived)" [ "$(status "$E" CapEff)" = $NET_ADMIN ]
check "re-exec'd engine Seccomp=2" [ "$(status "$E" Seccomp)" = 2 ]
check "lookup after engine restart" wait_for "curl -s 'http://127.0.0.1:8080/t?ip=192.0.2.1' | grep -q 'sw_bad4=in'"

echo "== worker crash"
w=$(workers | head -1)
kill -9 "$w"
check "worker respawned" wait_for '[ "$(count workers)" = 2 ] && ! workers | grep -qx '"$w"
for i in 1 2 3 4 5 6; do curl -s 'http://127.0.0.1:8080/t?ip=192.0.2.1' >> $RUN/after-crash.txt; done
check "lookups via respawned worker" [ "$(grep -c 'sw_bad4=in' $RUN/after-crash.txt)" = 6 ]

echo "== reload"
conf "ipset_blacklist sw_bad4 sw_bad6 sw_net4;"
$NGINX -c $CONF -s reload
check "new generation running" wait_for "curl -s 'http://127.0.0.1:8080/t?ip=198.51.100.7' | grep -q 'sw_net4=in'"
check "old helper gone" wait_for '[ "$(count keepers)" = 1 ] && [ "$(count engines)" = 1 ]'
check "drain logged" grep -aq 'draining helper' $RUN/error.log
mfds=$(ls /proc/"$(master)"/fd | wc -l)

echo "== failed reload keeps old config"
conf "ipset_blacklist sw_bad4 sw_missing;"
$NGINX -c $CONF -s reload
check "reload rejected" wait_for "grep -aq 'set \"sw_missing\": set does not exist' $RUN/error.log"
check "old config still serving" bash -c "curl -s 'http://127.0.0.1:8080/t?ip=198.51.100.7' | grep -q 'sw_net4=in'"
check "rejected helper cleaned up" wait_for '[ "$(count keepers)" = 1 ]'
conf "ipset_blacklist sw_bad4 sw_bad6 sw_net4;"

echo "== $RELOADS reloads"
for i in $(seq 1 "$RELOADS"); do
    kill -HUP "$(master)"
    sleep 0.05
done
check "settles to one helper" wait_for '[ "$(count keepers)" = 1 ] && [ "$(count engines)" = 1 ]'
check "master fds stable" [ "$(ls /proc/"$(master)"/fd | wc -l)" -le "$mfds" ]
check "lookup after reloads" bash -c "curl -s 'http://127.0.0.1:8080/t?ip=192.0.2.1' | grep -q 'sw_bad4=in'"
check "no zombies" [ -z "$(ps -eo stat= | grep '^Z')" ]

echo "== hostile worker frames"
for c in short long magic op family pad0 pad1 v4-trailing empty-mask mask-range cross-family ancillary; do
    old_workers=$(workers | tr '\n' ' ')
    kill -HUP "$(master)"
    wait_for '[ "$(count workers)" = 2 ] && [ "$(workers | tr "\n" " ")" != "'"$old_workers"'" ] && [ "$(count engines)" = 1 ]'
    E=$(engines)
    set -- $(workers)
    if out=$(python3 -I /src/tests/lifecycle/hostile.py "$c" "$1" "$2" 2>&1); then
        check "$c: channel closed, other channel fine" true
    else
        check "$c: $out" false
    fi
    check "$c: engine survived" [ "$(engines)" = "$E" ]
done

echo "== binary upgrade (USR2 + QUIT old)"
old_master=$(master)
kill -USR2 "$old_master"
check "new master" wait_for '[ -f $RUN/nginx.pid.oldbin ] && [ "$(master)" != "'"$old_master"'" ]'
check "two helpers during upgrade" wait_for '[ "$(count keepers)" = 2 ]'
kill -QUIT "$old_master"
check "old master gone" wait_for '! kill -0 '"$old_master"' 2>/dev/null'
check "back to one helper" wait_for '[ "$(count keepers)" = 1 ] && [ "$(count engines)" = 1 ]'
check "lookup after upgrade" bash -c "curl -s 'http://127.0.0.1:8080/t?ip=192.0.2.1' | grep -q 'sw_bad4=in'"

echo "== shutdown"
$NGINX -c $CONF -s quit
check "nginx gone" wait_for '[ -z "$(pgrep -x nginx)" ]'
check "helpers gone" wait_for '[ -z "$(keepers)" ] && [ -z "$(engines)" ]'

unexpected() {
    grep -aE '\[(alert|crit|emerg)\]' $RUN/error.log | grep -v -e sw_missing -e 'exited on signal 9'
    grep -aE 'engine (killed|exited)' $RUN/error.log | grep -v 'signal 9,'
}
unexpected | head -5 | sed 's/^/  log: /'
check "no unexpected alert/crit/emerg in error log" [ -z "$(unexpected)" ]

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
