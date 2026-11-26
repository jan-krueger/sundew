#!/bin/bash
# Lifecycle and privilege matrix (P0a). Runs inside the dev container.
set -u

RELOADS=${RELOADS:-100}
. /src/tests/lib.sh

echo "== startup failures"
stop_all; setup_sets
conf "ipset_denylist sw_missing;"
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
check "engine landlock enforced" grep -aqh 'landlock enforced' $RUN/start.err $RUN/error.log
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
check "v4 hit -> 403" is 192.0.2.1 403
check "v4 miss -> 200" is 192.0.2.2 200
check "v6 hit -> 403" is 2001:db8::1 403
check "v6 miss -> 200" is 2001:db8::2 200
check "v4-mapped v6 hit -> 403" is ::ffff:192.0.2.1 403
check "\$ipset_matched_set" bash -c "curl -sI -H 'X-Forwarded-For: 2001:db8::1' http://127.0.0.1:8080/ | grep -q 'X-Sundew: deny sw_bad6'"
check "real v6 client" [ "$(curl -s -o /dev/null -w '%{http_code}' 'http://[::1]:8080/')" = 200 ]

echo "== PREACCESS order: realip -> sundew -> limit_req"
lr() { grep -ac 'limit_req\[0\]' $RUN/error.log; }
n0=$(lr)
c1=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1:8082/order)
n1=$(lr)
c2=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.9' http://127.0.0.1:8082/order)
n2=$(lr)
check "location realip runs before sundew (banned XFF -> $c1)" [ "$c1" = 403 ]
check "sundew runs before limit_req (no limit_req on deny)" [ "$n1" = "$n0" ]
[ "$c2" = 200 ] && [ "$n2" -gt "$n1" ]; check "allowed request reaches limit_req ($c2)" [ $? = 0 ]

echo "== engine crash -> keeper re-execs"
old=$E
kill -9 "$E"
check "new engine" wait_for '[ -n "$(engines)" ] && [ "$(engines)" != "'"$old"'" ]'
E=$(engines)
check "same keeper" [ "$(keepers)" = "$K" ]
check "crash in nginx's error log" wait_for "grep -aq 'helper engine was killed by signal 9, restarting' $RUN/error.log"
check "re-exec'd engine CapEff=NET_ADMIN (ambient survived)" [ "$(status "$E" CapEff)" = $NET_ADMIN ]
check "re-exec'd engine Seccomp=2" [ "$(status "$E" Seccomp)" = 2 ]
check "lookup after engine restart" wait_for alive

echo "== worker crash"
w=$(workers | head -1)
kill -9 "$w"
check "worker respawned" wait_for '[ "$(count workers)" = 2 ] && ! workers | grep -qx '"$w"
n=0; for i in 1 2 3 4 5 6 7 8; do is 192.0.2.1 403 && alive && n=$((n + 1)); done
check "lookups via respawned worker" [ "$n" = 8 ]

echo "== reload"
conf "ipset_denylist sw_bad4 sw_bad6 sw_net4;"
$NGINX -c $CONF -s reload
check "new generation running" wait_for "is 198.51.100.7 403"
check "old helper gone" wait_for '[ "$(count keepers)" = 1 ] && [ "$(count engines)" = 1 ]'
check "drain logged" grep -aq 'draining helper' $RUN/error.log
mfds=$(ls /proc/"$(master)"/fd | wc -l)

echo "== failed reload keeps old config"
conf "ipset_denylist sw_bad4 sw_missing;"
$NGINX -c $CONF -s reload
check "reload rejected" wait_for "grep -aq 'set \"sw_missing\": set does not exist' $RUN/error.log"
check "old config still serving" is 198.51.100.7 403
check "rejected helper cleaned up" wait_for '[ "$(count keepers)" = 1 ]'
conf "ipset_denylist sw_bad4 sw_bad6 sw_net4;"

echo "== $RELOADS reloads"
for i in $(seq 1 "$RELOADS"); do
    kill -HUP "$(master)"
    sleep 0.05
done
check "settles to one helper" wait_for '[ "$(count keepers)" = 1 ] && [ "$(count engines)" = 1 ]'
# drained helpers' pidfds are dropped at the next reload
kill -HUP "$(master)"
wait_for '[ "$(count keepers)" = 1 ] && [ "$(count engines)" = 1 ]'
check "master fds stable" wait_for '[ "$(ls /proc/"$(master)"/fd | wc -l)" -le "$mfds" ]'
check "lookup after reloads" alive
check "no zombies" wait_for '[ -z "$(ps -eo stat= | grep "^Z")" ]'

echo "== hostile worker frames"
for c in short long magic op family pad0 pad1 v4-trailing empty-mask mask-range cross-family ancillary; do
    old_workers=$(workers | tr '\n' ' ')
    kill -HUP "$(master)"
    wait_for '[ "$(count workers)" = 2 ] && [ "$(workers | tr "\n" " ")" != "'"$old_workers"'" ] && [ "$(count engines)" = 1 ]'
    E=$(engines)
    set -- $(workers)
    kill -STOP "$1" "$2"
    out=$(python3 -I /src/tests/lifecycle/hostile.py "$c" "$1" "$2" 2>&1); rc=$?
    kill -CONT "$1" "$2"
    if [ $rc = 0 ]; then
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
check "lookup after upgrade" alive

echo "== shutdown"
$NGINX -c $CONF -s quit
check "nginx gone" wait_for '[ -z "$(pgrep -x nginx)" ]'
check "helpers gone" wait_for '[ -z "$(keepers)" ] && [ -z "$(engines)" ]'

unexpected() {
    grep -aE '\[(alert|crit|emerg)\]' $RUN/error.log | grep -v -e sw_missing -e 'exited on signal 9' -e 'helper channel closed' -e "closed this worker's channel"
    grep -aE 'engine (was )?(killed|exited)' $RUN/error.log | grep -v 'signal 9,'
}
unexpected | head -5 | sed 's/^/  log: /'
check "no unexpected alert/crit/emerg in error log" [ -z "$(unexpected)" ]

stop_all
check "no sanitizer reports" [ "$(san_reports)" = 0 ]
[ "$(san_reports)" = 0 ] || san_show
san_core | sed 's/^/  nginx core ubsan (not ours): /'
summary
