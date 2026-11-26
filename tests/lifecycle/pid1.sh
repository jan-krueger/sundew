#!/bin/bash
# nginx as PID 1 (no --init), daemon off. Runs on the host.
set -u
IMAGE=$1
C=sundew-pid1-$$
RUN=/tmp/sundew

docker run -d --name $C --cap-add NET_ADMIN --cap-add SYS_PTRACE \
    -v "$PWD":/src:ro -v "$2":/work "$IMAGE" bash -c "
        /src/docker/build.sh >/dev/null &&
        ipset create sw_bad4 hash:ip && ipset add sw_bad4 192.0.2.1 &&
        ipset create sw_bad6 hash:ip family inet6 &&
        mkdir -p $RUN/www && echo ok > $RUN/www/index.html &&
        sed -e 's|@RUN@|$RUN|g' -e 's|@SETS@|ipset_blacklist sw_bad4 sw_bad6;|' -e 's|@MAIN@||' -e 's|@HTTP@||' -e 's|@LOC@||' -e 's|@H3@||' -e '/ssl_certificate/d' \
            /src/tests/nginx.conf.in > $RUN/nginx.conf &&
        exec /opt/nginx/sbin/nginx -c $RUN/nginx.conf -g 'daemon off;'" >/dev/null

x() { docker exec $C bash -c "$1"; }
fail=0
check() { if x "$2" >/dev/null 2>&1; then echo "  ok   $1"; else echo "  FAIL $1"; fail=1; fi; }
wait_for() { for _ in $(seq 1 150); do x "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }

echo "== nginx as PID 1, daemon off"
wait_for "pgrep -x sundew-engine" || { docker logs $C | tail -20; docker rm -f $C >/dev/null; exit 1; }
check "nginx is PID 1" '[ "$(cat /proc/1/comm)" = nginx ]'
check "keeper reparented to PID 1" '[ "$(awk "/^PPid/{print \$2}" /proc/$(pgrep -x sundew-keeper)/status)" = 1 ]'
check "lookup" "[ \$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1:8080/) = 403 ]"
for _ in $(seq 1 20); do x "kill -HUP 1"; sleep 0.1; done
if wait_for '[ "$(pgrep -xc sundew-keeper)" = 1 ] && [ "$(pgrep -xc sundew-engine)" = 1 ]'; then
    echo "  ok   one helper after 20 reloads"
else
    echo "  FAIL one helper after 20 reloads"; fail=1
fi
check "no zombies" '[ -z "$(ps -eo stat= | grep ^Z)" ]'
check "lookup after reloads" "[ \$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.0.2.1' http://127.0.0.1:8080/) = 403 ]"
x "kill -QUIT 1"
for _ in $(seq 1 50); do [ "$(docker inspect -f '{{.State.Running}}' $C)" = false ] && break; sleep 0.2; done
if [ "$(docker inspect -f '{{.State.Running}}' $C)" = false ]; then echo "  ok   container exits on QUIT"; else echo "  FAIL container exits on QUIT"; fail=1; fi
docker logs $C 2>&1 | grep -aE 'unknown process|\[alert\]' | head -5 | sed 's/^/  log: /'
docker rm -f $C >/dev/null
exit $fail
