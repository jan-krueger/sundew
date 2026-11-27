#!/bin/bash
# Throughput and latency of the release image. Runs on the host.
# Usage: run.sh <release-image> <dev-image>
set -eu
IMAGE=$1
DEV=$2
NS=sundew-bench-ns-$$
C=sundew-bench-$$
CONF=$(mktemp -d)
DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-3}

cleanup() { docker rm -f $C $NS >/dev/null 2>&1; rm -rf "$CONF"; }
trap cleanup EXIT

NGINX_CPUS=${NGINX_CPUS:-0-5}
CLIENT_CPUS=${CLIENT_CPUS:-6-11}
WORKERS=${WORKERS:-4}

cat > "$CONF/nginx.conf" <<CONF
load_module modules/ngx_http_sundew_module.so;
user nginx;
worker_processes $WORKERS;
error_log /var/log/nginx/error.log warn;
events { worker_connections 4096; }
http { include /etc/nginx/conf.d/*.conf; }
CONF

cat > "$CONF/default.conf" <<'CONF'
access_log off;
set_real_ip_from 127.0.0.1;
real_ip_header X-Forwarded-For;
keepalive_requests 1000000;

server {
    listen 80;
    location = /off     { ipset_denylist off;            alias /usr/share/nginx/html/index.html; }
    location = /hit     { ipset_denylist bad4 big4;      alias /usr/share/nginx/html/index.html; }
    location = /nocache { ipset_denylist bad4 big4;  ipset_cache_ttl 0; alias /usr/share/nginx/html/index.html; }
    location = /big     { ipset_denylist big4;       alias /usr/share/nginx/html/index.html; }
    location = /rl      { ipset_denylist bad4;  ipset_ratelimit rate=65535 window=60s; alias /usr/share/nginx/html/index.html; }
}
CONF

docker run -d --name $NS --cap-add NET_ADMIN --cpuset-cpus "$CLIENT_CPUS" "$DEV" sleep infinity >/dev/null
docker exec $NS bash -c '
    ipset create bad4 hash:ip && ipset add bad4 192.0.2.1
    python3 -I -c "
for i in range(1000000):
    print(\"add big4 10.%d.%d.%d\" % (i >> 16 & 255, i >> 8 & 255, i & 255))
" | { echo "create big4 hash:ip maxelem 2000000"; cat; } | ipset restore'
docker run -d --name $C --cap-add NET_ADMIN --network container:$NS --cpuset-cpus "$NGINX_CPUS" \
    -v "$CONF/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$CONF/default.conf:/etc/nginx/conf.d/default.conf:ro" "$IMAGE" >/dev/null
sleep 2

cat > "$CONF/random.lua" <<'LUA'
-- a different client address on every request, none of them in a set
local n = 0
request = function()
  n = n + 1
  local ip = string.format("10.%d.%d.%d", 100 + math.random(0, 150), math.random(0, 255), math.random(1, 254))
  return wrk.format(nil, nil, { ["X-Forwarded-For"] = ip })
end
LUA
docker cp "$CONF/random.lua" $NS:/tmp/random.lua

run() {   # path, address or "random" -> "req/s mean-latency-ms"
    local args=(-H "X-Forwarded-For: $2")
    [ "$2" = random ] && args=(-s /tmp/random.lua)
    docker exec $NS wrk -t 4 -c 64 -d "${DURATION}s" --latency "${args[@]}" "http://127.0.0.1$1" 2>/dev/null |
        awk '/^Requests\/sec/ { rps = $2 }
             /^    Latency/ { v = $2; if (v ~ /us$/) v = v / 1000; else if (v ~ /ms$/) v = v + 0; else v = v * 1000; lat = v }
             END { printf "%s %.2f\n", rps, lat }'
}

median() { sort -n | awk '{ a[NR] = $0 } END { print a[int((NR + 1) / 2)] }'; }

CASES=(
    "No check (\`ipset_denylist off\`)|/off|192.0.2.9"
    "Cache hit, allowed|/hit|192.0.2.9"
    "Cache hit, denied (403)|/hit|192.0.2.1"
    "No cache: helper and kernel on every request|/nocache|192.0.2.9"
    "A new address on every request (all misses)|/hit|random"
    "All misses, set of 1,000,000 entries|/big|random"
    "Cache hit plus ipset_ratelimit, many clients|/rl|random"
)

# every round runs every case once, so drift (heat, turbo) spreads evenly
declare -A RPS LAT
for round in $(seq 1 "$ROUNDS"); do
    for i in "${!CASES[@]}"; do
        IFS='|' read -r _ path addr <<<"${CASES[$i]}"
        r=$(run "$path" "$addr")
        RPS[$i]+="${r% *} "
        LAT[$i]+="${r#* } "
    done
done

echo "| Case | Requests/s | Mean latency (ms) |"
echo "| --- | --- | --- |"
for i in "${!CASES[@]}"; do
    IFS='|' read -r label _ _ <<<"${CASES[$i]}"
    printf '| %s | %s | %s |\n' "$label" \
        "$(tr ' ' '\n' <<<"${RPS[$i]}" | grep . | median | awk '{ printf "%.0f", $1 }')" \
        "$(tr ' ' '\n' <<<"${LAT[$i]}" | grep . | median)"
done
echo
echo "nginx $(docker exec $C nginx -v 2>&1 | sed 's|.*/||'), $WORKERS workers on CPUs $NGINX_CPUS, wrk on CPUs $CLIENT_CPUS ($(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')), wrk -t 4 -c 64 -d ${DURATION}s, median of $ROUNDS interleaved rounds"
