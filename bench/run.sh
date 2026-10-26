#!/usr/bin/env bash
# verd vs nginx vs caddy+fastcache vs ferron — HLS-style edge benchmark.
#
#   ./bench/run.sh
#   DURATION=15s CONNECTIONS=128 PROTOS="tls" ./bench/run.sh
#
# Cells (apples-to-apples: every edge proxies to one shared origin, a
# verd static server on :8480 — identical miss path; freshness from
# origin Cache-Control so no edge gets a TTL override):
#
#   raw   /raw/seg0.ts + /raw/blob32.bin — each server's own static path
#   mem   /m3u8/chNNN.m3u8  — 100 channels x 24h sliding window (~700KB),
#         mutated live, origin max-age=2. RAM-backed caches only:
#         verd tier=ram, caddy_fc RAM-only (disk_size 0), ferron FerronCache,
#         nginx proxy_cache on tmpfs (nginx has no pure-RAM body cache —
#         ramdisk is its standard approach; mechanism unchanged)
#   disk  /ts/segNNNN.ts — 600 x 3MiB urandom segments (1.8GB working
#         set). Disk-backed caches only: verd tier=disk, caddy_fc
#         two-tier (sendfile hits), nginx proxy_cache on ext4.
#         ferron is EXCLUDED — its
#         cache is in-memory only (persist is a restart journal, never
#         the lookup path); substituting would break parity.
set -euo pipefail
cd "$(dirname "$0")/.."

DURATION=${DURATION:-8s}
CONNECTIONS=${CONNECTIONS:-64}
THREADS=${THREADS:-$(nproc 2>/dev/null || echo 4)}
M3U8_CHANNELS=${M3U8_CHANNELS:-100}
TS_FILES=${TS_FILES:-600}
# Go GC target for the caddy_fc leg (the remaining Go server;
# stock GOGC=100 costs ~25-30% throughput at this request rate)
GOGC=${GOGC:-800}
RAW_FILES="seg0.ts blob32.bin"
WWW=bench/www
RESULTS=bench/results.md
RESULTS_JSON=bench/results.json
PIDS=()
DOCKERS=()

have()    { command -v "$1" >/dev/null 2>&1; }
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for d in "${DOCKERS[@]:-}"; do docker rm -f "$d" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

# wrk: PATH, $WRK, or a locally-extracted deb (dpkg -x → LD_LIBRARY_PATH)
WRK=${WRK:-wrk}
if ! have "$WRK" && [ -x /tmp/wrk-local/usr/bin/wrk ]; then
    WRK=/tmp/wrk-local/usr/bin/wrk
    export LD_LIBRARY_PATH=/tmp/wrk-local/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
fi
have "$WRK" || { echo "wrk not found (apt install wrk, or set WRK=/path/to/wrk)"; exit 1; }

# ---------- fixtures ----------
mkdir -p "$WWW/m3u8" "$WWW/ts" "$WWW/raw" bench/.gen
export M3U8_CHANNELS TS_FILES
python3 - "$WWW/m3u8" "$M3U8_CHANNELS" <<'PY'
import os, sys
d, n = sys.argv[1], int(sys.argv[2])
# 24h sliding window @ 4s segments = 21600 EXTINF lines (~715KB)
for i in range(1, n + 1):
    p = os.path.join(d, "ch%03d.m3u8" % i)
    if os.path.exists(p):
        continue
    out = ["#EXTM3U", "#EXT-X-VERSION:3", "#EXT-X-TARGETDURATION:4",
           "#EXT-X-MEDIA-SEQUENCE:86400"]
    for s in range(21600):
        out.append("#EXTINF:4.000,")
        out.append("seg%08d.ts" % (64800 + s))
    open(p, "w").write("\n".join(out) + "\n")
PY
for i in $(seq 0 $((TS_FILES - 1))); do
    f=$(printf "$WWW/ts/seg%04d.ts" "$i")
    [ -f "$f" ] || head -c 3145728 /dev/urandom > "$f"
done
ln -f "$WWW/ts/seg0000.ts" "$WWW/raw/seg0.ts"
[ -f "$WWW/raw/blob32.bin" ] || head -c 33554432 /dev/urandom > "$WWW/raw/blob32.bin"

# shared self-signed cert for the HTTPS legs
if [ ! -f bench/.gen/bench.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout bench/.gen/bench.key -out bench/.gen/bench.crt \
        -subj "/CN=bench.local" 2>/dev/null
    chmod 644 bench/.gen/bench.key
fi

wait_port() {
    for _ in $(seq 1 100); do
        curl -sf -o /dev/null "http://127.0.0.1:$1/raw/seg0.ts" && return 0
        curl -sf -o /dev/null "http://127.0.0.1:$1/m3u8/ch001.m3u8" && return 0
        sleep 0.1
    done
    echo "server on :$1 never came up" >&2; return 1
}
wait_tls() {
    for _ in $(seq 1 100); do
        curl -skf -o /dev/null "https://127.0.0.1:$1/raw/seg0.ts" && return 0
        sleep 0.1
    done
    echo "TLS on :$1 never came up" >&2; return 1
}

# ---------- origin (shared miss path for every edge) ----------
cargo build --release --quiet
# warn keeps it quiet; rustls=error kills the IP-SNI warning spam wrk triggers
export VERD_LOG="warn,rustls=error"
./target/release/verd run --config bench/origin.toml &
PIDS+=($!); ORIGIN_PID=$!
for _ in $(seq 1 100); do
    curl -sf -o /dev/null "http://127.0.0.1:8480/m3u8/ch001.m3u8" && break; sleep 0.1
done
# a stale listener on :8480 would pass the check while our origin is dead
kill -0 "$ORIGIN_PID" 2>/dev/null || { echo "origin verd failed to start (port conflict?)" >&2; exit 1; }

# sliding-window mutator: slides one random playlist every ~0.25s
python3 bench/mutate.py "$WWW/m3u8" & PIDS+=($!)

# ---------- verd edge ----------
./target/release/verd run --config bench/verd.toml &
PIDS+=($!); EDGE_PID=$!
wait_port 8080; wait_tls 8443
kill -0 "$EDGE_PID" 2>/dev/null || { echo "edge verd failed to start" >&2; exit 1; }

# ---------- nginx edge ----------
mkdir -p bench/.gen/nginx-disk /dev/shm/verd-bench-nginx-mem 2>/dev/null || true
nginx_ok=0
if have nginx; then
    sed -e "s|WWWDIR|$PWD/$WWW|g" -e "s|CERTDIR|$PWD/bench/.gen|g" \
        -e "s|NGINXMEMDIR|/dev/shm/verd-bench-nginx-mem|g" \
        -e "s|NGINXDISKDIR|$PWD/bench/.gen/nginx-disk|g" \
        bench/nginx.conf > bench/.gen/nginx.conf
    nginx -c "$PWD/bench/.gen/nginx.conf" && nginx_ok=1
    PIDS+=("$(cat /tmp/verd-bench-nginx.pid 2>/dev/null || echo 0)")
elif have docker; then
    sed -e "s|WWWDIR|/srv/www|g" -e "s|CERTDIR|/srv/bench-gen|g" \
        -e "s|NGINXMEMDIR|/nginx-mem|g" -e "s|NGINXDISKDIR|/nginx-disk|g" \
        bench/nginx.conf > bench/.gen/nginx.docker.conf
    DOCKERS+=("$(docker run -d --network host \
        -v "$PWD/bench/.gen/nginx.docker.conf:/etc/nginx/nginx.conf:ro" \
        -v "$PWD/bench/.gen:/srv/bench-gen:ro" \
        -v "$PWD/$WWW:/srv/www:ro" \
        -v "$PWD/bench/.gen/nginx-disk:/nginx-disk" \
        --tmpfs /nginx-mem:rw,size=768m \
        nginx:alpine)")
    nginx_ok=1
else
    echo "nginx not found and docker unavailable; skipping nginx"
fi
[ "$nginx_ok" = 1 ] && { wait_port 8180 && wait_tls 9443 || nginx_ok=0; } || true

# ---------- caddy+fastcache edge (the fastcache handler is not
# a Souin storer — it owns the whole request path)
caddy_fc_ok=0
CADDY_FC_BIN=${CADDY_FC_BIN:-bench/.gen/caddy-fc}
if [ -x "$CADDY_FC_BIN" ] && "$CADDY_FC_BIN" list-modules 2>/dev/null | grep -q http.handlers.fastcache; then
    sed -e "s|/srv/www|$PWD/$WWW|g" -e "s|CERTDIR|$PWD/bench/.gen|g" \
        -e "s|/tmp/verd-bench-fastcache-mem|$PWD/bench/.gen/fastcache-mem|g" \
        -e "s|/tmp/verd-bench-fastcache-tls|$PWD/bench/.gen/fastcache-tls|g" \
        -e "s|/tmp/verd-bench-fastcache|$PWD/bench/.gen/fastcache|g" \
        bench/Caddyfile.fastcache > bench/.gen/Caddyfile.fastcache
    mkdir -p bench/.gen/fastcache bench/.gen/fastcache-tls bench/.gen/fastcache-mem
    GOGC=$GOGC "$CADDY_FC_BIN" run --config bench/.gen/Caddyfile.fastcache &
    PIDS+=($!); caddy_fc_ok=1
elif have caddy && caddy list-modules 2>/dev/null | grep -q http.handlers.fastcache; then
    sed -e "s|/srv/www|$PWD/$WWW|g" -e "s|CERTDIR|$PWD/bench/.gen|g" \
        -e "s|/tmp/verd-bench-fastcache-mem|$PWD/bench/.gen/fastcache-mem|g" \
        -e "s|/tmp/verd-bench-fastcache-tls|$PWD/bench/.gen/fastcache-tls|g" \
        -e "s|/tmp/verd-bench-fastcache|$PWD/bench/.gen/fastcache|g" \
        bench/Caddyfile.fastcache > bench/.gen/Caddyfile.fastcache
    mkdir -p bench/.gen/fastcache bench/.gen/fastcache-tls bench/.gen/fastcache-mem
    GOGC=$GOGC caddy run --config bench/.gen/Caddyfile.fastcache &
    PIDS+=($!); caddy_fc_ok=1
elif have docker; then
    docker image inspect verd-bench-caddy-fc >/dev/null 2>&1 || \
        docker build -q -f bench/caddy-fastcache.Dockerfile \
            -t verd-bench-caddy-fc bench >/dev/null
    mkdir -p bench/.gen/fastcache bench/.gen/fastcache-tls bench/.gen/fastcache-mem
    sed "s|CERTDIR|/srv/bench-gen|g" bench/Caddyfile.fastcache > bench/.gen/Caddyfile.fastcache.docker
    DOCKERS+=("$(docker run -d --network host \
        -v "$PWD/bench/.gen/Caddyfile.fastcache.docker:/etc/caddy/Caddyfile:ro" \
        -v "$PWD/bench/.gen:/srv/bench-gen:ro" \
        -v "$PWD/$WWW:/srv/www:ro" \
        -v "$PWD/bench/.gen/fastcache:/tmp/verd-bench-fastcache" \
        -v "$PWD/bench/.gen/fastcache-tls:/tmp/verd-bench-fastcache-tls" \
        -v "$PWD/bench/.gen/fastcache-mem:/tmp/verd-bench-fastcache-mem" \
        -e "GOGC=$GOGC" \
        verd-bench-caddy-fc)")
    caddy_fc_ok=1
else
    echo "caddy-fc: no fastcache caddy binary and no docker; skipping" >&2
fi
if [ "$caddy_fc_ok" = 1 ]; then
    wait_port 8290 && wait_tls 10444 || caddy_fc_ok=0
fi

# ---------- ferron edge ----------
ferron_ok=0
if have ferron; then
    sed -e "s|/srv/www|$PWD/$WWW|g" -e "s|CERTDIR|$PWD/bench/.gen|g" \
        bench/ferron.conf > bench/.gen/ferron.conf
    ferron run -c bench/.gen/ferron.conf &
    PIDS+=($!); ferron_ok=1
elif have docker; then
    sed -e "s|/srv/www|/srv/www|g" -e "s|CERTDIR|/srv/bench-gen|g" \
        bench/ferron.conf > bench/.gen/ferron.conf
    DOCKERS+=("$(docker run -d --network host \
        -v "$PWD/bench/.gen/ferron.conf:/etc/ferron/ferron.conf:ro" \
        -v "$PWD/bench/.gen:/srv/bench-gen:ro" \
        -v "$PWD/$WWW:/srv/www:ro" ferronserver/ferron:3)")
    ferron_ok=1
else
    echo "ferron not found and docker unavailable; skipping ferron"
fi
if [ "$ferron_ok" = 1 ]; then
    # Ferron lazily builds each vhost's module chain on its FIRST request:
    # if that request lands on a cache-less location (/raw), the cache
    # module never engages for that vhost. So the readiness gate must be
    # the first request each listener sees — no wait_port/wait_tls first.
    for pair in "http 8380" "https 11443"; do
        set -- $pair; scheme=$1; port=$2
        ok=0
        for i in $(seq 1 60); do
            resp=$(curl -sk -D - -o /dev/null "$scheme://127.0.0.1:$port/m3u8/ch001.m3u8" 2>/dev/null || true)
            if printf '%s' "$resp" | grep -qi "cache-status"; then ok=1; break; fi
            [ $((i % 20)) = 0 ] && echo "  ferron $scheme poll $i: $(printf '%s' "$resp" | head -1)" >&2
            sleep 0.3
        done
        if [ "$ok" != 1 ]; then
            echo "ferron $scheme cache never engaged; last response:" >&2
            printf '%s\n' "$resp" >&2
            ferron_ok=0; break
        fi
    done
fi

# ---------- warm caches + verify hits ----------
# every (server x proto x cell) store is warmed: caddy_fc/ferron keep
# per-listener stores, nginx keys include scheme, verd shares.
declare -A HTTP_PORT=( [verd]=8080 [nginx]=8180 [caddy_fc]=8290 [ferron]=8380 )
declare -A TLS_PORT=( [verd]=8443 [nginx]=9443 [caddy_fc]=10444 [ferron]=11443 )
enabled() { [ "$1" = verd ] || eval "[ \"\$${1}_ok\" = 1 ]"; }

# warm a prefix with real names: m3u8 chNNN.m3u8, ts segNNNN.ts
warm_mem() { # proto
    local scheme=$1
    for server in verd nginx caddy_fc ferron; do
        enabled "$server" || continue
        local port; [ "$scheme" = https ] && port=${TLS_PORT[$server]} || port=${HTTP_PORT[$server]}
        seq -f %03.0f 1 "$M3U8_CHANNELS" | xargs -P16 -I{} \
            curl -skf -o /dev/null "$scheme://127.0.0.1:$port/m3u8/ch{}.m3u8" 2>/dev/null || true
        if [ "$scheme" = http ]; then
            h=""
            for _ in 1 2 3 4; do h=$(verify_hit "$server" http "m3u8/ch001.m3u8"); [ -n "$h" ] && break; sleep 0.5; done
            echo "  $server mem: ${h:-<missing>}"
        fi
    done
}
warm_disk() {
    local scheme=$1
    for server in verd nginx caddy_fc; do
        enabled "$server" || continue
        local port; [ "$scheme" = https ] && port=${TLS_PORT[$server]} || port=${HTTP_PORT[$server]}
        seq -f %04.0f 0 $((TS_FILES - 1)) | xargs -P16 -I{} \
            curl -skf -o /dev/null "$scheme://127.0.0.1:$port/ts/seg{}.ts" 2>/dev/null || true
        if [ "$scheme" = http ]; then
            h=$(verify_hit "$server" http "ts/seg0001.ts")
            echo "  $server disk: ${h:-<missing>}"
        fi
    done
}
verify_hit() { # server scheme path — two fetches, report the last one's
    local port; [ "$2" = https ] && port=${TLS_PORT[$1]} || port=${HTTP_PORT[$1]}
    curl -sk -o /dev/null "$2://127.0.0.1:$port/$3" 2>/dev/null || true
    curl -sk -o /dev/null -D - "$2://127.0.0.1:$port/$3" 2>/dev/null | grep -aiE "x-cache|cache-status" | tr -d '\r' || true
}

echo "== warming + verifying mem cell (http+tls)"
warm_mem http; warm_mem https
echo "== warming + verifying disk cell (${TS_FILES} segments x 3MiB per store, http+tls)"
warm_disk http; warm_disk https

# ---------- wrk matrix ----------
SERVERS_MEM="verd"
SERVERS_DISK="verd"
[ "$nginx_ok" = 1 ] && { SERVERS_MEM="$SERVERS_MEM nginx"; SERVERS_DISK="$SERVERS_DISK nginx"; } || true

[ "$caddy_fc_ok" = 1 ] && { SERVERS_MEM="$SERVERS_MEM caddy_fc"; SERVERS_DISK="$SERVERS_DISK caddy_fc"; } || true
[ "$ferron_ok" = 1 ] && SERVERS_MEM="$SERVERS_MEM ferron" || true   # no disk cell — no disk cache exists

echo "# verd vs nginx vs caddy_fc vs ferron — edge cache benchmark" > "$RESULTS"
{
    echo
    echo "- duration $DURATION, $CONNECTIONS conns, $THREADS threads, $(date -Is)"
    echo "- mem: $M3U8_CHANNELS x ~715KB m3u8 (sliding, max-age=2); disk: $TS_FILES x 3MiB ts (max-age=300)"
    echo "- topology: edge -> shared verd origin :8480; freshness via origin Cache-Control"
    echo
    echo '| scenario | proto | file | server | req/s | MB/s |'
    echo '|---|---|---|---|---|---|'
} >> "$RESULTS"
echo '[' > "$RESULTS_JSON"; first=1

run() { # scenario proto path server [lua]
    local scheme=http port=${HTTP_PORT[$4]} script=""
    [ "$2" = tls ] && { scheme=https; port=${TLS_PORT[$4]}; }
    [ -n "${5:-}" ] && script="-s bench/$5"
    local url="$scheme://127.0.0.1:$port/$3" out rps tps mb
    out=$("$WRK" -d"$DURATION" -t"$THREADS" -c"$CONNECTIONS" $script "$url" 2>&1) || {
        echo "| $1 | $2 | $3 | $4 | FAIL | |" >> "$RESULTS"; return; }
    rps=$(echo "$out" | awk '/Requests\/sec/{print $2}')
    tps=$(echo "$out" | awk '/Transfer\/sec/{print $2}')
    mb=$(echo "$tps" | awk '{u=$0; sub(/[A-Za-z]+/,"",u); m=u;
          if ($0 ~ /GB/) m*=1024; else if ($0 ~ /KB/) m/=1024; else if ($0 ~ /TB/) m*=1048576;
          printf "%.0f", m}')
    printf '| %s | %s | %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4" "$rps" "$mb" >> "$RESULTS"
    [ $first = 0 ] && echo ',' >> "$RESULTS_JSON"; first=0
    printf '{"scenario":"%s","proto":"%s","path":"%s","server":"%s","req_s":%s,"mb_s":%s}' \
        "$1" "$2" "$3" "$4" "${rps:-0}" "${mb:-0}" >> "$RESULTS_JSON"
    echo "  $1/$2 $4: ${rps} req/s, ${mb} MB/s"
}

PROTOS=${PROTOS:-"http tls"}
for proto in $PROTOS; do
    echo "== proto: $proto"
    for f in $RAW_FILES; do
        for s in $SERVERS_MEM; do run "raw" "$proto" "raw/$f" "$s"; done
    done
    for s in $SERVERS_MEM;   do run "mem"  "$proto" "m3u8/ch001.m3u8" "$s" m3u8.lua; done
    for s in $SERVERS_DISK;  do run "disk" "$proto" "ts/seg0000.ts"   "$s" ts.lua; done
done

# ---------- handshake throughput (opt-in) ----------
# wrk reuses connections, so the matrix never measures handshake cost.
# HANDSHAKE_SECONDS=N runs `openssl s_time -new` (fresh full TLS 1.3
# handshakes, single-threaded client) against each server's TLS port.
if [ "${HANDSHAKE_SECONDS:-0}" -gt 0 ] && have openssl; then
    {
        echo; echo '## TLS 1.3 handshake throughput (openssl s_time -new, single client)'
        echo; echo '| server | conns/s |'; echo '|---|---|'
    } >> "$RESULTS"
    for s in $SERVERS_MEM; do
        port=${TLS_PORT[$s]}
        line=$(timeout $((HANDSHAKE_SECONDS + 30)) \
            openssl s_time -connect "127.0.0.1:$port" -new -time "$HANDSHAKE_SECONDS" 2>&1 \
            | tail -3 || true)
        cps=$(echo "$line" | awk '/connections.*user sec/{print $5; exit}')
        printf '| %s | %s |\n' "$s" "${cps:-fail}" >> "$RESULTS"
        echo "  handshake $s: ${cps:-fail} conns/s"
    done
fi

echo ']' >> "$RESULTS_JSON"
echo; echo "wrote $RESULTS / $RESULTS_JSON"; cat "$RESULTS"
