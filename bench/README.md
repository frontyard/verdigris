# Benchmarks

verd vs **nginx** vs **caddy+fastcache** vs **ferron** on an HLS-style
edge-cache workload, same machine, loopback-only.

## Topology

Every cache leg runs the server under test as an **edge in front of one
shared origin** — a verd static server on `127.0.0.1:8480` — so all
miss paths are identical. Freshness comes from the origin's
`Cache-Control` (`*.m3u8 → max-age=2`, `*.ts → max-age=300`); no edge
gets a TTL override.

## Cells — same storage class only, no substitutes

| | raw (`/raw/…`) | mem (`/m3u8/chNNN.m3u8`) | disk (`/ts/segNNNN.ts`) |
| --- | --- | --- | --- |
| verd | `static` route | `tier = "ram"` cache+proxy | `tier = "disk"` cache+proxy |
| nginx | `alias` + `sendfile` | `proxy_cache` on **tmpfs** (nginx has no pure-RAM body cache — ramdisk is its standard approach) | `proxy_cache` on ext4 |
| caddy_fc | `file_server` | `fastcache` handler, `disk_size 0` (**RAM-only**) | `fastcache` 64MB RAM + 2GB disk — bodies served from `*os.File` (sendfile-capable) |
| ferron | built-in static (sendfile-class on plaintext) | `cache` module — in-memory responses | **excluded** — ferron has no disk-lookup cache (`persist` is a restart journal only) |

A platform with no equivalent is **omitted** from that cell rather than
substituted — that's why ferron has no disk column and nginx's memory
cell is labeled tmpfs, not "RAM".

## Workload

- **mem**: 100 channel playlists (`ch001..ch100.m3u8`), each a 24h
  sliding-window manifest (~715KB, 21600 segments @ 4s). `mutate.py`
  slides a random playlist every ~0.25s during the run (live HLS DVR).
  `m3u8.lua` picks a random channel per request.
- **disk**: 600 × 3MiB `.ts` segments of `/dev/urandom` (incompressible,
  1.8GB working set). `ts.lua` picks a random segment per request.
- **raw**: `/raw/seg0.ts` (3MiB) + `/raw/blob32.bin` (32MiB) served from
  each server's own static path — the non-cached baseline.

Both HTTP and HTTPS legs run per cell. Caches are warmed (all objects
fetched once per protocol) and every edge's hit header is verified
before measurement: `x-cache: HIT` (verd), `X-Cache-Status` (nginx),
`Cache-Status: fastcache; hit` (caddy_fc), `Cache-Status: FerronCache`
(ferron).

## Run

```sh
./bench/run.sh                                    # defaults: 8s, 64 conns
DURATION=15s CONNECTIONS=128 PROTOS="tls" ./bench/run.sh
```

Env knobs: `DURATION`, `CONNECTIONS`, `THREADS`, `PROTOS` ("http tls"),
`M3U8_CHANNELS`, `TS_FILES`, `WRK` (path to wrk binary), `GOGC`
(default `800`, applied to the caddy_fc process — binary or container),
`HANDSHAKE_SECONDS` (opt-in `openssl s_time -new` per TLS port — wrk
reuses connections, so the matrix never measures handshake cost).

Ports (HTTP/TLS): verd `:8080`/`:8443`, nginx `:8180`/`:9443`,
caddy_fc `:8290`/`:10444`, ferron `:8380`/`:11443`,
origin `:8480` (admin `:8490`).
Writes `bench/results.md` + `bench/results.json`.

## Server notes / landmines

- **caddy_fc**: the `fastcache` handler — a standalone Caddy middleware
  (not a Souin storer) with RAM+disk tiers, `Cache-Status: fastcache;
  hit` on hits, and disk bodies served via `ServeContent` on a real
  file (kernel sendfile/splice). `ttl` is fallback-only, so origin
  `Cache-Control` drives freshness like every other edge. Resolution
  order in `run.sh`: `CADDY_FC_BIN`/`bench/.gen/caddy-fc` → local `caddy`
  with the module → `docker build` of `bench/caddy-fastcache.Dockerfile`,
  which `xcaddy`-builds `github.com/frontyard/fastcache` straight from
  GitHub (no checkout needed; append `@<ref>` to pin). To develop
  against a local checkout instead:
  `xcaddy build --with github.com/frontyard/fastcache=/path/to/fastcache`
  → copy the binary to `bench/.gen/caddy-fc`. Note: even `disk_size 0`
  needs a writable `path` (the index dir is mkdir'd at provision time).
- **ferron**: `ferronserver/ferron:3`, config `bench/ferron.conf`.
  - vhost names match the `Host` header — wildcard `*:8380`/`*:11443`
    is required for `127.0.0.1` requests.
  - `location` prefixes are stripped before proxying — upstream URL is
    `http://127.0.0.1:8480/m3u8` to restore the path.
  - **lazy module init**: each vhost's module chain is built on its
    *first* request — if that request hits a cache-less route, the
    cache never engages for that vhost. `run.sh` makes the
    `cache-status` gate ferron's very first request per listener.
  - `max-age=1` responses are instantly stale and never stored; the
    origin uses `max-age=2` (the floor all four edges honor).
  - `max_response_size` raised to 2MiB for the ~715KB playlists.
- **nginx**: `open_file_cache` remains only for the raw leg (fd cache,
  not body cache). Body caching is `proxy_cache` with
  `proxy_cache_revalidate` + `proxy_cache_lock`; `proxy_cache_valid`
  is a fallback — origin `Cache-Control` wins.
- **verd edge**: two named stores — `bench_mem` (ram, 256MiB) and
  `bench_disk` (disk, 2GiB). `x_cache = true` exposes the hit header.

## Caveats

Loopback CPU-bound benchmark — real NICs cap far lower. Run-to-run
variance on this box is ±10–40%; run multiple interleaved trials before
drawing conclusions. wrk's keep-alive means TLS handshake cost is not
measured (shared self-signed cert, `bench.local`).

Generated under `bench/` (git-ignored): `www/` fixtures, `.gen/` rendered
configs + cert, `cache-verd/` disk store, `results.*`.
