# Performance

Benchmark findings for verd vs nginx vs caddy+fastcache vs ferron —
what was measured, what was fixed, and what remains. All measurements
are loopback on a 24-thread host; see caveats before quoting numbers.

## TL;DR

Latest TLS-only run (8s × 64 conns, MB/s, 2026-10-23, `GOGC=800` on the
Go leg):

| cell | verd | nginx | caddy_fc | ferron |
|---|---|---|---|---|
| raw 3MiB | **15,534** | 13,240 | 12,390 | 10,557 |
| raw 32MiB | 14,346 | 12,657 | 12,616 | **14,531** |
| cached small-obj | 13,691 | 9,411 | 11,049 | **14,674** |
| cached disk 3MiB | **14,490** | 11,766 | 11,346 | — |

- Only HTTPS numbers are shown: they are the ones that matter for this
  deployment profile, and plaintext headline gaps ("nginx is 5-6x
  faster") are a **sendfile artifact** — `sendfile(2)` cannot cross a
  TLS socket, so over HTTPS everyone pays the same userspace copies.
- Handshake throughput (`openssl s_time -new`, full TLS 1.3 handshakes,
  single-threaded client, earlier run): ferron 2172, **verd 2017**,
  nginx 1180 conns/s — rustls+aws-lc is competitive.
- Three real bottlenecks were found and fixed over the benchmark
  history: the default 8KiB stream buffer (~8x), `tokio::fs`
  blocking-pool round trips for page-cached syscalls (~2.2x under TLS),
  and hyper's ~400KiB h1 write queue (+8-24% raw static).
- Remaining gaps are ferron at 32MiB raw (+1%) and small-object cache
  (+7%) — plausibly its own HTTP stack's lower per-request overhead,
  not body-path work.

## Methodology

`bench/run.sh` orchestrates all of this:

- **Load:** `wrk -d -t$(nproc) -c64` per cell; results to
  `bench/results.md` / `results.json`.
- **Workloads:**
  - `GET /raw/<file>` — plain static serving, incompressible fixtures
    (page-cache and sendfile semantics dominate; no codec shortcuts).
  - cached cells sit behind **one shared origin** (verd static on
    `:8480`) so miss paths are identical; freshness is origin
    `Cache-Control`, no per-edge TTL override.
  - **mem cell:** 100 frequently-mutated ~700KB objects,
    `max-age=2` — exercises hit-rate and freshness churn. Storage:
    verd `tier=ram`, caddy_fc RAM-only (`disk_size 0`), ferron
    in-memory, nginx `proxy_cache` on tmpfs (honestly labeled — nginx
    has no pure-RAM body cache).
  - **disk cell:** 600 × 3MiB incompressible objects, `max-age=300`.
    Storage: verd `tier=disk`, caddy_fc two-tier (64MB RAM + 2GB disk,
    large bodies sendfile — `promote_below` defaults keep 3MiB objects
    on the `*os.File` path), nginx `proxy_cache` ext4. **Ferron is
    excluded** — it has no disk-lookup mode (`persist` is a restart
    journal); substituting anything would break parity.
- **Server configs** (`bench/`):
  - verd: `static` route; `hybrid` RAM+disk cache (RAM
    promote-on-hit).
  - nginx: `sendfile on`, `open_file_cache max=10000` — note this
    caches fds/stat metadata, **not** response bodies; bodies still
    stream via sendfile/page cache.
  - caddy_fc: `file_server` for raw; `fastcache` handler for the cache
    cells (own request path, lock-free hits; RAM-only for mem, RAM+disk
    body files for disk). Needs an xcaddy build —
    `bench/caddy-fastcache.Dockerfile` fetches
    `github.com/frontyard/fastcache` from GitHub. (The plain-caddy
    Souin leg was dropped: an unpinned module rebuild changed its
    behavior so drastically the numbers stopped being meaningful.)
  - caddy_fc runs with `GOGC=800` — Go's default `GOGC=100` costs
    ~25-30% throughput at this request rate (measured in the fastcache
    repo's own bench history).
  - ferron: `ferronserver/ferron:3` docker image (or local binary),
    KDL config at `bench/ferron.conf`, access log off, compression
    off. Its `cache` module is a **shared in-memory store**
    (`FerronCache`, `coalesce_timeout 5s`, SWR/stale-if-error on by
    default, freshness from response headers only — no TTL override
    knob). Quirks: no prefix-strip (runner hardlinks fixtures into
    `www/raw/` + `www/cached/`), vhosts match `Host` (wildcard
    `*:<port>` required), and the image opens an HTTP/3 listener wrk
    never negotiates.
- **Cache verification:** every cell is warmed and hit-headers
  asserted (`x-cache`, `Cache-Status`) before timing. For ferron the
  gate must be the listener's very first request: it lazily builds each
  vhost's module chain on first use, and a first request to a
  cache-less location means the cache never engages.
- **TLS:** shared self-signed cert, TLS 1.3, wrk keep-alive
  (steady-state serving). Handshake throughput is measured separately
  via `HANDSHAKE_SECONDS` (`openssl s_time -new` per TLS port).
- nginx/caddy_fc/ferron auto-fall back to docker.

### Caveats

- Run-to-run variance on this box is ±10-40% — CPU frequency, wrk
  threads competing with the server, container start order. Compare
  medians, not single cells; last-cell results in a long matrix carry
  extra heat/contention.
- Loopback measures CPU-bound serving, not NIC limits. Real 10/25GbE
  deployments bottleneck differently.
- verd runs first in each cell (possible warm-up ordering effects).
- No single config makes all four servers do identical cache work —
  memory vs disk-vs-disk are separate cells by necessity (see the
  storage-class matrix in `bench/README.md`).

## Decisions and findings

### sendfile is plaintext-only — TLS numbers are the representative ones

`sendfile` moves bytes page-cache → socket-buffer kernel-side; nginx
sustains ~50 GB/s plaintext on loopback, and so does ferron — it has an
fd→socket path outside hyper (its HTTPS legs drop to userspace-buffered
speeds, which is how we know). Every server that buffers through
userspace tops out around ~10-15 GB/s, because each byte crosses the
kernel boundary twice.

hyper's `Body` is `poll_frame() -> Frame::data(Bytes)` — a
userspace-chunk abstraction with no fd-to-fd escape hatch. sendfile
would mean bypassing hyper's connection driver and the whole middleware
wrapper chain for static conns — an architectural amputation, not an
optimization. Since verd exists to terminate TLS, this is accepted:
on HTTPS everyone is in the same userspace class anyway.

### `tokio::fs` is wrong for page-cached VFS ops

Every `tokio::fs` call is a `spawn_blocking` round trip — task → pool
thread → wake — ~10x the cost of the syscall itself when the file is in
page cache. The static handler did several per request (stat,
`.br`/`.gz` probes, open) plus one per body chunk; fixing it moved
raw/TLS ~2.5 → ~5.8 GB/s at the time (`a8861d8`, `ae80955`).

The static handler now uses `std::fs` throughout; `FileBody` in
`src/body.rs` does blocking `read_at()` inline in `poll_frame` —
positioned reads, no shared fd-offset state, so a concurrent truncate
yields a short body rather than a misaligned range.

**Trade-off accepted:** a genuine disk stall blocks a worker thread
instead of the pool — the same trade nginx makes (and why it offers
`aio` as opt-in). The cache tier covers cold-disk workloads.

### 64KiB frames; larger transient buffers lose

The `ReaderStream` 8KiB default capped everything near ~1 GB/s (~128k
poll/write cycles per GB). 64KiB gave ~8x. 256KiB+/1MiB transient
buffers measured *slower* — allocator churn plus head-of-line stalls
between the read and the socket write. Don't "fix" sizes by scaling
them.

### hyper's h1 write queue: 128KiB, not the ~400KiB default

hyper's h1 dispatcher queues body frames until `max_buf_size` (default
≈417KiB) before flushing — six 64KiB frames `pread` + allocated + held
before the first byte hit the socket, and rustls caps buffered
ciphertext at 64KiB anyway so the batching bought nothing.
`max_buf_size(128KiB)` measured +8-24% raw static. The same setting
bounds hyper's *read* buffer, so `conn.rs` raises it to
`limits.header_bytes + 8KiB` when that is larger — oversized request
heads stay rejected.

### The pattern: small, steady hand-offs beat fewer syscalls

Confirmed three ways:

- Raising rustls's send buffer to 512KiB (one `write_vectored`
  encrypts+flushes hyper's whole queue, 3 `writev`/MiB instead of 16)
  measured 6-17% *slower* — reverted; rustls's 64KiB default is right.
- A read-ahead mpsc producer prefetching 8 chunks ahead: no gain — the
  blocking-pool bounce was the cost; an extra task + channel per
  connection just added a second hop.
- 256KiB+ frames regress (above). Each bigger-burst variant loses for
  the same reason.

### Disk-cache hits: `File` bodies + a per-object mmap

The disk-hit path was the weakest link (~5.6 GB/s vs nginx's
sendfile-able `proxy_cache`). Two changes landed it: `Stored.body`
became `Mem(Bytes) | File{fd,off,len}` so hits stream via `read_at`
instead of `tokio::fs::read` through the blocking pool; and the disk
index `Slot` carries a `OnceLock<FileMap>` — a read-only
`MAP_POPULATE` `mmap` validated once per object — so hits after the
first issue **zero syscalls**: each frame is a `Bytes` slice of the
shared map (`bytes::from_owner`).

This is why `forbid(unsafe_code)` was relaxed to `deny`: the single
`unsafe map()` is scoped to `body::imp` with its mutation/truncation
contract documented (cache objects are immutable once renamed; static
trees replace atomically — the same torn-read contract `sendfile(2)`
carries).

**Tried and rejected:** per-request mmap on the *static* path measured
~14.7 vs ~16.3 GB/s for `read_at` — under TLS the per-byte cost is
rustls encryption, so the syscalls mmap removes were never the
bottleneck. The map is kept only where it's amortized across requests.

Result: the disk cell went from last to first (see TL;DR) — verd
edges nginx `proxy_cache` under TLS.

### Per-request syscall profile is now minimal

`strace -c` on a 1MiB raw/TLS run: per request exactly 1 `statx`,
1 `openat`, 1 `close`, 1 `recvfrom`, 16 `pread64` (one per 64KiB
frame), and `writev`s. There is no fs round trip left to remove; the
remaining per-byte work is `pread` copy, `vec!` memset, AES-GCM, and
`writev`.

### Residual raw/TLS gap (~10-25%): accumulated pipeline cost

No single dominant cause remains — the delta vs caddy/ferron is the sum
of per-request/per-frame overhead:

- per-frame `vec![0u8; N]` memset — a third memory pass where caddy's
  `sync.Pool` reuses buffers. Unfixable in safe code (`libc::read` into
  `BytesMut` spare capacity is unsafe; per-request mmap was tried and
  is slower).
- boxed-dyn dispatch per poll: `UnsyncBoxBody` → `AccessLogBody` →
  `FileBody`;
- the full middleware chain per request plus RequestId/LogRecord;
- hyper h1 write loop vs Go's `io.Copy` pooled buffers / ferron's own
  HTTP stack.

Notably the cached path runs the same middleware chain and still wins —
the chain isn't the bottleneck.

### Competitor notes

- **caddy_fc (fastcache) is the Go benchmark to beat:** a standalone
  `http.handlers.fastcache` module that owns the whole request path —
  lock-free hits, RAM-resident small bodies, disk bodies served via
  `ServeContent` on a real file (kernel sendfile/splice). Its own bench
  history shows ~93% of nginx on sendfile-eligible bodies. The leg runs
  on `GOGC=800`; at Go's default `GOGC=100` the GC tax costs ~25-30%.
- **ferron is the closest Rust competitor:** sendfile-class on
  plaintext, parity with verd on TLS within the noise band. Its
  32MiB-raw and small-object-cache leads are per-request overhead in
  its own HTTP stack, not body-path work.
- **Storage class confounds comparisons:** FerronCache is pure
  in-memory, verd `hybrid` is RAM fronting journaled disk, fastcache
  is two-tier (RAM + sendfile-eligible disk bodies), nginx serves from
  fd-cache+sendfile. Cells must be matched by storage class —
  `bench/verd.toml` carries separate `ram` and `disk` stores so each
  cell routes to the right tier.

### Methodology bugs worth remembering

- `grep -i` on a `curl -si` response treats the binary body as binary
  input and can swallow header lines — verify cache engagement with
  `curl -s -D - -o /dev/null | grep -a`.
- `#[tokio::test]` is single-threaded: blocking `std::process::Command`
  or `TcpStream::read` in tests stalls the server under test.
- Fixture mutators need pid-unique tmp names — stale processes race on
  `<file>.tmp`.
- `set -e` + `var=$(curl …)` exits the whole script when the server
  hasn't bound yet (curl code 7) — guard substitutions with `|| true`.
- Docker Hub DNS flakes are transient; `docker image inspect` guards
  avoid rebuilding.

## Levers not (yet) pulled, ranked

1. **io_uring (`tokio-uring`/`monoio`)** — real async file I/O with zero
   blocking-pool hops; the large architectural answer. Under TLS the
   bound is per-byte encryption in rustls, not I/O scheduling — the
   disk-hit data shows the syscall path is already free of reads.
   Expected gain over the current design: small; cost: a platform
   rewrite. Deferred.
2. **sendfile** — only reachable by bypassing hyper for plaintext
   static conns; useless under TLS anyway. Ferron's ~54 GB/s proves the
   payoff is real and achievable in Rust — just not through
   `Body::poll_frame`. Out of scope for a TLS-only workload.
3. **kTLS** — if nginx+kTLS enters the comparison, userspace TLS
   libraries get their own sendfile-equivalent back; rustls doesn't
   support kTLS yet. The remaining ~10-20% raw/TLS gap to ferron at
   32MiB is in this class — it needs kernel offloading or a different
   TLS stack, not more body-path work.

## Reproducing

```sh
# full matrix (all servers, all cells)
./bench/run.sh

# the realistic config
DURATION=15s PROTOS="tls" ./bench/run.sh

# knobs: DURATION, CONNECTIONS, THREADS, PROTOS ("http tls"),
# fixture counts (M3U8_CHANNELS, TS_FILES), WRK=/path/to/wrk,
# HANDSHAKE_SECONDS=N (openssl s_time -new per TLS port)
```

Requirements: `wrk` (or extracted deb at `/tmp/wrk-local`), `openssl`,
`python3`; nginx/caddy_fc/ferron auto-fall back to docker (caddy_fc via
an xcaddy build of `github.com/frontyard/fastcache`; ferron via
`ferronserver/ferron:3`).
Generated fixtures/configs/results live under `bench/` and are
git-ignored. See `bench/README.md` for the storage-class matrix.
