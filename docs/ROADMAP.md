# Verdigris V1 Roadmap

Condensed execution plan for implementing all of `MISSION.md` V1. Each phase
ends with `cargo fmt --check && cargo clippy -D warnings && cargo test` green
and one commit. See the mission file for the authoritative spec.

## Architecture invariants

- Single static binary; module layout mirrors the request lifecycle.
- `Runtime` is an immutable snapshot behind `arc_swap`: reload builds a new
  runtime (reusing unchanged upstream pools/caches/ACME store), swaps, diffs
  listeners, drains the old one. In-flight requests finish on the old config.
- Bodies stream end-to-end; buffering only where a feature requires it
  (cache store, retries).
- Middleware order (per route): `ip_acl → auth → rate_limit → cors → cache →
  handler → compress → headers`. Exactly one handler per route.
- Route precedence: exact host before wildcard; exact path, then longest
  prefix, then regex (linear, last); `priority` breaks ties.
- Secrets only via `${VAR}` / `${file:...}` interpolation; redacted in
  `/admin/config` and logs. UTC RFC 3339 timestamps everywhere.
- `#![forbid(unsafe_code)]`; `cargo fmt` + `clippy -D warnings` enforced.

## Phases

- **P0** Scaffold: crate skeleton, CLI, licenses, lint configs, CI.
- **P1** Config: serde model (schema source), `${VAR}`/`${file:}` secrets,
  `include` dirs, `verd validate|fmt|schema`.
- **P2** Data plane: multi-listener hyper (h1+h2 auto), conn limits, all
  timeouts, request-id, graceful drain, `respond`/`redirect` handlers,
  access-log + health stubs.
- **P3** Router + static files: host index, matchit, normalization, index,
  listing, SPA/try_files, ranges, ETag/304, mime, precompressed, error pages.
- **P4** Proxy + LB: h1/https/h2c upstreams, pools+limits, X-Forwarded-*, hop-
  by-hop, header ops, rewrite, retry budget, rr/least_conn/ip_hash, active +
  passive health, DNS TTL re-resolution w/ LKG+grace, WebSocket/upgrade tunnel.
- **P5** TLS: rustls TLS1.2+, SNI resolver, manual certs hot reload,
  self-signed, HTTP→HTTPS redirect, security headers.
- **P6** Middleware: IP ACL, basic(argon2/htpasswd-bcrypt)/bearer/api-key auth,
  CORS, sharded token-bucket rate limit (429 + RateLimit-* + Retry-After,
  exemptions, dry-run).
- **P7** Compression: gzip/br/zstd via Accept-Encoding q-values, min-size +
  type allowlist.
- **P8** ACME: instant-acme, HTTP-01 + TLS-ALPN-01, EAB, renewal loop,
  on-demand (allowlist + rate limit), Pebble e2e, cert metrics.
- **P9** Cache: RAM (lru/lfu/fifo) + journaled disk + hybrid, limits, Vary key,
  CC/ETag revalidation, SWR/SIE, coalescing, negative caching, bypass rules,
  admin purge, X-Cache.
- **P10** Observability: full JSON/human access logs (filter, sample, file +
  SIGUSR1, 499), prometheus exporter, /health /ready, proc RSS/CPU.
- **P11** Admin + lifecycle: axum admin (auth, TLS opt), reload/purge/upstream-
  drain/config/version endpoints, SIGHUP + file-watch reload, `verd fmt`,
  systemd unit, multi-arch Dockerfile + compose.
- **P12** Docs + release: rustdoc everywhere, mdBook site (generated config
  reference), release workflow (multi-arch musl, checksums, cosign, SBOM,
  image push), bench suite vs nginx, fuzz targets, fault injection, soak,
  coverage gate.

## Open risks

- ~~`verd` is taken on crates.io (stale 0.1.0) — decide rename vs.
  name transfer before first crates release~~ — decided: the project is
  **Verdigris**; package, lib, binary, and `verd_` metric prefix are all
  `verd`. `cargo install verd` installs the `verd` binary.
- Upstream h2/h2c pooling is hand-rolled on `hyper::client::conn::http2`
  (`proxy/cluster.rs`). hyper-util's legacy client *can* do prior-knowledge
  cleartext h2 (`http2_only`), but it cannot express per-member
  `max_connections` with different semantics per protocol (open conns vs.
  streams), the checkout/return lifecycle tied to response-body completion,
  or least-conn `inflight` accounting — hence the custom pool. Remaining
  gap vs. the legacy pool: no "connecting" lock — concurrent checkouts
  while `member.h2` is empty each run a full dial + handshake (last writer
  wins in `member.h2`; loser conns serve one request then close). Bounded
  by the stream semaphore and self-cleaning, but a TLS+ALPN burst on https
  members is pricey. Fix if it ever matters: a per-member dial mutex that
  re-checks `h2_live()` before dialing.
- ~~Verify `bcrypt` crate accepts `$2y$` htpasswd hashes (P6)~~ — verified:
  bcrypt 0.19 parses `2y/2b/2a/2x` (crypt_blowfish `$2y$` == fixed `$2b$`
  algorithm) and verd exercises real `$2y$` verification in
  `middleware/auth.rs::basic_bcrypt_2y_accepted` and the e2e htpasswd test.
