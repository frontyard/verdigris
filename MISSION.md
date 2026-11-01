# Verdigris Mission

<!-- markdownlint-disable MD013 -->
<!-- This manifesto is written in long-line prose; the 80-col wrap
     enforced elsewhere doesn't apply here. -->

## Overview

Verdigris is a web server and reverse proxy designed to be simple to run and fast. It is written in Rust.

It targets developers and operators who self-host services, typically in Docker: people who want the performance of nginx, the zero-config TLS of caddy, and a configuration file they can read in one sitting. It is a single static binary with no runtime dependencies.

## Goals

- Simple: one TOML file, sane defaults, runs with zero config for the common case
- Fast: performance in the same class as nginx
- Safe: memory-safe by construction, secure defaults, no footguns
- Batteries included: TLS, caching, compression, load balancing, rate limiting and metrics are built in, not plugins

## Non-Goals

- Not an application server: no FastCGI, PHP, CGI or embedded scripting (Lua, JS)
- Not a CDN or edge network: no multi-region or distributed state; a single instance owns its own cache and rate-limit state
- Not a service mesh or control plane: no service discovery beyond static upstreams and DNS
- Not a Layer-4 proxy: no TCP/UDP forwarding, no TLS passthrough or SNI routing without termination
- Not a forward proxy: no `CONNECT`
- Not a WAF: no request-body inspection or managed rulesets
- Not a Kubernetes ingress controller
- No server-side templating (SSI, template rendering)
- No Windows support in V1
- No custom configuration language

## Architecture Principles

- Data plane built directly on `hyper`, `tower` and `rustls` for full control over connections, buffering and performance
- Control plane (health, metrics, admin API) built with Axum
- Async throughout, on Tokio
- Streaming by default: request and response bodies are not buffered unless a feature (caching, retries) requires it
- Lock-free or sharded shared state on the hot path; no global locks per request
- Every feature is per-route configurable and off unless enabled, except security defaults which are on

## Platforms

- Supported: Linux x86_64 and aarch64
- Development only: macOS
- Unsupported: Windows

## Configuration

- TOML only. Human readable, supports comments, no indentation pitfalls
- A single file by default (`verd.toml`); optional `include` of a directory of fragments (e.g. one file per site)
- Every option has a documented default; a minimal config is a few lines
- Secret interpolation from environment variables (`${VAR}`) and files (`${file:/run/secrets/x}`, for Docker and Kubernetes mounted secrets) so secrets never live in the config
- `verd validate` checks the config without starting the server
- A published JSON Schema for editor completion and validation
- Reload: triggered by `SIGHUP` or the admin API, optionally by file watch. Reload is atomic: an invalid new config is rejected, logged, and the running config stays in effect. In-flight requests finish on the old config
- Illustrative shape:

```toml
[[site]]
hosts = ["example.com", "www.example.com"]
root  = "/srv/www"

[[site]]
hosts = ["api.example.com"]
proxy = ["http://10.0.0.2:8080", "http://10.0.0.3:8080"]
```

## Performance

- Target: within 10% of nginx on requests/second and p99 latency for static files and plaintext reverse proxying on the same hardware
- Measured with a reproducible benchmark suite (e.g. `oha`/`wrk`) covering: small static file, large static file, reverse proxy keep-alive, reverse proxy with TLS, cache hit
- Metrics tracked: requests/second, p50/p99/p999 latency, memory (RSS) under load, CPU per request
- Benchmarks run in CI with regression thresholds
- Memory use is bounded: all caches, pools and buffers have configurable limits
- Routing cost is independent of the number of sites and routes (indexed host lookup, prefix tree for paths); regex routes are the only linear component and are evaluated last

## Security

- Secure defaults: TLS 1.2 minimum, HTTP to HTTPS redirect when TLS is enabled, directory listing off, server header minimal
- Timeouts on everything: TLS handshake, header read, body read, idle keep-alive, overall request deadline, upstream connect, upstream response. Protects against slowloris and stuck upstreams. Per-route overrides for long-lived streams (SSE, WebSocket)
- Limits on everything: max header size, max request body size, max concurrent connections, max connections per IP
- Configurable security response headers (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Content-Security-Policy); enabled by default where safe
- IP allow and deny lists, per site or per route, with CIDR support
- Trusted proxy list: `X-Forwarded-For` is only honoured from trusted addresses
- Path traversal and symlink escape prevention for static files
- Runs as non-root; can bind privileged ports via capabilities and drop privileges after bind
- Admin endpoints (metrics, health, admin API) served on a separate listener, bindable to localhost only; authentication required and TLS supported when bound beyond localhost
- Secrets (basic auth passwords, API keys) are stored hashed or injected via environment variables, never plaintext in the config
- Dependencies audited in CI (`cargo audit`, `cargo deny`)

## Protocols and Transport

- HTTP/1.1 and HTTP/2 on the client side; HTTP/1.1 and HTTP/2 (including h2c cleartext, typical for gRPC backends) to upstreams
- TLS via `rustls`, SNI, ALPN
- Protocol upgrade pass-through (WebSocket and other Upgrade mechanisms)
- Streaming bodies: chunked transfer, server-sent events, long-polling, gRPC pass-through over HTTP/2
- Keep-alive and connection pooling to upstreams
- Upstream TLS with configurable certificate verification
- Multiple listeners (address and port) per instance; IPv6 and dual-stack
- Graceful connection draining on shutdown and reload

## Routing

- Match on host (exact, wildcard `*.example.com`), path (prefix, exact, regex), method, headers and query parameters
- Path normalisation (dot segments, percent-encoding, duplicate slashes) applied before route matching, filesystem access and upstream forwarding
- Deterministic precedence: exact host before wildcard; exact path, then longest prefix, then regex; explicit priority as a tiebreaker. A regex route never overrides a prefix route; use a more specific prefix or an exact match instead
- Method, header and query conditions filter candidate routes but do not affect precedence; among routes whose conditions match, the most specific path wins
- A route has one handler (static files, proxy, redirect, fixed response) and any number of middleware (auth, rate limit, CORS, headers, cache, compression)
- Redirects (301, 302, 307, 308) including host and scheme redirects
- URL rewriting (path strip, prefix replace, regex rewrite)

## Features

### V1

#### TLS and certificates

- Automatic certificate issuance and renewal via ACME (Let's Encrypt and any ACME directory), like caddy
- ACME challenges: HTTP-01 and TLS-ALPN-01
- Configurable ACME directory URL (staging support), account email and External Account Binding (EAB) for other providers
- On-demand issuance for previously unseen hostnames; off by default, and when enabled gated by an explicit domain allowlist and issuance rate limits
- Manual certificate and key files per site, with hot reload on change
- Self-signed certificates for local development
- Certificate expiry and issuance failures exposed as metrics

#### Multiple sites

- Multiple domains and subdomains per instance, each with its own routes, TLS and settings
- Default site for unmatched hosts (configurable: 404, redirect, or a site)

#### Static file serving

- Index files, configurable per route
- Directory listing, off by default
- SPA fallback (serve `index.html` for unknown paths) and `try_files` style lookup
- Range requests, `ETag`, `Last-Modified`, conditional requests (`304 Not Modified`)
- MIME type mapping by extension, overridable
- Precompressed asset lookup (`.gz`, `.br`, `.zst`) when the client accepts
- Custom error pages
- Configurable `Cache-Control` per path pattern

#### Compression

- gzip, brotli and zstd response compression, negotiated via `Accept-Encoding`
- Configurable minimum size and content-type allowlist
- Applies to static and proxied responses

#### Reverse proxy

- HTTP/1.1 and HTTP/2 (including h2c) upstreams, plain or TLS
- Sets `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP` and `Forwarded`; honours them only from trusted proxies
- Request and response header manipulation: add, set, remove
- Hop-by-hop header handling (`Connection`, `Keep-Alive`, `TE`, `Upgrade`) per spec
- Path rewriting before forwarding
- Retries for idempotent requests on connection failure, with a retry budget (retried against a different upstream where possible)
- Active health checks (periodic probe; configurable path, interval, timeout, expected status) and passive health checks (mark unhealthy on failures); unhealthy upstreams are removed and re-added automatically
- Configurable behaviour when no upstream is healthy (502 or 503, custom body)
- Timeouts and limits per upstream: connect, response headers, idle, max connections
- Hostname upstreams re-resolved on TTL expiry and on failure; last-known-good addresses are retained on resolution failure and removed only after records are absent for a configurable grace period

#### Load balancing

- Algorithms: round-robin, least connections, IP hash
- Health-check aware: only healthy upstreams receive traffic

#### Rate limiting

- Keys: client IP, authenticated identity, route or an arbitrary header
- Algorithm: token bucket with configurable rate and burst
- Response: `429 Too Many Requests` with `Retry-After` and `RateLimit` headers (IETF draft, tracked until it stabilises)
- Exemptions for trusted IPs and CIDRs; optional log-only (dry-run) mode
- State is in-memory, per instance

#### CORS

- Allowed origins (exact, wildcard, regex), methods, headers, exposed headers, credentials, max age
- Preflight handling

#### Authentication

- Basic auth with hashed passwords: argon2 for inline credentials, bcrypt (`$2y$`) for htpasswd file compatibility
- Bearer token
- API key in header or query parameter
- Per route; authenticated identity available to rate limiting and access logs

#### Caching

- Caches static files and reverse proxy responses
- Eviction policies: LRU, LFU, FIFO
- Storage tiers: RAM, disk, hybrid (RAM in front of disk with promotion on hit)
- Limits: RAM size in bytes, disk size in bytes, total item count; eviction when any limit is exceeded, according to the policy
- Configurable maximum cacheable object size
- Disk cache persists across restarts with a crash-safe on-disk index (rebuilt on corruption)
- Cache key: method, host, path, normalised query string, and headers named by the response `Vary` header or by config
- Honours HTTP cache semantics: `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, revalidation of stale entries
- `stale-while-revalidate` and `stale-if-error` support
- Request coalescing: concurrent misses for the same key collapse into a single upstream fetch
- Configurable TTL override and negative caching (short TTL for error responses)
- Bypass rules: by method, by cookie, by header, by path pattern; authenticated requests bypass by default
- Invalidation: by TTL expiry, by eviction, and on demand via an admin purge API (single key, path prefix, everything)
- `X-Cache: HIT | MISS | BYPASS | STALE` response header, can be disabled

#### Observability

- Structured JSON access logs by default (Docker friendly), human-readable format optional
- Access log filtering (e.g. exclude health checks) and sampling for high-volume routes
- Access log fields: timestamp, request ID, client IP, method, host, path, status, bytes, duration, upstream, cache status, user agent, referer, protocol and TLS version
- Requests aborted by the client are logged with a distinct status (`499`, as nginx does) so they are not mistaken for server errors
- All timestamps in UTC, RFC 3339 format
- Log levels for the server log, separate from access logs
- Output to stdout/stderr; optional file output with reopen on `SIGUSR1` for logrotate
- Request ID generated or propagated (`X-Request-Id`)
- Prometheus exporter: requests total and duration histograms by site/route/status, active connections, upstream health and latency, cache hits/misses/size, rate limit rejections, TLS certificate expiry, config reload success/failure, process memory and CPU (bounded label cardinality: route IDs, not raw paths)
- `/health` (liveness) and `/ready` (readiness: config loaded, listeners bound, certificates available)

#### Lifecycle and operations

- CLI: `verd run`, `verd validate`, `verd version`, and (lower priority) `verd fmt`, a comment-preserving config formatter; config path and log level overridable via flags and environment variables
- Admin API surface: config reload, cache purge, upstream status and manual drain, running-config inspection, version
- Graceful shutdown on `SIGTERM`: stop accepting, drain with a configurable timeout; a second signal forces immediate exit
- Zero-downtime reload (see Configuration)
- Docker: official multi-arch image on a minimal base, running as non-root; example `Dockerfile` and `docker-compose.yml`
- Documented writable directories (certificate store, disk cache); runs on a read-only root filesystem
- systemd unit file example
- Distributed as a static binary via GitHub releases (signed artifacts, checksums, SBOM) and `cargo install`

#### Documentation

- API documentation via `rustdoc` on all public items, enforced in CI; published to docs.rs on each release
- A published documentation site (mdBook) covering installation, guides, configuration reference and operations; built and deployed by CI on every release, with a `main`-branch preview
- Configuration reference and JSON Schema generated from the same source, so documentation cannot drift from the implementation
- Doc examples run as tests (`cargo test --doc`); broken intra-doc links are build errors
- Guides: static site, reverse proxy with TLS, Docker Compose, performance tuning, migrating from nginx and caddy, migration between major versions

### V2

- HTTP/3 (QUIC)
- Authorization: RBAC, ABAC, OAuth2/OIDC forward authentication, JWT validation (JWKS)
- Client-certificate authentication (mTLS): verifying downstream clients and presenting client certificates to upstreams
- Plugin system: WebAssembly plugins (sandboxed, hot-loadable) for request and response filters
- ACME DNS-01 challenge and wildcard certificates; OCSP stapling
- Load balancing: weighted algorithms, consistent hashing, sticky sessions (cookie based), percentage-based traffic splitting
- Per-connection bandwidth throttling
- OpenTelemetry tracing
- PROXY protocol, Unix socket listeners and upstreams
- OpenAPI/Swagger specification for the admin API

## Testing and Quality

- Unit tests for all modules
- Integration tests that start the server with a real config and exercise every feature over the network
- End-to-end tests in Docker including ACME against a local test CA (e.g. Pebble)
- Benchmark suite run in CI with regression thresholds (see Performance)
- Fuzzing of the config parser and request handling paths
- Fault injection tests: upstream timeouts, connection resets, slow clients, disk full and index corruption for the cache
- Reload tested under load: zero dropped requests. Graceful shutdown tested under load: every in-flight request completes within the configured drain timeout
- Long-running soak test for memory growth; router precedence covered by property tests
- Code coverage measured in CI with a minimum threshold

## Engineering Principles

- License: MIT OR Apache-2.0
- Stable Rust with a declared minimum supported Rust version
- Readability over cleverness: explicit control flow, no magic, no surprising abstractions
- Sane organisation: the module layout mirrors the request lifecycle, so it is obvious where a feature lives
- `cargo fmt` and `cargo clippy -D warnings` enforced in CI
- `#![forbid(unsafe_code)]` by default; any `unsafe` must be isolated in a dedicated module with a written justification
- Release builds use LTO; PGO is evaluated against the benchmark suite and adopted only if it measurably helps
- Dependencies kept minimal and audited; no dependency added without a clear need
- Semantic versioning for releases; configuration is backwards compatible within a major version
- Every feature ships with tests and documentation in the same change
