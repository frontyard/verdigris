# Verdigris

**Documentation for verd 1.1.0.**

Verdigris is a self-hosting web server and reverse proxy in a single static
binary: nginx-class performance with Caddy-like zero-configuration TLS and
a readable TOML configuration.

## What it does

- HTTP/1.1 and HTTP/2 (plus h2c) on the same listener, downstream and upstream
- Static files with ranges, ETag/Last-Modified validators, precompressed variants
- Reverse proxy with load balancing, retries, health checks, HTTP upgrades (WebSockets)
- TLS termination with manual certificates, self-signed, or fully automatic
  ACME (Let's Encrypt) issuance — http-01, tls-alpn-01 and dns-01
  (Cloudflare) challenges, incl. wildcards
- Authentication (basic, bearer, API key), IP ACLs, CORS, rate limiting,
  compression (br/zstd/gzip), and a full HTTP response cache (RAM/disk/hybrid)
- Prometheus metrics, structured access logs, and an admin API with
  atomic config reloads (SIGHUP, file watch, or `POST /reload`)

## Design rules

- One binary, one `verd.toml`, no external dependencies at runtime.
- Configuration is validated before it can serve; a bad reload never
  interrupts traffic.
- Response bodies stream end-to-end; nothing buffers a whole body unless
  a feature explicitly requires it.

## For LLMs / tooling

The repository root ships `llms.txt` (curated summary + recipes) and
`llms-full.txt` (the whole book in one file), following the llmstxt.org
convention. Point a model at either, or give it the authoritative
`verd schema` JSON output — every config example in this book is
validated against the real parser in CI.
