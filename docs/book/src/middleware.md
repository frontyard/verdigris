# Middleware

Per-route, in order: `ip acl → CORS preflight → auth → rate limit →
cache → handler → security/cors/ratelimit headers → compression`.

## IP ACLs

```toml
[[site.route]]
prefix = "/internal"
ip_allow = ["10.0.0.0/8", "192.168.0.0/16"]
ip_deny = ["10.0.0.9/32"]
```

Client IP honours `X-Forwarded-For` only from `trusted_proxies`.

## Authentication

```toml
auth = { basic = { realm = "ops",
                   users = { ned = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$3nGf8u5Z2p2mJx0yq9Rk3g" } }}
# or: auth = { bearer = { tokens = ["${API_TOKEN}"] } }
# or: auth = { api_key = { location = "header", name = "x-api-key", keys = ["${KEY1}"] } }
```

Basic-auth passwords must be argon2id or bcrypt hashes (plaintext is
rejected at validation). The authenticated identity rides request
extensions into handlers, the access log, and rate-limit keys.

## CORS

```toml
cors = { origins = ["https://app.example.com", "*.staging.example.com"],
         methods = ["GET","POST"], headers = ["content-type"],
         credentials = true, max_age = "1h" }
```

Preflights short-circuit before auth; actual responses get ACAO/ACAC and
a `Vary: Origin`.

## Rate limiting

```toml
rate_limit = { rate = "10/s", burst = 20, key = "identity" }
# or: rate_limit = { rate = "600/m", burst = 20, key = "header:x-api-key" }
```

Token bucket per key (`ip`, `identity`, or `header:<name>`), with
`dry_run` (log-but-allow), `exempt` CIDRs, and `RateLimit-*` headers.
Idle buckets are swept automatically.

## Compression

```toml
compress = { types = ["text/*", "application/json"], min_bytes = "1KiB",
             algorithms = ["br", "zstd", "gzip"], level = 5 }
# or just: compress = true
```

Streams br/zstd/gzip by `Accept-Encoding` q-values; skips small bodies,
precompressed content, ranges, HEAD, no-transform responses, and upgrades.
