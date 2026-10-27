# Middleware

Per-route, in order: `ip acl → CORS preflight → auth → rate limit →
cache → handler → security/cors/ratelimit headers → compression`.

## Site defaults

Every middleware block also exists at site level and is inherited by
all of the site's routes — including the implicit `site.root` /
`site.proxy` catch-alls:

```toml
[[site]]
hosts = ["app.example.com"]
auth = { bearer = { tokens = ["${API_TOKEN}"] } }   # every route below
rate_limit = { rate = "100/s", key = "ip" }     # one shared bucket
ip_deny = ["203.0.113.0/24"]

[[site.route]]
prefix = "/public"
respond = { status = 200, body = "open" }
auth = { enabled = false }        # opt out of the site default

[[site.route]]
prefix = "/api"
proxy = "http://127.0.0.1:9000"
rate_limit = { rate = "10/s", key = "route" }   # replaces, doesn't merge
```

- A route block **replaces** the site block wholesale — except
  `response_headers` (`set`/`add` union, route keys win; `remove`
  concatenates) and `security`, which merge field-wise.
- `enabled = false` opts a route out of an inherited block; `security`
  additionally accepts the bare `security = false` spelling (it has no
  other dominant field).
- A site-level `rate_limit` builds **one shared limiter** across all
  routes that inherit it — `key = "ip"` limits each client site-wide.
- IP ACLs **tighten only**: denies union, and a request must pass both
  non-empty allow lists — a route can't widen a site ACL.
- `timeouts`, `limits`, and `security` also layer global → site →
  route.

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
