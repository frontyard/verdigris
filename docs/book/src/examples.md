# Examples

Each example is a complete `verd.toml` — copy it, replace the domains
and paths, check it with `verd validate`, then `verd run`. The HTTPS
examples assume DNS already resolves to the machine and ports 80 and
443 are reachable; drop the `[acme]` section and use `tls = "off"` or
`"self_signed"` where that's not true.

## Static site with automatic HTTPS

The flagship "zero-config TLS" case: a certificate is issued at first
request and renewed automatically; HTTP requests 308 to HTTPS.

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[[site]]
hosts = ["example.com", "www.example.com"]
tls = "auto"                    # ACME issues and renews the certificate
root = "/var/www/example.com"   # catch-all static route shorthand
```

Security headers (HSTS, X-Frame-Options, …) come from
`[server.security]` defaults — nothing to configure. See
[TLS, ACME & redirects](tls.md) and [Static file serving](static.md).

## Single-page application

`spa = true` serves `index.html` for paths that don't match a file, so
client-side routes like `/settings/billing` work on refresh. Hashed
bundles under `/assets/` get immutable far-future caching.

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[[site]]
hosts = ["app.example.com"]
tls = "auto"

[[site.route]]
prefix = "/"
static = { root = "/var/www/app/dist", spa = true,
           cache_control = { "/assets/*" = "public, max-age=31536000, immutable" } }
```

## Reverse proxy to one backend

`site.proxy` is the catch-all shorthand — every request forwards to the
app. `X-Forwarded-For`/`X-Forwarded-Proto` are set automatically.

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[[site]]
hosts = ["app.example.com"]
tls = "auto"
proxy = "http://127.0.0.1:3000"   # also accepts a cluster name or URL list
```

## Frontend and API on one domain

Serving the API under `/api` on the site's own domain avoids CORS
entirely. More specific prefixes win, so `/api` routes never touch the
static handler; `strip_prefix` removes `/api` before forwarding
(`/api/users` → `http://127.0.0.1:3000/users`).

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[[site]]
hosts = ["example.com"]
tls = "auto"

[[site.route]]
prefix = "/api"
proxy = { upstream = "http://127.0.0.1:3000",
          rewrite = { strip_prefix = "/api" } }

[[site.route]]
prefix = "/"
static = { root = "/var/www/site", spa = true }
```

## Load balancing across replicas

A named `[upstream.*]` cluster gives you balancing, health checking,
retries, and pool tuning. `h2c://` URLs speak cleartext HTTP/2 (gRPC)
to the backend.

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[upstream.api]
servers = ["http://10.0.0.11:8080", "http://10.0.0.12:8080",
           "http://10.0.0.13:8080"]
lb = "least_conn"                 # round_robin | least_conn | ip_hash
max_connections = 256             # per-member connection cap

[upstream.api.health.active]      # periodic probes on each member
path = "/healthz"
interval = "5s"
timeout = "2s"

[upstream.api.health.passive]     # kick members out on real failures
failures = 3
cooldown = "30s"

[upstream.api.timeouts]
connect = "3s"
response_header = "10s"

[[site]]
hosts = ["api.example.com"]
tls = "auto"
proxy = "api"                     # the cluster name
```

`upstream.api.unavailable` customizes the response (status, body) when
every member is down — handy for a branded maintenance page. See
[Reverse proxy & load balancing](proxy.md).

## Multiple sites on one instance

Sites are matched by `Host`; a `default` site catches everything else
(including requests to unknown names).

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[[site]]
hosts = ["example.com", "www.example.com"]
tls = "auto"
root = "/var/www/example"

[[site]]
hosts = ["blog.example.com"]
tls = "auto"
proxy = "http://127.0.0.1:9000"

# requests whose Host matches no site above land here
[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
respond = { status = 404, body = "unknown host" }
```

## Redirects: www → apex and domain moves

`redirect_host` covers the plaintext leg (`http://www` goes straight to
`https://example.com`); the redirect route handles HTTPS requests to
`www`. `{path}` and `{query}` substitute from the request, so links
keep working.

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[[site]]                          # canonical site
hosts = ["example.com"]
tls = "auto"
root = "/var/www/example"

[[site]]                          # www → apex
hosts = ["www.example.com"]
tls = "auto"
redirect_host = "example.com"     # http://www… → https://example.com…

[[site.route]]
prefix = "/"
redirect = { to = "https://example.com{path}{query}", status = 308 }
```

A permanent domain move is the same shape — every path 301s to the new
domain:

```toml
[[site]]
hosts = ["old.example.com", "www.old.example.com"]
tls = "auto"

[[site.route]]
prefix = "/"
redirect = { to = "https://new.example.com{path}{query}", status = 301 }
```

## WebSockets and other long-lived connections

Upgrade requests (WebSocket) are detected and tunneled automatically —
the only config that matters is timeouts: `request_deadline` would kill
a healthy stream and `send` bounds tunnel inactivity, so both are
disabled and liveness is left to the app's own ping/pong.

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[[site]]
hosts = ["live.example.com"]
tls = "auto"

[[site.route]]
prefix = "/ws"
proxy = { upstream = "http://127.0.0.1:4000" }
timeouts = { request_deadline = "0s", send = "0s" }
```

For SSE the same applies: streams must outlive the default deadline.

## Protected routes: auth plus an IP allowlist

Middleware composes per route — the LAN allowlist runs first, then
basic auth.

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[[site]]
hosts = ["grafana.internal.example"]
tls = "auto"

[[site.route]]
prefix = "/"
proxy = { upstream = "http://10.0.0.5:3000" }
ip_allow = ["10.0.0.0/8", "192.168.0.0/16"]
auth = { basic = { realm = "ops",
                   users = { oncall = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$3nGf8u5Z2p2mJx0yq9Rk3g" } } }
```

Password values must be argon2/bcrypt hashes — generate with `argon2`
or `htpasswd -B`; an `htpasswd` file path works instead of inline
`users`. For machine clients use `bearer` or `api_key` with `${VAR}`
interpolation. See [Middleware](middleware.md).

## Public API: rate limiting and CORS

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[upstream.api]
servers = ["http://10.0.0.11:8080", "http://10.0.0.12:8080"]

[[site]]
hosts = ["api.example.com"]
tls = "auto"

[[site.route]]
prefix = "/v1"
proxy = { upstream = "api" }
rate_limit = { key = "ip", rate = "100/m", burst = 25 }
cors = { origins = ["https://app.example.com"],
         methods = ["GET", "POST", "OPTIONS"],
         headers = ["content-type", "authorization"],
         max_age = "1h" }
# auth = { api_key = { location = "header", name = "x-api-key",
#                      keys = ["${KEY1}"] } }
```

Preflight `OPTIONS` requests short-circuit before auth. `key` selects
what a bucket applies to: `ip`, `identity` (authenticated user),
`route`, or `header:<Name>`.

## Response caching

Cache stores are named and shared; routes opt in. Freshness honors
upstream `Cache-Control`/`Expires` by default, `stale_*` covers the
gaps, and authenticated requests bypass automatically.

```toml
[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"

[cache.main]
tier = "hybrid"                   # hot objects in RAM, rest on disk
ram_bytes = "256MiB"
disk_bytes = "10GiB"
disk_path = "/var/lib/verd/cache"

[upstream.app]
servers = ["http://127.0.0.1:8080"]

[[site]]
hosts = ["cdn.example.com"]
tls = "auto"

[[site.route]]
prefix = "/"
proxy = { upstream = "app" }
cache = { store = "main", stale_while_revalidate = "30s",
          stale_if_error = "1h" }
```

See [Caching](caching.md) for tiers, purging, and `X-Cache`.

## Fixed responses: health checks and maintenance mode

`respond` needs no backend at all — a cheap health endpoint for the
load balancer, or a maintenance page during a deploy. `exact` matches
win over prefix routes regardless of declaration order.

```toml
[server]
listen = ["127.0.0.1:8080"]

[[site]]
default = true
tls = "off"

[[site.route]]
exact = "/healthz"
respond = { status = 200, body = "ok" }

[[site.route]]
prefix = "/"
respond = { status = 503, body = "back in a few minutes",
            headers = { "retry-after" = "300" } }
```

## Local development

Plain HTTP, pretty logs, files from the working directory:

```toml
[server]
listen = ["127.0.0.1:8080"]

[log]
format = "pretty"
level = "debug"

[[site]]
default = true
tls = "off"
root = "./public"
```

To test HTTPS locally swap the listener for
`{ addr = "127.0.0.1:8443", tls = true }` and set `tls = "self_signed"`
on the site — a throwaway certificate is generated at boot.

## Splitting a large config

One file per site keeps `verd.toml` small. `conf.d/*.toml` is a glob —
fragments load in sorted order, tables merge recursively, `[[site]]`
lists append, and a scalar set twice to different values is an error.

```toml
# /etc/verd/verd.toml
include = ["conf.d/*.toml"]

[server]
listen = ["0.0.0.0:80", { addr = "0.0.0.0:443", tls = true }]

[acme]
email = "ops@example.com"
```

```toml
# /etc/verd/conf.d/blog.toml — one fragment per site
[[site]]
hosts = ["blog.example.com"]
tls = "auto"
root = "/var/www/blog"
```

An empty `conf.d/` is fine — a glob matching nothing is ignored, while
a named file that doesn't exist is an error. `verd config` prints the
merged result with secrets redacted when you want to check what the
fragments added up to.
