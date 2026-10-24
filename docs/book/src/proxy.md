# Reverse proxy & load balancing

```toml
[upstream.app]
servers = ["http://app1:9000", "http://app2:9000"]
lb = "least_conn"                  # round_robin | least_conn | ip_hash

[upstream.app.limits]
max_connections = 256

[upstream.app.health.passive]
failures = 3
cooldown = "10s"

[upstream.app.health.active]
interval = "5s"
path = "/healthz"

[[site.route]]
prefix = "/api"
proxy = { upstream = "app", rewrite = { strip_prefix = "/api" } }
```

## Upstreams

- **Protocols**: `http://`, `https://`, `h2c://` (cleartext HTTP/2 with
  prior knowledge). ALPN on `https://` picks h2 automatically; a shared
  h2 connection multiplexes requests per member.
- **Balancing**: `round_robin` (default), `least_conn`, `ip_hash`.
- **Health**: passive (kick members out after N consecutive failures for
  a cooldown) and/or active (periodic HTTP probes on `path`, honours h1/h2).
- **Retries**: `retries.max_per_request` replays idempotent requests on
  connect/connection-failure; a cluster-wide `budget_fraction` caps
  concurrent retries so retries can't amplify an outage.
- **Timeouts**: `connect`, `response_header`, plus the route's
  `timeouts.request_deadline` and body read/write budgets.
- **DNS**: names resolve through the system resolver with TTL caching,
  failure grace, and re-resolution on connect errors.
- **Upgrades**: `Connection`/`Upgrade` tokens (e.g. WebSocket) are
  tunneled end-to-end; the tunnel closes when either side does.

Inline upstreams without a named cluster are fine for small configs:

```toml
[[site]]
hosts = ["app.example.com"]
proxy = ["http://127.0.0.1:9000"]      # catch-all route to an inline cluster
```

## Headers

Request headers can be set/cleared per route; `Host` is rewritten to the
member authority when `pass_host = true` (the default); set it `false`
to pass the client's original `Host` through. Hop-by-hop headers are
stripped; `X-Forwarded-For` is appended when the peer is trusted
(otherwise replaced) and `X-Forwarded-Proto` reflects the inbound scheme.
