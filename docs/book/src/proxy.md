# Reverse proxy & load balancing

```toml
[upstream.app]
servers = ["http://app1:9000", "http://app2:9000"]
lb = "least_conn"                  # round_robin | least_conn | ip_hash
max_connections = 256              # per-member connection cap

[upstream.app.health.passive]
failures = 3          # `passive = 3` works too
cooldown = "10s"

[upstream.app.health.active]
interval = "5s"
path = "/healthz"     # `health = "/healthz"` on the upstream is the same

[[site.route]]
prefix = "/api"
proxy = { upstream = "app", rewrite = { strip_prefix = "/api" } }
```

## Upstreams

- **Protocols**: `http://`, `https://`, `h2c://` (cleartext HTTP/2 with
  prior knowledge). ALPN on `https://` picks h2 automatically; a shared
  h2 connection multiplexes requests per member.
- **Balancing**: `round_robin` (smooth weighted), `least_conn`
  (`inflight / weight`), `ip_hash` (weight-proportional ring). Entries
  can carry `weight` and `backup`:

  ```toml
  [upstream.app]
  servers = [
    "http://app1:9000",                        # weight 1, primary
    { url = "http://app2:9000", weight = 3 },  # ~3/4 of requests
    { url = "http://app3:9000", backup = true },# standby only
  ]
  ```

  `backup` members serve only while no primary is healthy.

  When only `servers` matters, the table itself is optional:
  `upstream.app = "http://app1:9000"` is a one-member cluster, and a URL
  list or `{ url, weight, backup }` entry works the same —
  `upstream.app = ["http://a:9000", "http://b:9000"]`.
- **Health**: passive (kick members out after N consecutive failures for
  a cooldown) and/or active (periodic HTTP probes on `path`, honours h1/h2).
- **Retries**: `retries.max_per_request` replays idempotent requests on
  connect/connection-failure (`retries = 3` is the shorthand); a
  cluster-wide `budget_fraction` caps concurrent retries so retries
  can't amplify an outage. `unavailable = 503` sets the
  all-members-down status — the table form's `body` substitutes the
  request placeholders (`{uri}`, `{host}`, `{request_id}`, …), and
  statuses that forbid a body (1xx/204/304) are served bodyless.
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
proxy = "http://127.0.0.1:9000"        # catch-all route to an inline cluster
```

`site.proxy` also accepts a cluster name (`proxy = "app"`) or a URL
list. Inside a route, `proxy.upstream` accepts the same three shapes:
`"app"`, `"http://…"`, or `["http://…", …]`.

## Headers

Request headers can be set/cleared per route under
`proxy.request_headers` (bare `request_headers = false` disables it);
response headers under `route.response_headers`. Ops apply in order
remove → set → add.
`Host` is rewritten to the member authority by default
(`host_header = "upstream"`); set `host_header = "original"` to pass the
client's `Host` through, or any hostname (`host_header =
"api.internal"`) to force a value. `host_header = { value = "…" }`
sends a value verbatim even when it spells a keyword — the escape
hatch for an upstream literally named `upstream`. Setting `Host` via
`proxy.request_headers` overrides `host_header` (the validator warns).
Hop-by-hop headers are
stripped; `X-Forwarded-For` is appended when the peer is trusted
(otherwise replaced) and `X-Forwarded-Proto` reflects the inbound scheme.
