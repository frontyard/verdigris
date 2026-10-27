# Observability

## Server log

Diagnostics from the server itself — startup, listener binds, reloads,
upstream health transitions — go through `[log]`:

```toml
[log]
level = "info"               # error / warn / info / debug / trace,
                             # or env-filter style "verd=debug,hyper=info"
format = "json"              # or "pretty"
output = "stderr"            # or "stdout" / a file path
```

Precedence: `--log-level` / `VERD_LOG` (command line) overrides
`[log] level`, which overrides the built-in `info` default. Format and
output have no flag — they only come from the config file.

File output is appended and reopened on **SIGUSR1** (logrotate), same
as the access log.

## Access log

One JSON record per request (default), emitted when the response body
finishes — bytes and duration are what actually went over the wire. A
client that disconnects mid-body is logged as `499`.

```toml
[log.access]
format = "json"            # or "pretty"
output = "/var/log/verd/access.log"   # or "stdout" / "stderr"
filter = 'path != "/healthz" && status != 404'
sample = 0.25              # deterministic fraction
```

Fields: `ts` (RFC 3339 UTC), `req_id`, `client_ip`, `method`, `host`,
`path`, `proto`, `tls`, `route`, `status`, `bytes`, `duration_ms`,
`user_agent`, `referer`, `upstream`, `cache`, `identity`.

Filter terms support `=`/`!=`/`==`, `=~`/`!~` globs, and `>`/`<`/`>=`/`<=`
on `path`, `host`, `method`, `status`, `upstream`, `cache`, `identity`.

File output is reopened on **SIGUSR1** (logrotate).

## Metrics

`GET /metrics` on the admin listener exposes Prometheus text format.
Labels are deliberately bounded — route ids, store/cluster/member names
from the config, exact status codes, and a `method` label that folds
non-standard methods into `OTHER` — never hosts, paths or headers.
Metric handles are resolved once per config object, so steady-state
emission is a few atomic ops rather than a registry lookup per request.

- `verd_requests_total{method,status,route}` — completed requests
  (client aborts count as `status="499"`)
- `verd_request_duration_seconds{route}` — fixed-bucket histogram
  (`le` series for `histogram_quantile`), plus
  `verd_response_bytes_total` / `verd_request_bytes_total` per route
- `verd_cache_requests_total{store,result}`, `verd_cache_bytes`,
  `verd_cache_items`
- `verd_upstream_requests_total{cluster,member,result}`,
  `verd_upstream_healthy`, `verd_upstream_inflight`,
  `verd_upstream_duration_seconds`
- `verd_active_connections`, `verd_connections_total`,
  `verd_connections_rejected_total`, `verd_active_requests`,
  `verd_tls_handshake_errors_total`
- `verd_tunnels_total`, `verd_tunnels_active`,
  `verd_tunnel_bytes_total{direction}` — upgraded WebSocket/CONNECT
  tunnels
- `verd_ratelimit_rejected_total`, `verd_acme_issuance_total`,
  `verd_cert_expiry_seconds`, `verd_config_reloads_total{result}`
- `verd_process_resident_bytes`, `verd_process_cpu_seconds_total`,
  `verd_process_open_fds`, `verd_process_threads`,
  `verd_uptime_seconds` (read from `/proc` every 5 s)
- `verd_build_info{version,commit}` — always `1`

## Probes

`GET /health` is always `200 ok` (process alive). `GET /ready` returns
`503` until the config is built and every listener is bound — wire it to
your load balancer's readiness check.
