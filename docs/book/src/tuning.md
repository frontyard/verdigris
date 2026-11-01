# Tuning

## Limits

```toml
[limits]
header_bytes = "32KiB"        # total request header size
body_bytes = "10MiB"          # per-route override: route.limits.body_bytes

[server]
max_connections = 100000
max_connections_per_ip = 1000
```

## Timeouts

```toml
[timeouts]
header_read = "10s"    # until the first request's headers arrive
idle = "60s"           # keep-alive between requests
body_read = "30s"
send = "60s"           # write inactivity; also bounds silent tunnels
tls_handshake = "10s"
request_deadline = "0" # whole-request cap, per route; 0 = none
```

## Practical notes

- Bodies stream — `body_bytes` caps size without buffering.
- Keep-alive and h2 multiplexing are on by default; no tuning needed for
  typical workloads.
- For high-concurrency proxies raise `upstream.max_connections` (per
  member semaphore) and `nofile` (see the systemd unit).
- RAM cache tiers are fastest; `hybrid` trades a small hit latency for
  surviving restarts. Size `ram_bytes` to your hot set.
- Rate-limit buckets are per key; `key = "identity"` with auth avoids
  NAT'd-IP collateral.
