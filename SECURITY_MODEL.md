# Security model

This document describes who and what verdigris defends against. It is the
threat model security reviews and code scans start from. To report a
vulnerability, see [SECURITY.md](SECURITY.md).

Verdigris is open-source software that operators self-host, usually in
Docker. This model describes a typical operator deployment.

## Trust boundaries

1. **Internet client → listener**: TLS termination, HTTP/1.1, HTTP/2 and h2c
   parsing, routing, auth, IP ACLs and rate limiting. All input here is
   untrusted.
2. **Proxy → upstream**: upstream responses (headers, bodies, `Vary`,
   `Cache-Control`, `Set-Cookie`, `Location`) are semi-trusted. A malicious
   or compromised upstream is in scope.
3. **Admin listener** (`admin.listen`, default `127.0.0.1:2019`): reload,
   purge, drain/undrain, config and upstream inspection. If no
   `admin.token` is set, only loopback requests are accepted. A token is
   mandatory off-loopback.
4. **Process → local filesystem**: cache store (`src/cache/disk.rs`), ACME
   state (`acme.storage`, default `./verd-state/acme`, directories forced
   to `0700` by `src/fsperm.rs`) and TLS keys.
5. **Outbound to the ACME CA and DNS provider APIs** (`src/acme/dns.rs`),
   which carry account, EAB and DNS-provider credentials.

The operator and the configuration file (`verd.toml`, including `${VAR}`
and `${file:...}` interpolation) are trusted. Config-dependent issues are
still in scope where a plausible config (an empty secret, an unset
variable) silently weakens a security control.

## Components

| Component | Code |
|---|---|
| Server | `src/server/`, `src/router/`, `src/body.rs`: connections, HTTP parsing, timeouts, routing, path normalization |
| Proxy | `src/proxy/`: forwarding, `headers.rs` (`Forwarded`/`X-Forwarded-*`, hop-by-hop), load balancing, health checks, upgrades |
| Middleware | `src/middleware/` (auth, CORS, rate limiting, compression), `src/handler/` (static files, redirects, respond) |
| Cache | `src/cache/`: keying, HTTP semantics, RAM/disk store, tee |
| TLS & ACME | `src/tls/`, `src/acme/`: cert resolution, on-demand TLS, challenges, account and key storage |
| Admin & Config | `src/admin/`, `src/config/`, `src/cli.rs`, `src/observe/`, `src/fsperm.rs` |

Supporting code (`bench/`, `fuzz/`, `demo/`, `tests/`, `.github/workflows/`)
is in scope too.

## Entry points

- Data-plane listeners: every method, header, HTTP/2 frame, WebSocket
  upgrade, `Range` and conditional request.
- TLS handshake: SNI drives on-demand ACME issuance, gated by
  `acme.on_demand.allowed_hosts` and a rate floor of 5/hour.
- ACME HTTP-01 and TLS-ALPN-01 challenge responders.
- Admin API: `/health`, `/ready`, `/metrics`, `/version`, `/config`,
  `/upstreams`, `/reload`, `/purge`,
  `/upstreams/{cluster}/{member}/drain|undrain`.
- Upstream responses fed into the proxy and the cache.
- On-disk state loaded at startup: cache index and ACME storage.

## Assets

All of these are critical:

- **Cache integrity**: no poisoning, and no response belonging to one user
  served to another (`Authorization`, `Set-Cookie`, `Vary`, key collisions,
  request-target normalization).
- **TLS private keys and ACME account credentials**, including DNS-provider
  and EAB secrets.
- **Auth and ACL enforcement** on protected routes (basic, bearer, API key,
  IP ACLs, CORS).
- **Request integrity toward upstreams**: smuggling, desync, header
  injection, `Forwarded`/`X-Forwarded-*` spoofing.
- **Availability** of the proxy.
- The admin token, config secrets and access logs (which may contain
  credentials or personal data).

## Attackers

All of these are in scope:

- Unauthenticated internet clients on the data plane.
- Authenticated clients trying to escalate or bypass route auth and ACLs.
- Malicious or compromised upstream servers.
- Anyone on the network who can reach the admin listener.
- Local users on the same host (cache, ACME and TLS files on disk).

## Existing controls

- Admin listener: requires a token off-loopback, and refuses non-loopback
  requests when no token is set (`src/admin/mod.rs`).
- Cache keys use the raw request target and keep the port, and `%1F` is
  never decoded into the key separator (`src/cache/key.rs`).
- Incoming `Forwarded`/`X-Forwarded-*` values are only trusted from
  trusted peers (`src/proxy/headers.rs`).
- On-demand TLS: host allowlist plus rate limit (`src/acme/mod.rs`).
- ACME state directories are forced to `0700` (`src/fsperm.rs`).
- CI: CodeQL, ClusterFuzzLite, `cargo deny`, gitleaks, mutation testing,
  OpenSSF Scorecard.

## Out of scope

Nothing is ruled out. Denial of service, config-dependent weaknesses,
admin-reachable issues and supporting code are all in scope.
