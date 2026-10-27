# TLS, ACME & redirects

## Manual certificates

```toml
[server]
listen = [{ addr = "0.0.0.0:443", tls = true }]

[[site]]
hosts = ["example.com"]
tls = { cert = "/etc/verd/example.pem", key = "/etc/verd/example.key" }
```

SNI picks the right certificate per host; a `default` certificate covers
clients without SNI. Cert files are watched and **hot-reloaded** — rotate
the file and new handshakes use it, no restart.

## Self-signed (dev)

```toml
tls = "selfsigned"   # generates a throwaway cert per host at boot
```

## ACME — automatic certificates

```toml
[acme]
email = "ops@example.com"
directory = "https://acme-v02.api.letsencrypt.org/directory"
storage = "/var/lib/verd/acme"

[[site]]
hosts = ["example.com", "www.example.com"]
tls = "auto"
```

- Challenges: **http-01** (served on `/.well-known/acme-challenge/` over
  any plaintext listener), **tls-alpn-01** (answered during the TLS
  handshake on 443 — works when port 80 is blocked), and **dns-01**
  (TXT records published via a DNS provider API — required for
  wildcards, works with no ACME-reachable ports at all).
  `acme.challenge` picks the preference.
- Renewal runs automatically (lead time capped at a third of the
  certificate's lifetime) with retry backoff on failure.
- `[acme.on_demand]` (`enabled`, `allowed_hosts`, `rate`) issues certificates lazily
  on first handshake for allowlisted names, rate-limited to bound abuse.

### dns-01 (wildcard certificates, no public ports)

```toml
[acme]
challenge = "dns-01"

[acme.dns.cloudflare]
api_token = "${env:CF_API_TOKEN}"   # Zone.DNS:Edit + Zone.Zone:Read
# zone_id = "..."                   # optional — pins one zone
# resolver = "1.1.1.1"              # optional propagation-check NS
# propagation_timeout = "2m"

[[site]]
hosts = ["example.com", "*.example.com"]
tls = "auto"
```

verd creates `_acme-challenge.<host>` TXT records via the provider API,
waits for them to appear in public DNS, then tells the CA to validate
and deletes the records afterwards. Zones are discovered automatically
by walking up each hostname's labels (`zone_id` pins one instead), so
sites spanning multiple Cloudflare zones just work. The token supports
`${env:}`/`${file:}` interpolation like every other config string —
prefer it over a literal so the config file stays non-sensitive.

## HTTP→HTTPS and security headers

`site.redirect_https` (default on) answers plaintext requests with a
permanent redirect once a certificate exists for the host;
`site.redirect_host` overrides the target host. Security headers
(HSTS, CSP, X-Frame-Options, …) are set globally under
`[server.security]` and refined per route under
`route.security` — HSTS is only emitted over TLS.
