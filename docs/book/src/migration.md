# Migrating from nginx / Caddy

| nginx | verd.toml |
| --- | --- |
| `server { listen 443 ssl; }` | `server.listen = [{ addr = "0.0.0.0:443", tls = true }]` |
| `server_name example.com` | `hosts = ["example.com"]` on `[[site]]` |
| `location / { root … }` | `[[site.route]] path="/" static={root="…"}` |
| `proxy_pass http://app` | `proxy = "http://app"` or `{ upstream = "app" }` |
| `upstream { least_conn; }` | `[upstream.app] lb="least_conn"` |
| `limit_req_zone` | `route.rate_limit` |
| `add_header X-…` | `route.response_headers = { set = { … } }` |
| `access_log /var/log/x` | `[log.access] output = "/var/log/x"` |
| `ssl_certificate(…)` | `site.tls = { cert="…", key="…" }` |

| Caddy | verd.toml |
| --- | --- |
| `example.com { file_server }` | `hosts=["example.com"] tls="auto"` + static route |
| `reverse_proxy app:9000` | `proxy = "http://app:9000"` |
| automatic HTTPS | `tls = "auto"` + `[acme]` account block |
| `basic_auth` | `route.auth = { basic = { users = { name="hash" } } }` |

Wildcard hosts (`*.example.com`), regex routes, per-site trusted proxies,
and multi-site host routing match nginx semantics — the config reference
covers each knob.
