# Quickstart

Create `verd.toml`:

```toml
[[server.listen]]
addr = "0.0.0.0:8080"

[[site]]
default = true
tls = "off"

[[site.route]]
path = "/"
static = { root = "/var/www/site" }
```

Run it:

```sh
verd run                    # looks for ./verd.toml, then /etc/verd/
verd run -c ./verd.toml  # explicit path
verd validate               # check the config without serving
```

The admin listener comes up on `127.0.0.1:2019` — `/health`, `/ready`,
`/metrics` (Prometheus), `/version` are available immediately.

Change the config and reload without dropping connections:

```sh
kill -HUP $(pidof verd)          # SIGHUP reload
verd run --watch                 # or auto-reload on file change
curl -X POST localhost:2019/reload  # or via the admin API
```
