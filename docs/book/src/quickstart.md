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

## Try the admin API

Loopback is the default and needs no extra config — every request must
just carry a loopback `Host` (curl does this automatically):

```sh
curl http://127.0.0.1:2019/health        # → ok
curl http://127.0.0.1:2019/ready         # → ready (503 until fully up)
curl http://127.0.0.1:2019/version       # → {"version":"0.2.2","commit":...}
curl http://127.0.0.1:2019/upstreams     # → {"clusters":[...]}
curl http://127.0.0.1:2019/config        # live config, secrets shown as ***
curl http://127.0.0.1:2019/metrics       # Prometheus exposition
```

Set a token to protect it — **mandatory** if you bind beyond loopback:

```toml
[admin]
listen = "127.0.0.1:2019"      # or "0.0.0.0:2019" to reach it remotely
token = "${ADMIN_TOKEN}"  # interpolated from the environment
```

```sh
export ADMIN_TOKEN=change-me

# no token → 401
curl http://127.0.0.1:2019/health

# with token → ok
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:2019/health

# mutating endpoints work the same way
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:2019/reload
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:2019/purge -d '{"all": true}'
```

In Docker, `127.0.0.1` inside the container is the *container's*
loopback — `-p 2019:2019` can't reach it. Either bind the admin to
`0.0.0.0` with a token (and prefer `-p 127.0.0.1:2019:2019` so it stays
host-local), or query it with a shared-namespace helper:

```sh
docker run --rm --network container:<verd-container> \
  curlimages/curl -sS http://127.0.0.1:2019/health
```

See the [admin reference](admin.md) for the full endpoint list and
reload semantics.

Change the config and reload without dropping connections:

```sh
kill -HUP $(pidof verd)          # SIGHUP reload
verd run --watch                 # or auto-reload on file change
curl -X POST localhost:2019/reload  # or via the admin API
```
