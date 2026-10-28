# Admin API & lifecycle

The admin listener (`admin.listen`, default `127.0.0.1:2019`) is a
separate HTTP service from the data plane.

```toml
[admin]
listen = "127.0.0.1:2019"    # ":2019" binds all interfaces
# listen = ["127.0.0.1:2019", "127.0.0.1:2020"]   # or several —
                               # one admin API served on each address
token = "${ADMIN_TOKEN}"     # mandatory when listen is not loopback
tls = { cert = "admin.pem", key = "admin.key" }   # optional
# tls = "self_signed"        # or a generated localhost cert for dev
```

`admin = false` disables the listener entirely (the table's
`enabled = false` says the same thing); leftover `[admin]` fields are
reported as dead config.

| Endpoint | Description |
| --- | --- |
| `GET /health` | liveness |
| `GET /ready` | readiness (bind to your LB health check) |
| `GET /metrics` | Prometheus exposition |
| `GET /version` | version + commit |
| `GET /config` | the live config; secret values rendered `***` |
| `GET /upstreams` | per-cluster member health, drain, in-flight |
| `POST /reload` | re-read the config file, swap generations |
| `POST /purge` | `{store?, key? \| prefix? \| all:true}` cache purge |
| `POST /upstreams/{cluster}/{member}/drain` | remove member from rotation |
| `POST /upstreams/{cluster}/{member}/undrain` | restore member |

`{member}` is a member index or URL authority.

## Trust model

`token` is the only real authenticator. When it is set, every request
needs the bearer. When it is unset — allowed only because validation
*requires* `token` for any non-loopback `listen` — the gate is
header-based: `Host` must name a loopback interface (defeats DNS
rebinding through a browser), and mutating methods reject the
`Origin`/`Sec-Fetch-Site` markers a cross-origin page cannot
suppress. These checks stop **browsers**; they stop nothing else.

**Any local process can manage a tokenless listener.** Loopback is
shared by every uid on the machine, and a non-browser client simply
sends `Host: localhost` itself — `/reload`, `/purge`,
`/upstreams/.../drain` and read access to `/config` are all open to
it. If the host runs other software or other users, set `token`, or
wall the port off from other uids (netfilter `owner` match, a
dedicated network namespace, socket activation). A unix-domain
socket form — where filesystem permissions make the listener
owner-uid-only by construction — is planned; the design is recorded
in `docs/ROADMAP.md`.

`/version` reports `{"version":"x.y.z","commit":<sha-or-null>}` —
`version` is the crate version baked at compile time, `commit` is the
git SHA when the build sets `VERD_GIT_SHA` (release binaries do;
locally `null` otherwise). `verd version` prints the same fields.

## Reload semantics

SIGHUP, `POST /reload`, or `--watch` file changes all take the same path:

1. Re-read and validate the config. Errors keep the old generation —
   traffic is never interrupted.
2. Build a new runtime, reusing unchanged cache stores (RAM contents and
   disk indexes survive reloads).
3. Swap the runtime atomically; sockets that still match the listener set
   keep accepting against the new config, removed sockets drain, added
   sockets bind. Any bind failure aborts the whole reload.
4. In-flight requests finish on the old generation; new connections get
   the new one immediately.

The admin listener itself (address + TLS pair) is boot-fixed; the bearer
token rotates with the config.
