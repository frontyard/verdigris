# Configuration

Verdigris reads a single TOML file. `verd validate` checks it and
dry-runs the full runtime build (read-only — nothing is created), so a
green result means `verd run` would actually start; `verd config`
prints the merged, interpolated effective configuration (secrets
redacted); `verd fmt` normalizes whitespace in place preserving
comments; `verd schema` prints the generated JSON Schema.

## Field forms

Every field accepts exactly one shape — a scalar (`workers = 4`), a
string list (`hosts = ["a", "b"]`), a table (`proxy = { upstream =
"x" }`), or a list of tables (`[[site.route]]`). On top of that, two
ergonomic conveniences apply broadly:

- **Scalar sugar** — most list fields also accept a single bare value:
  `ip_allow = "10.0.0.0/8"` means `["10.0.0.0/8"]`. `include` is the
  deliberate exception (always a list).
- **Shorthands** — fields with one dominant setting accept a short
  form that expands to the table with defaults:

  ```toml
  [server]
  listen = [":8080"]                        # all interfaces

  [cache.mem]

  [[site]]
  hosts = ["example.com"]

  [[site.route]]
  prefix = "/old"
  redirect = "https://new.example{path}"   # { to = "…", status = 308 }

  [[site.route]]
  prefix = "/ping"
  respond = "pong"                          # { status = 200, body = "pong" }

  [[site.route]]
  prefix = "/api"
  proxy = "http://app:9000"                 # { upstream = "…" }
  rate_limit = "100/s"                      # { rate = "100/s", key = "ip" }
  # rate_limit = { rate = "100/s" }         # same — `key` defaults to "ip"
  compress = true                           # default compression on

  [[site.route]]
  prefix = "/files"
  static = "/srv/www"                       # { root = "/srv/www" }
  cache = "mem"                             # { store = "mem" }

  [[site.route]]
  prefix = "/gone"
  respond = 410                             # { status = 410, body = "" }
  ```

  More one-liners in the same spirit: `retries = 3` (a
  `max_per_request` count), `unavailable = 503` (the no-healthy-member
  status), `health = "/hc"` on an upstream (an `active` probe),
  `log.access = "/var/log/x.log"` (just the output destination), and
  `host_header = { value = "…" }` (verbatim even when the value spells
  a keyword like `"upstream"`).

  Sites get the same catch-all treatment as `root`/`proxy`:
  `site.respond` and `site.redirect` materialize an implicit `/` route
  — a whole site becomes `redirect = "https://apex.example{path}"` for
  the www → apex case. At most one catch-all shorthand per site.

  The closed shorthand list and the cap — at most two shorthand forms
  beside the table — live in `docs/config-grammar.md`; the per-field
  types are in the [reference](./reference.md).

Network fields (`ip_allow`, `ip_deny`, `trusted_proxies`,
`rate_limit.exempt`) take CIDRs *or* bare IPs — `"10.0.0.1"` parses as
the host route `10.0.0.1/32`.

Disabled blocks: every inheritable middleware block understands
`enabled = false`, which opts a route out of a site-level (or global)
default — and all of them take the bare spelling too: `auth = false`,
`cors = false`, `rate_limit = false`, `response_headers = false`,
`security = false`, `cache = false`, `compress = false`,
`log.access = false`. `server_header = false` omits the `Server`
header (as does `""`). A bare `false` carries no settings and never
warns; stray keys inside a disabled *table* do.

## Durations

Every duration field is a quoted string in humantime form — `"30s"`,
`"5m"`, `"2h"`, `"180d"` (`ms`, `us`, `ns`, `w`, `M`, `y` work too).
Bare integers are rejected: write the unit explicitly (`hsts_max_age =
"180d"`, not `180`).

## Match conditions

A route's `[route.match]` table adds conditions beyond the path:
`methods`, `headers`, and `query` maps. Values match exactly, or as a
regular expression when prefixed with `re:`:

```toml
[[site.route]]
prefix = "/api"
[site.route.match]
methods = ["GET", "HEAD"]
headers = { "x-internal" = "" , "x-env" = "re:^prod-" }
query = { "debug" = "1" }
```

An empty-string value means *presence-only* — `"x-internal" = ""`
matches any request that carries the header (to match a literally
empty value, use `re:^$`). Conditions only *filter* a route; they
never change which route wins on path specificity.

## Placeholders

`redirect.to`/`host`/`scheme` and `respond.body` substitute request
attributes written `{name}`:

| Placeholder | Value |
| --- | --- |
| `{path}` | request path (leading `/`) |
| `{host}` | request Host (normalized, port stripped) |
| `{query}` | raw query string including the leading `?` — empty when absent |
| `{method}` | request method |
| `{scheme}` | `http` or `https` |

The set is closed — any other `{…}` text passes through literally
(and `verd validate` warns, since it's usually a typo). Redirect
templates re-encode `{path}` before it lands in `Location`, so
`redirect = "https://new.example{path}"` is safe to copy-paste.

## Diagnostics

`verd validate` reports errors and warnings with the field path and
the file that set it (`site["name"].route[0]`, `upstream.api.servers[1]`).
Errors mean *will not work*; warnings mean *works, but probably not
what you meant* — dead config inside a disabled block, a catch-all
CIDR, a hostname-shaped redirect target. `--strict` promotes warnings
to failures for CI. `--format json` emits the same report as one
object; the shape is documented under [Command line](./cli.md).

## Includes

Split large configs across files:

```toml
include = ["conf.d", "extra-*.toml"]
```

``include` accepts files, directories (`*.toml` directly inside,
sorted), and glob patterns (`*` matches any characters in the file
name), and its entries interpolate like any other string —
`include = ["${VERD_EXTRA}"]` is valid. A named file or directory
that doesn't exist is an error; a
glob that matches nothing is silently ignored, so `conf.d/*.toml` can
be populated later. Tables merge recursively — `[[site]]` entries append,
`[upstream.*]` and `[cache.*]` tables merge by name — and **arrays
concatenate** rather than conflict. Scalars set to different values in
different fragments are an error. A file reachable through two include
paths (a "diamond") merges only once; an actual include cycle is an
error. Paths are always resolved relative to the file that writes the
`include` line.

## Paths

Filesystem paths in config are relative to **the directory of the file
that contains them** — never the process working directory. That holds
for `site.root`, `route.static.root`, `tls.cert`/`key`,
`auth.basic.htpasswd`, `cache.*.disk_path`, `acme.storage`,
`upstream.*.tls.ca`, and the log outputs, and each `include`d fragment
anchors to its own directory, so a config tree moves as a unit.
Absolute paths are untouched either way.

Two fields are exceptions by design: `static.error_pages` and
`static.try_files` name files *inside* `root`, so they stay
root-relative.

> **Breaking change:** these fields used to resolve against the
> process working directory. If you relied on that, prefix the
> affected values with the config directory (or make them absolute).

## Secrets and environment interpolation

Secrets never live in the file itself:

```toml
[admin]
token = "${ADMIN_TOKEN}"        # from the environment
# token = "${file:/run/secrets/admin-token}"   # or a file
```

`${VAR}` errors when unset; `${VAR:-default}` supplies a default, as
does `${file:/path:-default}` when the file is unreadable. Relative
`${file:}` paths resolve against the directory of the file that
contains the reference — the same anchor `include` uses — so a config
tree can be moved as a unit. A literal `${` is written `$${`. `verd
validate` resolves them, so CI can catch missing secrets.

## Top-level layout

| Section | Contents |
| --- | --- |
| `[server]` | listeners, limits, timeouts, connection caps, trusted proxies |
| `[admin]` | admin listener (`enabled` to disable), bearer token, optional TLS |
| `[log]` | server log + access log (format/output/filter/sample) |
| `[[site]]` | virtual hosts: hostnames, TLS mode, routes, trusted proxies |
| `[upstream.*]` | named upstream clusters for proxy routes |
| `[cache.*]` | named cache stores (RAM/disk/hybrid) for routes |
| `[acme]` | ACME account + certificate storage |

The full field-by-field listing is in the
[configuration reference](./reference.md).

## Editor integration

`verd schema` prints the JSON Schema for the config format. Point a
TOML language server (taplo, Even Better TOML) at it for completion,
hover docs, and inline diagnostics — save the schema next to the config
and reference it from the first line:

```sh
verd schema -o verd.schema.json
```

```toml
#:schema ./verd.schema.json
```

A schema generated from the installed binary always matches the
version in use.
