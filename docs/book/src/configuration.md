# Configuration

Verdigris reads a single TOML file. `verd validate` checks it and
dry-runs the full runtime build (read-only — nothing is created), so a
green result means `verd run` would actually start; `verd config`
prints the merged, interpolated effective configuration (secrets
redacted); `verd fmt` normalizes whitespace in place preserving
comments; `verd schema` prints the generated JSON Schema.

## Durations

Every duration field is a quoted string in humantime form — `"30s"`,
`"5m"`, `"2h"`, `"180d"` (`ms`, `us`, `ns`, `w`, `M`, `y` work too).
Bare integers are rejected: write the unit explicitly (`hsts_max_age =
"180d"`, not `180`).

## Includes

Split large configs across files:

```toml
include = ["conf.d", "extra-*.toml"]
```

`include` accepts files, directories (`*.toml` directly inside,
sorted), and glob patterns (`*` matches any characters in the file
name). A named file or directory that doesn't exist is an error; a
glob that matches nothing is silently ignored, so `conf.d/*.toml` can
be populated later. Tables merge recursively — `[[site]]` entries append,
`[upstream.*]` and `[cache.*]` tables merge by name — and **arrays
concatenate** rather than conflict. Scalars set to different values in
different fragments are an error. A file reachable through two include
paths (a "diamond") merges only once; an actual include cycle is an
error. Paths are always resolved relative to the file that writes the
`include` line.

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
| `[admin]` | admin listener, bearer token, optional TLS |
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
