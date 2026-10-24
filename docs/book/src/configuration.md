# Configuration

Verdigris reads a single TOML file. `verd validate` checks it without
starting; `verd fmt` formats it in place preserving comments;
`verd schema` prints the generated JSON Schema.

## Includes

Split large configs across files:

```toml
include = ["conf.d"]
```

`include` accepts files, directories (`*.toml` inside, sorted), and
globs. Sites merge, `[upstream.*]` and `[cache.*]` tables merge by name;
scalar sections must not conflict.

## Secrets and environment interpolation

Secrets never live in the file itself:

```toml
[admin]
token = "${ADMIN_TOKEN}"        # from the environment
# token = "${file:/run/secrets/admin-token}"   # or a file
```

`${VAR}` errors when unset; `${VAR:-default}` supplies a default.
`verd validate` resolves them, so CI can catch missing secrets.

## Top-level layout

| Section | Contents |
|---|---|
| `[server]` | listeners, limits, timeouts, connection caps, trusted proxies |
| `[admin]` | admin listener, bearer token, optional TLS |
| `[log]` | server log + access log (format/output/filter/sample) |
| `[[site]]` | virtual hosts: hostnames, TLS mode, routes, trusted proxies |
| `[upstream.*]` | named upstream clusters for proxy routes |
| `[cache.*]` | named cache stores (RAM/disk/hybrid) for routes |
| `[acme]` | ACME account + certificate storage |

The full field-by-field listing is in the
[configuration reference](./reference.md).
