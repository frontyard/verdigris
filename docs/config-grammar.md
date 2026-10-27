# Config grammar — the invariants `verd.toml` fields live by

`reference.md` documents every field's accepted type. This document is
the layer above it: the small, closed set of *forms* a field may take
and the policies that decide when a shorthand, a scalar, or an
off-switch is allowed. It exists so a config review scores against a
rubric instead of re-deriving the rules from neighboring fields.

**The grammar is frozen.** A new field must fit an existing form; a new
form requires amending this document in the same change that introduces
it. When a field deviates on purpose, the exception is written here —
"deliberate" is the only unlisted status allowed.

Field-level docs still live in `src/config/model.rs` doc comments (→
schema → `reference.md`); this doc is for people *changing* the model.

## Field shapes

Every field is exactly one of:

| Form | TOML | Use for |
| --- | --- | --- |
| scalar | `workers = 4`, `key = "identity"`, `on = true` | single values |
| string-list | `hosts = ["a", "b"]` | open-ended string sets |
| table | `proxy = { upstream = "x" }` | structured settings |
| list-of-tables | `[[site.route]]` | repeated structured items |
| shorthand | see below | the common one-field case |

A *shorthand* is an untagged form that deserializes to the same value as
the full form with defaults filling the rest. Shorthands exist only
where one field dominates the table — they are a closed set:

| Field | Accepted forms | Expands to |
| --- | --- | --- |
| `server.listen` | `"ip:port"` \| `{ addr, tls }` | `ListenAddr` |
| `site.proxy` | name \| URL \| `[urls]` | `UpstreamRef` |
| `route.proxy` | `upstream` shapes \| table | `ProxyHandler{upstream,…}` |
| `route.proxy.upstream` | name \| URL \| `[urls]` | `UpstreamRef` |
| `route.cache` | `"store"` \| table | `RouteCache{store,…}` |
| `route.compress` | `true`/`false` \| table | `CompressConfig`/`None` |
| `rewrite.replace_prefix` | `{ from, to }` | `PrefixPair` (map only) |
| `site.tls` | `"off"∣"auto"∣"self_signed"` \| `{cert,key}` | `SiteTls` |

Every shorthand has an `*Schema`/`repr` untagged wrapper for schemars
and a `deserialize_with` adapter — the `opt_route_cache`/`opt_compress`
pattern. No fourth spelling per field, ever: two forms is the cap.

**Parity.** Where site-level and route-level fields share semantics,
the route accepts at least the site shorthand: `route.proxy` accepts
every `site.proxy`/`upstream` shape; `route.cache`/`route.compress`
accept their terse forms.

## Scalar-vs-list

Simple string/scalar lists accept a single value as `["v"]` via the
`values::one_or_many` adapter: `hosts`, `listen`, `upstream.servers`,
`ip_allow`, `ip_deny`, `match.methods`, `auth.*` token/key lists,
`acme.on_demand.allowed_hosts`, `cache` bypass lists,
`trusted_proxies`, `vary_headers`.

Exceptions (deliberate, strict):

- `include` — merge order is semantically load-bearing, and
  "must be a list of path strings" is a better teaching error than
  silently treating one path as a set.
- `error_pages`/`cache_control` and other keyed maps — not lists.

## Off-switches

Every optional subsystem exposes `enabled = false` or is documented
here why not: `log.access.enabled`, `acme.on_demand.enabled`,
`admin.enabled`, `route.compress` (`false` also removes a table).

`server.listen` has no `enabled` — an empty list already means "no
sockets" and the validator requires at least one listener anyway.
Per-route middleware needs no switch — `Option<Table>` presence *is*
the switch.

## Diagnostics

- Load errors name the file (fragment, not just the main file), the
  field path (`site.0.route.2`), and file:line when the failure isn't
  an interpolation artifact.
- Unknown-field errors append `did you mean \`x\`?` from the expected
  set when a close spelling exists.
- `verd validate` diagnostics always carry a config path; errors are
  fatal, warnings never are (`--strict` promotes warnings for CI).
- Semantic rules prefer *errors* for "will not work" and *warnings*
  for "works but almost certainly not what you meant".

## Secrets

No secret material inline by design: `token`, `key`, `password`,
`*_tokens`, `Authorization`-style header values take `${VAR}`/
`${file:}`; `verd config`/admin `/config` redact by *path* (path-aware
`secret_at`), never by substring match.

## Auditing

The checklist is the items above, in order. The mechanical half lives
in `src/config` tests (`surface_audit`): a table-driven test asserts
each invariant behaviorally — every shorthand form parses, each
approved list accepts a scalar, `include` rejects one, `enabled`
fields disable their subsystem. When this doc gains an invariant, the
test gains a row; the audit is the diff between the doc's table and
the test's.
