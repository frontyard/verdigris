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
| `server.listen` | `"ip:port"`/`":port"` \| `{ addr, tls }` | `ListenAddr` |
| `site.proxy` | `upstream` shapes \| table | `ProxyHandler{upstream,…}` |
| `route.proxy` | `upstream` shapes \| table | `ProxyHandler{upstream,…}` |
| `route.proxy.upstream` | name \| URL \| `[urls]` | `UpstreamRef` |
| `route.static` | `"root"` \| table | `StaticHandler{root,…}` |
| `route.redirect` | `"url"` \| table | `RedirectHandler{to,…}` |
| `route.respond` | `"text"` \| table | `RespondHandler{body,…}` |
| `route.rate_limit` | `"100/s"` \| table | `RateLimitConfig{key:"ip",…}` |
| `route.cache` | `false` \| `"store"` \| table | `RouteCache{store,…}` |
| `route.compress` | `true`/`false` \| table | `CompressConfig` |
| `site.security`/`route.security` | `false` \| table | `RouteSecurity{enabled,…}` |
| `proxy.retries` | `false`/`true` \| table | `RetryPolicy` |
| `upstream.dns` | `"60s"` \| table | `UpstreamDns{grace}` |
| `upstream.health.active` | `"/path"` \| table | `ActiveHealth{path,…}` |
| `upstream.health.passive` | `5` \| table | `PassiveHealth{failures,…}` |
| `upstream.servers` entry | `"url"` \| `{url,weight,backup}` | `UpstreamServer` |
| `rewrite.replace_prefix` | `{ from, to }` | `PrefixPair` (map only) |
| `site.tls` | `"off"∣"auto"∣"self_signed"` \| `{cert,key}` | `SiteTls` |
| `log.access` | `false` \| table | `AccessLog{enabled,…}` |
| `acme.directory` | `"letsencrypt"`/`"letsencrypt-staging"` \| URL | resolved URL |

Every shorthand has an `*Schema`/`repr` untagged wrapper for schemars
and a `deserialize_with` adapter — the `opt_route_cache`/`opt_compress`
pattern. No fourth spelling per field, ever: two forms is the cap.
`server.listen`'s `":port"` spelling is an address-level nicety inside
the string form, not a third form; `acme.directory` aliases resolve to
their URL at load (one canonical value, no second shape).

**Parity.** Where site-level and route-level fields share semantics,
each accepts the same forms: `site.proxy` accepts every `route.proxy`
shape including the full `{ upstream, … }` table (the implicit
catch-all route carries the whole handler); the site-level middleware
defaults (`site.auth`, `site.cors`, `site.rate_limit`, `site.cache`,
`site.compress`, `site.response_headers`) accept exactly the route
forms — `site.rate_limit = "100/s"` works just like the route's.

## Scalar-vs-list

Simple string/scalar lists accept a single value as `["v"]` via the
`values::one_or_many` adapter: `hosts`, `listen`, `upstream.servers`
(a URL counts as one entry), `ip_allow`, `ip_deny`, `match.methods`,
`auth.*` token/key lists, `acme.on_demand.allowed_hosts`, all
`cache.bypass` lists (`methods`, `cookies`, `headers`, `paths`),
`static.index`, `static.try_files`, `*.remove` header lists
(`response_headers.remove`, `proxy.request_headers.remove`),
`trusted_proxies`, `vary_headers`.

Network fields additionally accept **bare IPs** — `"10.0.0.1"` parses
as the host route `10.0.0.1/32` (`::1` as `/128`). This covers
`ip_allow`, `ip_deny`, `trusted_proxies`, and `rate_limit.exempt`; a
`/prefix` remains valid everywhere.

Exceptions (deliberate, strict):

- `include` — merge order is semantically load-bearing, and
  "must be a list of path strings" is a better teaching error than
  silently treating one path as a set.
- `error_pages`/`cache_control` and other keyed maps — not lists.

## Off-switches

Every optional subsystem exposes `enabled = false` or is documented
here why not: `log.access` (`false` or `{ enabled = false }`),
`acme.on_demand.enabled`, `admin.enabled`, `proxy.retries`
(`false` ⇒ `max_per_request = 0`), `route.compress`/`route.cache`
(`false` ⇒ disabled table).

Route middleware blocks (`auth`, `cors`, `rate_limit`, `cache`,
`compress`, `response_headers`) carry `enabled = true` by default;
`enabled = false` is the opt-out that suppresses an inherited
site-level default. `site.security`/`route.security` take the bare
`false` spelling as well as `{ enabled = false }`. Settings left
inside a disabled block are dead config and `verd validate` warns.

`server.listen` has no `enabled` — an empty list already means "no
sockets" and the validator requires at least one listener anyway.

## Site-level defaults

A site may carry the same middleware blocks as a route — `auth`,
`cors`, `rate_limit`, `cache`, `compress`, `response_headers`,
`ip_allow`, `ip_deny`, `timeouts`, `limits`, `security` — and every
route inherits them, including the implicit `site.root`/`site.proxy`
catch-alls. Resolution:

- A route's own block wins whole-block (no field merge) — except
  `response_headers`, whose `set`/`add` maps union with route keys
  winning and whose `remove` concatenates, and `security`, which
  merges field-wise global → site → route.
- `enabled = false` at route scope opts out of the inherited block.
- A site `rate_limit` builds **one shared limiter** — every route that
  inherits it draws from the same buckets. A route's own `rate_limit`
  always gets a fresh limiter.
- ACLs tighten only: `ip_deny` unions site+route; both non-empty
  `ip_allow` lists must admit the client. A route can never widen a
  site ACL.

## Path anchoring

Filesystem paths in config are relative to **the file that contains
them** — the main file or an `include`d fragment — so a config tree
moves as a unit. This covers `site.*.root`, `route.*.static.root`,
`*.tls.cert`/`key`, `auth.basic.htpasswd`, `cache.*.disk_path`,
`acme.storage`/`ca_roots`, `upstream.*.tls.ca`, `log.output`,
`log.access.output`.

Deliberately *not* rebased: `static.error_pages` and
`static.try_files` — they name paths inside `root`, not on the
filesystem.

## Placeholders

`redirect.to`/`host`/`scheme` and `respond.body` share one closed set:
`{path}`, `{host}`, `{query}`, `{method}`, `{scheme}`. No others;
unknown `{...}` text passes through literally.

## Diagnostics

- Load errors name the file (fragment, not just the main file), the
  field path (`site[0].route[2]`), and file:line when the failure isn't
  an interpolation artifact.
- Semantic diagnostics carry the same fragment provenance — a bad
  field in `tls.toml` says `tls.toml`, not `verd.toml`.
- Site diagnostics label `site["name-or-first-host"]` — `site.name`
  is preferred, then the first host, then the index.
- Unknown-field *and* unknown-variant errors append `did you mean
  \`x\`?` from the expected set when a close spelling exists.
- `verd validate` diagnostics always carry a config path; errors are
  fatal, warnings never are (`--strict` promotes warnings for CI).
- Semantic rules prefer *errors* for "will not work" and *warnings*
  for "works but almost certainly not what you meant".
- Enum spellings are snake_case canonical with kebab-case aliases —
  `dns_01` and `dns-01` both parse; docs and errors show the snake
  form.

## Secrets

No secret material inline by design: `token`, `key`, `password`,
`*_tokens`, `Authorization`-style header values take `${VAR}`/
`${file:}`; `verd config`/admin `/config` redact by *path* (path-aware
`secret_at`), never by substring match.

The permission check runs per file: any fragment containing an inline
secret (not a `${file:}` reference) must be owner-only (`0600`-ish),
and every `${file:}` target is checked — a world-readable secret file
warns on the field that references it.

## Load balancing

`upstream.*.servers` entries are `"url"` or `{ url, weight, backup }`.
All three algorithms are weight-aware: `round_robin` uses smooth
weighted round-robin, `least_conn` compares `inflight / weight`, and
`ip_hash` places the client hash on a weight-proportional ring.
`backup = true` members serve only when no primary is healthy; the
`tried`-member retry exclusion applies within each tier.

## Auditing

The checklist is the items above, in order. The mechanical half lives
in `src/config` tests (`surface_audit`): a table-driven test asserts
each invariant behaviorally — every shorthand form parses, each
approved list accepts a scalar, `include` rejects one, `enabled`
fields disable their subsystem. When this doc gains an invariant, the
test gains a row; the audit is the diff between the doc's table and
the test's.
