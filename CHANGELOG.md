# Changelog

All notable changes to verd are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

How releases work: changes accumulate under the `[Unreleased]`
section. At release time the Bump workflow promotes it to
`## [x.y.z] - YYYY-MM-DD`, bumps `Cargo.toml`, and the release
workflow publishes the matching section as the GitHub release notes.

## [Unreleased]

### Added

- **Admin trust model documented** — `docs/book/src/admin.md` now
  spells out what a tokenless loopback admin listener does and does
  not protect against (any local uid can manage it; the browser
  checks only stop browsers), and `docs/ROADMAP.md` records the
  planned unix-domain socket design that closes the gap.

- **`dns-01` ACME challenge via Cloudflare** — `acme.challenge =
  "dns-01"` with `[acme.dns.cloudflare]` (`api_token`, optional
  `zone_id`, `resolver`, `propagation_timeout`) publishes
  `_acme-challenge` TXT records through the Cloudflare API, waits for
  public DNS propagation, and retracts them after validation. This
  enables wildcard certificates (`hosts = ["*.example.com"]`) and
  issuance on hosts with no ACME-reachable ports at all.
- **Route shorthand values** — `route.cache` accepts a bare store name
  (`cache = "main"`), `route.compress` accepts `compress = true`,
  and `route.proxy` accepts an upstream name, URL, or URL list —
  `[[site.route]] proxy = "https://api.internal"` now expands to
  `{ upstream = "…" }`, matching `site.proxy`.
- **Dominant-field shorthands** — `route.match` accepts a method or
  method list (`match = "GET"` → `{ methods = […] }`), `compress`
  accepts an algorithm or list (`compress = "br"`,
  `compress = ["br","zstd"]` at site and route level), and `auth.bearer`
  /`auth.basic` accept a bare string (`bearer = "tok"` →
  `{ tokens = ["tok"] }`, `basic = "u.htpasswd"` →
  `{ htpasswd = "u.htpasswd" }`). All expand to the full table with
  defaults; `bearer = "tok"` counts as an inline secret for
  file-permission warnings and `basic = "…"` anchors relative to its
  document like `htpasswd` does.
- **`admin.enabled = false`** — disables the admin listener entirely
  (default `127.0.0.1:2019` previously had no off-switch); `token`/`tls`
  set under `enabled = false` produce dead-config warnings.
- **Scalar sugar for simple lists** — single-value string/CIDR lists
  (`hosts`, `server.listen`, `upstream.servers`, `ip_allow`/`ip_deny`,
  `match.methods`, `bearer.tokens`, `api_key.keys`, CORS lists, cache
  bypass lists, `algorithms`, `exempt`, …) accept a bare value as a
  one-element list, so `hosts = "example.com"` parses. `include`
  deliberately stays strict (`docs/config-grammar.md` records why).
- **Config grammar documented and enforced** —
  `docs/config-grammar.md` freezes the accepted field shapes, shorthand
  parity rules, scalar-vs-list policy, off-switches, and diagnostic
  conventions; `surface_audit` tests assert each invariant behaviorally.
- **`[log]` server logging is now wired** — `log.level`, `log.format`
  and `log.output` actually configure the server log (they were parsed
  and documented but never applied). Level resolves `--log-level` /
  `VERD_LOG` over the config value over `info`; `format` selects `json`
  or `pretty`; `output` accepts `stdout`, `stderr` or a file path that
  is reopened on `SIGUSR1` for logrotate.
- **`verd init`** — scaffolds a starter `verd.toml` (`-o PATH` chooses
  the destination, `-o -` prints to stdout, `--force` overwrites).
- **`verd validate --format json` and `--strict`** — a machine-readable
  diagnostics report (severity, config path, message, plus the resolved
  source-file list) for CI and editor integrations; `--strict` also
  fails on warnings.
- **`verd fmt --all`** — formats every file reachable through
  `include`, not just the top-level file.
- **Unknown-field errors suggest close spellings** — a typo like
  `host = "a"` now fails with `did you mean \`hosts\`?` appended,
  across every `deny_unknown_fields` table uniformly.
- **Site-level middleware defaults** — `auth`, `cors`, `rate_limit`,
  `cache`, `compress`, `response_headers`, `ip_allow`/`ip_deny`,
  `timeouts`, `limits`, and `security` can be set on `[[site]]` and are
  inherited by every route (including the implicit `site.root`/
  `site.proxy` catch-alls). A route's own block replaces the site
  block (`response_headers` unions, `security` merges field-wise),
  `enabled = false` opts a route out, a site `rate_limit` shares one
  limiter across all inheriting routes, and IP ACLs tighten only —
  denies union, allow-lists must both admit.
- **Weighted and backup upstream servers** — `upstream.*.servers`
  entries accept `{ url, weight, backup }` alongside bare URLs.
  `round_robin` becomes smooth weighted round-robin, `least_conn`
  compares `inflight / weight`, `ip_hash` hashes onto a
  weight-proportional ring, and `backup = true` members serve only
  while no primary is healthy.
- **Handler and middleware shorthands** — `route.static = "/srv/www"`,
  `redirect = "https://…{path}"`, `respond = "pong"`, and
  `rate_limit = "100/s"` (per-IP) expand to their table forms.
- **More off-switches and scalar sugar** — `proxy.retries = false`,
  `log.access = false`, route `cache = false`, `upstream.dns = "60s"`,
  `upstream.health.active = "/healthz"`, snake-case `acme.challenge`
  aliases (`dns_01`, `tls_alpn_01`, `http_01`), custom
  `host_header = "api.internal"` values, and bare scalars for
  `static.index`, `static.try_files`, `cache.bypass.cookies`/`paths`,
  and `*.remove` header lists.
- **Unified template placeholders** — `redirect` targets and
  `respond.body` share `{path}`, `{host}`, `{query}`, `{method}`,
  `{scheme}` (`{method}` is new on redirect, `{query}` on respond).
- **`site.proxy` full-table parity** — a site catch-all now accepts the
  whole `route.proxy` table (`{ upstream, rewrite, request_headers,
  retries, host_header }`), not just an upstream reference.
- **`security = false`** — bare off-switch for `site.security` and
  `route.security`, suppressing all inherited security headers.
- **Bare-IP network entries** — `ip_allow`/`ip_deny`,
  `trusted_proxies`, and `rate_limit.exempt` accept `"10.0.0.1"` as
  the host route `10.0.0.1/32` (`::1` as `/128`) — the `/prefix` is no
  longer mandatory.
- **`redirect` status 303** — post/redirect/get joins the accepted
  statuses (301/302/303/307/308).
- **`acme.directory` aliases** — `"letsencrypt"` and
  `"letsencrypt-staging"` resolve to their URLs at load.
- **`listen = ":port"`** — the wildcard spelling binds all interfaces;
  a bare `"8080"` still errors rather than guessing the host intent.
- **`upstream.*.health.passive = 5`** — a failure count expands to
  `{ failures = 5 }` with the default cooldown, matching the `active`
  shorthand.
- **Arbitrary rate periods** — `RateSpec` accepts humantime periods, so
  `rate_limit = "10/30s"` means ten permits per 30 seconds.
- **`verd config --format json`** — the same redacted dump the admin
  `/config` endpoint serves; `toml` stays the default.
- **`verd fmt --diff`** — prints a line-level diff of pending changes
  instead of only failing (implies `--check`).
- **`did you mean` for named references** — unknown `upstream` names
  and `cache.store` values suggest the closest defined name, or list
  the defined ones.
- **Bare `false` for the remaining middleware blocks** —
  `auth = false`, `cors = false`, `rate_limit = false`, and
  `response_headers = false` work at site and route scope (a bare
  `false` carries no settings and produces no dead-config warning);
  `server_header = false` omits the `Server` header.
- **`admin.listen = ":port"`** — the wildcard spelling matches
  `server.listen` entries; the non-loopback `admin.token` rule still
  applies.
- **`rate_limit` table `key` defaults to `"ip"`** —
  `rate_limit = { rate = "10/s" }` no longer errors for a missing key.
- **More scalar shorthands** — `retries = 3` (`max_per_request`),
  `respond = 404`, `upstream.*.unavailable = 503`,
  `log.access = "/path"` (the output destination), `upstream.*.health =
  "/path"` (an `active` probe), and `host_header = { value = "…" }`
  (sent verbatim even when the value spells a keyword like
  `"upstream"`).
- **`site.respond` / `site.redirect`** — catch-all respond/redirect
  shorthands accepting every `route.respond`/`route.redirect` shape;
  `root`, `proxy`, `respond`, `redirect` remain mutually exclusive.
  A whole site can now be `redirect = "https://apex.example{path}"`.
- **`admin.tls = "self_signed"`** — a generated localhost certificate
  for the admin listener (development convenience); `{ cert, key }`
  stays the production form.
- **`-c -` / `VERD_CONFIG=-`** — `run`, `validate`, `config`, and `fmt`
  read the root document from stdin; `include` and `${file:}` resolve
  against the current directory and sources report `<stdin>`. `verd
  fmt -c -` prints the formatted document to stdout instead of writing
  a file.
- **`admin.listen` accepts a list** — `listen = ["127.0.0.1:2019",
  ":2020"]` serves the admin API on every address (one `token`/`tls`
  applies to all). The canonical dump renders it as an array even for
  a single listener.
- **`proxy.request_headers = false`** — the bare off-switch now works
  on the proxy header block too, matching the other middleware fields.
- **`error_pages` class keys** — `"4xx"`/`"5xx"` map a page to a whole
  status class; an exact code (`404`) wins over its class.
- **Four new placeholders** — `{uri}` (path + query as sent), `{args}`
  (query without `?`), `{remote_ip}` (client IP under the route's
  trust model), and `{request_id}` substitute in `respond.body`,
  `redirect.to`, and — new this release — `upstream.*.unavailable.body`.
- **Top-level off-switches and upstream shorthand** —
  `server.security = false` and `admin = false` are the one-word forms
  of `[server.security] enabled = false` / `[admin] enabled = false`,
  matching the site/route middleware spellings; and
  `upstream.<name> = "http://a:9000"` (or a URL list / `{ url, weight,
  backup }` entry) names a cluster without a table — shorthand for
  `servers` under cluster defaults.

### Build & CI

- **Doc snippets gated on every PR** — `ci.yml`'s `generated docs in
  sync` job now runs `docs/check-snippets.py`; previously it only ran
  in `docs.yml` on `docs/**` changes, so a `src/config`-only PR could
  break book/README TOML snippets with no check firing.
- **CodSpeed perf tracking** — `codspeed.yml` benchmarks the
  per-request pipeline in simulation mode (`benches/hot_paths.rs`:
  normalization, host/route matching incl. condition-rejection climbs
  and regex fallback, client-IP resolution, upstream pick, cache key +
  RAM lookup, forwarded-header rewrite, response decoration, config
  parse as control), posting regression reports on every PR.
- **Doc drift guards** — `gen-llms-full.py` now fails when `llms.txt`'s
  index skips a `SUMMARY.md` page and rewrites book-relative links to
  repo paths; `release.sh` keeps the `installation.md` download URL in
  lockstep with the version bump; and a `surface_audit` test asserts
  the JSON schema never marks a defaulted field required.

### Changed

- **Duration values must be strings** — all duration fields (e.g.
  `hsts_max_age`, timeouts, cache TTLs) now only accept quoted
  humantime strings like `"180d"` or `"30s"`; bare integers are
  rejected. `verd config` prints them back in the compact canonical
  form (`"180d"`).
- **`verd validate` performs a full dry build** — routes, middleware,
  upstreams, TLS material, access-log filters and auth files are all
  compiled read-only, so a valid result means `verd run` would actually
  start. Previously upstream URLs with paths, bad header names,
  malformed password hashes and unreadable htpasswd files only failed
  at startup.
- **`--watch` follows the config's real sources** — it now tracks the
  config file and its parents (atomic renames and editor save-swap
  patterns fire), every `include` file, `include` dirs/globs so new
  `*.toml` fragments are picked up, `${file:…}` secret files, and k8s
  `..data` symlink swaps; the set is re-derived after each reload so
  added or removed includes take effect without a restart. Events that
  merely touch unrelated files in watched directories — including the
  server's own log output — no longer trigger a reload.
- **Exit codes unified** — config and runtime failures exit `1`
  (including missing config, which used to exit `2`); `2` is reserved
  for CLI usage errors.
- **Wildcard hosts match longest suffix first** — `*.b.example.com`
  wins over `*.example.com` regardless of declaration order.
- **`true` documented on `false`-gated blocks** — every block that
  accepts `false` also parses `true` (the table with defaults and
  `enabled = true`); the docs now say so explicitly rather than
  leaving it an accident of the parser.
- **Malformed password hashes rejected at startup** — `auth.basic`
  argon2/bcrypt values are fully parsed (not just prefix-sniffed), so
  truncated or corrupt hashes fail `verd validate`/`verd run` instead
  of failing closed at request time.
- **`max_connections = 0` is an error** — on `server` and
  `upstream.*` limits; previously an upstream cap of zero was silently
  clamped to one.
- **Secret redaction is path-aware** — `verd config` and the admin
  `/config` dump now scrub password hashes, tokens and URL userinfo by
  field position instead of substring, so `tls.key` file paths,
  `eab.key_id`, and unrelated keys like `monkey` stay readable while
  `users = { u = "$argon2id$…" }` no longer leaks.
- **Pre-0.4.0 field names removed** — the compatibility aliases
  `route.proxy.headers` (use `request_headers`), `route.headers` (use
  `response_headers`), and `upstream.*.limits` (use `timeouts`) no
  longer parse; configs using them now fail schema validation.
- **Config surface tidied** — `route.path` (was an alias for `prefix`),
  the `conditions` alias for `route.match`, and the `["/a","/b"]` tuple
  form of `rewrite.replace_prefix` (use `{ from, to }`) are gone.
  `upstream.*.timeouts.max_connections` moved to
  `upstream.*.max_connections` (it was never a timeout).
- **`proxy.pass_host` is now `proxy.host_header`** —
  `host_header = "upstream"` (default) keeps the previous `pass_host =
  true` behaviour; `host_header = "original"` passes the client's `Host`
  through. The old bool read backwards (`true` did *not* pass the host).
- **Canonical enum spellings tightened** — `tls` mode is now spelled
  `self_signed` (`self-signed` still parses; `selfsigned` doesn't), and
  squashed variants like `leastconn`, `roundrobin`, `iphash`, `http01`,
  `dns01`, `tls-alpn01` are rejected — use the canonical or kebab-case
  spelling shown in `verd schema` / the reference docs.
- **Upstream pick now reads the clock once** — `lb::pick` evaluates all
  members against a single `Instant` (one `clock_gettime` per selection
  instead of one per member) and judges them at a consistent instant.
- **Bare `{ tls = true }` listen tables bind `:443`** — previously they
  defaulted `addr` to `0.0.0.0:80`, terminating TLS on the plaintext
  port.
- **Relative `${file:…}` paths resolve against the config file's
  directory** — the same anchor `include` uses; previously they
  resolved against the process working directory.
- **Schema errors name the fragment and line** — an unknown key in an
  included file now reports e.g. `conf.d/site.toml: TOML parse error at
  line 3` instead of blaming the merged document, and errors include
  the full field path.
- **`compress.algorithms` takes canonical names only** — `br`, `zstd`,
  `gzip`; the `brotli`/`gz` spellings are now rejected.
- **`hosts` values must be hostnames** — entries containing a scheme,
  path, or `host:port` (pasted URLs) are errors, and duplicates are
  compared after port/case/trailing-dot normalization.
- **New warnings for likely misconfigurations** — `error_pages` keys
  outside 400–599, `rate_limit key = "identity"` on routes with no
  auth, and `tls = "auto"` on non-public names (IPs, `localhost`,
  `.internal`, …) or on a hostless site without on-demand issuance.
- **BREAKING: config paths anchor to their file** — `site.root`,
  `route.static` / `route.static.root`, `tls.cert`/`key`, `auth.basic.htpasswd`,
  `cache.*.disk_path`, `acme.storage`/`ca_roots`,
  `upstream.*.tls.ca`, and the log outputs now resolve relative to the
  directory of the file (or `include`d fragment) that contains them
  instead of the process working directory, so a config tree moves as
  a unit. `static.error_pages` and `static.try_files` stay
  root-relative by design — they name paths *inside* `root`.
- **Diagnostics name sites and fragments** — site errors label
  `site["name-or-first-host"]` (`site.name` preferred), and semantic
  errors from `include`d fragments report the fragment file rather
  than only `verd.toml`.
- **`did you mean` covers enum variants** — a near-miss like
  `challenge = "dns01"` suggests the accepted spellings the same way
  unknown fields do.
- **`Host` set via `request_headers` warns** —
  `proxy.request_headers.set`/`add` carrying `host` overrides
  `host_header`; the validator now says so instead of letting it win
  silently.
- **BREAKING: `match.headers = { "x-a" = "" }` is presence-only** —
  an empty value now matches "header present", matching `match.query`'s
  rule (previously it matched a literally-empty value). Use `re:^$` to
  match empty values.
- **BREAKING: duplicate `site.name` rejected** — two sites sharing a
  `name` is an error; metric `route` labels collided before.
- **BREAKING: `validate --format json` has one shape** — every outcome
  emits `{ valid, strict, diagnostics, sources }`, with `"error"`
  added on load/dry-build failures (previously each failure class had
  its own key set).
- **Stricter semantic validation** — `verd validate` now errors on
  values that silently produced wrong behavior: `redirect.host`/
  `site.redirect_host` values that can't be a `Location` authority,
  `redirect.to` containing whitespace, `replace_prefix` missing a
  leading `/`, invalid `security` header values (`frame_options`,
  `referrer_policy`, `csp`, `cross_domain_policy`), a
  `server.server_header` that isn't a valid header value,
  `upstream.*.tls.sni` that isn't a DNS name, `rate_limit
  key = "header:<name>"` with an invalid header name, malformed
  `cache.bypass` methods/headers, malformed CORS methods/headers and
  scheme-less `cors.origins` entries, `acme.on_demand.allowed_hosts`
  entries that can't be allowlisted, invalid `log.access.filter`
  expressions, and upstream URLs with paths/queries/userinfo (previously
  only the scheme was checked). Catch-all CIDRs (`0.0.0.0/0`, `::/0`)
  in `trusted_proxies`, `rate_limit.exempt`, `ip_allow`, and `ip_deny`
  warn loudly; `{typo}` placeholders in `redirect`/`respond` templates
  warn; `host_header` values within edit distance 2 of `upstream`/
  `original` warn; missing `upstream.*.tls.ca`, `acme.ca_roots`, and
  `cache.*.disk_path` parents warn.
- **Field paths normalized** — serde and schema errors render
  `site[0].route[2]` instead of `site.0.route.2`, matching the
  `site["name"]` label style used by semantic diagnostics.
- **Cache build errors carry a field path** — disk-store failures
  report `cache.<name>: …` like upstream errors report
  `upstream.<name>: …`.
- **`admin.listen` normalizes to a list** — `verd config` and admin
  `/config` render `listen = ["127.0.0.1:2019"]` even when one
  listener is configured; consumers of the dump should treat it as an
  array.
- **`server_header = "off"` deprecated** — it still omits the header,
  but `verd validate` warns; prefer `false` (or `""`).
- **More dead-config and footgun diagnostics** — `verd validate` now
  catches: an `[acme]` block with no `tls = "auto"` site; `site`/`route`
  `ip_allow` entries that can never admit a client (outside every site
  allowlist entry or fully covered by `ip_deny`); duplicate
  `admin.listen` addresses and collisions with `server.listen`;
  `upstream.tls` settings on upstreams with no `https://` server and
  `tls.ca` under `verify = false`; `upstream.timeouts.connect`/
  `response_header = "0s"` (instant timeout — now an error);
  `rate_limit.burst = 0`; `log.output = "off"` or an empty path (a
  literal filename/`""`, not an off-switch) and missing log parent
  directories; `spa = true` with an empty or missing `index` fallback
  and `spa` + `listing` precedence; `cache.ttl = "0s"`,
  `cache.*.max_items = 0`, and invalid `cache.vary_headers`;
  `compress.types` entries that aren't `type/subtype`; `0s`/`0B` site
  and route `timeouts`/`limits` overrides; `error_pages` targets
  missing under `static.root`; and hop-by-hop/framing headers
  (`content-length`, `connection`, `transfer-encoding`, …) set via
  `respond.headers` or `request_headers`/`response_headers`, which now
  error instead of corrupting the wire.
- **Config shorthand errors name the offending key** — mistakes inside
  table and list forms (`compress = { algo = "br" }`, `hosts = [5]`)
  report the real problem instead of the generic "must be a …"
  fallback; in exchange a few scalar shorthands lose their
  value-specific reason (`dns = "banana"` drops the humantime detail,
  `admin.tls = "bogus"` no longer echoes the rejected mode).
- **Positional-array shorthand forms no longer parse** —
  `respond = [200, "text"]` and friends were an untagged-deserializer
  artifact, not a grammar form; arrays now only mean a field's
  documented list shorthand, as `docs/config-grammar.md` specifies.

### Security

- **`HEAD` requests no longer poison the cache** — a `HEAD` to an
  uncached, cacheable URL stored its empty body under the shared
  `GET` cache key, so every subsequent `GET` served `200` with
  `Content-Length: 0` and an empty body until the entry expired. Any
  unauthenticated client could blank any cached route. `HEAD`
  responses are never stored now; `HEAD` *lookups* still share the
  `GET` entry.
- **`/purge` prefix purge actually works** — stored metadata recorded
  the request *authority* in the field prefix purge matched on, so
  `{"prefix": "/api"}` silently removed 0 entries. Prefix purge now
  matches the request path as documented.
- **`X-Forwarded-For` can no longer be spoofed through repeated
  header lines** — `real_ip` read only the first `X-Forwarded-For`
  line, which is fully client-controlled when a trusted proxy appends
  its own line; all lines are now merged per RFC 7230 ordering before
  the trusted-chain walk, fixing `ip_allow`/`ip_deny`, per-IP rate
  limiting, and `{remote_ip}` identity behind such proxies.
- **Malformed `Host` values are rejected with `400`** — authorities
  containing `@`, whitespace, or other non-authority characters could
  reach `Location` construction (e.g. `Host: brand.com@evil.net` →
  `https://brand.com@evil.net/…` userinfo-disguised redirect) and
  `{host}` template substitution.
- **The admin listener enforces connection caps and io deadlines** —
  128 concurrent connections / 16 per IP, and any read or write
  stalled longer than 30s is dropped. The bearer check only runs
  after a request is parsed, so unauthenticated slowloris could
  previously pin unlimited sockets and tasks. Shutdown drains
  in-flight connections on a bounded 5s grace so an idle keep-alive
  socket can't hold process exit.
- **`respond` bodies can no longer reflect request data under markup
  content-types** — `{path}`, `{query}`, `{args}`, `{uri}`, and
  `{request_id}` combined with `text/html` (or any `+html`/`+svg`
  media type) was reflected XSS by configuration; it is now a config
  error rather than a warning. Alphabet-constrained placeholders
  (`{host}`, `{scheme}`, `{remote_ip}`, `{method}`) remain allowed,
  as does any placeholder under non-markup content-types.
- **`redirect.to` templates can no longer emit scheme-relative
  `Location`s** — a template starting with `{path}`/`{uri}` (or a lone
  `/`) combined with a decoded `/\host` path produced
  `Location: /\evil.com`, which WHATWG URL parsing folds into
  `//evil.com` — an open redirect to an attacker-chosen host.
  Scheme-relative targets are now refused (header dropped, warning
  logged).
- **ACME on-demand retries no longer drain the issuance rate limit** —
  repeated handshakes for a host whose issuance was already in flight
  consumed rate-window permits, so ~5 SNI probes could starve all
  on-demand issuance for the window. The gate now only charges when a
  new order actually starts.

### Fixed

- **Site-scoped `auth.basic.htpasswd` didn't rebase against its
  fragment** — a relative path in an `include`d file resolved against
  the CWD instead of the fragment's directory (route-level
  `htpasswd` was already covered). Site and route auth now anchor the
  same way.
- **`cache = true` produced `unknown cache store ""`** — an enabled
  cache with no store name now errors at validate time with
  `cache needs a store — cache = "<name>" or { store = "<name>" }`.
- **`cache_control` globs evaluate by specificity, not map order** —
  a `"*"` entry previously shadowed every more specific pattern
  (`BTreeMap` iterates sorted and first match won). Now fewest `*`
  then most literal characters wins: exact > `"*.css"` > `"*"`.
- **`proxy.request_headers = { enabled = false, … }` ignored** — the
  ops were built and applied despite `enabled = false`; the flag is
  honored now, and leftover settings warn as dead config.
- **`${file:}` under a path field inlined file contents as the path** —
  `cert = "${file:/x}"` or an `include` entry now fails at load with a
  teaching error instead of producing a bogus path (`${VAR}` stays
  legal).
- **`unavailable` could emit a body where the status forbids one** —
  `unavailable = { status = 204 }` produced invalid framing; bodyless
  statuses (1xx/204/304) now serve an empty body and no Content-Type.
- **`default = true` + `hosts = ["*"]` on one site** no longer
  double-counts as two default sites and spuriously fails validation.
- **Duplicate diagnostics removed** — listeners without TLS and
  out-of-range `retries.budget_fraction` were each reported twice.
- **`include` type errors surfaced** — a non-array `include` value or a
  non-string entry was silently ignored; both are now load errors.
- **Merge conflicts name the original source** — the diagnostic now
  reports which file first set the conflicting key.
- **Diamond `include` graphs duplicated arrays** — a fragment reachable
  via two include paths merged twice (e.g. `[[site]]` entries appeared
  twice); each file now merges once, and a genuine include cycle
  reports `include cycle` instead of the nesting-depth error.
- **Interpolation errors carry context** — `${VAR}` failures name the
  config key that needed the variable, and config-permission warnings
  only fire for files that were actually interpolated.
- **Unused definitions warn** — `[upstream.*]` and `[cache.*]` blocks
  never referenced by a route produce warnings.
- **CodSpeed bench broke `nextest` and image builds** — the new
  `[[bench]]` target rejected nextest's test-enumeration flags and was
  missing from the Docker build context. `verd::bench/hot_paths` is now
  excluded via `.config/nextest.toml` and the `Dockerfile` copies
  `benches/` so the manifest parses.
- **Release flow no longer leaves `llms-full.txt` stale** — the file
  embeds the version line from `introduction.md`, so every version
  bump invalidated it and broke the `generated docs in sync` CI check
  on release PRs. `release.sh` now regenerates it unconditionally
  (`--regen-docs` still gates the schema-driven `reference.md`).
- **Secret permission checks now cover every source file** —
  `include`d fragments containing inline secrets and `${file:…}`
  secret targets are checked for world-readable/writable permissions;
  previously only the main config file was checked, and a secret
  reference in a later fragment could attach the warning to the wrong
  file.
- **`cache.bypass.cookies`/`paths` scalar parity** — both accept a
  single string as a one-element list, matching the other bypass
  lists and the grammar doc.
- **`verd fmt --all` no longer blocked by schema errors** — `include`
  sources are enumerated with a syntax-only walk, so a config that
  fails model validation still formats (with a warning that validation
  was skipped); malformed TOML and missing `include` targets still
  fail.
- **`verd run -c - --watch` warns it cannot watch stdin** — the config
  has no file-backed source, so the flag was previously a silent no-op.
- **`rate` fields claimed a struct shape in the JSON schema** —
  `rate_limit.rate` and `acme.on_demand.rate` only accept strings like
  `"100/s"`; the generated schema now says so.
- **`text/html` respond check missed newer placeholders** — a
  `respond.body` reflecting `{uri}`, `{args}`, `{remote_ip}`, or
  `{request_id}` under `content-type: text/html` produced no warning;
  the check now covers every request-derived placeholder.
- **`acme.dns.cloudflare.api_base = "http://…"` was silent** — plain
  HTTP sends the API token unencrypted; `verd validate` now warns
  (`http://` stays accepted for test mocks, non-http(s) remains an
  error).
- **`respond = "404"` silently served 200** — the quoted form is a
  body, not a status; a three-digit body under the default status now
  warns that `respond = 404` (unquoted) sets the code.
- **`verd schema` over-required upstream server entry fields** —
  `{ url = "…" }` entries in `upstream.*.servers` parse with
  `weight = 1`/`backup = false`, but the schema marked all three
  fields required; it now requires only `url` and emits the real
  defaults, so schema-driven editors no longer flag valid configs.
- **Generated field reference dropped every enum/union's accepted
  forms** — `lb`, `tls`, `challenge`, `policy`, `tier`, `format`,
  api-key `location`, and the shorthand `*Schema` unions rendered as
  bare headings; each now lists every accepted form with its
  description.
- **Book fixes surfaced by the `llms-full.txt` review** — middleware
  claimed only `security` accepted the bare `x = false` spelling (all
  middleware blocks do), the `[server]` layout row implied `limits`/
  `timeouts` nest under it, the `llms.txt` index omitted six book
  pages, the first recipe validated `tls = "auto"` by accident (now
  `tls = "off"`), stale `0.2.2`/`v0.1.0` version strings, and
  book-relative links in `llms-full.txt` that resolved nowhere.
- **Config parse and `client_ip` perf regressions** — every shorthand
  deserializer now dispatches on the value's own type in one pass
  instead of buffering into serde's `Content` and retrying variants,
  and the X-Forwarded-For trust walk no longer allocates a list per
  request.
- **Oversized byte counts parse again** — `ByteSize` fields accept the
  full `u64` range from unsigned-capable formats; the new shorthand
  visitor narrowed integers to `i64` first. TOML integers are signed
  and unaffected.

## [0.4.1] - 2026-10-27

### Build & CI

- **Required `docker build + trivy scan` no longer hangs on unrelated
  PRs** — `docker.yml` now always runs on PRs and gates the build steps
  on whether Docker-relevant paths changed, so the required check
  always reports exactly one authoritative result instead of never
  running.

## [0.4.0] - 2026-10-26

### Added

- **Version shown in the docs** — the book title bar (every page) and
  the introduction page now carry the crate version; `release.sh`
  updates both on bump and the docs workflow fails the build if they
  drift from `Cargo.toml`.
- **Examples chapter in the docs** — complete copy-paste `verd.toml`
  recipes for the common cases: static + ACME, SPA, single-backend and
  load-balanced proxying, frontend+API on one domain, virtual hosting,
  redirects, WebSockets, auth + IP allowlists, rate limits + CORS,
  caching, health endpoints, local development, and `conf.d` splits.
- **`verd config` subcommand** — prints the effective configuration
  (includes merged, `${…}` interpolated, defaults applied) as TOML with
  secret values and URL credentials redacted.
- **Include globs** — `include = ["extra-*.toml"]` and
  `include = ["conf.d/site-*.toml"]` now expand as documented, sorted
  like directory entries. A glob that matches nothing is a no-op (a
  missing file or directory is still an error), so `conf.d/*.toml` can
  be populated later.
- **Interpolation escapes and file defaults** — `$${` renders a
  literal `${`, and `${file:/path:-fallback}` uses the fallback when
  the file is unreadable.
- **Friendlier value shapes** — `server.listen` accepts bare
  `"ip:port"` strings alongside `{ addr, tls }` tables; `site.proxy`
  accepts a cluster name, a single URL string, or a URL list;
  `route.proxy.upstream` accepts a single URL string too;
  `rewrite.replace_prefix` accepts `{ from, to }` in addition to the
  two-element array; `hsts_max_age` accepts humantime strings like
  `"180d"` in addition to raw seconds; `server.graceful_timeout` takes
  humantime strings like every other duration.
- **`log.access.output = "stderr"`** as a destination alongside
  `stdout` and file paths.
- **Enum aliases** — `lb` accepts `"round-robin"`, `"least-conn"`,
  `"ip-hash"` spellings; `tls` accepts `"self-signed"`/`"self_signed"`.

### Changed

- **Clearer field names with compatibility aliases** —
  `route.proxy.headers` is now `request_headers`, `route.headers` is
  `response_headers`, and `upstream.*.limits` is `upstream.*.timeouts`;
  the old names still parse. `site.proxy`/`route.path` remain aliases
  for the full forms, and validation messages now name sites by host
  (`site["example.com"].route[2]`) and list the offending handler keys.
- **`verd fmt` actually formats** — whitespace around `=` collapses to
  one space and trailing whitespace is stripped; comments, key order,
  and brace/comma spacing are preserved.

### Security

- **Wider dump redaction** — `verd config` and the admin `/config`
  endpoint now also blank values under `Authorization`- and
  `Cookie`-suffixed keys (e.g. `response_headers.set.Authorization =
  "${TOKEN}"` no longer prints the resolved credential). Matching is
  suffix-based, so `route.cache.bypass.cookies` — a list of cookie
  *names*, not secrets — stays visible.

### Fixed

- **`listen = [{ tls = true }]` parses again** — a `{ addr, tls }`
  listener table without `addr` once more binds the default
  `0.0.0.0:80` listener, matching pre-0.3 behavior instead of failing
  schema validation.
- **`verd fmt` reaches arrays** — `=` gaps inside inline tables nested
  in arrays (`listen = [{addr="127.0.0.1:8080"}]`) are now normalized,
  and `--check` flags the same input.
- **Spurious `redirect_https` warning** — `tls = "off"` sites no longer
  warn unless `redirect_https` is explicitly set.
- **Merge-conflict path** no longer ends with a trailing dot
  (`log.level.` → `log.level`), and the message notes that arrays
  append rather than conflict.
- **`site.proxy` is validated** — unknown cluster names and malformed
  URLs in the site-level shorthand are reported like route-level ones.

### Build & CI

- **ClusterFuzzLite continuous fuzzing** — the OSS-Fuzz submission
  ([google/oss-fuzz#16349](https://github.com/google/oss-fuzz/pull/16349))
  was declined (project not mature enough yet), so the same build
  contract now runs in-repo via `.clusterfuzzlite/` +
  `google/clusterfuzzlite` actions: PR fuzzing, daily batch fuzzing
  with a persistent corpus (`corpus` branch), weekly corpus prune +
  coverage report (`coverage` branch), and main-push builds for
  novel-crash detection. This supersedes the old `cargo fuzz` smoke
  job; the files in `.clusterfuzzlite/` stay copy-paste ready for a
  future OSS-Fuzz resubmission (`COPY` ↔ `git clone` swap is noted in
  the Dockerfile header).
- **Lint and secret-scan gates** — new `lint.yml` enforces
  `markdownlint`, `typos` (allowlist in `_typos.toml`), `actionlint`,
  a `gitleaks` history scan, and `dependency-review-action` on PRs;
  a changelog check also fails PRs that touch `src/` or `Cargo.*`
  without a `CHANGELOG.md` entry (`no-changelog` label skips).
- **Weekly dead-link sweep** — `links.yml` runs lychee over all
  tracked `.md`/`.txt` files; doc-example URLs and private IPs are
  excluded via `lychee.toml`.
- **`CI.md`** — documents every workflow, what each job gates vs.
  reports, the release pipeline flow, and deliberately-skipped checks.
- **Auditable release binaries** — `Cross.toml` installs a pinned,
  hash-verified `cargo-auditable` inside the `cross` build containers
  and `RUSTC_WORKSPACE_WRAPPER` embeds dependency metadata (`.dep-v0`)
  into the shipped binaries, so `cargo audit bin` can scan the
  artifact itself — complementary to the CycloneDX SBOM.
- **Egress auditing on privileged release jobs** — `release.yml` runs
  `harden-runner` (audit mode) on the OIDC/signing and GHCR-push jobs,
  logging outbound traffic for baseline before any blocking policy.
- **Semver-checks (advisory)** — `ci.yml` diffs the public `verd` API
  against the newest `v*` tag via `cargo semver-checks`; the report
  surfaces required-bump signal without gating (0.x may legitimately
  break the lib API between minors — flip to required at 1.0).
- **Weekly matrix checks** — `weekly.yml` runs the suite under
  `cargo test --release` (stable; different failure surface without
  debug/overflow checks) and on nightly rustc (advisory — catches
  upstream regressions early).
- **Shell script linting** — `lint.yml` runs `shellcheck -S warning`
  over every tracked `*.sh` (`release.sh`, `bench/run.sh`,
  `.clusterfuzzlite/build.sh`); info-level findings are tolerated for
  intentional idioms. Also fixes real findings: unquoted command
  substitutions in `bench/run.sh`, dead `DISK_OK`/`HIT_RE` tables, and
  unquoted `$SRC`/`$OUT` in the fuzz build.
- **Codecov thresholds** — `codecov.yml` makes the uploaded coverage
  actionable: project auto-baseline (±1%) and 80% patch targets as
  informational (non-gating) status checks.
- **AI code review** — Devin Review runs server-side via the Devin
  GitHub App (Settings → Review; a comment-posting workflow can't
  trigger it — bot-authored `/devin review` comments are filtered).
- **Workflow hygiene** — workflows now declare `concurrency` groups
  (cancel on PR updates; releases serialize per tag and corpus writes
  serialize globally, since a shared group can only hold one queued
  run and would silently drop pending tags) and per-job
  `timeout-minutes`. `ghcr.io/…:latest` is only pushed by the run
  whose tag is the newest `v*`, so a concurrent or re-run release of
  an older tag can't regress the image users pull.
- **Generated-docs gate on every PR** — `ci.yml` regenerates
  `docs/book/src/reference.md` and `llms-full.txt` and fails on
  drift; previously only enforced on `docs/**` paths via `docs.yml`.
- **Container build + scan on PRs** — `docker.yml` builds the musl
  `Dockerfile` and trivy-scans the image (SARIF to code scanning,
  fails on fixable HIGH/CRITICAL), closing the gap where the image
  only built at release time.
- **crates.io packaging gate** — `cargo publish --dry-run --locked`
  runs in CI so packaging breakage is caught before release.
- **CodeQL `security-and-quality`** — wider query suite than the
  default for the Rust analysis.
- **Codecov upload** — the existing `lcov.info` now also uploads to
  Codecov for PR diff-coverage comments; `fail_ci_if_error: false`
  keeps it advisory.
- **Weekly `cargo-mutants` sweep** — `mutants.yml` runs mutation
  testing (shuffled, ~100min cap) and archives `mutants.out/`; it
  reports surviving mutants without gating.

## [0.3.1] - 2026-10-26

### Added

- **Fully CI-driven releases** — dispatch `bump.yml` with a version: it
  bumps `dev` via `release.sh --no-tag`, auto-merges dev→main, then
  `tag.yml` tags the merge commit and dispatches `release.yml` (which
  also gained a manual `tag` input for re-releasing). Tags now always
  anchor in `main` history; no local release steps remain.
- **Top-level `LICENSE` file** — dual-license pointer (MIT OR
  Apache-2.0, SPDX) alongside `LICENSE-MIT`/`LICENSE-APACHE` so the
  CII "license in a standard location" criterion is met literally.
- **OpenSSF Best Practices badge** in the README — self-certification
  submitted at bestpractices.dev (project 15915).
- **Release signatures in Scorecard-detectable formats** — cosign now
  also emits detached `*.sig` + `*.pem` files alongside the
  `*.cosign.bundle` bundles; OpenSSF Signed-Releases scans release
  assets for these suffixes.

### Changed

- **Dependency refresh** — lockfile updates including tokio 1.54.1,
  memmap2 0.9.12, base64 0.23 (fuzz), brotli 9.1, icu 2.4, notify
  8.2.1; all within existing semver ranges, test suite green.

### Fixed

- **Release machinery bootstrap** — `bump.yml` now only reuses an
  *open* dev→main PR (a merged one previously blocked creation), and
  `release.sh` anchors its `[Unreleased]` heading match so inline
  mentions can no longer absorb the promoted section.
- **Cache e2e flake** — non-expiry test paths now get `max-age=60` so
  HIT assertions don't race a 1s freshness window on loaded runners.

## [0.2.7] - 2026-10-25

### Changed

- **Actions bumped for the Node 24 runner migration** — checkout v7,
  upload/download-artifact v7/v8, pages v5, docker v4/v7,
  action-gh-release v3, scorecard v2.5, cosign-installer v4 (all
  SHA-pinned). The unmaintained node20 `rustsec/audit-check` job was
  removed — `cargo deny check` already gates the same advisories db.
- **Container images carry OCI labels** — `licenses` ("MIT OR
  Apache-2.0") and `source` on both `Dockerfile` and
  `Dockerfile.release` for machine-readable license metadata.

## [0.2.6] - 2026-10-25

### Added

- **`cli.md` doc page** — reference for the `verd` subcommands, flags,
  env vars, and exit codes (completes the external-interface docs).

## [0.2.5] - 2026-10-25

### Added

- **`CONTRIBUTING.md`** — contribution requirements (CI gates, unsafe
  policy, changelog convention) referenced from the README; needed for
  the CII Best Practices criteria.

### Build & CI

- **Scorecard-driven fixes** — all container `FROM` images pinned
  by digest; `attest-build-provenance` publishes SLSA provenance for
  release tarballs (was cosign bundles scorecard can't see); a CodeQL
  Rust workflow adds SAST; a **cargo-machete** CI job rejects unused
  dependencies.

## [0.2.4] - 2026-10-25

### Added

- **`/version` and `verd version` now report the build commit SHA** —
  release binaries stamp `VERD_GIT_SHA` from the tag's commit; the
  source-build Dockerfile accepts `--build-arg VERD_GIT_SHA=`. A
  one-line `build.rs` (`cargo:rerun-if-env-changed`) makes the stamp
  reliable under cached builds; `admin.md` documents the field.

### Security

- **CI workflows hardened per zizmor audit** — `permissions: {}` at
  workflow level with per-job grants (was workflow-wide write),
  `persist-credentials: false` on every checkout, release `rust-cache`
  is `lookup-only` (cache-poisoning), and the fuzz run command no
  longer expands `${{ }}` inside `run:` (template-injection).

### Build & CI

- **zizmor workflow audit job** in CI — blocks regressions on the
  items above. **cargo-nextest** runs the test suite (~7s vs ~40s).
- **OSS-Fuzz integration submitted** ([google/oss-fuzz#16349](https://github.com/google/oss-fuzz/pull/16349))
  — `fuzz/oss-fuzz/` keeps the in-repo copy of `project.yaml`,
  `Dockerfile`, and `build.sh`; all 7 targets verified with
  `infra/helper.py` (`build_fuzzers` + `check_build` + smoke run).
- **OpenSSF Scorecard** runs weekly and on every `main` push
  (`.github/workflows/scorecard.yml`) — publishes results to the
  OpenSSF REST API, uploads SARIF to code scanning, and the README
  shows the score badge.
- **`release.sh` moved to the repo root** (was `scripts/release.sh`);
  `RELEASING.md` updated accordingly.

## [0.2.3] - 2026-10-25

### Build & CI

- **`scripts/release.sh`** automates the release flow: version bump
  (patch/minor/major/explicit), changelog section rename + link refs,
  `Cargo.lock` sync, release commit, `vX.Y.Z` tag, and push.

## [0.2.2] - 2026-10-25

### Changed

- **Quickstart documents the admin API** — loopback/token setup, curl
  examples, and the Docker loopback caveat.

## [0.2.1] - 2026-10-25

### Fixed

- **Release container image no longer fails to start** — CI artifact
  download stripped the execute bit, so the image's `/usr/bin/verd` was
  non-executable (`permission denied` on entrypoint). `Dockerfile.release`
  now uses `COPY --chmod=0755` and the release workflow restores the bit
  after artifact regrouping.

## [0.2.0] - 2026-10-25

### Security

- **Token-less admin listener hardened against CSRF/DNS rebinding.**
  Requests must carry a loopback `Host` (`localhost`, `*.localhost`,
  `127.0.0.0/8`, `[::1]`); mutating endpoints additionally reject
  `Sec-Fetch-Site: cross-site` and non-loopback `Origin` headers. A
  validation warning now flags `admin.token` unset even on loopback.
- **Rate-limit `key = "header:<Name>"` no longer allows memory
  exhaustion.** Bucket keys store a hash of the header value instead of
  the raw value — unique oversized values can't inflate the bucket map.
- **New `timeouts.send` (default `60s`)** — a write-side inactivity
  deadline: a `poll_write`/`poll_flush` stalled longer than this closes
  the connection (slow-client/slow-read DoS protection). Progress resets
  it, so large slow downloads are unaffected. Also bounds upgrade-tunnel
  inactivity in both directions; set `0s` on long-idle WebSocket routes.
- **Upgrade tunnels count against connection limits.** The connection's
  admission slot stays held for the tunnel's lifetime — `Upgrade:`
  requests can no longer escape `max_connections`/`max_connections_per_ip`.
- **`Forwarded`/`X-Forwarded-*` hardening:** the client `Host` is
  RFC-7239-quoted in `Forwarded` (`host=evil";for="spoof` can't inject
  pairs); trusted peers' inbound `X-Forwarded-Proto`/`-Host` are preserved
  instead of overwritten; multiple `Forwarded`/`X-Forwarded-For` headers
  merge instead of reading only the first; a spoofed inbound
  `X-Forwarded-Host` is dropped when the routed host is unfit to forward.
- **Exactly one outbound `Host` per proxied request** — `pass_host`
  emits the upstream authority; otherwise the `Host` verd routed on.
  Duplicate client `Host` headers collapse, and h2-inbound requests get
  a synthesized `Host` on h1 upstreams.
- **Query-parameter API keys are stripped from cache keys**
  (`key::strip_query_param`, decoded-name compare so `api_%6bey=` can't
  smuggle a credential into persisted entries). Validation warns when a
  cached route accepts query api keys.
- **`TRACE` removed from the retry/idempotent set** — echo probes are
  never replayed to another member.
- **`unreachable!` removed from the h2c upstream checkout path** — a
  misbehaving h2c upstream answering h1 is now an ordinary error, not a
  connection-task panic.
- **Credential fingerprints are keyed hashes** — `fingerprint` uses a
  per-process random `ahash` seed so access-log identities can't be
  precomputed offline; bearer/api-key comparison scans the full list
  (no positional early-exit).
- **Filesystem permissions:** cache `objects/` and ACME storage dirs are
  tightened to `0700` (with a warning); the config file warns when
  group/other-writable, or group/other-readable while holding inline
  credentials.
- **Validation warnings added** for `upstream.tls.verify = false` on
  `https://` servers (MITM-able), `limits.header_bytes > 1MiB` (buffer
  memory multiplier), `timeouts.send = "0s"`, and `respond` bodies that
  substitute request data under a `text/html` content-type (reflected
  XSS footgun).
- **`SECURITY.md`** — private vulnerability reporting policy.

### Changed

- **HTTP/2 inbound is explicitly bounded:** `max_concurrent_streams(200)`,
  `max_header_list_size = limits.header_bytes`, keep-alive pings 20s/10s.
- **Path normalizer rejects decoded control characters** (C0/C1/DEL) —
  requests now 400 instead of propagating `%09`-style bytes downstream.
- **`Location` headers are re-encoded** — `redirect` templates and
  static `dir/` redirects percent-encode the decoded path, so a raw
  space/control char can never corrupt the header.
- **`basic` auth-scheme match is case-insensitive** (RFC 9110).
- **systemd unit tightened:** `/etc/verd` is `ReadOnlyPaths`,
  `ProtectKernelLogs`, `RestrictSUIDSGID`, `LockPersonality`,
  `RestrictRealtime`, `RestrictNamespaces`.

### Fixed

- **Per-IP connection accounting race** — decrement+remove now happens
  under the shard `entry()` lock; a fresh admit for the same IP can no
  longer lose its count.
- **Demo config starts**: `[admin]` gets a token default
  (`${VERD_ADMIN_TOKEN:-verd-demo-admin}`) and `proxy` uses the
  `{ upstream = [...] }` table form.
- HTTP/2 keep-alive config now supplies `TokioTimer` — without it every
  h2 connection panicked with `You must supply a timer`.

### Build & CI

- All GitHub Actions are pinned to commit SHAs (with the tag in a
  trailing comment); `cargo deny check` runs advisories/bans/licenses/
  sources in CI; dependabot watches Cargo (`/` and `/fuzz`) and
  github-actions weekly.
- New fuzz targets: `headers_policy` (hop-by-hop stripping and
  forwarded-header invariants) and `static_resolve` (no `..`, control
  chars or NUL survive path normalization; document-root join can't
  escape), alongside `http_semantics`.
- GitHub release notes are now generated from `CHANGELOG.md` — the
  tagged version's section becomes the release body, with the
  auto-generated commit list appended.

### Coverage

Unit-test coverage (`cargo llvm-cov --lib`; e2e subprocess coverage not
merged, so real exercised coverage is higher):

| Metric    | Before | After  |
|-----------|--------|--------|
| Regions   | 79.15% | 81.49% |
| Functions | 76.06% | 76.66% |
| Lines     | 79.76% | 82.48% |

298 unit tests (+130 vs the pre-review baseline). Largest gains:
`config/validate.rs` 59%→99.9% lines, `config/values.rs` →99%,
`cli.rs` 8%→57%, `cache/stage.rs` 68%→92%, `cache/disk.rs` →95%,
`handler/static_files.rs` 66%→94.5%, `handler/redirect.rs` →100%,
`handler/respond.rs` →100%, `router/condition.rs` 59%→100%,
`admin/mod.rs` →82%, `body.rs` 61%→84%, `observe/accesslog.rs` →90%.
Residual low-coverage files (`server/conn.rs`, `server/service.rs`,
`cli::run`, `acme` orchestration, `tls/manual` error paths) are
socket-accept/process-boundary code exercised by the e2e suites rather
than unit tests — intentionally left to e2e/fault-injection coverage.

## [0.1.0] - 2026-10-25

Initial release: static files, TLS + ACME (http-01/tls-alpn-01/on-demand),
reverse proxy with load balancing and retries, response caching
(RAM/disk/hybrid), compression, rate limiting, CORS, security headers,
admin API with atomic reloads, Prometheus metrics.

[Unreleased]: https://github.com/frontyard/verdigris/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/frontyard/verdigris/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/frontyard/verdigris/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/frontyard/verdigris/compare/v0.2.7...v0.3.1
[0.2.7]: https://github.com/frontyard/verdigris/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/frontyard/verdigris/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/frontyard/verdigris/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/frontyard/verdigris/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/frontyard/verdigris/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/frontyard/verdigris/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/frontyard/verdigris/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/frontyard/verdigris/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/frontyard/verdigris/releases/tag/v0.1.0
