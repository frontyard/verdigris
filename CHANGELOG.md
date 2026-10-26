# Changelog

All notable changes to verd are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

How releases work: changes accumulate under the `[Unreleased]`
section. At release time the Bump workflow promotes it to
`## [x.y.z] - YYYY-MM-DD`, bumps `Cargo.toml`, and the release
workflow publishes the matching section as the GitHub release notes.

## [Unreleased]

### Fixed

- **Release machinery bootstrap** — `bump.yml` now only reuses an
  *open* dev→main PR (a merged one previously blocked creation), and
  `release.sh` anchors its `[Unreleased]` heading match so inline
  mentions can no longer absorb the promoted section.

## [0.3.0] - 2026-10-26

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

[Unreleased]: https://github.com/frontyard/verdigris/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/frontyard/verdigris/compare/v0.2.7...v0.3.0
[0.2.7]: https://github.com/frontyard/verdigris/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/frontyard/verdigris/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/frontyard/verdigris/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/frontyard/verdigris/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/frontyard/verdigris/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/frontyard/verdigris/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/frontyard/verdigris/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/frontyard/verdigris/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/frontyard/verdigris/releases/tag/v0.1.0
