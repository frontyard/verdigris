# Releasing

Releases are fully CI-driven — nothing runs on a maintainer machine.
Three workflows chain together:

1. **Bump** (`.github/workflows/bump.yml`, manual dispatch) — runs
   `release.sh --no-tag` on `dev`: version bump, changelog promotion,
   lockfile sync, `Release vX.Y.Z` commit. Pushes `dev`, opens (or
   reuses) the dev→main PR, enables auto-merge.
2. **Tag** (`.github/workflows/tag.yml`, on push to `main`) — when a
   merge lands, compares `Cargo.toml` version at `HEAD` vs `HEAD^1`.
   A change means a release commit arrived: it tags the merge commit
   `vX.Y.Z`, pushes it, and dispatches the Release workflow. Tags
   therefore always anchor in `main`'s history.
3. **Release** (`.github/workflows/release.yml`) — builds, signs,
   attests, publishes. Triggered by a pushed `v*` tag *or* manually
   with a `tag` input to (re)release an existing tag.

## Cut a release

Actions → **Bump** → Run workflow → enter `patch`/`minor`/`major` or an
exact `x.y.z` (check *regen docs* if `src/config/` changed). Everything
else follows automatically once the dev→main merge lands.

Requirements:

- A **`RELEASE_PAT` secret**: fine-grained PAT scoped to this repo with
  *Contents: read/write* + *Pull requests: read/write*. It is required
  because PRs created by `GITHUB_TOKEN` never trigger `pull_request`
  checks — the required checks would never report and auto-merge could
  not fire. (Settings → Secrets and variables → Actions.)
- **Auto-merge enabled** on the repo (Settings → General → Allow
  auto-merge); if it isn't, the Bump run leaves the PR open for a
  manual merge and the rest of the chain still fires.

## release.sh

The script stays the single implementation of bump mechanics
(version → changelog → lockfile → commit). Locally it's still usable
end-to-end (`./release.sh` bumps, tags, pushes — the tag push fires
release.yml directly). `--no-tag` makes it commit-only for the CI flow:
tags are created by `tag.yml` on `main`, never on `dev`.

## What CI produces

**Static binaries** (`cross build --release --locked` → musl, stripped):

- `verd-x86_64-unknown-linux-musl.tar.gz`
- `verd-aarch64-unknown-linux-musl.tar.gz`
- `checksums.txt` — one sha256 line per tarball and per `.deb`

**Distro packages** — each build leg wraps the exact musl binary that
ships in the tarball:

- `verd_<version>-1_amd64.deb` / `verd_<version>-1_arm64.deb` via
  `cargo deb --no-build --target <triple>` — installs `/usr/bin/verd`,
  the `packaging/verd.service` unit, and a commented default
  `/etc/verd/verd.toml` (a conffile); `postinst` creates the `verd`
  system user plus `/var/lib/verd` and `/var/log/verd`, and the unit
  is enabled + started.
- `verd-<version>-1.x86_64.rpm` / `verd-<version>-1.aarch64.rpm` via
  `cargo generate-rpm --target <triple> --arch <rpm-arch>` — same
  contents; `%config(noreplace)` protects `/etc/verd/verd.toml`,
  scriptlets create the user/dirs and run `systemctl preset`
  (Fedora/RHEL presets leave the unit disabled — enable it manually).
  Erasing keeps state (rpm has no purge); `dpkg --purge` on Debian
  removes it.

Metadata lives in `[package.metadata.deb]` /
`[package.metadata.generate-rpm]` in `Cargo.toml`; maintainer scripts
in `packaging/debian/` and scriptlets in `packaging/rpm/`. Locally:
`cargo deb --no-build` and `cargo generate-rpm` against an existing
`target/<triple>/release/verd`.

**Supply chain:**

- `verd-sbom.json` — CycloneDX SBOM via `cargo-sbom`
- `*.cosign.bundle` — keyless cosign signatures (OIDC identity token)
- `*.sig` + `*.pem` — detached signature + signing certificate per
  artifact (Scorecard-detectable formats)
- SLSA build provenance attestation (`actions/attest-build-provenance`)

**GitHub Release:** `softprops/action-gh-release` with notes curated
from the matching `CHANGELOG.md` section.

**Container image** — multi-arch (`linux/amd64`, `linux/arm64`) built
from `Dockerfile.release`, which packages the *same* CI-built binaries
that ship in the tarballs (not a second build). Pushed to GHCR:

```text
ghcr.io/frontyard/verdigris:v0.3.0
ghcr.io/frontyard/verdigris:latest
```

GHCR auth uses `GITHUB_TOKEN` — no extra secrets needed. The workflow
already declares `packages: write` and `id-token: write` (for cosign
keyless).

## Verifying artifacts

```sh
sha256sum -c checksums.txt --ignore-missing
cosign verify-blob verd-x86_64-unknown-linux-musl.tar.gz \
  --bundle verd-x86_64-unknown-linux-musl.tar.gz.cosign.bundle \
  --certificate-identity-regexp 'github.com/frontyard/verdigris' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify verd-x86_64-unknown-linux-musl.tar.gz \
  --repo frontyard/verdigris
```

## Local image builds

```sh
docker build -t verd .                 # Dockerfile: full source build
docker compose up --build              # demo stack
```

`Dockerfile.release` is for CI — it expects `dist/{amd64,arm64}/verd`
in the build context (the regrouped release artifacts), so a bare
`docker build -f Dockerfile.release .` will fail without them.

## crates.io

The package publishes as `verd`, but binaries and the container image
are the primary distribution channel. When a crates release is wanted:

```sh
cargo publish --dry-run
cargo publish
```

## Docs site

Unrelated to tags: every push to `main` that touches `docs/` rebuilds
the mdBook and deploys to GitHub Pages via `docs.yml`. Requires Pages
enabled in repo settings (source: GitHub Actions).

## Future work

**Automatic bump selection.** `bump.yml` currently requires the
maintainer to choose patch/minor/major. Idea: an `auto` mode (the
default) that picks the bump from the external contract:

- **Config schema** — commit a `schema.json` snapshot of `verd schema`
  (same generated-file discipline as `reference.md`) and diff it
  against the previous tag: removed field/enum variant, narrowed type,
  new `required`, changed `default` → breaking; additions → additive.
- **CLI** — snapshot normalized `verd <sub> --help` output; removed
  flag/subcommand/env var → breaking.
- **Admin API** — snapshot the route table (`src/admin/mod.rs`) and
  eventually response shapes.
- **Changelog categories** — still needed for *semantic* breaks a
  surface diff can't see (validation tightening, behavior changes):
  `Changed`/`Security` → breaking-ish, `Added` → additive, `Fixed`/
  `Build & CI` only → patch.
- **cargo semver-checks** — already advisory in `ci.yml` for the lib
  API; a corroborating signal, not the decision-maker.

Result = `max()` across signals. Strict-semver mapping: 0.x → breaking
and additive both minor, fix-only patch; ≥1.0 → breaking becomes major.
Known limits: `#[serde(alias)]` doesn't appear in schemars output, so
renames-with-alias (e.g. `headers` → `request_headers`) look like
removed fields and need an alias allowlist; behavioral breaks still
rely on the changelog signal.
