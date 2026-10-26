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
- `checksums.txt` — one sha256 line per tarball

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

## What CI produces

**Static binaries** (`cross build --release --locked` → musl, stripped):

- `verd-x86_64-unknown-linux-musl.tar.gz`
- `verd-aarch64-unknown-linux-musl.tar.gz`
- `checksums.txt` — one sha256 line per tarball

**Supply chain:**

- `verd-sbom.json` — CycloneDX SBOM via `cargo-sbom`
- `*.cosign.bundle` — keyless cosign signatures (OIDC identity token)
  on every tarball, `checksums.txt`, and the SBOM

**GitHub Release:** `softprops/action-gh-release` with generated notes.

**Container image** — multi-arch (`linux/amd64`, `linux/arm64`) built
from `Dockerfile.release`, which packages the *same* CI-built binaries
that ship in the tarballs (not a second build). Pushed to GHCR:

```
ghcr.io/frontyard/verdigris:v0.2.0
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
