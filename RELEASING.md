# Releasing

Releases are fully automated: pushing a `v*` tag runs
`.github/workflows/release.yml` end to end. There is no manual build
step on a maintainer machine.

## Before tagging

- CI green on `main` (`ci.yml`: fmt, clippy stable + MSRV 1.88, tests).
- `Cargo.toml` `version` bumped to the version you are about to tag —
  nothing in CI enforces tag↔version agreement, so keep them in sync
  yourself.
- If `src/config/` changed: regenerate `docs/book/src/reference.md`
  (`cargo run --quiet -- schema | python3 docs/gen-reference.py`) and
  `llms-full.txt` (`python3 docs/gen-llms-full.py`). The docs workflow
  fails on a stale `reference.md`.

## Cut a release

```sh
git tag -a v0.2.0 -m "verd v0.2.0"
git push origin v0.2.0
```

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
