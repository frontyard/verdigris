# Releasing

Releases are fully automated: pushing a `v*` tag runs
`.github/workflows/release.yml` end to end. There is no manual build
step on a maintainer machine.

## Cut a release

```sh
release.sh            # patch (default)
release.sh minor
release.sh major
release.sh 0.3.0      # explicit version
```

The script (`release.sh`) does, in order:

1. Guardrails: clean tracked tree, tag must not exist yet.
2. `Cargo.toml` version bump + `Cargo.lock` re-sync (CI builds
   `--locked`).
3. Changelog: `## [Unreleased]` content is moved under
   `## [x.y.z] - <today>`, a fresh `[Unreleased]` is left on top, and
   the compare link refs are updated. Skipped if the section already
   exists (e.g. written by hand).
4. Commits `Release vX.Y.Z`, creates annotated tag `vX.Y.Z`, pushes the
   branch and the tag.

Flags: `-y` skips the confirmation prompt; `--regen-docs` regenerates
`docs/book/src/reference.md` and `llms-full.txt` — needed when
`src/config/` changed during the cycle (the docs workflow fails on a
stale `reference.md`).

The tag push is what kicks off the release workflow — tag name and
`Cargo.toml` version are guaranteed to match because the script derives
the tag from the bump.

### If you tag by hand instead

```sh
git tag -a v0.2.0 -m "verd v0.2.0"
git push origin v0.2.0
```

then all of the above stays your responsibility: version↔tag agreement,
the `[Unreleased]` → dated-section rename, `Cargo.lock`, and pushing the
release commit alongside the tag.

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
