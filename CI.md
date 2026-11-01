# CI

Everything that runs in GitHub Actions, grouped by when it runs. Every
workflow lives in `.github/workflows/` and follows the same
conventions:

- **Pinned actions** — third-party actions are pinned to full-length
  commit SHAs (tag in a trailing comment); Dependabot proposes bumps.
- **Least privilege** — every workflow sets `permissions: {}` at the
  top level; each job grants only what it needs, with a comment
  explaining why.
- **Concurrency groups** — PR-triggered workflows group by
  `${{ github.workflow }}-${{ github.ref }}` and cancel superseded PR
  runs; scheduled/release workflows serialize deliberately
  (`cancel-in-progress: false`) because dropped runs lose work.
- **Timeouts** — every job sets `timeout-minutes`.
- **Advisory vs. gating** — checks that report signal without blocking
  are marked `continue-on-error: true`; the tables below note which is
  which.

## On every PR and push to `main`

### `ci.yml` — core correctness

| Job | What it does | Gate |
| --- | --- | --- |
| `fmt` | `cargo fmt --check` | blocks |
| `clippy` | `cargo clippy --all-targets -- -D warnings` on **stable + MSRV 1.88** | blocks |
| `test` | `cargo nextest run --all-targets` + `cargo test --doc` on stable + MSRV | blocks |
| `rustdoc` | `cargo doc` with warnings denied | blocks |
| `generated` | Regenerates `docs/book/src/reference.md` and `llms-full.txt`; fails if they drift | blocks |
| `package` | `cargo publish --dry-run --locked` | blocks |
| `deny` | `cargo deny check` — advisories, bans, licenses, sources | blocks |
| `coverage` | `cargo llvm-cov` with a 55% line floor; lcov upload to Codecov is **advisory** (a Codecov outage never gates a PR) | blocks |
| `machete` | `cargo machete` — unused dependencies | blocks |
| `semver` | `cargo semver-checks` vs newest `v*` tag — surfaces required-bump signal | **advisory** |
| `zizmor` | Online zizmor audit of all workflow files | blocks |

### `lint.yml` — text/tooling lint

| Job | What it does | Gate |
| --- | --- | --- |
| `markdownlint` | `markdownlint-cli2` on all docs (`.markdownlint.json`) | blocks |
| `typos` | `crate-ci/typos` spell check (`_typos.toml`) | blocks |
| `actionlint` | Workflow syntax + embedded shellcheck on run blocks | blocks |
| `shellcheck` | `shellcheck -S warning` over every tracked `*.sh` | blocks |
| `gitleaks` | Secret scanning on the PR diff | blocks |
| `dependency-review` | New/changed deps scanned for known vulns | blocks |
| `changelog` | Fails if `src/` changed without a `CHANGELOG.md` entry | blocks |

### `docker.yml` — container gate

Builds `Dockerfile` → scans the image with Trivy (SARIF to code
scanning; fails on fixable HIGH/CRITICAL) and runs informational
`trivy config` on both shipped Dockerfiles.

### `codeql.yml` — CodeQL

`security-and-quality` query suite on PRs, pushes, and weekly
(Wednesday 04:15 UTC). SARIF uploads feed the Security tab.

### `cflite_pr.yml` — PR fuzz smoke

ClusterFuzzLite builds the fuzz harnesses (~7 min, cached) and runs a
300-second fuzzing budget under the address sanitizer (the only one
Rust fuzz targets support). Seeds from the `corpus` storage branch —
known-crashing and interesting inputs are replayed before mutation, so
corpus replay is free inside the existing run.

### `cflite_build.yml` — fuzz build health

On every push: builds the fuzz harnesses with sanitizers so a broken
fuzz build is caught before the PR smoke or batch run finds it.

### `docs.yml` — mdbook

Builds the book on PRs (catches broken docs); deploys to GitHub Pages
on pushes to `main`.

### Devin Review — AI review

Not a workflow — Devin's GitHub App ignores `/devin review` comments
from `github-actions[bot]` (bot senders are filtered to prevent
trigger loops), so a comment-posting workflow can't drive it.
Auto-review is configured server-side instead: **Devin → Settings →
Review → add repo + trigger rules** (on-create / on-ready /
every-push). Manual `/devin review` comments from a human also work.

## Scheduled

| Workflow | Cadence | Job |
| --- | --- | --- |
| `cflite_batch.yml` | daily 03:17 UTC | Long fuzz batch; pushes evolved corpus to the `corpus` branch |
| `cflite_cron.yml` | Sunday 05:31 UTC | Corpus pruning + minimization; coverage report to `coverage` branch |
| `soak.yml` | Sunday 04:00 UTC | `cargo test --test fault -- --ignored` — long-running fault tests |
| `mutants.yml` | Wednesday 05:20 UTC | `cargo-mutants --shuffle --test-tool=nextest`, ~100-min cap; **advisory**, archives `mutants.out/` |
| `weekly.yml` | Tuesday 06:10 UTC | `cargo nextest run --release` on stable (gated) + full suite on nightly (advisory) |
| `links.yml` | Monday 06:45 UTC | `lychee` link check across docs (`lychee.toml`) |
| `scorecard.yml` | Monday 06:30 UTC + pushes | OpenSSF Scorecard → SARIF + public badge API |
| `codeql.yml` | Wednesday 04:15 UTC | Scheduled re-analysis (results persist between PRs) |

## Release pipeline

The release flow is: `bump.yml` → `dev → main` PR → merge → `tag.yml`
detects the version bump → pushes `vX.Y.Z` + dispatches `release.yml`.

- **`bump.yml`** — `workflow_dispatch`: bumps `Cargo.toml`, regenerates
  docs, pushes the release commit to `dev`, opens + auto-merges the
  `dev → main` PR. Serialized — concurrent dev-branch pushes conflict.
- **`tag.yml`** — on push to `main`: diffs `Cargo.toml` version HEAD vs
  first parent; when it changed, requires a matching `CHANGELOG.md`
  section, creates and pushes the annotated `vX.Y.Z` tag, then
  dispatches `release.yml` (token pushes don't chain-trigger
  workflows, hence the explicit dispatch with `actions: write`).
- **`release.yml`** — on `v*` tag push or `workflow_dispatch` with a
  tag:
  - `build`: static musl binaries (`x86_64` + `aarch64`) via `cross`,
    wrapped by `cargo-auditable` (`Cross.toml` installs a pinned,
    sha256-verified copy in the build containers) — binaries embed a
    `.dep-v0` section so `cargo audit bin` can scan the shipped
    artifact itself.
  - `sbom`: CycloneDX SBOM generation.
  - `release`: cosign keyless signing (OIDC), SLSA provenance
    attestation, GitHub release publication — runs under
    `harden-runner` egress auditing.
  - `image`: multi-arch GHCR image build/push — also `harden-runner`.
    The mutable `latest` tag is only published when the release tag is
    the newest non-prerelease `v*`, so concurrent/older releases can't
    regress it.
  - Concurrency is per-tag (`release-<tag>`): same-tag reruns
    serialize, different tags run in parallel without queue-drops.
- **Dependabot** — action/Cargo bumps (`.github/dependabot.yml`).

## Manual only

- **`bench.yml`** — `workflow_dispatch`; installs `wrk`/`nginx`, runs
  `bench/run.sh` for 15s, uploads `bench/results.*`.

## Deliberately not (yet) covered

- **PR perf regression** — the remaining structural gap; CodSpeed or a
  base-vs-head `bench/run.sh` compare is the candidate.
- **Sanitizers/Miri on the main crate** — one sanctioned `unsafe`
  (mmap); fuzzers already run under ASan/UBSan.
- **`cargo vet`, `loom`, `minimal-versions`, Semgrep, hadolint, taplo**
  — real gains but high maintenance or marginal over existing coverage.
- **Branch protection** — repo setting, not a workflow: mark the
  gating jobs above as required checks so "blocks" means blocks.
