# Contributing to verdigris

Bug reports and pull requests are welcome. For security issues, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Requirements for acceptable contributions

A PR is mergeable when it:

- **Passes CI locally first** — the same commands the workflow runs:
  ```sh
  cargo fmt --check
  cargo clippy --all-targets -- -D warnings
  cargo nextest run --all-targets   # or: cargo test --all-targets
  cargo doc --no-deps -D warnings
  cargo deny check                  # supply-chain policy
  ```
- **Keeps `#![deny(unsafe_code)]`** — the only sanctioned `unsafe` is the
  read-only mmap in `src/body.rs`; new unsafe needs a written
  justification in the PR description.
- **Includes tests for behavior changes** — unit tests for logic, and a
  `tests/` integration test when the change is observable over HTTP.
- **Adds a `CHANGELOG.md` bullet** under `## [Unreleased]` for any
  user-visible change (see the convention in `AGENTS.md`).
- **Follows the existing style** — compact idiomatic Rust, no comments
  unless explaining a non-obvious invariant, error messages as
  `lowercase_context`.
- **Keeps commits clean** — imperative subject lines, no secrets or
  vendored artifacts.

Docs: if you touch `src/config`, regenerate the reference —
`cargo run -- schema | python3 docs/gen-reference.py` — and ensure
`python3 docs/check-snippets.py` still passes.

## Process

1. Open an issue first for anything beyond a small fix.
2. Fork, branch from `main`, open a PR against `main`.
3. CI must be green (rustfmt, clippy on stable + MSRV 1.88, tests, audit,
   deny, coverage, zizmor, docs).

## License

Contributions are licensed under the project's dual
MIT OR Apache-2.0 license.
