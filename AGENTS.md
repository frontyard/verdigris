# Working agreements

## Changelog

`CHANGELOG.md` must stay current with user-visible changes. When a
change lands, add a **succinct** bullet under `## [Unreleased]` —
**always** `[Unreleased]`, never into an already-tagged version section
(tagged sections are frozen: the release workflow used them as the
published release notes, so post-release edits there would diverge from
what GitHub shows):

- Keep a Changelog format: `### Security` / `Added` / `Changed` /
  `Fixed` / `Build & CI` (create a heading only when it has entries).
- One bullet per change, bold lead-in, path/config keys in backticks,
  focus on impact not implementation. Internal-only refactors with no
  user-visible effect can be skipped.
- At release time the maintainer renames `## [Unreleased]` to
  `## [x.y.z] - YYYY-MM-DD` and bumps `Cargo.toml`; the release workflow
  publishes that section as the GitHub release notes automatically.

## Verification

`cargo test --all-targets`, `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check`, `cargo deny check`. `docs/book/src/reference.md` is
generated — regenerate with `cargo run -- schema | python3
docs/gen-reference.py > docs/book/src/reference.md`, never edit by hand.

## Config surface changes

Any change to accepted config shapes must follow
`docs/config-grammar.md` — the frozen list of field forms, shorthand
parity rules, the scalar-vs-list policy, off-switches, and diagnostic
conventions. New forms amend that doc in the same commit, and
`src/config`'s `surface_audit` tests mirror each invariant.
