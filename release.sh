#!/usr/bin/env bash
# Release helper: bump version → changelog → lockfile → commit → tag → push.
#
#   scripts/release.sh [patch|minor|major|x.y.z] [-y] [--regen-docs]
#
# - `patch` is the default; an explicit x.y.z is also accepted.
# - The changelog's `## [Unreleased]` content becomes `## [x.y.z] - <date>`
#   (skipped when that section already exists, e.g. written by hand).
# - Cargo.lock is re-synced (CI builds --locked).
# - Commits "Release vX.Y.Z", tags vX.Y.Z, pushes the branch + the tag.
#   The tag push triggers .github/workflows/release.yml which does the
#   rest: artifacts, signatures, GitHub release notes (from the matching
#   changelog section), and the multi-arch GHCR image.
#
# -y           skip the confirmation prompt
# --regen-docs regenerate docs/book/src/reference.md + llms-full.txt
#              (needed when src/config/ changed this cycle)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

bump=patch assume_yes=0 regen=0
for a in "$@"; do
    case "$a" in
        patch|minor|major) bump=$a ;;
        -y|--yes) assume_yes=1 ;;
        --regen-docs) regen=1 ;;
        [0-9]*.[0-9]*.[0-9]*) bump="$a" ;;
        *) echo "unknown arg: $a" >&2; exit 2 ;;
    esac
done

cur=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
case $bump in
    patch) new=$(awk -F. '{printf "%d.%d.%d", $1, $2, $3+1}' <<<"$cur") ;;
    minor) new=$(awk -F. '{printf "%d.%d.0", $1, $2+1}' <<<"$cur") ;;
    major) new=$(awk -F. '{printf "%d.0.0", $1+1}' <<<"$cur") ;;
    *) new=$bump ;;
esac

# --- guardrails -------------------------------------------------------------
git diff --quiet || { echo "uncommitted changes — commit or stash first" >&2; exit 1; }
git diff --cached --quiet || { echo "staged changes — commit or unstage first" >&2; exit 1; }
git rev-parse --verify "refs/tags/v$new" >/dev/null 2>&1 && { echo "tag v$new already exists" >&2; exit 1; }
grep -q "^## \[$new\]" CHANGELOG.md || grep -A6 '## \[Unreleased\]' CHANGELOG.md | grep -q '^- \*\*' \
    || { echo "warning: [Unreleased] is empty and no [$new] section exists" >&2; }

echo "current: $cur  →  new: $new"
if [ "$cur" = "$new" ]; then
    echo "version already $new — skipping bump (changelog/commit/tag only)"
fi
[ $assume_yes -eq 1 ] || { read -r -p "proceed? [y/N] " a; [ "$a" = y ] || exit 0; }

# --- version bump -----------------------------------------------------------
if [ "$cur" != "$new" ]; then
    sed -i "0,/^version = \"$cur\"/s//version = \"$new\"/" Cargo.toml
    cargo metadata --quiet --format-version 1 >/dev/null   # re-sync Cargo.lock
fi

# --- changelog: move Unreleased content under the dated heading -------------
if ! grep -q "^## \[$new\]" CHANGELOG.md; then
    python3 - "$new" <<'EOF'
import re, sys, datetime
v = sys.argv[1]
s = open('CHANGELOG.md').read()
date = datetime.date.today().isoformat()
s = s.replace('## [Unreleased]', f'## [Unreleased]\n\n## [{v}] - {date}', 1)
# link refs: Unreleased compares from the new tag; add the new version's
# compare link against the previous tag.
prev = re.search(r'^\[Unreleased\]: .*/v([0-9.]+)\.\.\.HEAD', s, re.M).group(1)
s = re.sub(r'^\[Unreleased\]: .*HEAD',
           f'[Unreleased]: https://github.com/frontyard/verdigris/compare/v{v}...HEAD', s, flags=re.M)
anchor = f'[Unreleased]: https://github.com/frontyard/verdigris/compare/v{v}...HEAD'
s = s.replace(anchor,
              anchor + f'\n[{v}]: https://github.com/frontyard/verdigris/compare/v{prev}...v{v}', 1)
open('CHANGELOG.md', 'w').write(s)
EOF
fi

if [ $regen -eq 1 ]; then
    cargo run --quiet -- schema | python3 docs/gen-reference.py > docs/book/src/reference.md
    python3 docs/gen-llms-full.py
fi

# --- commit, tag, push -------------------------------------------------------
git add Cargo.toml Cargo.lock CHANGELOG.md
[ $regen -eq 1 ] && git add docs/book/src/reference.md llms-full.txt || true
git diff --cached --quiet || git commit -m "Release v$new"
git tag -a "v$new" -m "verd v$new"
git push
git push origin "v$new"
echo "tagged and pushed v$new — the release workflow does the rest."
