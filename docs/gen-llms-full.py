#!/usr/bin/env python3
"""Concatenate llms.txt + every book page into llms-full.txt, in SUMMARY.md
order, so an LLM can ingest the whole corpus in one file. Regenerate with:

    python3 docs/gen-llms-full.py
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "docs", "book", "src")
OUT = os.path.join(ROOT, "llms-full.txt")


def rewrite_links(text: str) -> str:
    # book pages link siblings as (page.md) or (./page.md); rewrite to the
    # repo-relative path so links resolve — and lychee can check them —
    # from llms-full.txt at the repo root
    return re.sub(
        r"\]\((?:\./)?([A-Za-z0-9_-]+\.md(?:#[^)\s]*)?)\)",
        r"](docs/book/src/\1)",
        text,
    )


def main() -> int:
    order = []
    for m in re.finditer(r"\]\((\./[^)]+)\)", open(os.path.join(SRC, "SUMMARY.md")).read()):
        p = os.path.join(SRC, m.group(1)[2:])
        if os.path.exists(p):
            order.append(p)
    llms = open(os.path.join(ROOT, "llms.txt")).read()
    # the curated index must cover every book page, or llms.txt-only
    # readers never learn it exists
    linked = set(re.findall(r"\]\(docs/book/src/([A-Za-z0-9_-]+\.md)[^)]*\)", llms))
    missing = [os.path.basename(p) for p in order if os.path.basename(p) not in linked]
    if missing:
        print("error: llms.txt \"Doc pages\" does not link:", file=sys.stderr)
        for m in missing:
            print(f"  docs/book/src/{m}", file=sys.stderr)
        print("link every SUMMARY.md page so the index cannot drift", file=sys.stderr)
        return 1
    parts = ["# verdigris — complete documentation\n\n", llms, "\n\n"]
    for p in order:
        parts += ["\n\n---\n\n", rewrite_links(open(p).read()), "\n"]
    open(OUT, "w").write("".join(parts))
    print(f"wrote {OUT} ({len(order)} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
