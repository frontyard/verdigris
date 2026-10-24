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


def main() -> int:
    order = []
    for m in re.finditer(r"\]\((\./[^)]+)\)", open(os.path.join(SRC, "SUMMARY.md")).read()):
        p = os.path.join(SRC, m.group(1)[2:])
        if os.path.exists(p):
            order.append(p)
    parts = ["# verdigris — complete documentation\n\n",
             open(os.path.join(ROOT, "llms.txt")).read(), "\n\n"]
    for p in order:
        parts += [f"\n\n---\n\n", open(p).read(), "\n"]
    open(OUT, "w").write("".join(parts))
    print(f"wrote {OUT} ({len(order)} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
