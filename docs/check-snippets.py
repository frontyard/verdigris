#!/usr/bin/env python3
"""Validate every ```toml block in the book against `verd validate`.

Blocks that are complete configs run as-is. Fragments are wrapped in
enough context to validate: route-level fields get a [[site.route]] +
respond handler, site-level fields get [[site]], and snippets that open
with a table header are treated as top-level config. A `conf.d/` dir is
provided so `include` snippets resolve, and dummy env vars cover
`${VAR}` interpolation.

Usage: docs/check-snippets.py [path/to/verd]
Exit status is non-zero when any block fails to validate.
"""
import glob
import os
import re
import subprocess
import sys
import tempfile

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "..", "target", "release", "verd"
)
BIN = os.path.abspath(BIN)

ROUTE_FIELDS = re.compile(
    r"^(auth|cors|rate_limit|compress|security|response_headers|cache|limits"
    r"|timeouts|ip_allow|ip_deny|proxy|static|respond|redirect|exact|prefix"
    r"|regex|match|priority)\s*="
)
SITE_FIELDS = re.compile(r"^(tls|hosts|name|root|proxy|redirect_https"
                         r"|redirect_host|trusted_proxies|default)\s*=")

ENV = dict(
    os.environ,
    ADMIN_TOKEN="x" * 24,
    API_TOKEN="x" * 24,
    KEY1="x" * 24,
    CF_API_TOKEN="x" * 24,
)

def wrap(block: str) -> str:
    stripped = "\n".join(
        l for l in block.splitlines() if not l.lstrip().startswith("#")
    ).strip() or block
    if "[[site" in stripped or stripped.startswith(("include", "[")):
        if "[[site.route]]" in stripped and "[[site]]" not in stripped:
            block = f"[[site]]\ndefault = true\n{block}"
        # a route table shown without a handler gets a dummy one so the
        # snippet is a complete config
        if "[[site.route]]" in block and not re.search(
            r"^\s*(static|proxy|redirect|respond)\s*=", block, re.M
        ):
            idx = block.rindex("[[site.route]]")
            eol = block.index("\n", idx)
            block = (
                block[:eol] + '\nrespond = { status = 200, body = "ok" }' + block[eol:]
            )
        return block + "\n"
    if ROUTE_FIELDS.match(stripped):
        return (
            "[[site]]\ndefault = true\n[[site.route]]\nprefix = \"/\"\n"
            'respond = { status = 200, body = "ok" }\n' + block + "\n"
        )
    if SITE_FIELDS.match(stripped):
        return f"[[site]]\ndefault = true\n{block}\n"
    return block + "\n"

def main() -> int:
    fails = 0
    files = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "book/src/*.md")))
    files.append(os.path.join(os.path.dirname(__file__), "..", "llms.txt"))
    files.append(os.path.join(os.path.dirname(__file__), "..", "README.md"))
    for f in files:
        for i, m in enumerate(re.finditer(r"```toml\n(.*?)```", open(f).read(), re.S)):
            body = wrap(m.group(1).strip())
            with tempfile.TemporaryDirectory() as td:
                os.mkdir(os.path.join(td, "conf.d"))
                p = os.path.join(td, "cfg.toml")
                open(p, "w").write(body)
                r = subprocess.run(
                    [BIN, "validate", "-c", p],
                    capture_output=True, text=True, env=ENV, cwd=td,
                )
            if r.returncode != 0:
                fails += 1
                print(f"=== {os.path.basename(f)} block#{i} ===")
                print(body[:400])
                print("---", (r.stderr or r.stdout)[:300])
    print(f"{fails} failing snippet(s)")
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
