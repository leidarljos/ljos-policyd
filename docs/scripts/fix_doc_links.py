#!/usr/bin/env python3
"""Rewrite org/rst file hyperlinks in exported RST to Sphinx :doc: roles."""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Pandoc anonymous links: `label <foo.org>`__  and single `_` form.
_LINK = re.compile(
    r"`([^`<]+)\s+<((?![a-z][a-z0-9+.-]*:)[^>]+?\.(?:rst|org))>`__?"
)


def fix_text(t: str) -> str:
    def repl(m: re.Match[str]) -> str:
        label = m.group(1).strip().replace("\n", " ")
        target = m.group(2)
        name = Path(target).name
        if name.endswith(".org"):
            name = name[: -len(".org")]
        elif name.endswith(".rst"):
            name = name[: -len(".rst")]
        return f":doc:`{label} <{name}>`"

    t = _LINK.sub(repl, t)
    # Pandoc glues the next section title onto the end of a raw:: html block,
    # which Sphinx reads as an unexpected unindent. Re-separate them wherever
    # a directive body ends and a section title begins.
    t = re.sub(r"\n(   </div>)\n(?=\S)", r"\n\1\n\n", t)
    return t


def main() -> int:
    src = Path("docs/source")
    if not src.is_dir():
        print("docs/source missing", file=sys.stderr)
        return 1
    n = 0
    for path in sorted(src.glob("*.rst")):
        raw = path.read_text(encoding="utf-8")
        fixed = fix_text(raw)
        if fixed != raw:
            path.write_text(fixed, encoding="utf-8")
            n += 1
            print(f"fixed links in {path.name}")
    print(f"fix_doc_links: updated {n} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
