#!/usr/bin/env python3
"""Finish the org to RST export: restore the toctree, refuse a corrupting shape.

Two failures here are quiet rather than loud, which is why they are checked
instead of trusted:

- Pandoc drops a trailing ``rst`` export block often enough that a build comes
  out with every guide orphaned and no way to reach it from the index.
- A line that begins with ``[12]`` is a footnote *definition* in RST. When the
  citation markers in this project's prose land at column zero, docutils eats
  the surrounding sentence into a footnote nobody references. The build still
  succeeds; the page loses text.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# The pages a site has are the org files it has, index aside, in a fixed order.
_ORG = Path(__file__).resolve().parents[1] / "orgmode"
_ORDER = ["getting-started", "howto", "reference", "explanation", "architecture"]
PAGES = [p for p in _ORDER if (_ORG / f"{p}.org").is_file()] + sorted(
    q.stem for q in _ORG.glob("*.org") if q.stem not in _ORDER and q.stem != "index"
)

TOCTREE = """

.. toctree::
   :maxdepth: 1
   :caption: Guides
   :hidden:

""" + "".join(f"   {page}\n" for page in PAGES)

_FOOTNOTE_DEF = re.compile(r"^\[\d+\]")


def restore_toctree(index: Path) -> None:
    text = index.read_text(encoding="utf-8")
    if ".. toctree::" in text:
        print("index.rst: toctree present")
        return
    index.write_text(text.rstrip("\n") + TOCTREE, encoding="utf-8")
    print("index.rst: toctree restored")


def bracket_leading_lines(path: Path) -> list[tuple[int, str]]:
    return [
        (number, line)
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1)
        if _FOOTNOTE_DEF.match(line)
    ]


def main() -> int:
    source = Path("docs/source")
    index = source / "index.rst"
    if not index.is_file():
        print("missing docs/source/index.rst after export", file=sys.stderr)
        return 1
    restore_toctree(index)

    missing = [page for page in PAGES if not (source / f"{page}.rst").is_file()]
    if missing:
        print(f"missing exported pages: {', '.join(missing)}", file=sys.stderr)
        return 1

    failed = False
    for org in sorted(Path("docs/orgmode").glob("*.org")):
        for number, line in bracket_leading_lines(org):
            print(
                f"{org}:{number}: a line starting with a citation marker becomes an "
                f"RST footnote and swallows the sentence; rewrap it\n    {line}",
                file=sys.stderr,
            )
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
