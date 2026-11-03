#!/usr/bin/env python3
"""Stop pandoc's org reader splitting two spans this tree actually writes.

Pandoc closes a ``=verbatim=`` span at an ``=`` that is followed by a
quote. A shell assignment is written that way (``HOME="$PWD/.home"``),
so the span ends at ``HOME`` and the next ``=word=`` is swallowed by the
leftover marker. The rst is still valid, sphinx exits 0, and the page
shows a broken literal.

Pandoc also reads ``word_word`` as a subscript. The org wrote an
ordinary word (``inet_aton``). The subscript is not that word, and
the page already names it in a code span, so the underscore is put
back as one.

Both stand-ins are a single character. A longer token changes the line
length, and ``--wrap=preserve`` then reflows a paragraph that was fine.
The characters are not used in these org sources. Blocks pandoc already
leaves alone (source, export, example) are not rewritten: an HTML
attribute is also written ``="``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# U+2261 IDENTICAL TO. One character, absent from the org sources, and
# passed through by pandoc 3.7.0.2 as ordinary text inside a code span.
_EQ = "≡"
# U+2260 NOT EQUAL TO. Same constraints, for an underscore pandoc would
# otherwise turn into a subscript.
_US = "≠"

_OPEN = ("#+begin_src", "#+begin_export", "#+begin_example")
_CLOSE = ("#+end_src", "#+end_export", "#+end_example")


def _in_block(line: str, depth: int) -> int:
    head = line.lstrip().lower()
    if depth == 0 and head.startswith(_OPEN):
        return 1
    if depth and head.startswith(_CLOSE):
        return 0
    return depth


def guard_text(text: str) -> str:
    out: list[str] = []
    depth = 0
    for line in text.splitlines(keepends=True):
        depth = _in_block(line, depth)
        if depth or line.lstrip().lower().startswith(_CLOSE):
            out.append(line)
            continue
        guarded = line.replace('="', _EQ + '"')
        pieces: list[str] = []
        i = 0
        while i < len(guarded):
            ch = guarded[i]
            if (
                ch == "_"
                and i > 0
                and i + 1 < len(guarded)
                and guarded[i - 1].isalnum()
                and guarded[i + 1].isalnum()
            ):
                pieces.append(_US)
            else:
                pieces.append(ch)
            i += 1
        out.append("".join(pieces))
    return "".join(out)


def unguard_text(text: str) -> str:
    """Put the stand-ins back.

    An underscore inside a code span is an underscore. One in prose
    becomes a code span: that is the word pandoc had turned into a
    subscript, and it is how this page already writes ``inet_aton``.
    """
    text = text.replace(_EQ, "=")
    out: list[str] = []
    i = 0
    while True:
        start = text.find("``", i)
        if start < 0:
            out.append(_prose_underscore(text[i:]))
            break
        out.append(_prose_underscore(text[i:start]))
        end = text.find("``", start + 2)
        if end < 0:
            out.append(text[start:].replace(_US, "_"))
            break
        out.append(text[start : end + 2].replace(_US, "_"))
        i = end + 2
    return "".join(out)


def _prose_underscore(text: str) -> str:
    return re.sub(
        rf"([A-Za-z0-9]+){_US}([A-Za-z0-9]+)",
        r"``\1_\2``",
        text,
    )


def guard_dir(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    org = sorted(src.glob("*.org"))
    if not org:
        print(f"pandoc_org: no org files in {src}", file=sys.stderr)
        raise SystemExit(1)
    for path in org:
        (dest / path.name).write_text(
            guard_text(path.read_text(encoding="utf-8")),
            encoding="utf-8",
        )


def unguard_dir(src: Path) -> None:
    for path in sorted(src.glob("*.rst")):
        raw = path.read_text(encoding="utf-8")
        fixed = unguard_text(raw)
        if fixed != raw:
            path.write_text(fixed, encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "guard":
        guard_dir(Path(argv[2]), Path(argv[3]))
        return 0
    if len(argv) == 3 and argv[1] == "unguard":
        unguard_dir(Path(argv[2]))
        return 0
    print("usage: pandoc_org.py guard SRC DEST | unguard RST_DIR", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
