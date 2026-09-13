#!/usr/bin/env python3
"""Two things the org sources have to get right, checked before they export.

A line that starts with digits and a dot is an ordered list item to Org,
whatever the author meant. A sentence that wrapped so a number landed in
column zero therefore renders as a stray list and splits the paragraph
around it, and neither the exporter nor sphinx complains: the result is
valid, just wrong. One of those shipped.

And the explanation page says every numbered reference has a row in the
audit table and that each was resolved before it was pasted. That claim
is only worth something if the numbering itself holds together, so the
citations and the entries are checked against each other here.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ORG = ROOT / "docs" / "orgmode"
NUMBERED = re.compile(r"^(\d+)\.\s")
CITED = re.compile(r"\[(\d+)\]")


def stray_list_items(text: str, references_at: int | None) -> list[tuple[int, str]]:
    """Numbered lines outside the deliberate reference list."""
    out = []
    for lineno, line in enumerate(text.split("\n"), 1):
        if not NUMBERED.match(line):
            continue
        if references_at is not None and lineno > references_at:
            continue
        out.append((lineno, line))
    return out


def references_line(text: str) -> int | None:
    for lineno, line in enumerate(text.split("\n"), 1):
        if line.strip() == "* References":
            return lineno
    return None


def bibliography_problems(text: str, references_at: int) -> list[str]:
    body, refs = text.split("\n")[: references_at - 1], text.split("\n")[references_at - 1 :]
    defined: list[int] = [int(m.group(1)) for line in refs if (m := NUMBERED.match(line))]
    cited = {int(m.group(1)) for m in CITED.finditer("\n".join(body))}
    problems = []
    for number in sorted({n for n in defined if defined.count(n) > 1}):
        problems.append(f"reference {number} is defined twice")
    if defined and sorted(set(defined)) != list(range(1, max(defined) + 1)):
        missing = [n for n in range(1, max(defined) + 1) if n not in defined]
        problems.append(f"the reference list skips {missing}")
    for number in sorted(cited - set(defined)):
        problems.append(f"[{number}] is cited and has no entry")
    for number in sorted(set(defined) - cited):
        problems.append(f"reference {number} has an entry and is cited nowhere")
    return problems


def main() -> int:
    findings: list[str] = []
    for path in sorted(ORG.glob("*.org")):
        text = path.read_text()
        at = references_line(text)
        for lineno, line in stray_list_items(text, at):
            findings.append(
                f"{path.relative_to(ROOT)}:{lineno}: a wrapped line starts a numbered "
                f"list: {line.strip()[:60]!r}"
            )
        if at is not None:
            for problem in bibliography_problems(text, at):
                findings.append(f"{path.relative_to(ROOT)}: {problem}")
    for finding in findings:
        print(f"check_org: {finding}", file=sys.stderr)
    if findings:
        return 1
    print("check_org: org sources are consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
