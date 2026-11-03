#!/usr/bin/env python3
"""The crate's name and version, read from Cargo.toml.

The version is written in that file. Cog calls ``version_line`` for each
sample of ``ljos-policyd version``. Run as a program on a tag build, this
checks the tag against the same version.
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CARGO = _ROOT / "Cargo.toml"


def package() -> tuple[str, str]:
    with _CARGO.open("rb") as fh:
        data = tomllib.load(fh)
    pkg = data["package"]
    return pkg["name"], pkg["version"]


def version_line(backend: str = "phronesis") -> str:
    """The line a phronesis build prints for ``ljos-policyd version``."""
    name, version = package()
    return f"{name} {version} ({backend})"


def main() -> int:
    tag = os.environ.get("GITHUB_REF_NAME", "")
    name, version = package()
    if not tag.startswith("v"):
        print(f"the ref {tag} is not a version tag", file=sys.stderr)
        return 1
    numbered = tag[1:]
    if numbered != version:
        print(
            f"the tag {tag} and {name} {version} in Cargo.toml disagree",
            file=sys.stderr,
        )
        return 1
    print(f"{name} {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
