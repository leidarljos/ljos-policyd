#!/usr/bin/env python3
"""The crate's name and version, read from Cargo.toml.

The version is written in that file. Cog calls ``version_line`` for the
README sample of ``ljos-policyd version``. Run as a program on a tag
build, this checks the tag against the same version.
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


def _phronesis() -> dict:
    with _CARGO.open("rb") as fh:
        data = tomllib.load(fh)
    return data["package"]["metadata"]["phronesis"]


def phronesis_rev() -> str:
    """The phronesis commit a build fetches, from Cargo.toml."""
    rev = _phronesis()["rev"]
    if (
        not isinstance(rev, str)
        or len(rev) != 40
        or any(c not in "0123456789abcdef" for c in rev)
    ):
        raise SystemExit("package.metadata.phronesis.rev is not a full commit")
    return rev


def phronesis_version() -> str:
    """The phronesis version named beside that commit, for readers."""
    version = _phronesis()["version"]
    if not isinstance(version, str) or not version:
        raise SystemExit("package.metadata.phronesis.version is empty")
    return version


def main() -> int:
    if sys.argv[1:] == ["--phronesis-rev"]:
        print(phronesis_rev())
        return 0
    if sys.argv[1:] == ["--phronesis-version"]:
        print(phronesis_version())
        return 0
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
