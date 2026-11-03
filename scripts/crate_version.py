#!/usr/bin/env python3
"""The crate's name and version, read from Cargo.toml.

The version is written in that file. Cog calls ``version_line`` for each
sample of ``ljos-policyd version``.
"""

from __future__ import annotations

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
