#!/usr/bin/env python3
"""Write the Open Graph card from the repository logo.

Reads ``docs/source/_static/logo.svg`` (it embeds ``mark.svg``) and writes
``docs/source/_static/og.png`` at 1200 by 630. The logo keeps its own ground,
``#0B0B0A``, and sits in the middle of that card. Requires ``rsvg-convert``
and Pillow.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from PIL import Image

_STATIC = Path(__file__).resolve().parents[1] / "source" / "_static"
_LOGO = _STATIC / "logo.svg"
_OUT = _STATIC / "og.png"
_WIDTH = 1200
_HEIGHT = 630
_GROUND = (0x0B, 0x0B, 0x0A)
_LOGO_WIDTH = 960


def main() -> None:
    if not _LOGO.is_file():
        raise SystemExit(f"missing logo: {_LOGO}")
    with tempfile.TemporaryDirectory() as tmp:
        rendered = Path(tmp) / "logo.png"
        subprocess.run(
            ["rsvg-convert", "-w", str(_LOGO_WIDTH), str(_LOGO), "-o", str(rendered)],
            check=True,
            cwd=_STATIC,
        )
        logo = Image.open(rendered).convert("RGBA")
        canvas = Image.new("RGB", (_WIDTH, _HEIGHT), _GROUND)
        canvas.paste(logo, ((_WIDTH - logo.width) // 2, (_HEIGHT - logo.height) // 2), logo)
        canvas.save(_OUT, "PNG")
    size = Image.open(_OUT).size
    if size != (_WIDTH, _HEIGHT):
        raise SystemExit(f"{_OUT} is {size[0]}x{size[1]}, want {_WIDTH}x{_HEIGHT}")
    print(f"wrote {_OUT} ({_WIDTH}x{_HEIGHT})")


if __name__ == "__main__":
    main()
