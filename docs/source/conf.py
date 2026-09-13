"""Sphinx configuration for the ljos-policyd project site (Shibuya theme)."""

from __future__ import annotations

from pathlib import Path

_DOCS = Path(__file__).resolve().parent
_ROOT = _DOCS.parent.parent

project = "ljos-policyd"
copyright = "2026, Rohit Goswami"
author = "Rohit Goswami"
release = "0.1.0"
version = "0.1"

extensions = [
    "sphinx.ext.mathjax",
    "sphinx_copybutton",
    "sphinx_design",
]

templates_path = ["_templates"]
exclude_patterns: list[str] = []

html_theme = "shibuya"
html_static_path = ["_static"]
html_favicon = "_static/favicon.svg"
html_logo = "_static/logo.svg"
html_title = "ljos-policyd"
html_css_files = ["custom.css"]

html_context = {
    "source_type": "github",
    "source_user": "leidarljos",
    "source_repo": "ljos-policyd",
    "source_version": "main",
    "source_docs_path": "/docs/source/",
}

html_theme_options = {
    "accent_color": "gold",
    "color_mode": "dark",
    "dark_code": True,
    "github_url": "https://github.com/leidarljos/ljos-policyd",
    "nav_links": [
        {"title": "Get started", "url": "getting-started"},
        {"title": "How-to", "url": "howto"},
        {"title": "Reference", "url": "reference"},
        {"title": "Explanation", "url": "explanation"},
    ],
}

# Offline builds must not reach for an inventory.
intersphinx_mapping: dict = {}

copybutton_prompt_text = r"\$ "
copybutton_prompt_is_regexp = True
