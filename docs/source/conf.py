"""Sphinx configuration for the ljos-policyd project site (Shibuya theme)."""

from __future__ import annotations

import html
import re
from pathlib import Path

_DOCS = Path(__file__).resolve().parent
_ROOT = _DOCS.parent.parent
_ORG = _ROOT / "docs" / "orgmode"
_SITE = "https://leidarljos.github.io/ljos-policyd/"
_OG_IMAGE = _SITE + "_static/og.png"
_EDIT = "https://github.com/leidarljos/ljos-policyd/blob/main/docs/orgmode/{stem}.org"

# Generated pages have no org source. The others take #+title and #+description.
_GENERATED = {
    "search": ("Search", "Search the ljos-policyd documentation."),
    "genindex": ("Index", "Index of the ljos-policyd documentation."),
}

project = "ljos-policyd"
copyright = "2026, Rohit Goswami"
author = "Rohit Goswami"
release = "0.4.5"
version = "0.4.5"

extensions = [
    "sphinx.ext.mathjax",
    "sphinx_copybutton",
]

templates_path = ["_templates"]
exclude_patterns: list[str] = []

html_theme = "shibuya"
html_static_path = ["_static"]
html_favicon = "_static/favicon.svg"
html_logo = "_static/mark.svg"
html_title = "ljos-policyd"
html_css_files = ["custom.css"]
html_baseurl = _SITE
html_copy_source = True
html_show_sourcelink = True
# Empty, so the copied source is ``_sources/<page>.rst`` and the view-source
# URL names that file. The default ``.txt`` asked GitHub for ``page.rst.txt``.
html_sourcelink_suffix = ""

html_context = {
    "source_type": "github",
    "source_user": "leidarljos",
    "source_repo": "ljos-policyd",
    "source_version": "main",
    "source_docs_path": "/docs/source/",
}

html_theme_options = {
    "accent_color": "gold",
    "color_mode": "auto",
    "dark_code": True,
    "open_in_chatgpt": False,
    "open_in_claude": False,
    "og_image_url": _OG_IMAGE,
    "github_url": "https://github.com/leidarljos/ljos-policyd",
    "nav_links": [
        {"title": "Get started", "url": "getting-started"},
        {"title": "How-to", "url": "howto"},
        {"title": "Reference", "url": "reference"},
        {"title": "Explanation", "url": "explanation"},
        {"title": "Search", "url": "search"},
    ],
}

# Offline builds must not reach for an inventory.
intersphinx_mapping: dict = {}

copybutton_prompt_text = r"\$ "
copybutton_prompt_is_regexp = True

_H1_OPEN = re.compile(r"<h1\b([^>]*)>", re.I)
_H1_BLOCK = re.compile(r"<h1\b[^>]*>(.*?)</h1>", re.I | re.S)
_HEADERLINK = re.compile(r"<a\b[^>]*\bheaderlink\b[^>]*>.*?</a>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_BLANK_ANCHOR = re.compile(r"<a\b[^>]*>", re.I)
_TARGET_BLANK = re.compile(r"""\btarget\s*=\s*(['"])_blank\1""", re.I)
_REL = re.compile(r"""\brel\s*=\s*(['"])(.*?)\1""", re.I)


def _org_field(pagename: str, key: str) -> str | None:
    path = _ORG / f"{pagename}.org"
    if not path.is_file():
        return None
    prefix = f"#+{key}:"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lower().startswith(prefix.lower()):
            return line.split(":", 1)[1].strip()
    return None


def _page_title(pagename: str) -> str | None:
    if pagename in _GENERATED:
        return _GENERATED[pagename][0]
    return _org_field(pagename, "title")


def _page_description(pagename: str) -> str | None:
    if pagename in _GENERATED:
        return _GENERATED[pagename][1]
    return _org_field(pagename, "description")


def _heading_text(inner: str) -> str:
    text = _HEADERLINK.sub("", inner)
    text = _TAG.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def _demote_extra_h1(body: str, title: str) -> str:
    """One h1, the page title. Other headings stay h2 with class ``ll-h1``.

    ``ll-h1`` keeps the size and spacing an h1 had, so a section that used
    to be the page's only heading level does not change size.
    """
    texts = [_heading_text(m.group(1)) for m in _H1_BLOCK.finditer(body)]
    if len(texts) == 1 and texts[0] == title:
        return body

    def open_tag(match: re.Match[str]) -> str:
        attrs = match.group(1)
        if re.search(r"\bclass\s*=", attrs, re.I):
            attrs = re.sub(
                r"""\bclass\s*=\s*(['"])""",
                r"class=\1ll-h1 ",
                attrs,
                count=1,
                flags=re.I,
            )
        else:
            attrs = attrs + ' class="ll-h1"'
        return f"<h2{attrs}>"

    body = _H1_OPEN.sub(open_tag, body)
    body = re.sub(r"</h1>", "</h2>", body, flags=re.I)
    return f'<h1 class="ll-sr-only">{html.escape(title)}</h1>\n' + body


def _on_page(app, pagename, templatename, context, doctree) -> None:
    del app, templatename, doctree
    title = _page_title(pagename)
    if title:
        context["title"] = title
    description = _page_description(pagename)
    meta = context.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        context["meta"] = meta
    if description and not meta.get("description"):
        meta["description"] = description
    if not meta.get("cover"):
        meta["cover"] = _OG_IMAGE
    body = context.get("body")
    if title and isinstance(body, str) and "<h1" in body.lower():
        context["body"] = _demote_extra_h1(body, title)


def _edit_org(app) -> None:
    """Edit this page opens the org file the export builds from."""

    def edit_source_link(filename: str) -> str | None:
        stem = filename
        for suffix in (".rst.txt", ".rst", ".org", ".md", ".txt"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        if not (_ORG / f"{stem}.org").is_file():
            return None
        return _EDIT.format(stem=stem)

    app.builder.templates.environment.globals["edit_source_link"] = edit_source_link


def _rel_noopener(tag: str) -> str:
    if not _TARGET_BLANK.search(tag):
        return tag
    found = _REL.search(tag)
    if not found:
        return tag[:-1] + ' rel="noopener noreferrer">'
    tokens = found.group(2).split()
    for name in ("noopener", "noreferrer"):
        if name not in tokens:
            tokens.append(name)
    return tag[: found.start(2)] + " ".join(tokens) + tag[found.end(2) :]


def _blank_noopener(app, exception) -> None:
    if exception is not None:
        return
    out = Path(app.outdir)
    for path in out.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        fixed = _BLANK_ANCHOR.sub(lambda m: _rel_noopener(m.group(0)), text)
        if fixed != text:
            path.write_text(fixed, encoding="utf-8")


def setup(app) -> None:
    app.connect("builder-inited", _edit_org, priority=900)
    app.connect("html-page-context", _on_page)
    app.connect("build-finished", _blank_noopener)
