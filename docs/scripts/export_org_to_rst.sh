#!/usr/bin/env bash
# Export docs/orgmode/*.org → docs/source/*.rst
# Prefer pandoc (available on many hosts); optional: VISSUE_DOC_EXPORTER=emacs
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
ORG_DIR="docs/orgmode"
OUT_DIR="docs/source"
mkdir -p "$OUT_DIR"

exporter="${VISSUE_DOC_EXPORTER:-auto}"
if [[ "$exporter" == "auto" ]]; then
  if command -v pandoc >/dev/null 2>&1; then
    exporter=pandoc
  elif command -v emacs >/dev/null 2>&1; then
    exporter=emacs
  else
    echo "error: need pandoc or emacs to export org → rst" >&2
    exit 1
  fi
fi

# Before the export, because both classes this catches produce valid output
# that renders wrong, so nothing downstream will complain about them.
python3 docs/scripts/check_org.py

echo "export_org_to_rst: using $exporter"
if [[ "$exporter" == "emacs" ]]; then
  emacs --batch -l docs/export.el
else
  shopt -s nullglob
  files=("$ORG_DIR"/*.org)
  if ((${#files[@]} == 0)); then
    echo "error: no org files in $ORG_DIR" >&2
    exit 1
  fi
  for org in "${files[@]}"; do
    base="$(basename "$org" .org)"
    # --columns wide enough that pandoc emits simple tables rather than grid
    # tables, which at 400 it does for every table here. A grid cell is wrapped
    # to its column width, and wrapping splits a long `=verbatim=` across two
    # lines: docutils then has an inline literal that never closes, which is a
    # broken literal on the rendered page. The split point moves with the
    # pandoc version, so the same source built clean on one host and warned on
    # another.
    pandoc -f org -t rst --wrap=preserve --columns=400 -o "$OUT_DIR/${base}.rst" "$org"
    echo "  wrote $OUT_DIR/${base}.rst"
  done
fi

python3 docs/scripts/fix_doc_links.py

# Restore the toctree pandoc drops, and refuse an org line that would turn
# into an RST footnote and eat the sentence around it.
python3 docs/scripts/finish_export.py
