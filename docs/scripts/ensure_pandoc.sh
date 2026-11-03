#!/usr/bin/env bash
# docs/source is the output of this pandoc. Ubuntu 26.04, which the docs
# runner uses, installs it from apt (pandoc 3.7.0.2+ds-1 on the 2026-10-31
# docs run). Pandoc 3.1 and 3.13 reflow the same org, so the diff check
# would fail with no change in the sources. If apt is already this
# version it is kept; otherwise the upstream tarball replaces it.
set -euo pipefail

need=3.7.0.2
have=""
if command -v pandoc >/dev/null 2>&1; then
  have="$(pandoc --version | awk 'NR==1 { print $2 }')"
fi
if [[ "$have" == "$need" ]]; then
  echo "pandoc $need"
  exit 0
fi

archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
curl -fsSL -o "$archive" \
  "https://github.com/jgm/pandoc/releases/download/${need}/pandoc-${need}-linux-amd64.tar.gz"
sudo tar -C /usr/local --strip-components=1 -xzf "$archive"
hash -r
got="$(pandoc --version | awk 'NR==1 { print $2 }')"
if [[ "$got" != "$need" ]]; then
  echo "ensure_pandoc: expected pandoc $need, found ${got:-nothing}" >&2
  exit 1
fi
echo "pandoc $need"
