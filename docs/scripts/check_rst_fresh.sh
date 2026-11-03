#!/usr/bin/env bash
# Fail when docs/source is not what export_org_to_rst.sh just wrote.
# Run it after that script. A new org page is an untracked rst; git diff
# alone would not see it, so those paths are marked intent-to-add first.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Same pin as need= in ensure_pandoc.sh. Checked here so a host whose
# pandoc reflows the export fails on the version instead of a wall of
# wrapping.
need=3.7.0.2
have="$(pandoc --version | awk 'NR==1 { print $2 }')"
if [[ "$have" != "$need" ]]; then
  echo "check_rst_fresh: pandoc is $have, and docs/source is generated with $need." >&2
  echo "Run docs/scripts/ensure_pandoc.sh, then docs/scripts/export_org_to_rst.sh." >&2
  exit 1
fi

others="$(git ls-files --others --exclude-standard -- docs/source)"
if [[ -n "$others" ]]; then
  # shellcheck disable=SC2086
  git add --intent-to-add -- $others
fi

# Against HEAD, not the index: a staged export that was not regenerated
# from the org on this run still fails.
if ! git diff --exit-code HEAD -- docs/source; then
  echo "docs/source does not match docs/orgmode." >&2
  echo "Run docs/scripts/export_org_to_rst.sh and commit the rst it writes." >&2
  exit 1
fi
echo "check_rst_fresh: docs/source matches the org export"
