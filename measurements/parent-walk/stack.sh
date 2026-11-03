#!/bin/sh
# stack.sh WRAPPER... runs chain.sh under each wrapper in turn, the first
# one outermost. Each wrapper runs this script again with the rest.
here=$(cd "$(dirname "$0")" && pwd)
[ $# -eq 0 ] && exec "$here/chain.sh"
w=$1; shift
case $w in
  script) exec script -qec "$0 $*" /dev/null ;;
  make) printf 'all:\n\t%s %s\n' "$0" "$*" | exec make -s -f - ;;
  sudo) exec sudo -n env PATH="$PATH" "$0" "$@" ;;
  node) exec node -e 'const r = require("child_process").spawnSync(process.argv[1], process.argv.slice(2), {stdio: "inherit"}); process.exit(r.status)' "$0" "$@" ;;
  python3) exec python3 -c 'import subprocess, sys; sys.exit(subprocess.call(sys.argv[1:]))' "$0" "$@" ;;
  bash) exec bash -c '"$@"; exit $?' bash "$0" "$@" ;;
  sh) exec sh -c '"$@"; exit $?' sh "$0" "$@" ;;
  *) echo "stack.sh: no wrapper named $w" >&2; exit 2 ;;
esac
