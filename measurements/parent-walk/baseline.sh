#!/bin/sh
# baseline.sh BIN RUNS CHECKS prints one CSV row per line timed per run.
# It splits the shallow row's time: the python3 spawn alone (`/bin/true`),
# the warning line, the same line with no `git` on PATH, and an `ls` line.
# Each run shifts the order by one, so every line takes every slot.
set -e
bin=$1 runs=$2 checks=$3
here=$(cd "$(dirname "$0")" && pwd)
py=$(command -v python3)
line() {
  case $1 in
    true) "$py" "$here/time_check.py" /bin/true "$checks" ;;
    warn) "$py" "$here/time_check.py" "$bin" "$checks" ;;
    warn-no-git) PATH=/nonexistent "$py" "$here/time_check.py" "$bin" "$checks" ;;
    ls) "$py" "$here/time_check.py" "$bin" "$checks" check -- ls ;;
  esac
}
echo "run,line,p50_ms"
i=1
while [ "$i" -le "$runs" ]; do
  set -- true warn warn-no-git ls
  k=$(( (i - 1) % 4 ))
  while [ "$k" -gt 0 ]; do first=$1; shift; set -- "$@" "$first"; k=$((k - 1)); done
  for name in "$@"; do echo "$i,$name,$(line "$name")"; done
  i=$((i + 1))
done
