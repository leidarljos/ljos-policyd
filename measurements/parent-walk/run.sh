#!/bin/sh
# run.sh BIN RUNS DEPTH CHECKS prints one CSV row per run.
# A run times CHECKS checks from python3, and CHECKS more under DEPTH + 1
# extra shells. Odd runs time the shallow row first and even runs the
# nested row first, so the order is ABBA over each pair of runs. Run it
# where no terminal, sshd or tmux is a parent, or the walk stops there.
set -e
bin=$1 runs=$2 depth=$3 checks=$4
here=$(cd "$(dirname "$0")" && pwd)
# chain.sh run from python3 has the parents a check run from python3 reads.
shallow_steps=$(python3 -c 'import subprocess, sys; subprocess.call(sys.argv[1:])' "$here/chain.sh" | cut -d: -f1)
nested_steps=$((shallow_steps + depth + 1))
shallow() { python3 "$here/time_check.py" "$bin" "$checks"; }
nested() { "$here/nest.sh" "$depth" python3 "$here/time_check.py" "$bin" "$checks"; }
echo "run,order,depth,checks,shallow_ms,nested_ms,shallow_steps,nested_steps"
i=1
while [ "$i" -le "$runs" ]; do
  if [ $((i % 2)) -eq 1 ]; then
    order=shallow-first; s=$(shallow); d=$(nested)
  else
    order=nested-first; d=$(nested); s=$(shallow)
  fi
  echo "$i,$order,$depth,$checks,$s,$d,$shallow_steps,$nested_steps"
  i=$((i + 1))
done
