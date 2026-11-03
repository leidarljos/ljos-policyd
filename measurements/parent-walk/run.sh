#!/bin/sh
# run.sh BIN CAP RUNS DEPTH CHECKS prints one CSV row per run.
# A run times CHECKS checks from python3, then CHECKS more under DEPTH + 1
# extra shells. CAP is the binary's PARENT_WALK_STEPS, so the step count of
# a walk that hits it is right. Run it where no terminal, sshd or tmux is
# a parent, or the walk stops there.
set -e
bin=$1 cap=$2 runs=$3 depth=$4 checks=$5
here=$(cd "$(dirname "$0")" && pwd)
# chain.sh run from python3 has the parents a check run from python3 reads.
shallow_steps=$(python3 -c 'import subprocess, sys; subprocess.call(sys.argv[1:])' "$here/chain.sh" | cut -d: -f1)
nested_steps=$((shallow_steps + depth + 1))
[ "$nested_steps" -gt "$cap" ] && nested_steps=$cap
echo "run,cap,depth,checks,shallow_ms,nested_ms,shallow_steps,nested_steps,us_per_step"
i=1
while [ "$i" -le "$runs" ]; do
  s=$(python3 "$here/time_check.py" "$bin" "$checks")
  d=$("$here/nest.sh" "$depth" python3 "$here/time_check.py" "$bin" "$checks")
  per=$(python3 -c "import sys; s, d, a, b = map(float, sys.argv[1:]); print(f'{(d - s) * 1000 / (b - a):.2f}')" "$s" "$d" "$shallow_steps" "$nested_steps")
  echo "$i,$cap,$depth,$checks,$s,$d,$shallow_steps,$nested_steps,$per"
  i=$((i + 1))
done
