# Parent walk depth

`PARENT_WALK_STEPS` in `src/open.rs` caps how many parents a check reads.
The walk looks for a terminal, sshd or tmux.
This file is where the cap comes from.

## The cap

The walk stops at init.
It also stops at a missing parent or at a pid it read before.
Seats can nest to any depth in ljos.
So no chain depth bounds the walk, and time sets the cap instead.

The budget is 1.2 ms for a walk that finds no terminal.
`measurements/check-latency.md` times the release build.
Its slowest check moved by up to 1.2 ms between runs.
A walk inside that budget adds no more than a check already varies by.

One step costs 8.68 µs here, the median of 8 runs below.
The code rounds that up to 9 µs, so the cap stays inside the budget.
The cap is 1.2 ms divided by 9 µs, which is 133 parents.
At the median cost, a walk of 133 steps takes 1.15 ms.

Past the cap the verdict is unchanged.
Only `ancestry=person` is missing.

## Machine and code

Machine: `Intel(R) Xeon(R) Processor`, 8 cores, Linux 6.12, Ubuntu 24.04.
Init on this machine is tini.
Code: the commit 'Derive the parent walk cap from a latency budget'.
It was built with rustc 1.99.1 and the host table.
The cap 38 rows are the commit 'Give the parent walk cap a measured basis', built the same way.

macOS was not measured.
Its chains may differ from Linux, under Terminal.app, iTerm2 or a tmux that launchd starts.
It reads parents through libproc, so its step cost may differ too.

## What a step costs

A run times 1000 checks of `ljos-policyd check -- rm -rf /srv/x`.
python3 spawns them one after another in `/tmp`.
The run then times 1000 more under the 101 extra shells of `nest.sh 100`.
Every check spawns a process and loads the table.
That fixed cost is the same in both rows.
So the difference of the two p50 times is the walk.

Neither chain has a terminal, sshd or tmux in it.
The shallow walk reads 7 parents and reaches init.
With the cap at 133, the nested walk reads 108 parents.
The cap 38 build stops it at 38.
A depth of 100 stays under the new cap.
It puts 0.89 ms of walk between the rows.
That is about 30 times the 0.03 ms interquartile range of the shallow row.

Each step cost in the table is the median of 8 runs, with the interquartile range after it.
The quartiles of those runs are `statistics.quantiles` with the inclusive method.

| cap | shallow p50 ms | nested p50 ms | µs per step |
|---:|---:|---:|---:|
| 38 | 11.59 (11.58 to 11.60) | 11.89 (11.87 to 11.90) | 9.75 (9.45 to 10.30) |
| 133 | 11.59 (11.59 to 11.62) | 12.48 (12.47 to 12.49) | 8.68 (8.68 to 8.74) |

The cap 38 rows spread wider, because that walk adds 31 steps and not 101.
The cap 38 build also has no set of read pids.
The per-run rows are in `parent-walk/runs-cap38.csv` and `parent-walk/runs-cap133.csv`.

## Where a terminal sits

These chains were not used to set the cap.
They show how deep common wrappers put a tmux server.
Each line comes from `chain.sh` in a tmux session.
It gives the count of parents, then their names, nearest first.

```text
3: bash tmux: server tini
4: nest.sh bash tmux: server tini
4: script bash tmux: server tini
5: make stack.sh bash tmux: server tini
5: sudo sudo bash tmux: server tini
4: node bash tmux: server tini
4: python3 bash tmux: server tini
14: sh bash python3 node sudo sudo sh make stack.sh bash script bash tmux: server tini
```

The last line stacks nine wrappers.
They are `script`, `bash`, `make`, `sh`, `sudo`, `node`, `python3`, `bash` and `sh`.
Its tmux server is parent 13.
The chain of a coding CLI, its hook runner and `ljos hook` was not measured here.
The nested seat test in `tests/parent_walk.rs` builds that chain.
It nests seats as deep as the cap allows.

## Reproduce

The scripts are in `measurements/parent-walk/`.
Start the timings from a plain shell.
No terminal, sshd or tmux may sit among its parents:

```sh
cargo build --release
M=$PWD/measurements/parent-walk
B=$PWD/target/release/ljos-policyd
cd /tmp
$M/run.sh "$B" 133 8 100 1000 > runs-cap133.csv
python3 $M/summary.py runs-cap133.csv
```

The timings take the cap of that build as the second argument of `run.sh`.
It only sets the step count of a walk that hits the cap.

For a chain line, run `chain.sh` or `stack.sh` from bash in a tmux session:

```sh
W="script bash make sh sudo node python3 bash sh"
tmux new-session -d "bash -lc '$M/stack.sh $W >> /tmp/chains.txt'"
```
