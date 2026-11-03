# Parent walk depth

A check walks up its parents to find a terminal, sshd or tmux.
The walk in `person_at_terminal` in `src/open.rs` has no step cap.
This file shows that the walk terminates and times one step.

## Why the walk ends

The walk stops at the first terminal, sshd or tmux.
It stops at init, whose parent is 0.
It also stops at an unreadable parent, such as a process that has exited.
Before each step it records the pid as read.
It stops when it meets a pid it has recorded already.

So a walk reads each pid at most once.
Every pid it reads names a process that was alive at that read.
Say nothing on the chain exits during the walk.
Then it reads the live processes above the check and no more.
In any case it reads no more parents than there are pids.
On Linux that is `pid_max`, which is 4194304 on this machine.
No 64-bit kernel allows more, by `PID_MAX_LIMIT` in `include/linux/threads.h`.
On macOS it is `PID_MAX`, 99999, in `bsd/sys/proc_internal.h` of xnu.

A deep chain makes the walk slow, but the walk still ends.
The verdict does not depend on the walk.
Only the `ancestry=person` note does.

## Machine and code

Machine: `Intel(R) Xeon(R) Processor`, 8 cores, Linux 6.12, Ubuntu 24.04.
Init on this machine is tini.
Code: the commit 'Drop the parent walk step cap'.
It was built with rustc 1.99.1 and the host table.

macOS was not measured.
Its chains may differ from Linux, under Terminal.app, iTerm2 or a tmux that launchd starts.
It reads parents through libproc, so its step cost may differ too.

## What a step costs

A run times 1000 checks of `ljos-policyd check -- rm -rf /srv/x`.
python3 spawns them one after another in `/tmp`.
The run also times 1000 more under the 101 extra shells of `nest.sh 100`.
Odd runs time the shallow row first, and even runs time the nested row first.
Every check spawns a process and loads the table.
That fixed cost is the same in both rows.
So the difference of the two p50 times is the walk.

Neither chain has a terminal, sshd or tmux in it.
The shallow walk reads 7 parents and reaches init.
The nested walk reads 108 parents.
A depth of 100 puts 0.87 ms of walk between the rows.
That is over 40 times the 0.02 ms interquartile range of the shallow row.

Each cell is the median of 8 runs, with the interquartile range after it.
The µs per step of a run comes from its raw p50 times and step counts.
The quartiles are `statistics.quantiles` with the inclusive method.

| shallow p50 ms | nested p50 ms | µs per step |
|---:|---:|---:|
| 11.60 (11.59 to 11.61) | 12.47 (12.47 to 12.48) | 8.68 (8.55 to 8.73) |

At 8.68 µs a step, the 14 parents of the stacked chain below take about 0.12 ms.
The 135 parents of the nested seat test take about 1.17 ms.
The per-run rows are in `parent-walk/runs.csv`.

## Why a check here takes 11.6 ms

`measurements/check-latency.md` gives a host-table p50 of 0.95 ms over its fixture lines.
The shallow row here is 11.60 ms, and the walk is not the cause.
`baseline.sh` times four lines through the same python3 spawn, 8 runs each:

| line | p50 ms |
|---|---:|
| `/bin/true` | 0.31 (0.31 to 0.33) |
| `check -- rm -rf /srv/x` | 11.58 (11.58 to 11.59) |
| the same check with no `git` on `PATH` | 0.81 (0.78 to 0.83) |
| `check -- ls` | 0.85 (0.85 to 0.85) |

The python3 spawn costs about 0.3 ms.
The `rm -rf /srv/x` line runs `git` once, and the check waits for it in 10 ms polls.
That wait is most of the 11.6 ms.
It is the same in the shallow and the nested row, so the difference still measures the walk.
The per-run rows are in `parent-walk/baseline.csv`.

## Where a terminal sits

These chains show how deep common wrappers put a tmux server.
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
The nested seat test in `tests/parent_walk.rs` builds a chain of that shape.
Its tmux is parent 135.

## Reproduce

The scripts are in `measurements/parent-walk/`.
Start the timings from a plain shell.
No terminal, sshd or tmux may sit among its parents:

```sh
cargo build --release
M=$PWD/measurements/parent-walk
B=$PWD/target/release/ljos-policyd
cd /tmp
$M/run.sh "$B" 8 100 1000 > runs.csv
$M/baseline.sh "$B" 8 1000 > baseline.csv
python3 $M/summary.py runs.csv baseline.csv
```

For a chain line, run `chain.sh` or `stack.sh` from bash in a tmux session:

```sh
W="script bash make sh sudo node python3 bash sh"
tmux new-session -d "bash -lc '$M/stack.sh $W >> /tmp/chains.txt'"
```
