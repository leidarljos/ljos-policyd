# Parent walk depth

`PARENT_WALK_STEPS` in `src/open.rs` is how many parents a check reads, looking for a terminal, sshd or tmux, before it stops.
This file is where its value comes from.

Machine: Intel(R) Xeon(R) Processor, 8 cores, Linux 6.12, Ubuntu 24.04.
Code: commit 8c315430e84f0f0fc93f881beeeca946d8b8637f, with the cap first at 64 and then at `PARENT_WALK_STEPS`, built with rustc 1.99.1, host table.
The chains and the timings were measured on Linux only. macOS was not measured.

## How deep a terminal sits

Each line is a process run in a tmux session, with its parents listed from the nearest one up to init.
The number is how many parents it has.
The script that prints them is at the end.

    3: bash tmux: server tini
    4: sh bash tmux: server tini
    4: script bash tmux: server tini
    5: sh make bash tmux: server tini
    6: sh sudo sudo bash tmux: server tini
    6: sh sh node bash tmux: server tini
    4: python3 bash tmux: server tini

The tmux server forks away from the terminal that started it, so its parent is init, or the user's service manager on a desktop.
Whatever started tmux, such as an IDE terminal or a desktop session, is not on the walk's path.
The walk stops at the first terminal, sshd or tmux, so the cap only has to reach that far.

With every wrapper on this machine stacked in one chain, a `script` running `bash` running `make`, then `sh`, `sudo`, `node`, `python3`, `bash` and `sh`, the tmux server is parent 19:

    20: sh l5.sh bash python3 l4.sh sh node l3.sh sh sudo sudo l2.sh sh sh make bash script bash tmux: server tini

A seat started inside another seat, for example from that seat's hook, repeats the part of the chain below the tmux server.
So the cap is twice the deepest chain: 2 × 19 = 38.
A check whose terminal is further up than that does not get `ancestry=person`. It still answers as before.

## What a step costs

Each row is 1000 `ljos-policyd check -- rm -rf /srv/x` runs spawned one after another from python3 in `/tmp`.
In the shallow row python3 has 4 parents, so the walk reads 5 parents and reaches init.
The nested row runs under 100 more shells, so the walk reads parents until it reaches the cap.
Every check spawns a process and loads the table, so each time is mostly fixed cost. Only the difference between the rows is the walk.
Three runs of each pair, p50 in ms:

| cap | shallow | nested | difference | extra steps | µs per step |
|---:|---:|---:|---:|---:|---:|
| 64 | 11.59 | 12.09 | 0.50 | 59 | 8.5 |
| 64 | 11.51 | 12.06 | 0.55 | 59 | 9.3 |
| 64 | 11.56 | 12.06 | 0.50 | 59 | 8.5 |
| 38 | 11.60 | 11.88 | 0.28 | 33 | 8.5 |
| 38 | 11.55 | 11.88 | 0.33 | 33 | 10.0 |
| 38 | 11.56 | 11.98 | 0.42 | 33 | 12.7 |

At 38 steps, a walk that finds no terminal costs about 0.3 to 0.4 ms. With the cap at 64, it cost about 0.5 ms.

## Reproduce

`chain.sh` prints the parents of the process that runs it:

    #!/bin/sh
    p=$PPID n=0 line=
    while [ -n "$p" ] && [ "$p" != 0 ]; do
      n=$((n+1)); line="$line $(cat /proc/$p/comm)"
      p=$(awk '/^PPid:/{print $2}' /proc/$p/status)
    done
    echo "$n:$line"

`nest.sh N CMD...` runs CMD under N more shells:

    #!/bin/sh
    n=$1; shift
    if [ "$n" -gt 0 ]; then "$0" $((n-1)) "$@"; exit $?; fi
    "$@"

The timings came from `nest.sh 100 python3 time_check.py target/release/ljos-policyd 1000` and from the same python3 line without `nest.sh`.
`time_check.py` runs the check N times with `LJOS_POLICYD_DAEMON` unset and prints nearest-rank percentiles.
