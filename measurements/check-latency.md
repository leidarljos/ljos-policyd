# `ljos-policyd check` latency

Each number is the wall time of one `ljos-policyd check -- ARGV` process, from spawn to exit, the way a hook calls it.
Checks run one after another.
The lines are the command lines in `tests/fixtures`: every argv `ljos hook` sent policyd in the pyopts17 review (the `A` rows), and every policydpy2 program in the three shapes the hook sends one, plus its shell lines under `bash -c`.
That is 4008 argvs, most of them `python3` lines, since the reviews they come from were of python lines.
Each check runs in a small python project under `target/`, with its own `PHRONESIS_STATE_DIR` and deny log, and with none of the daemon, config, pack, user-allow or consent variables set.
The first row is a first check into a fresh state directory, done 100 times, so the embedded pack is unpacked each time.
The other rows share one state directory.
Percentiles are nearest rank.

Reproduce with:

    cargo bench --bench check_latency
    PHRONESIS_DIR=/path/to/phronesis-prefix cargo bench --bench check_latency

Machine: Intel(R) Xeon(R) Processor (family 6 model 207), 8 cores, Linux 6.12 with a 250 Hz tick.
Code: commit 367ba3927158716ad613cc2876dd4f90d696839d, built with rustc 1.99.1.
phronesis: commit 7d115de79407a54e0be5050f95107cfa08fe6277, the one CI links, built with gcc 13.3.

## phronesis linked, idle

This is the release build.

    ljos-policyd 0.6.4 (phronesis)
    cpu: Intel(R) Xeon(R) Processor (family 6 model 207), 8 cores
    commit: 367ba3927158716ad613cc2876dd4f90d696839d

| lines | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---:|---:|---:|---:|---:|
| first check, fresh state dir | 100 | 3.59 | 4.61 | 4.69 | 4.81 |
| pyopts17/corpus.tsv | 481 | 3.11 | 4.11 | 4.45 | 4.71 |
| pyopts17/ordinary.tsv | 638 | 3.28 | 4.35 | 4.78 | 5.30 |
| pyopts17/risky.tsv | 230 | 3.00 | 3.94 | 4.84 | 5.17 |
| policydpy2/ordinary.tsv | 1060 | 3.05 | 4.18 | 4.41 | 6.04 |
| policydpy2/items.tsv | 348 | 3.06 | 4.15 | 4.39 | 4.55 |
| policydpy2/classes.tsv | 1251 | 3.11 | 4.22 | 4.45 | 6.39 |
| every fixture line, warm | 4008 | 3.11 | 4.22 | 4.49 | 6.39 |

    slowest: policydpy2/classes.tsv:123 shape 2, 6.39 ms
    not allow or not exit 0: 0

Three runs gave an every-line p50 of 3.11 to 3.15 ms and a p99 of 4.48 to 4.51 ms.
One set's p99 moved by up to 0.4 ms between runs, and the max by up to 1.2 ms.

## phronesis linked, every core busy

The same build, with one `sh -c 'while :; do :; done'` per core running for the whole bench.
The times fall on 4 ms steps, the scheduler tick: a check waits for a core, it does not do more work.

    ljos-policyd 0.6.4 (phronesis)
    cpu: Intel(R) Xeon(R) Processor (family 6 model 207), 8 cores
    commit: 367ba3927158716ad613cc2876dd4f90d696839d

| lines | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---:|---:|---:|---:|---:|
| first check, fresh state dir | 100 | 8.11 | 12.13 | 12.13 | 12.14 |
| pyopts17/corpus.tsv | 481 | 8.00 | 12.13 | 12.25 | 16.13 |
| pyopts17/ordinary.tsv | 638 | 8.07 | 12.15 | 12.26 | 15.99 |
| pyopts17/risky.tsv | 230 | 7.98 | 12.11 | 12.18 | 16.00 |
| policydpy2/ordinary.tsv | 1060 | 8.00 | 12.13 | 12.24 | 17.08 |
| policydpy2/items.tsv | 348 | 7.99 | 12.13 | 14.95 | 16.00 |
| policydpy2/classes.tsv | 1251 | 8.00 | 12.13 | 12.23 | 16.02 |
| every fixture line, warm | 4008 | 8.00 | 12.13 | 12.24 | 17.08 |

    slowest: policydpy2/ordinary.tsv:34 shape 2, 17.08 ms
    not allow or not exit 0: 0

## Host table only, idle

A build that found no phronesis.

    ljos-policyd 0.6.4 (host table)
    cpu: Intel(R) Xeon(R) Processor (family 6 model 207), 8 cores
    commit: 367ba3927158716ad613cc2876dd4f90d696839d

| lines | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---:|---:|---:|---:|---:|
| first check, fresh state dir | 100 | 0.92 | 1.16 | 1.20 | 1.21 |
| pyopts17/corpus.tsv | 481 | 0.91 | 1.15 | 1.25 | 1.29 |
| pyopts17/ordinary.tsv | 638 | 0.94 | 1.19 | 1.24 | 1.34 |
| pyopts17/risky.tsv | 230 | 0.94 | 1.12 | 1.21 | 1.24 |
| policydpy2/ordinary.tsv | 1060 | 0.92 | 1.19 | 1.26 | 1.43 |
| policydpy2/items.tsv | 348 | 0.94 | 1.19 | 1.21 | 1.24 |
| policydpy2/classes.tsv | 1251 | 0.98 | 1.19 | 1.26 | 1.49 |
| every fixture line, warm | 4008 | 0.95 | 1.19 | 1.25 | 1.49 |

    slowest: policydpy2/classes.tsv:211 shape 2, 1.49 ms
    not allow or not exit 0: 0

## Hook time budget

policyd sets no time budget on a check.
The last one stopped the pack's answer at the 300 ms connect timeout, and 367ba39 took it out because it printed `allow	fail-open	timeout` for lines the pack allows.
These tables give no reason to put one back: with every core busy, the slowest of these 4108 checks took 17.1 ms.
The wait a hook gives a check is set in ljos: `GUARD_TIMEOUT` is 5 s in ljos 0.37.0.
That is about 290 times the slowest busy check above and about 400 times its p99 of 12.2 ms, so on this machine it fires only on a check that hangs.
