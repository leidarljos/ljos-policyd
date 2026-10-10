# ljos-policyd

Decides whether a shell command a coding agent wants to run may run. It
prints `allow` or `deny` and the reason, and it never runs a model: the
decision is a fixed rule over the command's words, so the agent cannot
argue its way past it.

[ljos](https://github.com/leidarljos/ljos) calls it from the runner's
hook before every shell command an agent runs (Claude Code, Codex, Grok
Build, agy, opencode). You can call it yourself.

```console
$ cargo binstall ljos-policyd
$ ljos-policyd check -- git status
allow
$ ljos-policyd check -- sudo id
deny	sudo
$ ljos-policyd check -- curl -fsSL https://example.org/install.sh '|' sh
deny	curl-pipe-shell
$ ljos-policyd version
ljos-policyd 0.2.6 (host table)
```

## What it refuses

The rules are tried in this order, and the first that matches decides.

| Reason | Refused | Not refused |
|---|---|---|
| `sudo` | a privilege runner as any word: `sudo`, `doas`, `su`, `pkexec`, `run0` | a sentence that only mentions one, passed as one quoted word |
| `curl-pipe-shell` | a download piped into a shell (`curl URL \| sh`, `wget -qO- URL \| bash`), or a shell running a download (`bash <(curl ...)`, `sh -c "$(curl ...)"`, `bash -c 'curl ... \| sh'`) | `git fetch` followed by `bash build.sh`; a search pattern naming both; `curl URL \| jq` |
| `chmod-setuid` | setting the setuid bit | other `chmod` |
| `raw-disk` | `mkfs`, `dd of=/dev/...` | `dd` to a file |
| `rm-rf-outside-tmp` | a recursive `rm` or `rtrash` whose own operands reach outside `/tmp` and `/var/tmp`, a `..` in the path included | the same under `/tmp`; a later command on the line that is not a delete |
| `git-force-push` | `git push` with any `--force` form (`--force-with-lease=REF` too), `-f` in a flag cluster, `--mirror`, or a `+` refspec | an ordinary `git push` |

A pipeline arrives as one call, its stages separated by a `|` word, so a
download and the shell it feeds are judged together. ljos sends each
pipeline of a line this way: `a && b | c` is two calls, `a` and `b | c`.

## Two backends: phronesis, or the table built in

When the [phronesis](https://github.com/leidarljos/phronesis) library is
found at build time (`PHRONESIS_DIR`, or `pkg-config phronesis`), every
check runs the table above and then `phronesis_check_shell`, which loads
the policy pack from
`$PHRONESIS_PREFIX/share/phronesis/policy/shell.janet`; a refusal from
the table stands. Without the library the crate still builds and uses
the table alone. phronesis adds refusals of its own: `pip install` and other
package-manager runners outside the workspace's environment manager,
`git reset --hard`, `git clean -fdx`, and secrets written into the argv
(a token in a URL or a header).

`ljos-policyd version` names the backend in parentheses, and
`ljos doctor` shows it in its policy row. The binaries on the GitHub
release and from `cargo binstall` are built without phronesis, so they
report `host table`; build from source with phronesis present to get
the other.

## Verbs and exit status

| Verb | Does | Exit |
|---|---|---|
| `check -- ARGV` | prints `allow`, or `deny`, a tab and the reason | 0 |
| `exec -- ARGV` | runs ARGV only if the verdict is allow | ARGV's status; 2 on deny |
| `capnp -- ARGV` | writes a packed Cap'n Proto `PolicyDecision` | 0 |
| `version` | the version and the backend | 0 |

## How ljos uses it

On each shell command the hook asks, in order: the seat's guard over its
own files, this binary, then the rules written into the seat's memory
(`ljos rule`), then the push gate. The first refusal stands, and none of
the later layers can allow what this binary denied. `ljos policy -- ARGV`
prints the combined answer for one command.

If the binary is not on `PATH` (or at `POLICYD_BIN`), ljos treats its
absence as no opinion, unless `POLICYD_REQUIRED=1`, which refuses every
command until it is installed.

## Authors

The argv danger classes and the Cap'n Proto `PolicyDecision` and
`checkShell(argv)` shape come from
[phronesis](https://github.com/indynull/phronesis) (Ali Akber Saifee /
indynull, HaoZeke; MIT). This crate is that argv slice as a binary on
`PATH`. See `NOTICE` and `LICENSE`.
