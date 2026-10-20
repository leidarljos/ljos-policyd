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
ljos-policyd 0.4.5 (phronesis)
```

## What it refuses

The rules are tried in this order, and the first that matches decides.

| Reason | Refused | Not refused |
|---|---|---|
| `sudo` | a privilege runner as any word: `sudo`, `doas`, `su`, `pkexec`, `run0` | a sentence that only mentions one, passed as one quoted word |
| `curl-pipe-shell` | a download piped into a shell or an interpreter that reads its program on stdin, directly or through a later stage (`curl URL \| sh`, `wget -qO- URL \| bash`, `curl URL \| python3`, `curl URL \| tee f \| sh`); a shell, `source`, `.`, `eval` or an interpreter running a download (`bash <(curl ...)`, `source <(curl ...)`, `sh -c "$(curl ...)"`, `python3 <(curl ...)`, `bash -c 'curl ... \| sh'`); a file a fetch on the line saves and a later command runs (`curl -o i.sh URL && sh i.sh`, `wget URL/i.sh && ./i.sh`) | `git fetch` followed by `bash build.sh`; a search pattern naming both; `curl URL \| jq`; `curl URL \| python3 -m json.tool` or `\| python3 parse.py`; `curl -o FILE URL` that nothing on the line runs |
| `decoded-pipe-shell` | a decoder's output piped into a shell (`echo ... \| base64 -d \| sh`, `xxd -r ... \| sh`, `zcat x.gz \| bash`), or a shell running a decoder (`bash -c "$(base64 -d f)"`, `sh <(base64 -d f)`) | decoding to a file or into `grep` |
| `chmod-setuid` | setting the setuid or setgid bit with `chmod` or `install -m`: an octal mode whose leading digit holds 4 or 2 (`4755`, `04755`, `2775`), or a clause that adds `s` (`u+s`, `g+s`, `+s`) | other modes (`0755`, `1777`, `+x`, `u-s`) |
| `raw-disk` | `mkfs` on a device, `dd of=` a block device, `wipefs -a`, `sgdisk`, `sfdisk`, `fdisk`, `parted`, `blkdiscard`, `mkswap` or `shred` on a block device, `cryptsetup luksFormat`, `badblocks -w`, a `>` redirection into a block device | `mkfs` on an image file, `dd` to a file or `/dev/null`, the listing forms (`fdisk -l`, `parted print`, `sfdisk --dump`, `wipefs` without `-a`) |
| `recursive-chmod-chown` | a recursive `chmod`, `chown`, `chgrp` or `setfacl` from `/`, a home directory or a system tree (`/etc`, `/usr`, `/var`, ...), or a recursive `chmod` to `000`, `a-rwx`, `777` or `o+w` outside `/tmp` | `chmod -R u+w target`, `chown -R $USER ./build`, `chmod -R 700 ~/.ssh` |
| `find-delete-outside-tmp` | `find ... -delete`, or `-exec`, `-execdir` or `-ok` running `rm`, `shred` or `unlink`, whose starting points reach outside `/tmp` and `/var/tmp`; no starting point means the current directory | the same under `/tmp`; `find` without a delete; `find -exec grep`; a cleanup inside the tree whose name tests all name files a tool writes again (`find . -name '*.pyc' -delete`, `find . -name .DS_Store -delete`), unless the line can `cd` out of the tree |
| `rm-rf-outside-tmp` | a recursive `rm` or `rtrash` whose own operands reach outside `/tmp` and `/var/tmp`, a `..` in the path included; also `python -c`, `node -e`, `ruby -e` or `perl -e` code that calls `shutil.rmtree`, `rmSync(..., {recursive})`, `rm_rf`, `rm_r` or `remove_tree` outside `/tmp` | the same under `/tmp`; a build output directory named as a plain relative path (`rm -rf target/`, `rm -rf node_modules`, `rm -rf ./build`, `web/.venv`) or a top-level scratch directory (`rm -rf ./tmp/test-output`, `.tmp`, `temp`), unless the line can `cd` out of the tree; a later command on the line that is not a delete |
| `git-force-push` | `git push` with `--force`, `-f` in a flag cluster, `--mirror`, or a `+` refspec; a `--force-with-lease` push onto `main`, `master` or `develop`, or one whose words name no branch (no refspec, `HEAD`, a wildcard, `--all`). ljos asks rather than refuses, and reads a bare lease push's branch from the checkout | an ordinary `git push`, `git push -u origin BRANCH`, `--force-if-includes` alone, and a lease push onto any other branch, which the remote refuses when it holds commits you have not fetched |
| `git-reset-hard` | `git reset --hard` | `--soft`, `--mixed`, `reset FILE` |
| `git-clean-force` | `git clean` with `-f` (`-fd`, `-fdx`, `--force`) | `git clean -n` |
| `git-stash-clear` | `git stash clear` | `stash pop`, `list`, `drop` |
| `git-discard-worktree` | `git checkout -- .` or `git checkout .`, `git restore .` or `:/`, and `git restore` with no path | `checkout BRANCH`, `checkout -- FILE`, `restore FILE`, `restore --patch` |
| `git-push-delete` | `git push --delete`, `-d` in a flag cluster, or a refspec with an empty source (`:main`, `:refs/tags/v1.0`) | `push origin main:main`, `push --dry-run` |
| `git-branch-force-delete` | `git branch -D`, `--delete --force` | `branch -d`, which refuses an unmerged branch |
| `git-reflog-expire` | `git reflog expire` with `--expire=now` or `=all`, `git reflog delete` | `reflog expire` with a date, `reflog show` |
| `git-history-rewrite` | `git filter-branch`, `git filter-repo` | `git rebase` |
| `git-update-ref-delete` | `git update-ref -d` | `update-ref REF VALUE` |
| `git-worktree-force-remove` | `git worktree remove --force` | `worktree remove` without `--force`, which refuses a dirty tree |

The git rules also apply when the command word is a variable: `g=git;
$g push -f` reads `$g` as `git`, and `$GIT reset --hard` with no
assignment on the line is read as git too. A `-c alias.NAME=...` on the
line is judged as what the alias runs, and the value of a `-c` key git
runs as a command (`core.sshCommand`, `core.pager`, `credential.helper`,
...) is judged as a shell line. `busybox` and `toybox` run the applet
after them. An inline program
(`python3 -c`, `node -e`, `perl -e`, `ruby -e`) has its `os.system`,
`subprocess.*`, `execSync` and `system` strings read as shell lines.

A pipeline arrives as one call, its stages separated by a `|` word, so a
download and the shell it feeds are judged together. ljos sends each
pipeline of a line this way: `a && b | c` is two calls, `a` and `b | c`.
A function definition's body (`f() { ...; }`, `function f { ...; }`) is
judged as the commands it runs.

## Two backends: phronesis, or the table built in

When the [phronesis](https://github.com/leidarljos/phronesis) library
(0.2.4 or later) is found at build time (`PHRONESIS_DIR`, or `pkg-config
phronesis`), every check runs the table above and then
`phronesis_check_shell`, on the line and on each command the table found
inside it: past `env`, `nice` and the other wrappers, inside `sh -c`
scripts and substitutions. A refusal from the table stands, and a refusal
from phronesis carries the pack's own reason after the tab. Without the
library the crate still builds and uses the table alone.

The build links phronesis and the Cap'n Proto C runtime statically and
embeds phronesis's default pack, so the binary needs no phronesis install
and keeps no path from the machine that built it. A word is handed to the
pack whole, up to 128 KiB, and a line may carry up to 32768 words. Past
either limit, or a command body over 512 KiB, the line is `field-too-long`
and the reason, such as `field-too-long: argv word exceeds 131072 bytes`.
On first use it writes the pack under `$PHRONESIS_STATE_DIR` (default
`~/.local/state/ljos-policyd`) and loads it from there. The default pack
refuses what the table refuses and also secrets written into the argv (a
token in a URL or a header). `LJOS_POLICYD_PACK=seat` loads the seat pack
instead, which adds uv-only Python and refuses `pip`, `npm`, `yarn`,
`pnpm`, `bun` and `poetry`. A pack named in `PHRONESIS_JANET_PACK` replaces
both.

`ljos-policyd version` names the backend in parentheses, and
`ljos doctor` shows it in its policy row. The binaries on the GitHub
release are built with phronesis and report `phronesis`. A source build
without the library reports `host table`, and the doctor warns about it.

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
