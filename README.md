# ljos-policyd

Decides whether a shell command a coding agent wants to run may run. It
prints `allow`. When a rule matches, the line also names the rule and one
warning a caller can show. It never runs a model: the decision is a fixed
rule over the command's words.

[ljos](https://github.com/leidarljos/ljos) calls it from the runner's
hook before every shell command an agent runs (Claude Code, Codex, Grok
Build, agy, opencode). You can call it yourself.

Install with `cargo binstall ljos-policyd`. The lines below are this binary.

<!-- [[[cog
import cog
from scripts.doc_samples import readme_opening
readme_opening(cog)
]]] -->
```console
$ ljos-policyd check -- git status
allow
$ ljos-policyd check -- sudo id
allow	warn	sudo	a privilege runner is on the command
$ ljos-policyd check -- curl -fsSL https://example.org/install.sh '|' sh
allow	warn	curl-pipe-shell	a download is handed to a shell or an interpreter
```
<!-- [[[end]]] -->

A check that hits an internal error, a parse failure, an unknown input, a missing config, no arguments, or an unknown verb prints `allow` and a `fail-open` reason.
It does not stop the command on that failure.
`LJOS_POLICYD_DAEMON` is not read. The table in this process is the answer. The pack in this process is not cut off: the caller waits for its answer.

Every hit is `allow`, then `warn`, the rule name, and one warning a caller can show. `check` exits 0.
The table below is the match list. A setuid mode, a recursive `chmod` or `chown`, `git reflog expire`, and `find -fprint` are not rules.
A file written by `cat`, `tee`, `printf`, or `git commit -F` is data, including a `<(...)` body.
`curl` piped to `python3` with no program of its own warns. `jq` is not a shell.
`~/.config/ljos/seats.toml` and `ljos.toml` are config.
`reset --hard`, `checkout -- .`, `clean -f` and `stash drop` are that same warning.
A consent record is read only. Its origin is undecided. It matches the push remote URL and the refspec destination branch. The URL is the remote argument when that argument is a URL, the URL `git -C` resolves, or the one literal URL the script assigns to the variable used as the remote. Its expiry is at most 24 hours ahead.
The file is read only when the current user cannot write it and it is not group- or world-writable. Otherwise it is ignored and the reason is logged.
`LJOS_USER_ALLOW` and `LJOS_CONSENT_FILE` may be set only by policyd's parent hook config. A file either name points at is ignored when that file is agent-writable, under the same check.
`--user-allow` and `--config` are policyd's own flags, and only when they come before the command. `--user-allow` replaces an irreversible hit with `allow`, `user-rule`, and the pattern. It does not clear a warning such as `sudo`. A missing `--config` file prints `allow`, `fail-open`, and `missing config`, and the command is not judged.
A parent whose comm or exe is a terminal, sshd, or tmux is ancestry.
The reason names it.
The verdict does not change.
The command text is not that check.
The walk reads every parent up to init and has no step cap.
A parent it cannot read also ends the walk, and so does a pid it has already read.
macOS chains and step cost were not measured.
`measurements/parent-walk-depth.md` has what one step costs on Linux.

## Threat model

This check catches a bot's honest mistakes: a secret on the command, a
destructive command, a history rewrite, or a write of its own hooks or
policy. It is not a security sandbox against a bot that hides a path on purpose.
A literal path in a redirect, in `tee` or `sponge`, in `cp`, `install`
or `mv`, or in an interpreter `open` or `write` call is checked. A name
built by concatenation, by `Path.home()`, or by an interpreter this
check does not read, is outside that model.

## What the table matches

The rules are tried in this order, and the first that matches is the reason.
That match is `allow`, `warn`, the rule name, and one warning. The command is not stopped.

| Reason | Matched | Not matched |
|---|---|---|
| `sudo` | a privilege runner as any word: `sudo`, `doas`, `su`, `pkexec`, `run0` | a sentence that only mentions one, passed as one quoted word |
| `curl-pipe-shell` | a download piped into `sh`, `bash`, or `zsh`, directly or through a later stage (`curl URL \| sh`, `wget -qO- URL \| bash`, `curl URL \| tee f \| sh`); a shell, `source`, `.`, `eval` or an interpreter running a download (`bash <(curl ...)`, `source <(curl ...)`, `sh -c "$(curl ...)"`, `bash -c 'curl ... \| sh'`); a file a fetch on the line writes and a later command runs, including a redirection or `tee` (`curl -o i.sh URL && sh i.sh`, `curl URL > i.sh && sh i.sh`, `curl URL \| tee i.sh && ./i.sh`, `wget URL/i.sh && ./i.sh`). A download piped into `python3` with no program of its own (`curl URL \| python3`, `\| python3 -`, `\| python3 /dev/stdin`) is the same reason as a warning | `git fetch` followed by `bash build.sh`; a search pattern naming both; `curl URL \| jq`; `\| python3 -m json.tool`, `\| python3 parse.py` or `\| python3 -W ignore parse.py`; `curl -o FILE URL` or `curl URL > FILE` that nothing on the line runs; `echo hi \| tee run.sh && sh run.sh` |
| `decoded-pipe-shell` | a decoder's output piped into a shell (`echo ... \| base64 -d \| sh`, `xxd -r ... \| sh`, `zcat x.gz \| bash`), or a shell running a decoder (`bash -c "$(base64 -d f)"`, `sh <(base64 -d f)`) | decoding to a file or into `grep` |
| `raw-disk` | `mkfs` on a device, `dd of=` a block device, `wipefs -a`, `sgdisk`, `sfdisk`, `fdisk`, `parted`, `blkdiscard`, `mkswap` or `shred` on a block device, `cryptsetup luksFormat`, `badblocks -w`, a `>` redirection into a block device | `mkfs` on an image file, `dd` to a file or `/dev/null`, the listing forms (`fdisk -l`, `parted print`, `sfdisk --dump`, `wipefs` without `-a`) |
| `find-delete` | `find -delete` whose start is outside the work tree. `/tmp`, `/var/tmp` and `/home` all print this warning. The warning text says outside `/tmp` for each of them | `find` without `-delete`; `find -exec grep`; a name-filtered delete inside the work tree (`find . -name '*.pyc' -delete`) |
| `find-exec-rm` | `find -exec`, `-execdir` or `-ok` running `rm`, `shred` or `unlink` outside the work tree | `find -exec grep` |
| `exec-unresolved` | `find -exec`, `-execdir`, `-ok` or `-okdir` whose command word is empty, is `{}`, or is still a `$` name | `find -exec echo` |
| `feeder-rm` | `xargs` or `parallel` running `rm` | `xargs` running `wc` |
| `rm-rf-outside-tmp` | a recursive `rm` or `rtrash` whose own operands reach outside `/tmp` and `/var/tmp`, a `..` in the path included; also `python -c`, `node -e`, `ruby -e` or `perl -e` code that calls `shutil.rmtree`, `rmSync(..., {recursive})`, `rm_rf`, `rm_r` or `remove_tree` outside `/tmp` | the same under `/tmp`; a build output directory named as a plain relative path (`rm -rf target/`, `rm -rf node_modules`, `rm -rf ./build`, `web/.venv`) or a top-level scratch directory (`rm -rf ./tmp/test-output`, `.tmp`, `temp`), unless the line can `cd` out of the tree; a later command on the line that is not a delete |
| `git-force-push` | `git push --force`, `-f` in a short cluster, `--mirror`, a `+` refspec (`+main`, `+feature`, `+develop`), or `--force-with-lease` of any branch, including `feature` and `develop`. The printed line is the same warning for each | an ordinary `git push`, `git push -u origin BRANCH`, `--force-if-includes` alone, `--no-force-with-lease` |
| `git-reset-hard` | `git reset --hard` | `--soft`, `--mixed`, `reset FILE` |
| `git-clean-force` | `git clean` with `-f` (`-fd`, `-fdx`, `--force`) | `git clean -n` |
| `git-stash-clear` | `git stash clear` | `stash pop`, `stash list` |
| `git-stash-drop` | `git stash drop` | `stash pop`, `stash list` |
| `git-discard-worktree` | `git checkout -- .` or `git checkout .`, `git restore .` or `:/`, and `git restore` with no path | `checkout BRANCH`, `checkout -- FILE`, `restore FILE`, `restore --patch` |
| `git-push-delete` | `git push --delete`, `-d` in a flag cluster, or a refspec with an empty source (`:main`, `:refs/tags/v1.0`) | `push origin main:main`, `push --dry-run` |
| `git-branch-force-delete` | `git branch -D`, `--delete --force` | `branch -d`, which refuses an unmerged branch |
| `git-history-rewrite` | `git filter-branch`, `git filter-repo` | `git rebase`, `git reflog expire`, `git reflog delete`, `git reflog show` |
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

Makefile, npm, pnpm, yarn, bun and just recipes are not read. The
line is judged as written.

`cargo build` and `cargo run` are not read that way. The `build.rs` they
compile and run is project code, the same as any other program a build
system builds and then executes. The guard does not try to judge build
scripts. A build script that runs `git push -f` is outside what a line
check can see.

## Two backends: phronesis, or the table built in

When the [phronesis](https://github.com/leidarljos/phronesis) library
(0.2.5 or later) is found at build time (`PHRONESIS_DIR`, or `pkg-config
phronesis`), every check runs the table above and then
`phronesis_check_shell`, on the line and on each command the table found
inside it: past `env`, `nice` and the other wrappers, inside `sh -c`
scripts and substitutions. A hit from the table is the warning on the
allow line, and a hit from phronesis is that same line with the pack's
own reason. Without the library the crate still builds and uses the table alone.

The build links phronesis and the Cap'n Proto C runtime statically and
embeds phronesis's default pack, so the binary needs no phronesis install
and keeps no path from the machine that built it. The C shim follows the
installed schema's bare-pointer or typed-list representation of `List(Text)`
without changing the wire message. A word is handed to the
pack whole, up to 128 KiB, and a line may carry up to 32768 words. Past
either limit, or a command body over 512 KiB, the printed line is `allow`,
`fail-open`, and `field-too-long` with the reason, such as
`field-too-long: argv word exceeds 131072 bytes`.
On first use it writes the pack under `$PHRONESIS_STATE_DIR` (default
`~/.local/state/ljos-policyd`) and loads it from there. The default pack
names what the table names and also secrets written into the argv (a
token in a URL or a header). `LJOS_POLICYD_PACK=seat` loads the seat pack
instead, which adds uv-only Python and warns on `pip`, `npm`, `yarn`,
`pnpm`, `bun` and `poetry`. A pack named in `PHRONESIS_JANET_PACK` replaces
both.

`ljos-policyd version` names the backend in parentheses, and
`ljos doctor` shows it in its policy row. The binaries on the GitHub
release are built with phronesis and report `phronesis`.

<!-- [[[cog
import cog
from scripts.doc_samples import readme_release_version
readme_release_version(cog)
]]] -->
```console
$ ljos-policyd version
ljos-policyd 0.7.0 (phronesis)
```
<!-- [[[end]]] -->

A source build
without the library reports `host table`, and the doctor warns about it.
The sample is the binary this tree just built.

<!-- [[[cog
import cog
from scripts.doc_samples import readme_host_version
readme_host_version(cog)
]]] -->
```console
$ ljos-policyd version
ljos-policyd 0.7.0 (host table)
```
<!-- [[[end]]] -->

## Verbs and exit status

| Verb | Does | Exit |
|---|---|---|
| `check -- ARGV` | prints one verdict line, see below | 0, or 2 for a `deny` line |
| `exec -- ARGV` | prints a warning on stderr when a rule matches, then runs ARGV. `block-on-warning true` in `--config` prints the warning and `exec: not run because block-on-warning is on`, and does not run ARGV | ARGV's status, or 2 when that setting stops the command |
| `capnp -- ARGV` | writes a packed Cap'n Proto `PolicyDecision` with decision allow | 0 |
| `check-mail --config PATH [--argv [--] RECIPIENT...]` | reads one RFC 5322 message on stdin and prints JSON. The verdict is `allow`. `reasons` carry the rule and the warning | 0. A missing `--config` is usage and exits 2 |
| `replay [DENY_LOG]` | re-judges every line of a deny log with this build and the person's rules, and counts how many would run now | 0 when the log can be read. 2 when there is no log or it cannot be read |
| `version` | the version and the backend | 0 |
| `help`, `--help`, `-h` | prints the usage lines | 0 |

An argv of one word that holds whitespace or a shell operator is read as a shell line, the same as `sh -c` of that word, and any other argv is the program and its arguments.

`check` prints one line, fields separated by a tab:

| Line | Meaning |
|---|---|
| `allow` | the command may run as given |
| `allow`<TAB>`warn`<TAB>`rule`<TAB>`warning` | a rule matched. The command may run. `rule` is the token. `warning` is one line a caller can show. A mention of a credential path in `python`, `perl`, `ruby` or `node` `-c` or `-e` is `credential-mention` |
| `allow`<TAB>`fail-open`<TAB>`reason` | the check could not finish. The command may run |
| `allow`<TAB>`rewrite`<TAB>`new line` | the command may run, and the hook should run `new line` instead |
| `allow`<TAB>`consent`<TAB>`rule` | a consent record matched |
| `allow`<TAB>`user-rule`<TAB>`pattern` | a user allow matched |
| `deny`<TAB>`rule`<TAB>`warning` | a rule matched and block-on-warning is on. The command should not run |

A warning blocks only when you ask for it. Put the line `block-on-warning true` in the file `--config PATH` names. It is off by default: without that line, a warning stays allow. For `check`, a line that would warn then prints `deny` with the same rule and warning, and `check` exits 2. For `exec`, the warning is printed on stderr, then `exec: not run because block-on-warning is on`, and the command is not run; the exit status is 2. A check that fails open is still allow with the setting on: an error, or a missing config file. `LJOS_POLICYD_DAEMON` is not read. `capnp` and `check-mail` do not read it.

`python x.py` and `python3 x.py` rewrite to `uv run x.py`, arguments included, when the working directory or a parent has `pyproject.toml` or `uv.lock`, or the script file has a PEP 723 `# /// script` block. Otherwise the line stays as written. `python -c` stays as written: `uv run` does not take `-c`. When that tree asks for uv, `python -m` becomes `uv run -m`.

<!-- [[[cog
import cog
from scripts.doc_samples import readme_rewrite
readme_rewrite(cog)
]]] -->
```console
$ # no project file
$ ljos-policyd check -- python x.py
allow
$ # pyproject.toml in the working directory
$ ljos-policyd check -- python x.py
allow	rewrite	uv run x.py
$ ljos-policyd check --user-allow 'rm -rf /home*' -- rm -rf /home
allow	user-rule	rm -rf /home*
$ ljos-policyd exec -- echo ran
ran
$ ljos-policyd replay deny.log
was deny	git-force-push	now allow	warn	git-force-push	a force push rewrites a published branch	git push --force origin main
1 logged line: 1 still warn, 0 now allow
```
<!-- [[[end]]] -->

The first `python x.py` has no project file. The second is run in a directory with `pyproject.toml`.

With phronesis linked and its seat pack loaded, bare `python x.py` is `python-requires-uv-run`. That hit is answered with the same rewrite, project file or not, since the pack's law is the reason to run through uv. The hook judges the rewritten line again, so a script with no PEP 723 block still meets `python-missing-pep723` there. `python -c` under that pack is allow with that rule and a warning.

The hook returns that line as the tool's updated input where the runner has one, and as a note where it does not.

| Runner | Field |
|---|---|
| Claude Code `PreToolUse` | `hookSpecificOutput.updatedInput.command` is the new line, with `permissionDecision` `allow` |
| Cursor `preToolUse` and `beforeShellExecution` | `updatedInput.command` is the new line |
| Codex and any runner without that field | a note whose text is the new line, so the agent runs that line |

The deny log records an irreversible hit, at `$LJOS_POLICYD_DENY_LOG`, or `$XDG_STATE_HOME/ljos-policyd/deny.log` (default `~/.local/state/ljos-policyd/deny.log`). Each line is the unix time, a tab, the reason, a tab, and the command. A log that cannot be written leaves the printed line as it is, and one line on stderr names the path and the error. With no `HOME`, `XDG_STATE_HOME` or `LJOS_POLICYD_DENY_LOG`, and when `LJOS_POLICYD_DENY_LOG` is empty, that line is `deny log not written: <no path>: no log path is set`. The printed line for those hits is allow with the warning. Logged hits include a force or a `+` refspec of `main`, `master`, or `develop`, a lease of `main` or `master` (a lease of `develop` only when that name is the remote HEAD), a `find -delete` outside `/tmp` and `/var/tmp`, a download piped into a shell, and `cat` of a credential file. A force, a `+` refspec, or a lease of `feature`, a `find -delete` under `/tmp` or `/var/tmp`, a `wc` count of a credential file, `sudo`, a credential mention, and `git reset --hard` print a warning and are not logged. `ljos-policyd replay` reads that log back and prints, for each line, `was deny`, the reason it was recorded, `now`, and the verdict this build gives it, then how many of them would run. The command is a shell line. A line written by this build starts with the word `'quoted'`, and the argv follows it. A word that holds a space, a quote, or a shell character is single-quoted, and any other word is written as itself. Replay drops that word and reads the argv back. A line that does not start with `'quoted'` is an older log, the argv joined on spaces. On an older line a shell `-c` script stays one word, including a script that contains a quote, so `bash -c cat '/a b'` is still that script and not a command whose `$0` is `/a b`. Any other older line splits on spaces. A tab or a newline inside a word is stored as a space.

The person's word comes first. A rule in `$XDG_CONFIG_HOME/ljos/user-rules.json` with the verdict `allow` and the basis `person`, which `ljos rule --user PATTERN --verdict allow --why ...` writes only at the person's own terminal, prints `allow` for every line its pattern matches. The table and the pack are not run. The pattern is matched against the argv as one line, each of its pipelines, and a shell `-c` script and its pipelines, with the glob ljos uses. A runner cannot write such a rule.

Makefile, npm, pnpm, yarn, bun and just recipes are not read. A python program is not analysed. Writing or mentioning an ordinary file is not a warning. `sudo`, a recursive `rm` outside `/tmp` and the build directories, a force push, a secret in an argument, a write of a hook or policy file (`seat-guard-path`), a remote shell, and a raw disk write each name a warning. `find -delete`, `find -exec rm`, and `xargs` or `parallel` running `rm` do too. So does `mv` onto `/dev/null` or another whole tree outside the work tree, and `rsync` with `--delete` over that tree. `git reset --hard`, `git clean -fd`, `git stash clear` or `drop`, and `git checkout -- .` or `git restore .` are warnings as well.

## Outbound mail

`check-mail` reads one message on stdin and the config at `PATH`. It
prints one JSON object. The verdict is `allow`. Where this section says
a header is refused, that condition is a reason: `code` is the rule name
and `detail` is the warning. The send is not held. An empty reason list
is not a grant to send.

<!-- [[[cog
import cog
from scripts.doc_samples import readme_mail
readme_mail(cog)
]]] -->
```console
$ ljos-policyd check-mail --config mail.conf < message.eml
{"verdict":"allow","reasons":[]}
$ ljos-policyd check-mail --config mail.conf < blocked.eml
{"verdict":"allow","reasons":[{"code":"recipient-domain-denied","detail":"to blocked.test"}]}
```
<!-- [[[end]]] -->

The message on stdin is the whole input. `sendmail -t recipient`
adds that recipient to the ones in the headers, and this check
does not see it. The caller must pass no recipient arguments, or
pass the same recipients to
`check-mail --config PATH --argv [--] RECIPIENT...`. An argv
recipient is judged as a recipient.

The config is one key per line. `identity` is the address `From` must
be. `deny-file` and `pack-law` name the other two files. A relative
path is read from the directory of the config file.

```
identity mailseat@example.test
deny-file deny.txt
pack-law law.txt
subaddress +-=
```

`subaddress` is optional. When the line is omitted the separators
are `+-=`. The value is those characters, and it replaces the
default. `.`, `@`, `%` and `!` are not separators.

`From` has to be that one address after ASCII case folding only.
The mailbox is the address in angle brackets, read from the raw
header after a folded line is joined. A local part or domain that
NFKC or the removal of a skipped character would change is a
refusal, including a zero-width character or a fullwidth spelling.
An encoded-word in a display name is decoded for display only,
and an encoded addr-spec is a refusal. A second `From`, a
`From` that does not parse, a group in `From`, or any other
address is a refusal.
`Reply-To`, `Sender`, `Return-Path`, `Errors-To`,
`Disposition-Notification-To`, `Return-Receipt-To`,
`Delivery-Receipt-To`, `Mail-Followup-To` and `Mail-Reply-To` must
stay clear of an identity in the deny file, and of a domain named
by the pack-law file. `Sender`, `Errors-To` and `Return-Path`,
when present, must be the identity under the same rule as `From`.
An empty `Return-Path` is not that address. Any `Resent-*` header
is a refusal, and so is any `Apparently-To`. `To`, `Cc` and `Bcc`
are refused when the mailbox is an `address` line in the deny
file, and when that domain, or a parent of it, is named by the
deny file or by the pack-law file. An `address` line is that
mailbox, not the whole domain. It also covers that local part,
one `subaddress` separator, and anything after the separator.
On an address rule for `gmail.com` or `googlemail.com` the two
domains are one domain, and dots in the local part are ignored.
On an address rule for `fastmail.com`, a mailbox at
`<local>@<user>.fastmail.com` (one label, then `fastmail.com`)
is `<user>@fastmail.com`. A hyphen in that label is part of the
user name. A decoded user label that contains ZWJ or ZWNJ is not
used; the `xn--` form is kept. Domain rules and `From` are not
matched this way.
An address at `@[ ... ]` is a
domain literal and is a refusal. So is a domain that is not a
hostname after IDNA, such as one with an underscore, a `!` or a
`+`, a label that starts or ends with a hyphen, a label over 63
characters or a name over 253: no rule could name it. An
all-numeric domain is a
refusal, judged after IDNA. That includes a dotted quad, a
shorter form `inet_aton` accepts, a hex label (`0x`) and a
label with a leading zero. U+3002 or U+FF61 between the
numbers is still that address. A source route
(`<@host:mailbox>`) is a refusal. `@`, `%` or `!` in a local
part is a refusal, quoted or not, including a backslash escape
inside the quotes. A local part that NFKC changes into ASCII
punctuation, such as a fullwidth `@`, `%`, `!` or `+`, is a
refusal. A local part that contains a default ignorable code point,
a noncharacter, an unassigned or private-use code point, a format
or control character, or a space separator is a refusal. A
zero-width space or a braille blank is still removed before the
address is compared. A decimal digit is the ASCII digit of the
same value, so `user` and U+0661 is `user1`. ASCII `0` is not
`o`. An enclosing mark is removed with the nonspacing marks. A
spacing mark whose base is ASCII is a refusal; one on a
non-ASCII base stays.
A local part that mixes Latin with Cyrillic or Greek is
`mixed-script`, the same rule as a domain label. The whole local
part is one label. A local part wholly in Cyrillic or Greek is a
different mailbox and is not folded to the Latin it looks like.
A format character is a refusal, so a Devanagari, Persian or
Sinhala local part that uses ZWJ or ZWNJ is `recipient-unparsed`,
and so is an emoji ZWJ sequence, a keycap (digit, VS16, U+20E3)
or a tag flag. A variation selector is a refusal, including VS16
after an emoji and a Mongolian free variation selector. A quoted
space is a refusal, whether the space is ASCII or NBSP. Plain
Devanagari, including a virama with no joiner, Arabic including
tatweel, CJK, Hangul, Thai, a single emoji, and an emoji with a
skin tone are still addresses.
A recipient domain, or a domain on a header checked against the
deny file, is refused when one of its labels mixes Latin with
Cyrillic or Greek after NFKC and IDNA.

A deny-file domain is compared after NFKC and IDNA, so a fullwidth
spelling and the punycode form are the same domain. Case is folded
as the address skeleton folds it, so ß is ss and ı and İ are i. A
character a reader skips, such as a zero-width space or a braille
blank, is
removed before that comparison. A homoglyph that those two passes
leave alone stays a different domain. `From` is not compared that
way: only ASCII case folding, and a spelling those passes would
change is refused.

The deny file's lines are `address`, `domain`, `handle`, `term` and
`pair`. This check uses `address` and `domain`. The other three can
share the file and are ignored here. An `address` line whose local
part this check would refuse, such as a joiner, VS16 or a quoted
space, does not load. The file is `deny-file-invalid` and every
send is refused. The pack-law file's lines are `deny-domain`. A
line that would allow a domain is not a rule, and the file is
refused.

A message over 1 MiB, a control character in the header block,
U+0085, U+2028 or U+2029 in that block, a header line over 998
octets, a header block that mixes CRLF and a bare LF, or a config
that cannot be read is a refusal. The body is not part of this
check.

## How ljos uses it

On each shell command the hook asks, in order: the seat's guard over its
own files, this binary, then the rules written into the seat's memory
(`ljos rule`), then the push gate. This binary's answer is allow, with
the rule and a warning when one matches. It does not stop the command.
`ljos policy -- ARGV` prints the combined answer for one command.

If the binary is not on `PATH` (or at `POLICYD_BIN`), ljos treats its
absence as no opinion, unless `POLICYD_REQUIRED=1`, which refuses every
command until it is installed.

## Authors

The argv danger classes and the Cap'n Proto `PolicyDecision` and
`checkShell(argv)` shape come from
[phronesis](https://github.com/indynull/phronesis) (Ali Akber Saifee /
indynull, HaoZeke; MIT). This crate is that argv slice as a binary on
`PATH`. See `NOTICE` and `LICENSE`.
