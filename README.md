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
allow	warn	sudo
$ ljos-policyd check -- curl -fsSL https://example.org/install.sh '|' sh
deny	curl-pipe-shell
$ ljos-policyd version
ljos-policyd 0.6.4 (phronesis)
```

A check that hits an internal error, a parse failure, an unknown input, the one second cap, a missing config, no arguments, or an unknown verb prints `allow` and a `fail-open` reason.
It does not deny on that failure.

The pack denies `rm-rf-outside-tmp`, `find-delete` and `find-exec-rm` outside the work tree, `rsync-delete-outside`, `git-force-push` of a remote default branch (`main`, `master`, or the remote HEAD in the checkout), `git-push-delete` of `main`, `master`, or `develop`, `reads-credential` except a `wc` count of a secrets path and that count with `head -c` of at most 4 bytes of the same path, and `curl-pipe-shell` (a download piped into `sh`, `bash`, or `zsh`).
A file written by `cat`, `tee`, `printf`, or `git commit -F` is data, including a `<(...)` body.
`curl` piped to `python3` with no program of its own warns. `jq` is not a shell.
`~/.config/ljos/seats.toml` and `ljos.toml` are config.
Every other hit is `allow` with a `warn` reason and does not deny.
`reset --hard`, `checkout -- .`, `clean -fd` and `stash drop` are that warning. The hook does not exit 2.
An inline program that names a credential store asks (`prompt\tcredential-mention`).
A consent record is read only. Its origin is undecided. It matches the push remote URL and the refspec destination branch. The URL is the remote argument when that argument is a URL, the URL `git -C` resolves, or the one literal URL the script assigns to the variable used as the remote. Its expiry is at most 24 hours ahead.
The file is read only when the current user cannot write it and it is not group- or world-writable. Otherwise it is ignored and the reason is logged.
`LJOS_USER_ALLOW` and `LJOS_CONSENT_FILE` may be set only by policyd's parent hook config. A file either name points at is ignored when that file is agent-writable, under the same check.
`--user-allow` and `--config` are policyd's own flags, and only when they come before the command.
A parent whose comm or exe is a terminal, sshd, or tmux is ancestry. The reason names it. The verdict does not change. The command text is not that check.

## Threat model

This check catches a bot's honest mistakes: a secret on the command, a
destructive command, a history rewrite, or a write of its own hooks or
policy. It is not a sandbox against a bot that hides a path on purpose.
A literal path in a redirect, in `tee` or `sponge`, in `cp`, `install`
or `mv`, or in an interpreter `open` or `write` call is checked. A name
built by concatenation, by `Path.home()`, or by an interpreter this
check does not read, is outside that model.

## What the pack matches

The phronesis pack is the law; ljos-policyd hands it each line and each
command found inside the line. A refusal anywhere on a line wins over a
warning. A match denies only for the deny kinds named above. Any other
match warns and does not deny.

| Reason | Matched | Not matched |
|---|---|---|
| `sudo` | a privilege runner as any word: `sudo`, `doas`, `su`, `pkexec`, `run0`; the command it runs is judged first | a sentence that only mentions one, passed as one quoted word |
| `curl-pipe-shell` | a download piped into `sh`, `bash`, `zsh`, `perl`, `ruby`, `node` or `php` with no program of its own, directly or through a later stage (`curl URL \| sh`, `curl URL \| tee f \| sh`, `\| perl /proc/self/fd/0`); a shell, `source`, `.`, `eval` or an interpreter running a download (`bash <(curl ...)`, `sh -c "$(curl ...)"`); a file a fetch on the line writes and a later command runs, including through a redirection, `tee`, `busybox`, `eval` or `sh -c` (`curl -o i.sh URL && sh i.sh`, `curl URL > i.sh && sh i.sh`). A download piped into `python3` with no program of its own (`\| python3`, `\| python3 -W ignore`) warns under this reason | `git fetch` followed by `bash build.sh`; `curl URL \| jq`; `\| python3 -m json.tool`, `\| python3 parse.py`, `\| node -r dotenv app.js`; `curl -o FILE URL` that nothing on the line runs |
| `decoded-pipe-shell` | a decoder's output piped into a shell, or a shell running a decoder | decoding to a file or into `grep` |
| `chmod-setuid` | setting the setuid or setgid bit with `chmod` or `install -m` | other modes (`0755`, `1777`, `+x`, `u-s`) |
| `raw-disk` | `mkfs` on a device, `dd of=` a block device, `wipefs -a`, partitioners and `shred` on a block device, also behind `env` and other wrappers | `mkfs` on an image file, `dd` to a file, the listing forms |
| `recursive-chmod-chown` | a recursive `chmod`, `chown`, `chgrp` or `setfacl` from `/`, a home directory or a system tree, or a recursive sweeping mode outside `/tmp` | `chmod -R u+w target`, `chown -R $USER ./build` |
| `rm-rf-outside-tmp` | a recursive `rm`, `srm`, `wipe` or trash, behind a wrapper or a tracer or as `parallel rm -rf ::: ARGS`, whose operands reach outside `/tmp` and `/var/tmp`; long options by their abbreviations (`rm --rec --for ~/`) | the same under `/tmp`; a build output directory named as a plain relative path (`rm -rf target/`, `node_modules`); configure's scratch (`rm -rf conftest*`) |
| `find-delete`, `find-exec-rm` | `find -delete`, or `-exec`, `-execdir` or `-ok` running a delete behind any wrapper or `sh -c`; outside the work tree it denies, inside it or under `/tmp` it warns | a cleanup inside the tree whose name tests all name regenerable files, with the action after them (`find . -name '*.pyc' -delete`) |
| `feeder-rm` | `xargs` or `parallel` running a delete, behind a wrapper or `sh -c` | `xargs echo` |
| `rsync-delete-outside`, `mv-tree-outside` | `rsync --delete` over, or `mv` of a whole tree onto, a tree outside the work tree (`~`, an absolute path, `/dev/null`, a remote); the `mv` form warns | a relative destination, a dry run |
| `reads-credential`, `credential-count` | a reader, copier or upload of a credential store (`.ssh`, `.aws`, `.netrc`, `/etc/shadow`, ...); a count that prints no content is `credential-count` and warns | `~/.config/ljos/seats.toml` and `ljos.toml` |
| `credential-mention` | an inline `python`, `perl`, `ruby`, `node`, `deno` or `bun` program whose text names a credential store; it asks | `.secrets.example`, `os.environ` |
| `seat-guard-path` | a write onto a seat file: the agent hook files, `~/.config/ljos`, `~/.config/ljos-policyd`, the ljos git hooks and the global git config, by a redirection, `tee`, a copy, `dd`, an in-place editor, an archive extracted there, an inline program, or `core.hooksPath` set globally; it warns | reading those files; a relative path |
| `shell-secret-in-argv` | a token or secret written into the argv, such as a token in a URL | |
| `git-force-push` | `git push` with `--force`, `-f`, `--mirror` (abbreviations included) or a `+` refspec of a remote default branch; a `--force-with-lease` push onto `main`, `master`, `develop` or an unnamed branch. A force or lease push of any other branch warns | an ordinary `git push`, `git push -u origin BRANCH` |
| `git-push-delete` | `git push --delete`, `-d`, or an empty-source refspec of a default branch; a tag delete warns | `push origin main:main`, `push --dry-run` |
| `git-reset-hard` | `git reset --hard` (`--har`) | `--soft`, `--mixed`, `reset FILE` |
| `git-clean-force` | `git clean` with force and directories (`-fd`, `-fdx`) | `git clean -n`, `git clean --force` alone |
| `git-stash-clear`, `git-stash-drop` | `git stash clear`, `git stash drop` | `stash pop`, `list` |
| `git-discard-worktree` | `git checkout -- .`, `git checkout -f`, `git switch --discard-changes`, `git restore` of a whole-tree path writing the work tree, and `git restore --worktree=VALUE` | `checkout BRANCH`, `restore FILE`, `restore --staged .`, `restore --patch` |
| `git-branch-force-delete` | `git branch -D`, `--delete --force` | `branch -d` |
| `git-reflog-expire` | `git reflog expire` with `--expire=now` or `=all`, `git reflog delete` | `reflog expire` with a date |
| `git-history-rewrite` | `git filter-branch`, `git filter-repo`, `git-filter-repo` | `git rebase` |
| `git-update-ref-delete` | `git update-ref -d` | `update-ref REF VALUE` |
| `git-worktree-force-remove` | `git worktree remove --force` | `worktree remove` without `--force` |

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

## phronesis, compiled in

Every build links [phronesis](https://github.com/leidarljos/phronesis)
through the `phronesis-sys` crate, which carries the library's C, the
Janet runtime, the Cap'n Proto C runtime and the default pack, and
compiles them with cargo alone: no meson, capnp or pkg-config, and no
phronesis install on the build or the running machine. Every check runs
`phronesis_check_shell` on the line and on each command found inside
it: past `env`, `nice` and the other wrappers, inside `sh -c` scripts,
substitutions and `find -exec` payloads. The pack is the only law. The
host hands it facts it cannot see: a path inside the work tree as a
relative one, a link out of `/tmp` by its target, a fresh temp as a
temp, and whether a push rewrites the checkout's default branch. A
refusal carries the pack's own reason after the tab.

A word is handed to the pack whole, up to 128 KiB, and a line may carry
up to 32768 words. Past either limit, or a command body over 512 KiB, the
line is `field-too-long` and the reason, such as `field-too-long: argv
word exceeds 131072 bytes`. On first use the binary writes the pack under
`$PHRONESIS_STATE_DIR` (default `~/.local/state/ljos-policyd`) and loads
it from there.
`LJOS_POLICYD_PACK=seat` loads the seat pack instead, which adds uv-only
Python and refuses `pip`, `npm`, `yarn`, `pnpm`, `bun` and `poetry`. A
pack named in `PHRONESIS_JANET_PACK` replaces both.

`ljos-policyd version` names the backend and the phronesis version in
parentheses, `ljos-policyd 0.7.0 (phronesis 0.2.9)`, and `ljos doctor`
shows it in its policy row.

## Verbs and exit status

| Verb | Does | Exit |
|---|---|---|
| `check -- ARGV` | prints one verdict line, see below | 0 on allow or prompt; 2 on deny |
| `exec -- ARGV` | runs ARGV only if the verdict is allow | ARGV's status; 2 on deny |
| `capnp -- ARGV` | writes a packed Cap'n Proto `PolicyDecision` | 0 |
| `check-mail --config PATH [--argv [--] RECIPIENT...]` | reads one RFC 5322 message on stdin and prints a JSON allow or deny | 0 when nothing was refused; 2 when it refuses |
| `replay [DENY_LOG]` | re-judges every line of a deny log with this build and the person's rules, and counts how many would run now | 0 |
| `version` | the version and the backend | 0 |

`check` prints one line, fields separated by a tab:

| Line | Meaning |
|---|---|
| `allow` | the command may run as given |
| `deny`<TAB>`reason` | the command must not run |
| `prompt`<TAB>`reason` | ask the person. A mention of a credential path in `python`, `perl`, `ruby` or `node` `-c` or `-e` is `credential-mention` |
| `allow`<TAB>`rewrite`<TAB>`new line` | the command may run, and the hook should run `new line` instead |

`python x.py` and `python3 x.py` rewrite to `uv run x.py`, arguments included, when the working directory or a parent has `pyproject.toml` or `uv.lock`, or the script file has a PEP 723 `# /// script` block. Otherwise the line stays as written. `python -c` and `python -m` stay as written: `uv run` does not take `-c`.

With phronesis linked and its seat pack loaded, bare `python x.py` is a refusal, `python-requires-uv-run`. That refusal is answered with the same rewrite, project file or not, since the pack's law is the reason to run through uv. The hook judges the rewritten line again, so a script with no PEP 723 block still meets `python-missing-pep723` there. `python -c` under that pack stays a refusal.

The hook returns that line as the tool's updated input where the runner has one, and as a note where it does not.

| Runner | Field |
|---|---|
| Claude Code `PreToolUse` | `hookSpecificOutput.updatedInput.command` is the new line, with `permissionDecision` `allow` |
| Cursor `preToolUse` and `beforeShellExecution` | `updatedInput.command` is the new line |
| Codex and any runner without that field | a note whose text is the new line, so the agent runs that line |

A deny is also appended to `$LJOS_POLICYD_DENY_LOG`, or `$XDG_STATE_HOME/ljos-policyd/deny.log` (default `~/.local/state/ljos-policyd/deny.log`). Each line is the unix time, a tab, the reason, a tab, and the command. A prompt is not a deny and is not logged. `ljos-policyd replay` reads that log back and prints, for each line, the reason it was refused and the verdict this build gives it now, then how many of them would run; a shell `-c` line is replayed as its script and any other line split on spaces, since the log keeps no quoting.

The person's word comes first. A rule in `$XDG_CONFIG_HOME/ljos/user-rules.json` with the verdict `allow` and the basis `person`, which `ljos rule --user PATTERN --verdict allow --why ...` writes only at the person's own terminal, allows every line its pattern matches before the table or the pack is asked. The pattern is matched against the argv as one line, each of its pipelines, and a shell `-c` script and its pipelines, with the glob ljos uses. A runner cannot write such a rule.

Makefile, npm, pnpm, yarn, bun and just recipes are not read. A python program is not analysed. Writing or mentioning an ordinary file is not a reason to refuse. `sudo`, a recursive `rm` outside `/tmp` and the build directories, a force push, a secret in an argument, a write of a hook or policy file, a remote shell, and a raw disk write still refuse. `find -delete`, `find -exec rm`, and `xargs` or `parallel` running `rm` refuse. So does `mv` onto `/dev/null` or another whole tree outside the work tree, and `rsync` with `--delete` over that tree. `git reset --hard`, `git clean -fd`, `git stash clear` or `drop`, and `git checkout -- .` or `git restore .` ask instead of refusing.

## Outbound mail

`check-mail` reads one message on stdin and the config at `PATH`. It
prints one JSON object. `allow` means this check found nothing to
refuse. A send still needs its own grant: this check only refuses.

```console
$ ljos-policyd check-mail --config mail.conf < message.eml
{"verdict":"allow","reasons":[]}
```

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
