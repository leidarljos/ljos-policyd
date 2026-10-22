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
ljos-policyd 0.5.0 (phronesis)
```

## What it refuses

The rules are tried in this order, and the first that matches decides.

| Reason | Refused | Not refused |
|---|---|---|
| `sudo` | a privilege runner as any word: `sudo`, `doas`, `su`, `pkexec`, `run0` | a sentence that only mentions one, passed as one quoted word |
| `curl-pipe-shell` | a download piped into a shell or an interpreter that reads its program on stdin, directly or through a later stage (`curl URL \| sh`, `wget -qO- URL \| bash`, `curl URL \| python3`, `curl URL \| python3 /dev/stdin`, `curl URL \| python3 -W ignore`, `curl URL \| tee f \| sh`); a shell, `source`, `.`, `eval` or an interpreter running a download (`bash <(curl ...)`, `source <(curl ...)`, `sh -c "$(curl ...)"`, `python3 <(curl ...)`, `bash -c 'curl ... \| sh'`); a file a fetch on the line writes and a later command runs, including a redirection or `tee` (`curl -o i.sh URL && sh i.sh`, `curl URL > i.sh && sh i.sh`, `curl URL \| tee i.sh && ./i.sh`, `wget URL/i.sh && ./i.sh`) | `git fetch` followed by `bash build.sh`; a search pattern naming both; `curl URL \| jq`; `curl URL \| python3 -m json.tool`, `\| python3 parse.py` or `\| python3 -W ignore parse.py`; `curl -o FILE URL` or `curl URL > FILE` that nothing on the line runs; `echo hi \| tee run.sh && sh run.sh` |
| `decoded-pipe-shell` | a decoder's output piped into a shell (`echo ... \| base64 -d \| sh`, `xxd -r ... \| sh`, `zcat x.gz \| bash`), or a shell running a decoder (`bash -c "$(base64 -d f)"`, `sh <(base64 -d f)`) | decoding to a file or into `grep` |
| `chmod-setuid` | setting the setuid or setgid bit with `chmod` or `install -m`: an octal mode whose leading digit holds 4 or 2 (`4755`, `04755`, `2775`), or a clause that adds `s` (`u+s`, `g+s`, `+s`); an inline program that passes such a mode to `chmod` (`os.chmod(path, 0o4755)`, `chmodSync(path, 0o2755)`, `File.chmod(04755, path)`, `chmod 04755`) | other modes (`0755`, `1777`, `+x`, `u-s`, `os.chmod(path, 0o755)`, `chmod 0755`) |
| `raw-disk` | `mkfs` on a device, `dd of=` a block device, `wipefs -a`, `sgdisk`, `sfdisk`, `fdisk`, `parted`, `blkdiscard`, `mkswap` or `shred` on a block device, `cryptsetup luksFormat`, `badblocks -w`, a `>` redirection into a block device | `mkfs` on an image file, `dd` to a file or `/dev/null`, the listing forms (`fdisk -l`, `parted print`, `sfdisk --dump`, `wipefs` without `-a`) |
| `recursive-chmod-chown` | a recursive `chmod`, `chown`, `chgrp` or `setfacl` from `/`, a home directory or a system tree (`/etc`, `/usr`, `/var`, ...), or a recursive `chmod` to `000`, `a-rwx`, `777` or `o+w` outside `/tmp` | `chmod -R u+w target`, `chown -R $USER ./build`, `chmod -R 700 ~/.ssh` |
| `find-delete-outside-tmp` | `find ... -delete`, or `-exec`, `-execdir` or `-ok` running `rm`, `shred` or `unlink`, whose starting points reach outside `/tmp` and `/var/tmp`; no starting point means the current directory | the same under `/tmp`; `find` without a delete; `find -exec grep`; a cleanup inside the tree whose name tests all name files a tool writes again (`find . -name '*.pyc' -delete`, `find . -name .DS_Store -delete`), unless the line can `cd` out of the tree |
| `find-write-outside-tmp` | `find -fprint`, `-fprint0`, `-fprintf` or `-fls` whose file is absolute and outside `/tmp` and `/var/tmp`, or a relative path that climbs (`find / -fprint /etc/x`, `find . -fprint /etc/x`, `find / -fprintf /etc/x '%p\n'`, `find . -fprint ../out`, `find / -fprint /tmp/../etc/x`) | that file under `/tmp` or `/var/tmp` (`find /tmp -fprint /tmp/out`); `/dev/null`, `/dev/stdout` and `/dev/stderr`; a plain relative path, because a redirection to that path is allowed (`find . > files.txt`, so `find . -name '*.c' -fprint files.txt` and `find . -fls out`); `find -print` and `find -printf`; a `-fprint` word that belongs to the `-exec` command |
| `rm-rf-outside-tmp` | a recursive `rm` or `rtrash` whose own operands reach outside `/tmp` and `/var/tmp`, a `..` in the path included; also `python -c`, `node -e`, `ruby -e` or `perl -e` code that calls `shutil.rmtree`, `rmSync(..., {recursive})`, `rm_rf`, `rm_r` or `remove_tree` outside `/tmp` | the same under `/tmp`; a build output directory named as a plain relative path (`rm -rf target/`, `rm -rf node_modules`, `rm -rf ./build`, `web/.venv`) or a top-level scratch directory (`rm -rf ./tmp/test-output`, `.tmp`, `temp`), unless the line can `cd` out of the tree; a later command on the line that is not a delete |
| `git-force-push` | `git push` with `--force`, `-f` in a flag cluster, `--mirror`, or a `+` refspec; a `--force-with-lease` push onto `main`, `master` or `develop`, or one whose words name no branch (no refspec, `HEAD`, a wildcard, `--all`). ljos asks rather than refuses, and reads a bare lease push's branch from the checkout. A branch the checkout protects is ljos's question too | an ordinary `git push`, `git push -u origin BRANCH`, `--force-if-includes` alone, and a lease push onto any other branch (`feature`, `mainline`, `develop-fix`, `release`), which the remote refuses when it holds commits you have not fetched |
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

A task runner is judged on what its target runs. `make` and `just` read
the target from the Makefile or justfile, `cargo make` from
`Makefile.toml`, and `npm run`, `pnpm`, `yarn` and `bun run` read the
script from `package.json`. The file is read where the runner runs: the
working directory, the one a `cd` or `pushd` earlier on the line enters,
or the one `-C`, `--prefix` or `--cwd` names. Each line of the recipe is
judged as above, so `cd ~/proj && make clean-all` whose recipe runs
`rm -rf ~` is ``make clean-all runs `rm -rf ~`: rm-rf-outside-tmp``, and
`make test` and `npm run build` still run. Nothing is spawned. A missing
or unreadable file, or a directory the line does not name (`cd "$DIR"`),
leaves the line judged as written. `cd -` enters `OLDPWD`, and without
it a runner after `cd -` is refused.

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
scripts and substitutions. A refusal from the table stands, and a refusal
from phronesis carries the pack's own reason after the tab. Without the
library the crate still builds and uses the table alone.

The build links phronesis and the Cap'n Proto C runtime statically and
embeds phronesis's default pack, so the binary needs no phronesis install
and keeps no path from the machine that built it. The C shim follows the
installed schema's bare-pointer or typed-list representation of `List(Text)`
without changing the wire message. A word is handed to the
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
| `check-mail --config PATH [--argv [--] RECIPIENT...]` | reads one RFC 5322 message on stdin and prints a JSON allow or deny | 0 when nothing was refused; 2 when it refuses |
| `version` | the version and the backend | 0 |

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
