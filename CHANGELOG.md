# Changelog

<!-- towncrier release notes start -->

## Unreleased

## 0.5.0 (2026-10-22)

### Features

- An outbound envelope is refused when From is not the configured identity, when Reply-To, Sender or Return-Path names a deny-file identity, or when a recipient domain is named by the deny file or the pack-law file. Domains are compared after NFKC and IDNA, so a fullwidth or punycode form of a denied domain is that domain. An empty result is not a grant to send.
- Folded headers, encoded-words and a repeated From are read as one message. A fold stays the same header and keeps the space where the line broke, an encoded-word is the text it names, and a second From stays a second header so a later check can refuse it instead of picking one copy.
- `ljos-policyd check-mail` reads an RFC 5322 message on stdin and a config path, and prints a JSON allow or deny. Allow means this check found nothing to refuse. A send still needs its own grant.

### Fixes

- A Resent-* header replaces the envelope after the check. Errors-To, Disposition-Notification-To and Return-Receipt-To name a mailbox the same way Reply-To does, so a deny-file identity on those headers is a refusal too.
- A `#` that starts a word in a script comments out the rest of its line, so `true # ; cd safe` followed by `make clean-all` on the next line no longer follows the commented-out `cd` and reads `make` where the shell is.
- A `$NAME` or `${NAME}` in an `env -S` string is read as the value the line assigned it, when the line assigns it one value and sets it no other way, since the shell expands the string before env splits it. `CMD="git push --force origin main"; env -S "${CMD}"` is refused, and `env -S "$CMD"` with `CMD='-C evil make clean-all'` reads `evil/Makefile`.
- A `>&file`, `>& file` or `1>&file` redirection counts as a write of that file, so `echo 'git push -f' >&x.sh; sh x.sh` is refused as `script-written-on-line`. `>&` was read only as a copy of a descriptor; it is one only when the word after it is a number or `-` (`2>&1`, `>&-`).
- A `BASHOPTS` or `SHELLOPTS` set in front of a shell, or exported before it, to a value that names `lastpipe` or that the line does not show may turn `lastpipe` on in that shell, so `BASHOPTS=lastpipe bash -c "true | cd evil; make clean-all"` is refused.
- A `BASH_ENV` file that starts another `bash` is read only a bounded number of times and then refused as `startup-script-unshown`. `export BASH_ENV=loop.sh; bash -c 'echo ok'`, with a `bash -c` in `loop.sh`, overflowed the guard's stack, since each bash the file starts sources it again.
- A `BASH_ENV` or `ENV` in the guard's own environment counts as exported to every shell the line starts: with `BASH_ENV=evil.sh` inherited, `bash -c 'echo ok'` was allowed, although that bash sources evil.sh first. The file is judged as one the line exported, and `env -u BASH_ENV`, `env -i` and `unset BASH_ENV` still take it out.
- A `BASH_ENV` or `ENV` startup file is judged for every form of a non-interactive `bash` or `sh`, not only for a `-c` script: `BASH_ENV=evil.sh bash ok.sh`, `export BASH_ENV=evil.sh; bash ok.sh` and `BASH_ENV=evil.sh bash < ok.sh` were allowed, although the shell sources the file before a script file or stdin as well.
- A `CDPATH` set earlier on the line, alone or with `export`, `declare`, `readonly` or `typeset`, is searched by a later `cd` or `pushd`: `export CDPATH=../lib; cd proj && make clean-all` read only `proj/Makefile` here and allowed the `rm -rf ~/` in `../lib/proj/Makefile`, where the shell runs make. One set in a pipeline stage, a subshell or a background list is not followed, one set past `&&` or `||` is searched along with the one before it, and one the line sets some other way (`read CDPATH`, `${CDPATH:=dir}`, `CDPATH=dir :`) leaves the runner after the `cd` refused.
- A `CDPATH` set in front of a `cd` or `pushd`, or of the shell that runs one, is the one searched: `CDPATH=../lib cd proj && make clean-all` and `CDPATH=../lib sh -c 'cd proj && make clean-all'` read only `proj/Makefile` here and allowed the `rm -rf ~/` in `../lib/proj/Makefile`, where the shell runs make. A value the line does not show (`CDPATH=$LIB cd proj`) leaves the runner after the `cd` refused.
- A `HOME` set in front of a bare `cd`, or of the shell that runs it, is the one entered, and one set earlier on the line is also where `~` and a later bare `cd` go: `HOME=project cd && make clean-all` and `export HOME=project; cd ~ && make clean-all` read the Makefile in the environment's home and allowed the `rm -rf ~` in `project/Makefile`, where the shell runs make. A `HOME` the line does not show (`HOME=$(mktemp -d) cd`), or that may hold either of two values, leaves the runner after the `cd` refused.
- A `NAME+=value` word is read as an assignment, as the shell and `env` read it, so it no longer hides the command after it: `FOO+=1 git push -f origin main` and `env A+=1 git push --force` were allowed, `FOO+=1 make clean-all` did not read the Makefile, and `FOO+=1 cd project && make clean-all` read the Makefile where the line started instead of in `project`.
- A `case` arm is judged on the command after its pattern, so `case "$x" in a) git push --force ;; esac` is refused as `git-force-push`, and a `cd` in an arm moves the runner after `esac` as any other `cd` that may not run.
- A `case` pattern with the `)` on its own (`*[!_$as_cr_alnum]* )`)
  was read as the command. The `$` in the brackets dropped the
  directory. A pattern cannot move the shell, so the directory stays.
- A `cd` or `pushd` now takes `..` off the path by name, as the shell's
  default logical `cd` does, so `cd lnk/.. && make clean-all` reads the
  Makefile where the line started even when `lnk` is a symbolic link to
  another directory. `cd -P`, and `set -P` earlier on the line, still
  resolve the link.
- A `cd` or `pushd` through `CDPATH` enters only the first entry that holds the path, as bash does, with an empty or `.` entry standing for the working directory, so `CDPATH=:../lib cd proj && make clean-all` and `CDPATH=.:../lib cd proj && make clean-all` read `./proj/Makefile` alone and are allowed again when `proj` is here. Every entry that held the path was read, so a `../lib/proj` the shell never enters refused the line.
- A `cd` or `pushd` to a path the line does not show, through a variable, a substitution or `~user` (`PWD=evil; cd "$PWD"`, `cd "$X"`), leaves the line in a directory it does not follow, so a runner after it is refused rather than read where the line was. `$PWD` is still read as the one directory the line is in when the line shows that and does not set `PWD`.
- A `cd` or `pushd` to a relative path whose first part is not `.` or `..` also enters each `CDPATH` entry that holds the path, as the shell may: with `CDPATH=~/lib`, `cd proj && make clean-all` read only `./proj/Makefile` and allowed the `rm -rf ~` in `~/lib/proj/Makefile`, where the shell runs it.
- A `cd` or `pushd` whose target is a glob or a brace is not a directory the line shows, and a relative `source` after an unresolved `cd` is not read from the last directory the walk could name.
- A `cd` whose path by name is no directory is now also judged through the
  links, where bash enters it when the logical path fails. `cd lnk/../x &&
  make clean-all`, with `x` only beside the target of `lnk`, read no
  Makefile and let the recipe there run.
- A `cd` whose target the line does not resolve left the directory
  untracked, so `cd "$X" && source .venv/bin/activate` was refused
  unread even when that file was in the directory the line had just
  left. The directory is unknown, and a relative `source` is read from
  the last directory the walk could name. A runner there stays
  untracked, and a file that is missing or unreadable stays unread.
- A `cd` written in a here-document was run, so the commands after the
  document were read in that directory. The body is text for anything
  other than a shell. A shell that takes the document as its script
  still runs it, and an expansion in an unquoted body still runs.
- A `cd`, `pushd` or `env -C` path that starts with `$HOME` or `${HOME}`
  now expands from the `HOME` the line shows, as `~` does, and `~login`
  expands from the password database. `cd $HOME/proj && make test` and
  `cd ~user/proj && make test` now read the Makefile in proj, where every
  make after such a cd was refused as one that may run anywhere. Such a
  path searches `CDPATH` only when `HOME` is relative, and a `CDPATH`
  entry with `$` in it still names no directory the line shows, since the
  shell expanded it when `CDPATH` was set.
- A `cp`, `mv`, `ln` or `install` into a directory now counts as writing
  each source's name there, not the whole directory, so
  `cp config.mk . && sh ./configure` is no longer refused. A recursive
  copy still counts as writing all of the directory.
- A `popd` that fails, on a word it does not take (`popd x`, `popd +x`, `popd -q`) or with nothing left to pop on the stack the line built (after `dirs -c`, or past its last `pushd`), leaves a runner after it refused as running in an untracked directory. Each was read as a bare `popd`, or as staying put, so `pushd evil && popd x; make clean-all` read the Makefile where the line started while bash runs make in `evil`.
- A `sed` or `cat` of `$0` was the script being judged, so the copy could be sourced without being read. `sed` `i`, `a`, `c` and `e`, `sed -f`, a `y` or `s` that drops `#`, and `cat` with a file argument write a different script. A variable counts only when it is exactly `$0`, and a `cd` drops that trust.
- A `set -P` in a file the line sources, or `physical` in a `SHELLOPTS`
  given to a bash the line starts, now counts for each later `cd`, as
  `set -P` on the line does. `source ./p.sh; cd lnk/.. && make clean-all`
  and `env SHELLOPTS=physical bash -c 'cd lnk/.. && make clean-all'` read
  the Makefile where the line started, while bash enters the one that
  holds the link's target.
- A `shopt` with an option or flag the line does not show (`opt=lastpipe; shopt -s $opt`, `shopt -s last*`), or a command word the line does not show, is taken to turn `lastpipe` on, so a `cd` or an assignment in the last stage of a pipeline after it is not followed.
- A `source` or `.` of a file the guard can read is judged by the same
  rules as the line. `source ../evil/force.sh` was allowed when the file
  ran `git push -f` or `make -C ../evil clean-all`, because only the
  directory walk saw the text. The walk now hands that text to the deny
  rules before it tracks the directory.
- A `source` or `.` of a literal path to a regular file the guard can
  read keeps the directory when that file does not move the shell or set
  `HOME`, `CDPATH` or `PWD`. `source .venv/bin/activate && make test` is
  allowed again. `eval`, a command word the line does not show, and a
  file that cannot be read still leave the line untracked.
- A `trap` action is judged as a script, so `trap "git push -f" EXIT` is refused as `git-force-push`. A `trap` whose action may move the shell (`trap 'cd evil' DEBUG`, `trap "$X" DEBUG`) leaves the line untracked, so a runner after it is refused.
- A `|` between `case` patterns was read as a pipeline, so `a | sh | b)`
  was an unshown script on `sh`'s stdin. The pattern is not a command
  either: `cd` or a glob there moved the shell or counted as a write.
  A `|` in an arm body is still a pipeline, and the arm is still judged.
- A backslash before a newline in a shell script now joins the two lines,
  as the shell does, instead of keeping the newline in the next word. This
  closes bypasses such as `cd project && \` followed by `make clean-all` on
  the next line, which now reads the recipe in project.
- A backtick inside `(test ...)` was read as a command of this shell,
  so the directory was dropped and `make` after it was untracked. The
  subshell runs in its own shell, and its body is walked there. A `cd`
  in that subshell still moves only the subshell, and `$c` when `c` is
  `cd` still drops this one.
- A bare dotted-quad domain was accepted as a name, so it never met a domain rule, and a resolver connects to that address. An all-numeric domain, including one written with fullwidth digits, is a refusal.
- A brace group no longer hides directory changes. A line such as
  `{ cd project && make clean-all; }` now tracks `cd` before the runner is
  read.
- A command that writes `PWD` through a name glued to its option (`printf -vPWD`, `wait -pPWD`) sets it, so `$PWD` after it is no longer read as the directory the line is in and a `cd "$PWD"` is not followed.
- A command the guard does not know to leave files alone (`rsync`, `tar`,
  `unzip`, `patch`, `git checkout`, `python -c`, `make`, a binary, ...)
  now counts as writing anything under the directory it runs in, so a
  shell script the same line runs after it is refused as
  `script-written-on-line`. A short list of commands known to write
  nothing (`echo`, `cat`, `grep`, `ls`, `test`, `cd`, read-only `git`,
  ...) does not count, and a binary run after a build is not a script.
- A command word containing a glob and a slash was a program that might
  write any file, so `/usr/bin/foo*` made a later script look written by
  the line. A glob is not one program. A command the guard does not know,
  with no glob in its name, may still write anything where it runs.
- A command word that an `alias` earlier on the line defines is judged as the alias's body, so `alias m="make clean-all"; cd ../evil; m` reads the Makefile in `../evil` and `alias p='git push -f'; p` is refused as `git-force-push`. An alias whose body the line does not show leaves the line untracked, so a runner after it is refused.
- A control keyword in front of `cd` now keeps directory tracking aligned
  with shell behavior. Lines such as
  `if cd project; then make clean-all; fi` and
  `while cd project; do make clean-all; done` now read the runner in the
  directories those forms can reach.
- A deny-file `domain` or pack-law `deny-domain` rule for an all-numeric domain such as a dotted quad loaded, but a recipient at that domain is refused before it is compared, so the rule matched nothing. Rule domains are now read by the same parser as recipient domains, and such a line refuses the file with only the line number as detail.
- A deny-file address blocked that mailbox in Reply-To and not in To, Cc or Bcc, so the message could be sent straight to an address the file had refused. The same address is a refusal in those recipient headers. It is still that mailbox, not the whole domain.
- A domain or deny-domain value that is not a hostname after IDNA refuses the file. A star, a colon, a slash, an at-sign and whitespace are in that set. The error names the line and not the value. A domain rule already covers subdomains, so a wildcard is not how to write one.
  An address rule with a star, or with a character a parsed recipient cannot carry, is refused the same way. A rule that loaded and matched nothing would let the recipient through.
- A download handed to an interpreter as `/dev/stdin`, or with only a valued flag in front of it (`python3 -W ignore`, `node --require mod`), now reads as `curl-pipe-shell`, as does a file a redirection or `tee` saves and a later command runs (`curl URL > i.sh && sh i.sh`, `curl URL | tee i.sh && ./i.sh`). An inline `chmod` with a setuid or setgid mode (`os.chmod(path, 0o4755)`, `chmodSync(path, 0o2755)`, `File.chmod(04755, path)`) reads as `chmod-setuid`. `curl URL | python3 parse.py`, `curl URL > data.json`, `os.chmod(path, 0o755)`, `chmod 0755` and `git push --force-with-lease origin feature` stay allowed, including a branch whose name only contains `main`.
- A file redirected onto the stdin of a shell that has no script operand is that shell's script, and is judged: `sh <evil.sh`, `sh 0<evil.sh`, `sh < evil.sh`, `bash -s < evil.sh` and `busybox ash <evil.sh` were allowed, or refused as unshown stdin, without the file being read. It counts as a script the line runs, so `cp evil.sh ok.sh; sh < ok.sh` is refused as `script-written-on-line`. A path the line does not show, or a process substitution there, is still unshown.
- A file run by its path (`./build.sh`, `exec ./x`, `env ./x`, `sub/run`) is read and judged, where before only a script handed to a shell was: `./direct.sh` holding `git push -f` was allowed. A compiled program, known by its ELF or Mach-O magic number, is not read. A file with a shell's `#!` line, or none, is judged as a shell's script file; one for Python, Perl, Ruby, Node, Deno or Bun as that interpreter's inline program; and one for any other interpreter is refused as `script-unread`, as is a relative path in a directory the walk does not follow. A leading `~` is read from `HOME`, and an interpreter name keeps its version and any suffix off (`perl5.38-x86_64-linux-gnu`).
- A file that a `source` or `.` reads is scanned with the aliases the line defined before it expanded, so `alias go='cd evil'; source ./env.sh && make clean-all` with `env.sh` calling `go` leaves the line untracked and the runner is refused.
- A fullwidth percent or at-sign in a local part passed the route check, because NFKC folds it only later. A local part that NFKC changes into ASCII punctuation, including fullwidth `@`, `%`, `!` and the other fullwidth marks, is a refusal.
- A generated configure removes `confdefs.h`, `a.out` and `conf$$*`
  along with `conftest*`. The comment the file starts with is only a
  hint that those names are that file's temps. `/`, a home directory
  and a variable assigned to a real path stay refused, and a file
  without the comment does not get the temps.
- A generated configure runs `. "./$as_me.lineno"` only on the
  failure side of `||`, then `exit`. That side cannot fall through,
  so losing the directory there was sticking for every later command,
  including `. ./conftest.sh`. The commands after the list now keep
  the side that does not exit. A command before `exit` is still judged,
  and the same source without `exit` still drops the directory.
- A generated configure writes `name ()` and `{` on the next line. The
  newline was a separator, so the body ran at the definition and `eval`
  inside it dropped the directory. The brace still closes the
  definition. A call of that function still runs the body.
- A group in From was accepted when its mailbox was the identity. RFC 5322 does not allow a group there, and receivers parse the syntax differently. A group in From is a refusal. A group in a recipient header still contributes its mailboxes.
- A header block that mixes CRLF and a bare LF has two places a reader can split off the body. The earlier split drops the headers between them, including a recipient the other reader still sends. That block is refused.
- A header line over 998 octets was accepted. A hop that wraps the line without folding turns the tail into a new header, so a Bcc past column 998 was never judged. A header line over that limit is a refusal.
- A later word that only names `HOME` or `CDPATH` (a grep pattern, a commit message, `printenv HOME`, `${#HOME}`, `docker -e HOME=...`, `env HOME=dir cmd`) no longer loses the value the line set, so `HOME=dir; printenv HOME; cd ~ && make test` is allowed again. Only a command that writes the variable in this shell (`read`, `mapfile`, `getopts`, `printf -v`, `wait -p`, `for`, `select`, `declare` with other flags, `let`, `eval`, or `${NAME:=value}`) leaves it untracked.
- A leading `command`, `command -p` or `builtin` no longer hides a `cd`
  or `pushd` from the directory tracker. A line like
  `command cd project && make clean-all` now reads the runner where it
  actually runs.
- A make, npm or just target's recipe is now also judged as one script,
  its lines in order, so a recipe line that writes a script a later line
  runs is refused as `script-written-on-line`.
- A non-interactive `bash` reads `BASH_ENV` and a non-interactive `sh`
  reads `ENV` before its `-c` script. `BASH_ENV=../evil/force.sh bash -c
  'echo ok'` was allowed when that file ran `git push -f`. A literal file
  is judged as a sourced script, including one `export` set earlier on
  the line. A value the line does not show leaves the shell unknown.
- A parent that is not there yet, or that the same line creates, may be a symlink by the time `rm -rf` runs. The check was reading the starting directory and treating a missing parent as a real one, so `cd` and an earlier `ln` were ignored.
- A quote in a here-document ran on past the delimiter and hid every
  command after it, so a force-push that followed help text was allowed.
  The body is read on its own up to the delimiter line. A quote in the
  body stops there, and the next command is still judged. A shell whose
  script is the document is still judged on that text.
- A quoted or escaped `;`, `&&`, `||`, `|` or `&` in a script (`echo ';'`, `find ... \;`) is an argument, not a separator, so `echo ';' cd safe && make clean-all` no longer follows a `cd` that never runs and reads `make` where the shell is.
- A recipient or reply domain whose label mixes Latin with Cyrillic or Greek is a lookalike of a name it is not. The check reads each label after NFKC and IDNA, including a punycode form of the same label, and refuses the mix.
- A redirection in a `pushd` no longer hides a bare `pushd` or a stack index: `pushd safe >/dev/null && pushd >/dev/null && make clean-all` and `pushd safe && pushd 2>/dev/null +1 && make clean-all` swap back to where the line started, and read its Makefile there. Both read only `safe` and allowed the `rm -rf ~` in the Makefile the shell runs.
- A redirection standing before the command was taken as the command,
  so `>conftest.c echo` counted as a program that might write any file.
  The command is the word after the redirection. An unknown command
  there may still write anything, and a script the redirection names is
  still judged when a later command runs it.
- A redirection that closes a descriptor (`2>&-`, `>&-`, `<&-`) is read as a whole word, so the word after it is the `cd` or `pushd` target: `cd 2>&- project && make clean-all` took `project` for the redirection's file, read the Makefile in home, and allowed the `rm -rf ~` in `project/Makefile`, where the shell runs it.
- A redirection that stores its descriptor in a variable, `{fd}>file`, is no longer taken for the `cd` or `pushd` target, so `cd {fd}>/dev/null evil && make clean-all` follows the `cd` and refuses the `rm -rf ~` in `evil/Makefile`. `{HOME}>file` or `{CDPATH}>file` sets that variable in the shell, so it is no longer followed after one.
- A script a command earlier on the line may write, and a later command sources or runs, is refused as `script-written-on-line`: `echo 'git push -f' > x.sh; source x.sh`, `echo hi | tee run.sh && sh run.sh`, `curl -o x.sh URL; source x.sh` and `echo ... > x.sh; BASH_ENV=x.sh bash -c ...` were judged by what the file held on disk before the line ran. Paths are placed the way the `cd` walk places directories, through subshells, `-c` scripts and `&`, and a write to a path the line does not show (`> "$OUT"`) counts for any script run after it. A file only read (`echo x > out.txt; cat out.txt`) stays allowed.
- A script file was judged as one flat argv, so a subshell or a substitution in the file never met the deny rules. A file and a shell's `-c` text are the same parse. `sh -c "$(cat s.sh)"` and `eval "$(cat s.sh)"` read that file, and a `cat` whose path is not shown is refused.
- A script reached through a symlink is read as the file the link names, the way the kernel opens it, so `sh link.sh`, `source link.sh` and `BASH_ENV=link.sh bash -c ...` with link.sh pointing at a refused script are refused. The file was opened without following links and nothing was read, so the line was allowed. A loop of links still opens nothing, and a link to a missing file runs nothing.
- A script refused as `script-written-on-line` now says why when the
  write is not a plain path: the variable that may name the script, with
  a hint to write to a literal path, or the unknown command that may
  write any file where it runs.
- A script the guard cannot judge is refused as `script-unread` rather than allowed unread: one past the read limit, now 4 MiB rather than 64 KiB, a loop of links, a fifo or other file that is not a regular file, or a relative path run or sourced in a directory the line may be in but the walk does not follow (`cd "$X" && sh x.sh`). `sh big.sh` with a refused command past the first 64 KiB was allowed. A script the line may run from several directories (`cd evil; bash force.sh`) is read in each. A missing file, or a directory, runs nothing and stays allowed.
- A script the line writes with `echo`, `printf` or a here-document whose
  every word is literal, and then runs, is now judged on that text
  instead of refused, so `echo 'echo ok' > build/run.sh && sh
  build/run.sh` passes. Lines of a here-document something other than a
  shell reads no longer count as commands that may write a script.
- A script with bytes that are not UTF-8 is judged with each bad byte replaced, as bash still runs the commands it can parse: `sh bin.sh`, with a stray byte before `git push -f`, was allowed because the file was not read as text.
- A shell `-c` script that runs one of its positional parameters as code
  (`eval "$1"`, `. "$1"`, `exec "$@"`) is now refused as
  `xargs-script-unshown` when `xargs`, `parallel` or a variable read from
  stdin fills those parameters.
- A shell function runs in the shell that calls it. `go() { cd evil; }; go
  && make clean-all` was allowed, because the `cd` in the body never
  moved the walk and `make` was read where the line started. The walk now
  keeps a function defined on the line or in a sourced file and judges
  the body at the call, so the recipe is the one in `evil`. A body or a
  name the line does not show leaves the line untracked. `command` and
  `builtin` still run the program.
- A shell that reads its script from stdin is judged on it: the text of a here-string (`bash <<< "git push -f"`) is read as the script, and a pipe into a shell (`echo "git push -f" | bash`), a `bash -s` fed no here-string or heredoc, or a here-string holding an expansion is refused as `shell-stdin-unshown`.
- A shell whose script operand is `<(...)` runs that substitution's
  output. `bash <(echo git push -f)` and `bash <(cat ../evil/force.sh)`
  were allowed: a process substitution was judged only when it
  downloaded. Literal `echo` or `printf` text, and a `cat` of a literal
  file, are judged as the script. Anything else is unknown.
- A short address rule stays on its own domain. ed@outlook.com denies that mailbox and a subaddress, and not ed@hotmail.com. A longer rule still crosses the family: john@outlook.com denies john@hotmail.com, john@live.com, john@msn.com and john@outlook.de. Those domains are not one mailbox. The skeleton prefix is what crosses.
- A source route was parsed and then discarded, so only the final mailbox was judged. An MTA that honours the route relays through those hosts. The route is a refusal.
- A stage before a `|` in a sourced file runs in a subshell and no longer makes the file look like it moves the shell, so the `case "$(uname)" in CYGWIN*|MSYS*|MINGW*)` block in a Python 3.13 venv's `activate` keeps `source .venv/bin/activate && make test` allowed.
- A subshell or command substitution reads a task runner's file where the command holding it runs, so `cd project && (make clean-all)` and `cd project && echo $(make clean-all)` read `project/Makefile`. Inside a `sh -c` script both were read where the line started, and allowed. `cd project && (make test)` stays allowed.
- A task runner that `xargs` runs is refused as `xargs make may take a target from stdin`, since the words `xargs` adds can name any target: `cd project && printf '%s\n' clean-all | xargs make` read the default goal and allowed the `rm -rf ~` in `project/Makefile`, and `echo clean-all | xargs make test` runs both targets. `cd project && ls | xargs wc -l` stays allowed.
- A task runner that may run in a directory past the sixteen a line's `cd`s are followed through is refused as `may run in an untracked directory`, where the directory was dropped and the runner read only in the rest, and a `cd` into a directory without the search bit no longer counts as entering it. After `cd project`, eighteen `cd`s into mode-000 directories before `make clean-all` read only those directories and allowed the `rm -rf ~` in `project/Makefile`.
- A task runner the line enters with `cd` is judged on what its target runs. `cd ~/proj && make clean-all`, `bash -lc 'cd ~/proj && npm run nuke'` and `pushd ~/proj && make clean-all` read the Makefile or `package.json` in the directory the line enters, and `popd` goes back. The file used to be read only in the checker's own working directory, so these lines were allowed whenever it ran anywhere else. `bun run` reads `package.json` scripts as `npm run` does; a bare `bun build` or `bun test` is bun's own tool and is not read. `make test` and `npm run build` stay allowed, and a directory the line does not name (`cd "$DIR"`, `cd -`) or a missing file leaves the verdict as before.
- A task runner's file is read in every directory the line may run it in. A `cd` sent to the background with `&` or run as a pipeline stage moves only its own subshell, so `cd safe & make clean-all` reads the Makefile where the line starts. An assignment in front of `cd` no longer hides it (`FOO=1 cd project && make clean-all`), and a script handed to a shell or `eval` starts where the line has moved to (`cd project && bash -lc 'make clean-all'`). The line goes on past a `cd` that fails at `;` or `||`, so `cd missing; make clean-all` reads the Makefile both where the `cd` goes and where it starts, and is refused if either recipe is. Each of these lines was allowed. `cd project && make test` stays allowed, and `cd safe && make clean-all` reads only `safe`.
- A value is known only from a plain assignment. `export`, `read`, `for`, `eval` and the other binders do not prove it, an `IFS` assignment turns variable suffixes off, and `$0` is the script only for a marked `sh FILE` or `./FILE`. An `rm` does not clear a file it names.
- A variable `read`, `mapfile` or `readarray` fills from stdin earlier on the line is refused as `stdin-variable-script` where a later command runs it as a script or as its command word: `read x; sh -c "$x"`, `read -r c; eval "$c"`, `read f; source "$f"`, `read c; $c`. These were allowed, as the script was the `$x` the line shows. Passing such a variable as an argument (`read x; echo "$x"`) stays allowed.
- A word that only names `PWD` (`echo PWD`, `grep PWD`, `env PWD=/x cmd`) no longer stops `$PWD` being read as the directory the line is in. Only an assignment in this shell, or a command that writes the name it takes (`read PWD`, `printf -v PWD`, `unset PWD`, `((PWD=1))`), does.
- A write in a loop body, in a substitution of the same command, or by
  the command that runs the script (`sh x.sh >> x.sh`) now counts for a
  script the line runs, whatever the order the line shows them in, so
  `for i in 1 2; do sh ok.sh; cp evil.sh ok.sh; done` is refused.
- Address rules folded only the gmail pair and one fastmail shape. Provider aliases are now a table of families, each with its domains, its subaddress separators and its local-part folding, and `+` is a separator on gmail and fastmail even when `subaddress` leaves it out. Proton's four domains are one mailbox, and so are Apple's three, each with `+`. Microsoft's domains stay separate and cut on `+`. A Yahoo rule for a disposable `<base>-<keyword>` address covers the base and every keyword on it. An `alias` line in the config adds a family.
- An EXIT trap that changes directory was treated as moving every
  command after it, so `make` following `trap 'cd /' EXIT` was refused
  as untracked. The trap runs when the shell exits. Its action is still
  judged. A trap on any other signal still moves the commands after it.
- An `env -S` string that still holds a `$` once the values the line shows are read in (`env -S "$X"`, `env -S "git ${SUB:-push} -f"`) is refused as `env-split-string-unshown`, since what it runs may be any command. A more specific refusal from inside the string still names itself.
- An `env -u BASH_ENV`, `env --unset=BASH_ENV` or `env -i` in front of a shell starts it without the exported startup file, so that shell is no longer refused for the file's text: `export BASH_ENV=evil.sh; env -u BASH_ENV bash -c 'echo ok'` is allowed. An assignment `env -i` makes after it is still read.
- An `eval`, `source` or `.` that runs in this shell, or a command word the line does not show (`c=cd; $c evil`), leaves the directory, the stack, `HOME`, `CDPATH` and `PWD` untracked, since what it runs may move the shell or set them. `eval cd evil; make clean-all` and `source env.sh && make clean-all` are refused.
- An `rm` in `if`, after `||` or `&&`, in the background, or after `rm` was defined as a function or an alias was still recorded. The file it named then counted as removed, so a later source of what the line had written was not judged. A removal counts only when that `rm` runs at the top level of the line.
- An `xargs` or `parallel` whose input lands where the command reads a script is refused as `xargs-script-unshown`: through a replace string (`printf 'rm -rf ~/Documents' | xargs -I{} sh -c '{}'`, `parallel sh -c {} ::: ...`) or as the words xargs appends when the command ends where its script would be (`xargs sh -c`, `xargs bash`, `xargs python3 -c`, `xargs eval`). The script was read as the `{}` the line shows, and allowed. Input that lands in positional arguments (`xargs -n1 sh -c 'echo "$1"' _`) stays allowed.
- An address at `@[ ... ]` was accepted as a domain, so a recipient or a reply path in that shape was not the denied name and was not refused. A domain literal is not a name this check can compare, and the header is refused.
- An address rule also denies by skeleton: the local part after NFKC and case folding, with `.`, `_`, `-`, `+` and `=` removed. A recipient whose skeleton starts with the rule's, at that domain or one in its family, is refused, so `johndoe@proton.me` now covers `john.doe@pm.me`, `john_doe@protonmail.com` and `john-doe@proton.me`. This over-blocks on purpose.
  The Yahoo and Microsoft families are patterns (`yahoo.*`, `ymail.*`, `outlook.*`, `hotmail.*`, `live.*`, `msn.*`) that cover every country suffix, so `yahoo.com.br` and `outlook.co.uk` get their family too. An `alias` line may use the same `<label>.*` form.
  A `domain` or `deny-domain` rule on a domain of a shared family covers the whole family: `domain gmail.com` refuses `googlemail.com`, `domain pm.me` refuses the other Proton domains, and `domain icloud.com` refuses `me.com` and `mac.com`.
  `shop@user.fastmail.com` is `user+shop@fastmail.com`, as Fastmail delivers it, instead of `user@fastmail.com`: a rule for either spelling covers the other, and a subdomain rule no longer denies every tag on the user. The subdomain fold also runs on the domains a `shared` family adds and is folded again, so `dots` reaches a dotted user label.
  A punycode subdomain label is decoded to Unicode before it becomes the local part, so `x@bücher.fastmail.com` matches a rule for `bücher@fastmail.com`.
  An `alias` line that names one domain or one flag twice refuses the config.
- An address rule covered only a `+` tag, so qmail and Postfix `-` or `=` extensions, a dotted gmail local part, googlemail.com, and a fastmail user subdomain were still delivered. Separators come from `subaddress` (default `+-=`). The gmail pair is one domain with dots ignored, and `local@user.fastmail.com` is that user at fastmail.com.
- An address rule matched the mailbox and not a local+tag subaddress, so Reply-To of evil+x was allowed while evil itself was refused. Most providers deliver the tag to that mailbox. The rule covers the subaddress.
- An address rule whose local-part skeleton is empty refuses the deny file. The error names the line and not the address. A deny file that does not load refuses every send, so a rule of only transparent characters cannot match every local part at that domain.
  Skeleton case folding runs twice, so capital sharp s folds to ss. A rule and a recipient written with Turkish I, Greek sigma, ß, a fullwidth letter or another NFKC compatibility form meet in either direction.
- An address rule whose skeleton is shorter than three characters no longer refuses the deny file. It still matches that mailbox, a subaddress and the same skeleton, including a Fastmail tag of one character. The prefix match, which would treat jo as john, is not used for it. An empty skeleton still refuses the file, and the error still names the line.
- An apostrophe in a comment inside a subshell was read as a quote,
  so the subshell ran on to the next one. configure's
  `if ( # -L didn't work. )` then hid the assignments that show
  `$ac_clean_files` is scratch, and its exit `rm` was refused.
- An arithmetic command or expansion that names `HOME` or `CDPATH` (`((HOME=5))`, `$((HOME=5))`) leaves that variable untracked, since it evaluates in the shell that runs the line and may assign it, so a runner after `cd ~` is refused.
- An array element assignment whose subscript holds `=` (`a[b=c]=1`) is split at the `=` after the matching `]`, as bash splits it, so `a[b=c]=1 git push --force origin main` is refused and `a[b=c]=1 cd evil && make clean-all` follows the `cd`.
- An assignment after a control keyword no longer hides the `cd` behind it: `if FOO=1 cd project; then make clean-all; fi` and `{ FOO=1 cd project && make clean-all; }` read the Makefile where the line started and allowed the `rm -rf ~` in `project/Makefile`, where the shell runs make.
- An assignment to an array element, `NAME[i]=value` or `NAME[i]+=value`, in front of a command is read as an assignment, so `a[0]=1 cd evil && make clean-all` follows the `cd` and `a[0]=1 git push --force origin main` is refused. One to `HOME[0]` or `CDPATH[0]` leaves that variable untracked.
- An encoded-word was decoded before the address was read, so a decoded parenthesis became a comment and the mailbox inside it was never compared. The mailbox is the raw unfolded address. A display name may still be decoded, and only for display. An encoded addr-spec is a refusal.
- Arithmetic that only reads `HOME` or `CDPATH` (`echo $((HOME))`, `(( HOME == 1 ))`) leaves the value the line set, so `cd ~` after it is followed. An assignment operator after the name, past any subscript, or `++` or `--` next to it (`((HOME=5))`, `((HOME++))`, `((HOME <<= 1))`) still leaves it untracked.
- Bash expands `{push,-f}` before the command runs, and the judge was still looking at the braces. A brace word is the command it expands to. `make -C`, `source` and `cd` do not follow a directory written with braces.
- Configure's `$as_me.lineno` and `conf$$.file` were refused as
  scripts the line had written. One is a `sed` of the script being
  judged and is sourced in that run; the other is created in the
  tracked directory and removed there. `$$` is only digits, so the
  second is not some other path. A bare `$file` still taints a later
  script.
- Each file a `sed -i` (or `--in-place`) edits counts as a file the line writes, so `sed -i 's/echo ok/git push -f/' ok.sh; . ok.sh` is refused as `script-written-on-line` rather than judged by the text ok.sh held before the edit. A `sed` that only prints stays a reader.
- Every deny-file-invalid and pack-law-invalid error names the line. An unknown key, a missing value and a pack-law line that is not deny-domain only said deny-file or pack-law, so the line had to be found by hand. The detail is still not the value.
- From was compared after NFKC, ignorable stripping and case folding, so a zero-width character or a fullwidth spelling matched the identity while the header that was sent named a different mailbox. From now has to equal the identity after ASCII case folding only, and a spelling those passes would change is a refusal.
- Pack-law domains were judged only on To, Cc and Bcc. A reply, a receipt or a follow-up could still name that domain, and the other side's mailer would use it. The same domain is a refusal on every header this check watches.
- Postfix opens a quoted local part and routes on @, % and ! after it strips a local domain, including when a backslash escapes the character. The quoted form was accepted, so that route was never judged. A quoted local part that holds any of the three is a refusal.
- Postfix rewrites an unquoted percent-hack or bang-path local part when the domain is local, then relays to that address. The characters were accepted, so the rewritten domain was never judged. An unquoted local part that holds either is a refusal.
- Raw newline and carriage-return characters in shell script strings are
  now treated as command separators. This closes bypasses such as
  `bash -lc $'true\nrm -rf ~'`, which now splits and checks both commands.
- Redirections before a `cd` or `pushd` target are now ignored when the
  tracker resolves the entered directory. This closes forms like
  `cd 2>/dev/null project && make clean-all` and
  `cd > /dev/null project && make clean-all`.
- Sender, Errors-To and Return-Path were checked against the deny file only, so the message could name an operator other than the identity. When one of those headers is present it has to be the identity, under the same rule as From. An empty Return-Path is not that address.
- Sendmail -t delivers to Apparently-To, and a MUA follows Delivery-Receipt-To, Mail-Followup-To and Mail-Reply-To. Apparently-To is a refusal on its own. The other three are deny-file identities, the same way Reply-To is.
- The `&` of a redirection (`2>&1`, `>&2`, `<&3`, `&>log`) inside a `-c` script stays in its word instead of reading as a list sent to the background, so `sh -c 'pushd project >/dev/null 2>&1 && make clean-all'` reads `project/Makefile` again and is refused for its `rm -rf ~`; it was read where the line started and allowed. A lone `&` still sends its list to the background.
- The `time` keyword, with or without `-p`, no longer hides a `cd` after it, so `time cd evil && make clean-all` reads `evil/Makefile` and refuses the `rm -rf ~` in it. `/usr/bin/time` is still read as a program that runs the `cd` in a child.
- The all-numeric check ran before IDNA, so a dotted quad written with U+3002 or U+FF61 was read as an address and still allowed. Hex labels, leading-zero labels, and the shorter forms inet_aton accepts were names too. The check reads the IDNA form and refuses those shapes.
- The autoconf marker is the leading comment, which 2.71 writes on line 3. It names temps in the current directory only. `core`, `a.out`, `b.out` and `config.status` are not recursive deletes.
- The brace cap counted every word on the line, so an ordinary command of a few hundred paths was refused as an expansion the line does not show. The cap is how wide one brace may grow.
- The command string `mapfile` or `readarray` runs with `-C` is now
  judged, and one that takes the lines it reads as code (`mapfile -C eval
  < cmds.txt`) is refused as `xargs-script-unshown`.
- The file a shell runs as its script (`bash evil.sh`, `env -C dir sh run.sh`, `cd dir && bash run.sh`) is judged as a sourced file is, in the directory the line has reached. `bash evil.sh` was allowed whatever the file held, since only a `-c` script was read. A file that is not there runs nothing and stays allowed.
- The pack's pass had no directory, so a relative scratch name was treated as a symlink and left unchanged. `rm -rf conftest*` was then refused after the host had allowed it. That pass uses the directory the host checked.
- The skeleton is NFD, combining marks removed, case folded twice, combining marks removed again, then NFC. Dropping only a combining dot that survives NFKC left a mark that had already composed with the letter before it, so abc followed by U+0301 and x was not denied by abc. The same composition left Lithuanian i + U+0307 + U+0300 different from ì. Both are one skeleton now. The second removal drops the dot that case folding İ produces.
- The target of a `cp`, `mv` or `ln` counts as a file the line writes, so a script copied, moved or linked into place and then sourced or run on the same line is refused as `script-written-on-line`: `cp evil.sh ok.sh; source ok.sh`, `mv evil.sh ok.sh; ./ok.sh`, `ln -sf evil.sh ok.sh; . ok.sh`. A `-t` or `--target-directory` directory covers every script under it.
- The word after an `xargs -i` is the command it runs: GNU xargs takes the replace string of `-i` only in the same word (`-i{}`). It was read as the value, so `xargs -i git push -f` was judged as `push -f` and allowed.
- The words "Generated by GNU Autoconf" counted on any comment line, so a script could mark itself as a generated configure and remove `a.out`. The marker counts only on the first two lines, and it is not a pass.
- U+0085, U+2028 and U+2029 passed the header control check, which looks at bytes. A reader that splits lines on them, as Python's str.splitlines does, would see a new header. Those characters in the header block are a refusal.
- With `HOME` unset or empty, a `cd` path `$HOME/x` now enters `/x`, as
  bash expands it, and so does `~/x` with `HOME` empty, while `cd $HOME`,
  or `cd ~` with `HOME` empty, stays. Such a path was read as one the line
  does not show, so `unset HOME; cd $HOME/abs/proj && make test` and
  `export HOME=; cd ~ && make test` were refused.
- With `HOME` unset, `~` is the home in the user's passwd entry, as bash expands it, so `unset HOME; cd ~/x && make clean-all` reads `~/x/Makefile` and refuses the `rm -rf ~` in it again. The `~` was read as naming no directory, and the runner was judged where the line started.
- With `shopt -s lastpipe` on the line, a `HOME` or `CDPATH` the last stage of a pipeline writes (`echo ../lib | read CDPATH`) is left untracked, since bash then runs that stage in the current shell, so a runner after the `cd` is refused.
- With `shopt -s lastpipe` on the line, a `cd`, `pushd` or `popd` in the last stage of a pipeline (`true | cd evil && make clean-all`) leaves the directory untracked, and a `dirs` there leaves the stack untracked, since bash may run that stage in the current shell, so a runner after it is refused.
- `#` after any `)` was a comment. In `a$(true)#` that `)` closes the substitution and the word continues, so the rest of the line, including a later command, was skipped. `#` starts a comment there only when the `)` closes a subshell or a case pattern.
- `$'...'` ANSI-C quoted words now decode in shell tokenization, so command
  words and `cd` targets are read as the shell runs them. This closes
  bypasses such as `cd $'project' && make clean-all`.
- `$PWD` or `${PWD}` in a `HOME` or `CDPATH` the line assigns is the one directory the line is in, when the line shows that and does not set `PWD`, so `export HOME="$PWD/.home"; cd ~ && make test` is allowed again. Every `$` in the value used to leave the variable untracked, which refused the runner after the `cd ~`.
- `$as_echo` after configure assigns it to `printf`, `print` or `sh -c`
  was an unseen command, so the directory was dropped. The word keeps
  the directory when every branch's value is a command that does not
  move the shell. `cd`, an `if` with no `else`, and `eval` of a script
  the line does not show still drop it. An absolute `SHELL` from the
  environment is that program.
- `. "./$x"` and `. "$x"` dropped the directory without reading the file. The path is the value the script assigns, and that file is judged. A substitution, a glob or a value the line does not show is refused.
- `>conftest.$ac_ext` was a write to a path the line does not show, so
  every later script looked written by it. The `$` is the extension
  configure substitutes, and `conftest*` is the same scratch glob. A
  literal file such as `conftest.in` is still judged when a later
  command runs it, and a `$` in any other name still may name a script.
- `>|`, the redirection that overwrites a file under `noclobber`, stays one word instead of a `>` and a pipe, so `cd >| /dev/null evil && make clean-all` follows the `cd` and refuses the `rm -rf ~` in `evil/Makefile`. The split made the `cd` a pipeline stage, which moves nothing.
- `ENV=/dev/null; (unset ENV) && unset ENV; sh` was refused as an
  unshown startup file. One side of the `&&` still holds `/dev/null`
  and the other has unset it, which sources nothing. A shown value
  stays that value. Two different values are still not one file, and a
  branch that may leave a real file in place is still judged.
- `MAKEFLAGS`, `MFLAGS` and `GNUMAKEFLAGS` were ignored, in the
  environment and on the line, so `-f`, `-C` and `--include-dir` there
  did not choose the makefile make reads. They are parsed as make's own
  options. A flag string that does not parse refuses the line.
- `NAME+=value` appends to what an earlier assignment on the line put in NAME when a later `$NAME` command word is resolved, so `g=git; g+=" push"; $g --force origin main` is refused as a force push. The append was recorded as a separate variable and `$g` read as plain `git`.
- `ash`, `hush` and `mksh` are shells, so `busybox ash evil.sh`, `busybox hush -c 'git push -f'` and `toybox sh -c ...` are judged by the script they run. busybox ran its applet, but only `sh` among its shells was known, and `busybox ash -c 'git push -f'` was allowed.
- `cd -` and `pushd -` enter `OLDPWD`, which each `cd`, `pushd` and `popd` on the line moves, so `cd - && make clean-all` reads the Makefile the shell goes back to; it read the one where the line was and allowed the `rm -rf ~` in `$OLDPWD/Makefile`. Without `OLDPWD` in the environment, and inside a recipe, a runner after `cd -` is refused as `may run in an untracked directory`.
- `confdefs` was scratch with no generated header, and a trailing `/` was stripped before the name was checked. GNU `rm` follows a symlink written that way, so `rm -rf confdefs/` deletes the target. A trailing slash is not scratch, `confdefs` needs the header, and a symlink in the path is refused.
- `dd of=`, `install` and `perl -i` now count as writing their file, so a
  script one of them writes and the same line then runs is refused.
- `dirs` stops reading options at `--`, so `dirs -- -c` no longer drops the stack the line built and a `popd` after it is followed back to where the `pushd` left.
- `env -C DIR` and `env --chdir=DIR` read a task runner's file in `DIR` for the one command they run, so `env -C project make clean-all` reads `project/Makefile` and is refused where it was allowed. `env -C project true && make clean-all` still reads the Makefile where the line is.
- `env -S STRING` splits STRING into words the way GNU env does and reads them in the option's place, then the words after it. `env -S -v git push --force origin main` and `env -S '' git push --force origin main` were allowed because only the string was judged, and `env -S '-C evil' make clean-all` and `env -iS '-C evil make clean-all'` read no Makefile, though env runs make in `evil`.
- `env` flags are read as GNU `env` reads them: short flags cluster and the first that takes a value takes the rest of the word or the next word, and a long flag may be cut to any prefix that names only it. `env -iC project make clean-all` and `env --chd project make clean-all` took `project` for the command, so no Makefile was read and the `rm -rf ~` in `project/Makefile`, where env runs make, was allowed; `env -iS 'git push -f'` and `env --sp='git push -f'` hid the force push.
- `eval $ac_prev=\$ac_option` assigns the option to a name the case
  just set (`prefix`, `bindir`, or empty). That was an unseen command,
  so the directory was lost for the rest of the script. A value that
  is `cd`, or a name the line does not show, still is.
- `eval enable_$ac_useropt=no` assigns to a name built from a value the
  line does not show, such as one `expr` or `sed` printed. That was an
  unseen command, so `sh configure` lost the directory for the rest of
  the script. An `eval` of anything other than lone `NAME=value` words,
  or of a value with a substitution, still does.
- `eval enable_$ac_useropt=no` kept the directory for any value of the
  expansion. `x;cd evil;y` makes that eval run `cd`. The directory now
  stays only when the expansion is proven to be name characters.
- `find -exec` runs its payload, and a wrapper runs the command after
  it. `find . -exec git push -f ';'` was allowed because only an `-exec`
  of `rm`, `shred` or `unlink` was refused, and `parallel` was not a
  wrapper. The payload is judged as a command. A command word the line
  does not show is unknown.
- `hostname`, `print`, `emulate` and `setopt` were unknown commands, so
  each one made a later script look written by the line. They write no
  file. A command the guard does not know, under another name, may still
  write anything where it runs.
- `include`, `-include` and `sinclude` were dropped, so a recipe that
  lives in an included makefile was never judged. Includes are read
  relative to the directory make runs in. A cycle, a nest past the
  dependency bound, a missing required include, or a file that cannot
  be read refuses the line.
- `lastpipe` is taken to be on only where `shopt -s` or `set -o` names it, alone, behind `builtin` or `command`, or in an `eval`, or where a `shopt` or `set` word is one the line does not show. A word that only names it (`echo lastpipe | read HOME`) no longer leaves `HOME` or `CDPATH` untracked.
- `make -C "$d"`, `make -C $(echo bld)` and `make -C bl*` found no makefile and were allowed. The directory is not one the line spells out, so the recipes there were never judged. A directory that is empty, or holds `$`, a backtick or a glob, is refused.
- `make -C build` read the makefile in `build`, then judged a recipe
  such as `$(MAKE) -f CMakeFiles/Makefile2` from the directory make was
  started in. That file lives under `build`. The recipe is judged
  there, and a dangerous line in it is still refused.
- `popd -n` drops the entry under the top of the directory stack and `popd +N` or `popd -N` the entry it names, all without moving, and only a `popd` that drops the top enters the entry under it. Every `popd` used to enter that entry, so `pushd safe && pushd .. && popd +1 && make clean-all` read `safe/Makefile` and allowed the `rm -rf ~` in the Makefile where the shell stays and runs make, and `pushd safe && popd -n && make clean-all`, which stays in `safe`, was refused.
- `popd` reads no option or index past `--`, as bash does, so `pushd evil && pushd ../safe && popd -- +1 && make clean-all`, where the bare `popd` returns to `evil` and runs the `rm -rf ~` in its Makefile, is refused again. The `+1` after `--` was taken as an index, which left the line in `safe`.
- `pushd -n DIR` puts `DIR` on the directory stack without entering it, and `pushd +N`, `pushd -N` and a bare `pushd` enter the directory they bring to the top, so `pushd -n safe && make clean-all` reads the Makefile where the line is and `pushd project && pushd other && pushd +1 && make clean-all` reads `project/Makefile`. Both were allowed. A `pushd` into a directory the line does not name still takes its place on the stack, and an index past a `pushd` that may have failed reads every directory on the stack.
- `rm -rf "$tmp"` was refused whenever `tmp` was not a literal path
  under `/tmp`, so a script that had just set `tmp` from `mktemp` or
  from `${TMPDIR-/tmp}/name.$$` could not remove that directory. The
  name is scratch when every assignment in the same script is, and a
  later assignment to a real path poisons it. A variable the script
  never sets stays refused.
- `rm -rf conftest* confdefs.h` is configure deleting the header it
  is about to write again. `confdefs.h` is scratch in the build
  directory, like `conftest*`. `/`, a home directory, and `..` stay
  refused. `a.out` still needs the generated-configure header.
- `rm -rf conftest*`, `conftest.*` and `autom4te.cache`, the scratch an
  autoconf `configure` makes and removes, are now allowed like build
  output, so reading a `configure` script refuses fewer of its lines.
- `rm -rf conftst$IFS..`, `libconftest.dylib$IFS$x`, `conf$$$IFS..` and a backtick after `conftest` were scratch. The suffix split into another operand. A suffix is scratch only when it is literal, or one variable the script assigns to a single path piece.
- `source <(cat x.sh)` and `. <(cat x.sh)` were allowed. A process
  substitution, `/dev/stdin`, `/dev/fd/*` or `/proc/self/fd/*` is not a
  file the guard can open, so that script is unshown.
- `time` after `command` or `builtin` is read as the time program rather than the keyword, as bash reads it, so the `cd` in `command time cd evil; make clean-all` moves only the program's child and the `make` after it is read where the line was.
- `tmp=`(umask 077 && mktemp -d "./confXXXXXX")`` hides `mktemp`
  inside one word, so `rm -rf "$tmp"` was not the directory just made.
  The group is read on its own. It is a subshell, not a file the line
  runs. A temp created outside `/tmp` stays refused.
- `unset -f BASH_ENV` (or `ENV`) takes out a function of that name and leaves an exported startup file in place, so the next `bash -c` is still judged against it. It was taken to drop the file, and `export BASH_ENV=evil.sh; unset -f BASH_ENV; bash -c 'echo ok'` was allowed.
- check-mail reads the message on stdin and does not see recipients passed to sendmail -t. The caller must pass no recipient arguments, or pass them to `check-mail --argv` so each one is judged as a recipient.
- libtool removes `conftst*` after renaming a conftest object, and
  `libconftest.dylib*` after the Apple single-module probe. Those are
  scratch in the build directory, the same as `conftest*`. A parent
  directory or `/` is still refused, and without the configure header
  the names are not a pass.
- phronesis v0.2.5 refuses `rm -rf "$tmp"` after `mktemp`, and
  `rm -rf conftest*`, because its recursive-delete rule has no binding
  for a scratch variable and no configure scratch name. The host table
  already allowed those operands. The line the pack judges names each
  of them under `/tmp`, and every other word is unchanged, so a secret
  beside that `rm` is still refused.

### Documentation

- The reference omitted reason codes check-mail already returns, including an unparsed recipient, an unreadable deny file or pack-law file, and an identity that is not one mailbox. Every code the check can print is listed.

### Miscellaneous

- A small Autoconf 2.71 tree generated by autoreconf is judged as a whole, and the verdict on that tree is the denial the check prints.
- The test workflow runs on a push to any branch, so a work branch
  whose name has no date still gets the host and phronesis jobs before
  it is merged. Pull requests are unchanged.
- `( c[d] ../[e]vil )` is a subshell whose words look like a case pattern. It does not enter that directory, so `make` stays in the directory the line started in.


## 0.4.6 (2026-10-20)

### Fixes

- The C shim builds with installed schemas that represent `List(Text)` as a bare pointer as well as schemas that use a typed pointer list. Both forms encode the same argument-list message.
- The Cap'n runtime is capnp 0.27. capnp 0.20.6 exposes unsound `constant::Reader::get` and `StructSchema::new` (RUSTSEC-2025-0143). The checked-in schema code is regenerated with capnpc 0.27.0.

### Miscellaneous

- ljos-policyd links phronesis 0.2.5 or later. The shell secret check matches a vendor prefix only at a token boundary, so `git commit -m 'fix task-creation'`, `cat disk-usage.rs` and `git checkout risk-notes` are allowed. A `curl -H` header that carries an `sk-proj-` bearer key is still `shell-secret-in-argv`.

## 0.4.5 (2026-10-20)

### Fixes

- The table let seven destructive lines through. A download piped into `python3`, `perl`, `ruby` or `node`, or into a shell through a later stage such as `tee`, now reads as `curl-pipe-shell`, as does `source <(curl ...)`, `. <(curl ...)`, `eval "$(curl ...)"` and a file that `curl -o` or `wget` saves and a later command on the line runs. `chmod` with a leading-zero or setgid mode (`04755`, `2755`, `g+s`) and `install -m 4755` read as `chmod-setuid`. A `git push --force-with-lease` onto `main`, `master` or `develop`, or one that names no branch (no refspec, `HEAD`, a wildcard, `--all`), now reads as `git-force-push`, which ljos turns into a question for the person. A lease push onto any other branch stays allowed, as do `curl URL | python3 -m json.tool`, `curl -o FILE URL`, `chmod 0755` and `git push -u origin BRANCH`.

### Documentation

- The README sample of `ljos-policyd version` prints 0.4.4, the current release.
- The docs site no longer loads sphinx-design, which no page used. custom.css states the insets of the header, the copy-page buttons and the edit link as plain lengths, with no change on screen. `.impeccable/config.json` records the detector ignores for the vendored theme stylesheet, command flags in code, and the house paper colour, each with its reason.
- The reference names the phronesis 0.2.3 limits: a word up to 128 KiB, up to 32768 words, and a Cap'n command body of 512 KiB. Past a limit the answer is `field-too-long` and the host's reason.

### Miscellaneous

- A pull request into develop or main that touches the docs now exports the org sources, builds the site with Sphinx `-n -W`, and runs impeccable 4.5.2 on the built pages against `.impeccable/config.json`. Any finding fails the run. A pull request never publishes the site.
- Each release archive gets a GitHub build attestation from the release workflow, so `gh attestation verify` and the ljos installer can check that this repository built it. Releases before this one have none, and the installer counts them as not published. The release notes line now says what the program does in plain words.
- ljos-policyd links phronesis 0.2.4 or later. Built against 0.2.3, the phronesis law matched `+s` anywhere in a chmod word, so `chmod 644 README+s.md` was refused as a setuid mode and `denies_a_setuid_or_setgid_mode` failed; 0.2.4 reads `+s` only as a mode clause.

## 0.4.4 (2026-10-18)

### Features

- A phronesis refusal reads as the code's name, then the pack's own text (`path-outside-workspace: path outside workspace`). A pack that wrote no text still names its code instead of the bare word `phronesis`.

### Fixes

- Concurrent checks that share a state directory no longer unset the embedded pack. Each check used to delete `pack-<hash>` and rename its own copy into place, so the one that lost the race loaded nothing and answered `deny` with an empty reason (`deny\tphronesis`) for a harmless line such as `git add slug.py test_slug.py`. The pack is now written to a private directory and renamed into place while a lock is held, a pack of the same content hash that is already there is left as it is, and a seat that still cannot load its pack answers `deny\tpack-unavailable`. Checks in one workspace retry a torn read of the shared seat slot instead of answering `bind-failed`.
- A long argument is judged on what it says. A word of 512 bytes or more was refused before the pack read it, so `echo` of a long program was denied with no reason of its own. Release and test builds link phronesis v0.2.3, which keeps each word up to 128 KiB and up to 32768 words. Past those limits, or a command body over 512 KiB, the line is `field-too-long` and the host's reason, as in `field-too-long: argv word exceeds 131072 bytes`.

## 0.4.3 (2026-10-17)

### Fixes

- The crate version reads 0.4.3, so `ljos-policyd --version` and the binstall archive name match the release tag; the v0.4.2 archives still called themselves 0.4.1.

## 0.4.2 (2026-10-14)

### Miscellaneous

- Release binaries link phronesis v0.2.2, whose generated schema C builds under `-Werror` on current macOS clang. The Intel macOS cross file names a C++ compiler, which c-capnproto's meson build now asks for. A manual run of the release workflow builds every target on a branch and publishes nothing; only a `v*` tag publishes.

## 0.4.1 (2026-10-13)

- A phronesis build embeds the compiled images phronesis installs beside its packs (`shell.jimage`, `seat.jimage`) and unpacks them with the sources. phronesis then loads the law from the image and skips the Janet boot image and compiler, so an allowed line takes about 2.3 ms instead of 7.3 ms. With a phronesis that ships no images, the build embeds only the sources and phronesis compiles them as before.
- A line that runs a task runner is judged on what the target runs. `make <target>` reads the Makefile in the working directory (or the one `-C` and `-f` name) and follows the target's prerequisites up to eight levels; `npm run`, `pnpm`, `yarn` and a bare `npm <script>` read the `scripts` of `package.json`, with its `pre` and `post` scripts; `just` and `cargo make` read their recipe files. Each recipe line is judged by the table and phronesis, so `make clean-all` whose recipe runs `rm -rf ~` and `npm run nuke` whose script runs `rm -rf ~/` are refused, and `make test` and `npm run build` still run. A missing or unreadable file leaves the verdict as before. Files are read in-process and cached by mtime and size; nothing is spawned.
- More ways to delete a tree are refused. `rm-rf-outside-tmp` covers a recursive `rm` without `-f` and the trash commands (`rtrash -r`, `trash`, `trash-put`, `gtrash`, `rmtrash`, `gio trash`) given the root, a home directory or a system tree; `rtrash -r /etc` and `trash-put ~` were allowed. `mv-to-dev-null` refuses `mv` into `/dev/null`, and `rsync-delete-root-tree` refuses an `rsync` with a `--delete` flag into the root, a home directory or a system tree. A recursive `setfacl` that strips every entry (`-b`, `-k`) or gives everyone write meets `recursive-chmod-chown` wherever it starts outside `/tmp`, as a sweeping `chmod` does. The command a `docker run`, `podman run` or `nerdctl run` passes the container is judged with each path under a bind mount read as the host path it reaches, so `docker run --rm -v $HOME:/h alpine rm -rf /h/projects` is refused and `docker run --rm alpine rm -rf /app/build` still runs.
- `find-delete-outside-tmp` allows a cleanup of files a tool writes again inside the tree, such as `find . -name '*.pyc' -delete` and `find . -name .DS_Store -delete`. Every starting point is `.` or a plain relative path outside `.git`, and every `-name`, `-iname` or `-path` test names bytecode, objects, patch leftovers, editor swap files or folder metadata from the list in the source. `find . -delete`, `find . -name '*.rs' -delete`, a home, absolute or `..` start, an `-o`, `!` or `-not` in the expression, and a line whose `cd` can leave the tree are still refused.
- `rm-rf-outside-tmp` allows a recursive delete of a top-level scratch directory named as a plain relative path, `tmp`, `.tmp` or `temp`, or a path under one, such as `rm -rf ./tmp/test-output`. `rm -rf ./src`, `src/tmp`, `tmp/../src` and `tmp/.git` are still refused.
- Both need phronesis 0.2.1 or later in a phronesis build, whose default pack makes the same two allowances; phronesis 0.2.0 still refuses these lines after the table allows them.

## 0.4.0 (2026-10-11)

- A phronesis build links phronesis 0.2 and the Cap'n Proto C runtime statically, with no runtime path, and embeds phronesis's default pack. The binary runs on a host with no phronesis install. `build.rs` finds the library under `lib`, `lib64` or `lib/<multiarch>`, and the `pkg-config` route compiles the ShellCheck shim as the `PHRONESIS_DIR` route does.
- phronesis judges every command the table reads inside a line (past wrappers, inside `sh -c` scripts and substitutions), not only the outer line. Its refusal prints the pack's reason after the tab; every phronesis refusal used to read `banned-runner`.
- phronesis state lives under one directory per workspace, so a check in a second workspace is judged like one in the first. With one shared directory phronesis kept the first workspace and refused every line outside it.
- `LJOS_POLICYD_PACK=seat` loads phronesis's seat pack, which adds uv-only Python and the package-manager refusals. The default pack no longer has them.
- The release workflow builds phronesis from source on all four targets, so the release binaries report `(phronesis)`. CI tests a phronesis build beside the table-only one.
- `raw-disk` covers the other ways to wipe a disk: `wipefs -a`, `sgdisk`, `sfdisk`, `fdisk`, `parted`, `blkdiscard`, `mkswap` and `shred` given a block device, `cryptsetup luksFormat`, `badblocks -w`, and a `>` redirection into a block device. Each tool's listing flags stay allowed. `mkfs` on an image file and `dd of=/dev/null` are no longer refused; only a block device is a disk.
- `recursive-chmod-chown` refuses a recursive `chmod`, `chown`, `chgrp` or `setfacl` that starts at `/`, a home directory or a system tree, and a recursive `chmod` that removes every permission or gives everyone write. `chmod -R 777 /` and `chown -R nobody ~` were allowed before.
- `decoded-pipe-shell` refuses a decoder's output handed to a shell: `base64 -d`, `xxd -r`, `openssl base64 -d`, `zcat`, `rev` and the other decoders piped into `sh` or `bash`, or run inside a shell's `$(...)`, `<(...)` or backticks. `echo ... | base64 -d | sh` was allowed before; the table cannot read what such a script runs.
- A function definition's body is judged: `f(){ git push -f; }; f` and `function f { rm -rf ~/x; }` were allowed before.
- More git calls that lose work are refused: `git-push-delete` for `push --delete`, `push -d` and an empty-source refspec such as `:main` or `:refs/tags/v1.0`, `git-branch-force-delete` for `branch -D`, `git-reflog-expire` for `reflog expire --expire=now` and `reflog delete`, `git-history-rewrite` for `filter-branch` and `filter-repo`, `git-update-ref-delete` and `git-worktree-force-remove`. `branch -d`, `reflog expire` with a date and `worktree remove` without `--force` stay allowed, and so does `stash drop`, as before.
- A `-c` on the git line no longer hides what runs. `git -c alias.p='push -f' p` is judged as `git push -f`, an alias that starts with `!` is judged as a shell line, and so is the value of a key git runs as a command, such as `core.sshCommand`, `core.pager` or `credential.helper`.
- `find -exec rm`, `-execdir rm`, `-ok rm`, and `shred` or `unlink` in their place, meet the same starting-point rule as `find -delete`. `busybox` and `toybox` run the applet after them, so `busybox rm -rf ~/x` meets the `rm` rule.
- `rm-rf-outside-tmp` allows a recursive delete of a build output directory named as a plain relative path: `node_modules`, `target`, `dist`, `build`, `.venv`, `__pycache__`, `.next` and the other tool caches listed in the source, or a path under one. A path with `..`, `~`, `$`, a glob, an absolute start or a `.` part is still refused, and so is the whole line when a `cd` or `pushd` on it can leave the tree. `rm -rf node_modules` and `rm -rf target/` were refused before.

## 0.3.0 (2026-10-10)

- `git push --force-with-lease`, in any form, and `--force-if-includes` are allowed. The remote refuses them when it holds commits the pusher has not fetched, so they are the safe way to rewrite a branch. Adding `--force`, `-f` or a `+` refspec is still refused.
- New refusals for git calls that drop uncommitted work: `git-reset-hard`, `git-clean-force` (`-f`, `-fd`, `-fdx`), `git-stash-clear`, and `git-discard-worktree` for `checkout -- .`, `checkout .`, `restore .` and `restore` with no path. `find-delete-outside-tmp` refuses `find -delete` outside `/tmp`.
- An inline program is read: the strings `python -c`, `node -e`, `perl -e` and `ruby -e` code hands to `os.system`, `subprocess.*`, `execSync` or `system` are judged as shell lines, and a recursive tree delete outside `/tmp` (`shutil.rmtree`, `rmSync` with `recursive`, `rm_rf`) is `rm-rf-outside-tmp`.
- A variable command word does not hide git: `g=git; $g push -f` reads `$g` from the assignment, and `$GIT push -f` with no assignment meets the git rules.
- A test runs the 24 lines of the launch comparison through the table.
- A script the table reads also runs the commands inside its `$(...)`, backticks, `<(...)`, `>(...)` and `( ... )` subshells, nested to four levels, and the table judges each. `eval ARGS` is read as a script, and the command after `if`, `then`, `do`, `{`, `!` and `coproc` is the one judged. A substitution is one word of its command, so a `;` inside it no longer cuts the script. `sh -c 'echo $(git push -f)'` was allowed before. Single quotes and an escaped `$` stay text.
- `cargo binstall ljos-policyd` builds from source on a target with no release tarball, such as Windows or musl Linux. The `compile` strategy was off, so binstall failed there. cargo-quickinstall stays off.
- The table judges every command a line runs through a wrapper or a shell. `env`, `nice`, `nohup`, `time`, `exec`, `command`, `timeout`, `xargs`, `setsid`, `stdbuf`, `ionice` and leading `NAME=value` words are taken off, with their flags, and a shell's `-c` script (`sh -c`, `bash -lc`, `sh -c -- SCRIPT`, `bash -o pipefail -c`) is read as its own line. So is the string `env -S`, `flock FILE -c` and `watch` hand to a shell. `env git push -f` and `sh -c "git push -f"` were allowed before, and so was every hook that asks this binary.

## 0.2.6 (2026-10-10)

- `git-force-push` refuses every push that can overwrite the remote: a `+` refspec
  (`git push origin +main`), `--force-with-lease=REF`, `-f` inside a flag
  cluster such as `-fu`, and `--mirror`. Only the bare words `--force`, `-f`
  and `--force-with-lease` were refused before.
- `rm-rf-outside-tmp` reads a `..` in an operand as outside `/tmp`, so
  `rm -rf /tmp/../home/u` is refused.
- The explanation says why a model cannot mediate. An unmatched command
  is an allow. Fail-closed is `POLICYD_REQUIRED`, and it covers a
  missing binary.

## 0.2.5 (2026-10-04)

- A phronesis build runs the built-in table first and keeps its refusals,
  so it refuses `rm -rf` outside `/tmp`, setuid `chmod` and raw-disk
  writes as the table build does; phronesis adds its own refusals after.
- `ljos-policyd version` names the backend: `phronesis` or `host table`.
- The README says what is refused, in what order, and how to tell which
  backend a binary uses.

## 0.2.4 (2026-10-04)

- The recursive-delete rule judges each `rm` or `rtrash` on a hooked line
  by its own operands. Redirections, separators and later commands no
  longer count as delete targets, and a second delete after `;`, `&&`,
  `||` or `|` is judged too.
- Everything in 0.2.3, which was published without the line above and is
  yanked.

## 0.2.3 (2026-10-04, yanked)

- `curl-pipe-shell` refuses a download handed to a shell: a fetching stage
  piped into a shell stage, or a shell running a download through `$( )`,
  `<( )`, backticks or `-c`. A line that names a download tool and a shell
  without that (`git fetch`, then `bash build.sh`; a pattern `curl|shell`)
  is no longer refused.
- `PHRONESIS_DIR` / `pkg-config phronesis` enables `phronesis_check_shell`
  as the check. Missing library still compiles (host argv table).
- A seated check binds the host slot to the process cwd and loads the
  Janet pack from `$PHRONESIS_PREFIX/share/phronesis/policy/shell.janet`.

## 0.2.2 (2026-09-15)

- README names the `capnp` verb.

## 0.2.1 (2026-09-15)

- Usage names `check|exec|capnp|version`. A missing or unknown verb
  no longer pretends the binary is check and exec only.

## 0.2.0 (2026-09-15)

- Cap'n `PolicyDecision` / `Decision` / `checkShell(argv)` as the typed
  API, derived from phronesis (Ali Akber Saifee / indynull, HaoZeke;
  MIT). Seat, model, and audio planes stay out.
- `ljos-policyd capnp -- argv` writes a packed PolicyDecision.
- 0.1.1 argv classes (privilege, remote-exec, setuid, raw disk, force
  with lease) are the phronesis shell-danger table, same authors.


## 0.1.1 (2026-09-15)

- Privilege runners include `su`, `pkexec`, `run0`.
- Remote-exec covers wget and fetch as well as curl.
- `chmod` setuid and `dd`/`mkfs` to raw disks are deny.
- `git push --force-with-lease` is deny.
- `python -c` stays allow: this hook sits on a general agent shell.

## 0.1.0

First public release.
