# Changelog

## Unreleased

- A phronesis build links phronesis 0.2 and the Cap'n Proto C runtime statically, with no runtime path, and embeds phronesis's default pack. The binary runs on a host with no phronesis install. `build.rs` finds the library under `lib`, `lib64` or `lib/<multiarch>`, and the `pkg-config` route compiles the ShellCheck shim as the `PHRONESIS_DIR` route does.
- phronesis judges every command the table reads inside a line (past wrappers, inside `sh -c` scripts and substitutions), not only the outer line. Its refusal prints the pack's reason after the tab; every phronesis refusal used to read `banned-runner`.
- phronesis state lives under one directory per workspace, so a check in a second workspace is judged like one in the first. With one shared directory phronesis kept the first workspace and refused every line outside it.
- `LJOS_POLICYD_PACK=seat` loads phronesis's seat pack, which adds uv-only Python and the package-manager refusals. The default pack no longer has them.
- The release workflow builds phronesis from source on all four targets, so the release binaries report `(phronesis)`. CI tests a phronesis build beside the table-only one.

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
