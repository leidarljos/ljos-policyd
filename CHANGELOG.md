# Changelog

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
