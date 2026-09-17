# Changelog

## Unreleased

- The crate `links = "phronesis"`. Builds probe `pkg-config phronesis`
  or `PHRONESIS_DIR`. The argv table is still in this crate until the
  check is called through `phronesis_check_shell`.

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
