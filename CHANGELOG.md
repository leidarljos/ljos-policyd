# Changelog

## 0.1.1 (2026-09-15)

- Privilege runners include `su`, `pkexec`, `run0`.
- Remote-exec covers wget and fetch as well as curl.
- `chmod` setuid and `dd`/`mkfs` to raw disks are deny.
- `git push --force-with-lease` is deny.
- `python -c` stays allow: this hook sits on a general agent shell.

## 0.1.0

First public release.
