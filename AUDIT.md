# policyd rule families

Counted on `a7909f90` before this pare, and on the tree after it.
Rust outside the generated Cap'n schema was 43249 lines before and 19559 after.
Generated schema stayed 9409 lines. `src/lib.rs` is 12979 lines. The bash
lexer and the mail law are still the bulk of that. The rewrite lives in
`src/rewrite.rs` and the credential ask in `src/ask.rs`.

| Family | Where | Incident | Call |
|---|---|---|---|
| Privilege (`sudo`, `doas`, `su`, `pkexec`, `run0`) | the lexer | First argv law. Privilege was in the first deny set. | KEEP |
| Remote exec (`curl` or `wget` into a shell) | the lexer | A download handed to a shell, not a line that only names both. | KEEP |
| Raw disk | the lexer | `mkfs`, `dd` of a device, partition tools. | KEEP |
| `rm -rf` of a home or the root | the lexer | A recursive delete of `/`, `~`, `$HOME` or `/home/user`. | KEEP |
| Force push and history rewrite of published branches | the lexer | Force push, filter-branch, filter-repo, update-ref delete. | KEEP |
| Secrets in argv and credential paths | `disk.rs` plus the reader | A token or a credential file on the command. | KEEP |
| Inline `-c` or `-e` that names a credential path | `ask.rs` | `python3 -c "open('/home/u/.ssh/id_rsa')"` was a deny. | ASK `credential-mention` |
| Writes of hook and policy files | seat guard | Seat guard paths and the policyd config. | KEEP |
| Mail law | `mail.rs` and `envelope.rs` | Outbound envelope for the send ballot. | KEEP |
| Bash lexer (`sh -c`, `$cmd`, pipes, quotes) | most of `src/lib.rs` | The denies above have to see through a shell. | KEEP |
| uv rewrite | `rewrite.rs` | `python x.py` becomes `uv run x.py` when uv fits. | KEEP |
| Written then run | removed | A script the line writes and then runs. | DELETE |
| Python static analysis | removed | Inline python, including a mention of a hook path. | DELETE |
| Makefile and npm recipe walk | removed | `make clean-all` judged by the recipe. | DELETE |
| Empty argv | the table | A file write with no command words. | ALLOW |
| Nimvault and the sealed relay | removed | A vault runner and one configured secret. | DELETE |
| Find delete, find print and find exec | removed | `find -delete` and a payload the line shows. | DELETE |
| xargs, parallel and read feeds | removed | Words a feeder appends. | DELETE |
| Setuid and recursive mode changes | removed | `chmod 4755` and `chmod -R`. | DELETE |
| mv and rsync tree deletes | removed | `mv` onto `/dev/null`, `rsync --delete`. | DELETE |
| Brace expansion of a command | removed | `{push,-f}` turned into the command. | DELETE |
| Unshown script guesses | removed | A pipe into a shell, a process substitution. | DELETE |
| Writes outside the tree | removed | An ordinary file write. | DELETE |
| Local git lost work | `harm.rs` | `reset --hard`, `clean -fd`, `stash clear` or `drop`, `checkout -- .`, `restore .`. | ASK |
| Find delete and a feeder running rm | `harm.rs` | `find -delete`, `find -exec rm`, `xargs` or `parallel` running `rm`. | KEEP as a deny |
| mv or rsync delete of an outside tree | `harm.rs` | A whole tree outside the work tree, including `/dev/null`. | KEEP as a deny |

The deny list that remains is sudo, `rm -rf` of a home or the root, a force
push or a history rewrite of a published branch, a secret in argv, a write
of a hook or policy file, remote exec, and raw disk. The mail check is
unchanged. An inline program that names `~/.ssh`, `~/.gnupg`, `~/.aws`,
`.env`, or another credential directory asks instead of denying.
