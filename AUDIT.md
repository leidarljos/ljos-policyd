# policyd rule families

Counted on `a7909f90` before this pare, and on the tree after it.
Rust outside the generated Cap'n schema was 43249 lines before and 35879 after.
Generated schema stayed 9409 lines. `src/lib.rs` is 28667 lines. The bash
lexer and the mail law are still the bulk of that.

| Family | Lines before | Commit | Incident | Call |
|---|---:|---|---|---|
| Privilege (`sudo`, `doas`, `su`, `pkexec`, `run0`) | in the lexer | `20e1f51`, `15509ac` | First argv law. Privilege was in the first deny set. | KEEP |
| Remote exec (`curl` or `wget` into a shell) | in the lexer | `15509ac`, `5217bdd` | A download handed to a shell, not a line that only names both. | KEEP |
| Raw disk | in the lexer | `15509ac` | `mkfs`, `dd` of a device, partition tools. | KEEP |
| `rm -rf` of a home or the root | in the lexer | `af977c2`, `62408a9` | A recursive delete judged by its own operands. | KEEP |
| Force push and history rewrite of published branches | in the lexer | `89e32a4`, `ce58b5a` | Every force push form, then lost work git. | KEEP |
| Secrets in argv and credential paths | `disk.rs` 158, plus the reader in the lexer | `3e126cb` and the pack | A token or a credential file on the command. | KEEP |
| Inline `-c` or `-e` that only names a credential path | was inside `pyprog.rs` | `690ca64` | `python3 -c "open('/home/u/.ssh/id_rsa')"` was a deny. | SIMPLIFY to `prompt` `credential-mention` |
| Writes of hook and policy files | seat guard in the lexer | `9710088`, `d2b9154` | Seat guard paths and the policyd config. | KEEP |
| Mail law | `mail.rs` 1381 and `envelope.rs` 3806 | `eee6b29`, `3966918` | Outbound envelope for the send ballot. | KEEP |
| Bash lexer (`sh -c`, `$cmd`, pipes, quotes, `cd`) | most of `src/lib.rs` | `face058` then the October cd and word fixes | The denies above have to see through a shell. | KEEP |
| Written then run (`script-written-on-line`, "may write any file") | tests `script_written.rs` 1017, plus the tracker in the lexer | `c272c76` | A script the line writes and then runs. False refusals on ordinary writes. | DELETE |
| Python static analysis | `pyprog.rs` 4732 | `0412b8b` through `50d3763` | Inline python, including a mention of a hook path. | DELETE |
| Makefile and npm recipe walk | `scripts.rs` 1638 | `07627ed` | `make clean-all` judged by the recipe. | DELETE |
| Empty argv | one deny in the table | `20e1f51` | A file write with no command words (`README.md`). | SIMPLIFY to allow |
| `xargs` script input | the xargs check in the lexer | `9f139f9` | `rg` piped to `xargs` refused as `xargs-script-unshown`. | SIMPLIFY so a read only `rg` or `grep` search is allowed |

The deny list that remains is sudo, `rm -rf` of a home or the root, a force
push or a history rewrite of a published branch, a secret in argv, a write
of a hook or policy file, remote exec, and raw disk. The mail check is
unchanged. An inline program that names `~/.ssh`, `~/.gnupg`, `~/.aws`,
`.env`, or another credential directory asks instead of denying.
