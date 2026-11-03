# policyd rule families

<!-- [[[cog
import cog
from scripts.doc_samples import audit_lines
audit_lines(cog)
]]] -->
Counted with `wc -l`.
Rust outside the generated Cap'n schema is 25602 lines.
Generated schema is 9409 lines. `src/lib.rs` is 490 lines.
<!-- [[[end]]] -->
The bash lexer lives in `src/words.rs` (quotes), `src/shells.rs`
(`sh -c`), `src/pipeline.rs` (pipes) and `src/names.rs` (`$cmd`).
The mail law is `src/mail.rs` and `src/envelope.rs`. The rewrite lives in
`src/rewrite.rs`. A credential path named from `python`, `perl`, `ruby`
or `node` `-c` or `-e` is handled in `src/ask.rs` and prints a warning.

The printed line is `allow`. A rule adds `warn`, the rule name, and one
warning. The samples are this binary.

<!-- [[[cog
import cog
from scripts.doc_samples import audit
audit(cog)
]]] -->
```console
$ ljos-policyd check -- sudo id
allow	warn	sudo	a privilege runner is on the command
$ ljos-policyd check -- chmod 4755 /tmp/x
allow
$ ljos-policyd check -- python3 -c 'open("/home/u/.ssh/id_rsa")'
allow	warn	credential-mention	a program names a credential path
$ ljos-policyd check -- make clean-all
allow
```
<!-- [[[end]]] -->

| Family | Where | Incident | Call |
|---|---|---|---|
| Privilege (`sudo`, `doas`, `su`, `pkexec`, `run0`) | the lexer | First argv law. Privilege was in the first deny set. | warn on allow, `sudo` |
| Remote exec (`curl` or `wget` into a shell) | the lexer | A download handed to a shell, not a line that only names both. | warn on allow, `curl-pipe-shell` |
| Raw disk | the lexer | `mkfs`, `dd` of a device, partition tools. | warn on allow, `raw-disk` |
| `rm -rf` outside `/tmp` and the build directories | the lexer | A recursive force delete of `./src`, `/etc`, `~/` or a home. | warn on allow, `rm-rf-outside-tmp` |
| Force push and history rewrite of published branches | the lexer | Force push, filter-branch, filter-repo, update-ref delete. | warn on allow |
| Secrets in argv and credential paths | `disk.rs` plus the reader | A token or a credential file on the command. | warn on allow, `reads-credential` |
| Inline `-c` or `-e` that names a credential path | `ask.rs` | `python3 -c "open('/home/u/.ssh/id_rsa')"` was a deny. | warn on allow, `credential-mention` |
| Writes of hook and policy files | seat guard | Seat guard paths and the policyd config. | warn on allow, `seat-guard-path` |
| Mail law | `mail.rs` and `envelope.rs` | Outbound envelope for the send ballot. | verdict `allow`; reasons keep their codes |
| Bash lexer (`sh -c`, `$cmd`, pipes, quotes) | `words.rs`, `shells.rs`, `pipeline.rs`, `names.rs` | The warnings above have to see through a shell. | KEEP |
| uv rewrite | `rewrite.rs` | `python x.py` becomes `uv run x.py` when uv fits. | `allow`, `rewrite`, the new line |
| Written then run | removed | A script the line writes and then runs. | DELETE |
| Python static analysis | removed | Inline python, including a mention of a hook path. | DELETE |
| Makefile and npm recipe walk | removed | `make clean-all` judged by the recipe. | DELETE. The line is `allow` |
| Empty argv | the table | A file write with no command words. | `allow` |
| Nimvault and the sealed relay | removed | A vault runner and one configured secret. | DELETE |
| Find delete, find print and find exec | removed | `find -delete` and a payload the line shows. | `find -delete` and `find -exec rm` warn. An unresolved `find -exec` warns with `exec-unresolved`. `find -fprint` is `allow` |
| xargs, parallel and read feeds | removed | Words a feeder appends. | `xargs` or `parallel` running `rm` warns, `feeder-rm` |
| Setuid and recursive mode changes | removed | `chmod 4755` and `chmod -R`. | DELETE. The line is `allow` |
| mv and rsync tree deletes | removed | `mv` onto `/dev/null`, `rsync --delete`. | warn on allow |
| Brace expansion of a command | removed | `{push,-f}` turned into the command. | DELETE |
| Unshown script guesses | removed | A pipe into a shell, a process substitution. | DELETE |
| Writes outside the tree | removed | An ordinary file write. | DELETE |
| Local git lost work | `harm.rs` | `reset --hard`, `clean -fd`, `stash clear` or `drop`, `checkout -- .`, `restore .`. | warn on allow |
| Find delete and a feeder running rm | `harm.rs` | `find -delete`, `find -exec rm`, `xargs` or `parallel` running `rm`. | warn on allow |
| mv or rsync delete of an outside tree | `harm.rs` | A whole tree outside the work tree, including `/dev/null`. | warn on allow |

The rules that remain are sudo, a recursive `rm` outside `/tmp` and the build directories, a force
push or a history rewrite of a published branch, a secret in argv, a write
of a hook or policy file, remote exec, and raw disk. Each one is allow
with the rule name and one warning. The mail check prints allow and keeps
its reasons. An inline program that names `~/.ssh`, `~/.gnupg`, `~/.aws`,
`.env`, or another credential directory warns with `credential-mention`.
`chmod 4755` and `make clean-all` print `allow`.
