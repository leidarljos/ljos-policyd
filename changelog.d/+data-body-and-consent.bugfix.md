Policyd now reads a quoted here-document body as data, as bash does.
A note written with `cat` or `git commit -F` no longer denies.
Inside an unquoted body, bash still runs `$(...)`, backticks and `<(...)` even after a `#` or a quote, and policyd judges each one.
A process substitution outside a here-document gets the verdict of the command it runs.
A download saved with `curl -o` or `wget` and then run by a shell denies, the same as a pipe into `sh`.
A pipe from `curl` into `python3` only warns, and a pipe into `jq` allows.
Reading `seats.toml` or `ljos.toml` counts as config, not as a credential read.
Policyd only reads a consent record and never writes one.
A record clears a deny when its push URL and destination branch match the push, and it expires within 24 hours.
A lost-work prompt warns and no longer exits 2.
A fault, an empty argument list or an unknown verb allows.
