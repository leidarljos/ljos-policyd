`find -exec` runs its payload, and a wrapper runs the command after
it. `find . -exec git push -f ';'` was allowed because only an `-exec`
of `rm`, `shred` or `unlink` was refused, and `parallel` was not a
wrapper. The payload is judged as a command. A command word the line
does not show is unknown.
