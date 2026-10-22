A leading `command`, `command -p` or `builtin` no longer hides a `cd`
or `pushd` from the directory tracker. A line like
`command cd project && make clean-all` now reads the runner where it
actually runs.
