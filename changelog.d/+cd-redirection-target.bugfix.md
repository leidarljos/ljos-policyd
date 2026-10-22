Redirections before a `cd` or `pushd` target are now ignored when the
tracker resolves the entered directory. This closes forms like
`cd 2>/dev/null project && make clean-all` and
`cd > /dev/null project && make clean-all`.
