A `cd`, `pushd` or `env -C` path that starts with `$HOME` or `${HOME}`
now expands from the `HOME` the line shows, as `~` does, and `~login`
expands from the password database. `cd $HOME/proj && make test` and
`cd ~user/proj && make test` now read the Makefile in proj, where every
make after such a cd was refused as one that may run anywhere. Such a
path searches `CDPATH` only when `HOME` is relative, and a `CDPATH`
entry with `$` in it still names no directory the line shows, since the
shell expanded it when `CDPATH` was set.
