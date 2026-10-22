A `cd`, `pushd` or `env -C` path that starts with `$HOME` or `${HOME}`
now expands from the `HOME` the line shows, as `~` does, and `~login`
expands from the password database. `cd $HOME/proj && make test` and
`cd ~user/proj && make test` now read the Makefile in proj, where every
make after such a cd was refused as one that may run anywhere.
