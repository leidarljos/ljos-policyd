With `HOME` unset or empty, a `cd` path `$HOME/x` now enters `/x`, as
bash expands it, and so does `~/x` with `HOME` empty, while `cd $HOME`,
or `cd ~` with `HOME` empty, stays. Such a path was read as one the line
does not show, so `unset HOME; cd $HOME/abs/proj && make test` and
`export HOME=; cd ~ && make test` were refused.
