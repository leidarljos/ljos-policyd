A backtick inside `(test ...)` was read as a command of this shell,
so the directory was dropped and `make` after it was untracked. The
subshell runs in its own shell, and its body is walked there. A `cd`
in that subshell still moves only the subshell, and `$c` when `c` is
`cd` still drops this one.
