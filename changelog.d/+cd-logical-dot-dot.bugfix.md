A `cd` or `pushd` now takes `..` off the path by name, as the shell's
default logical `cd` does, so `cd lnk/.. && make clean-all` reads the
Makefile where the line started even when `lnk` is a symbolic link to
another directory. `cd -P`, and `set -P` earlier on the line, still
resolve the link.
