A `cd` whose path by name is no directory is now also judged through the
links, where bash enters it when the logical path fails. `cd lnk/../x &&
make clean-all`, with `x` only beside the target of `lnk`, read no
Makefile and let the recipe there run.
