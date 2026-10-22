A `set -P` in a file the line sources, or `physical` in a `SHELLOPTS`
given to a bash the line starts, now counts for each later `cd`, as
`set -P` on the line does. `source ./p.sh; cd lnk/.. && make clean-all`
and `env SHELLOPTS=physical bash -c 'cd lnk/.. && make clean-all'` read
the Makefile where the line started, while bash enters the one that
holds the link's target.
