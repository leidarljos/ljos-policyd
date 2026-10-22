A shell function runs in the shell that calls it. `go() { cd evil; }; go
&& make clean-all` was allowed, because the `cd` in the body never
moved the walk and `make` was read where the line started. The walk now
keeps a function defined on the line or in a sourced file and judges
the body at the call, so the recipe is the one in `evil`. A body or a
name the line does not show leaves the line untracked. `command` and
`builtin` still run the program.
