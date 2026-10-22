A shell whose script operand is `<(...)` runs that substitution's
output. `bash <(echo git push -f)` and `bash <(cat ../evil/force.sh)`
were allowed: a process substitution was judged only when it
downloaded. Literal `echo` or `printf` text, and a `cat` of a literal
file, are judged as the script. Anything else is unknown.
