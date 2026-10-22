A generated configure runs `. "./$as_me.lineno"` only on the
failure side of `||`, then `exit`. That side cannot fall through,
so losing the directory there was sticking for every later command,
including `. ./conftest.sh`. The commands after the list now keep
the side that does not exit. A command before `exit` is still judged,
and the same source without `exit` still drops the directory.
