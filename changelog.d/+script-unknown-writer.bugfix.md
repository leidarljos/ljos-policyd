A command the guard does not know to leave files alone (`rsync`, `tar`,
`unzip`, `patch`, `git checkout`, `python -c`, `make`, a binary, ...)
now counts as writing anything under the directory it runs in, so a
shell script the same line runs after it is refused as
`script-written-on-line`. A short list of commands known to write
nothing (`echo`, `cat`, `grep`, `ls`, `test`, `cd`, read-only `git`,
...) does not count, and a binary run after a build is not a script.
