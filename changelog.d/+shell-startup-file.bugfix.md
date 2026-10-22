A non-interactive `bash` reads `BASH_ENV` and a non-interactive `sh`
reads `ENV` before its `-c` script. `BASH_ENV=../evil/force.sh bash -c
'echo ok'` was allowed when that file ran `git push -f`. A literal file
is judged as a sourced script, including one `export` set earlier on
the line. A value the line does not show leaves the shell unknown.
