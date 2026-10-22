A `source` or `.` of a file the guard can read is judged by the same
rules as the line. `source ../evil/force.sh` was allowed when the file
ran `git push -f` or `make -C ../evil clean-all`, because only the
directory walk saw the text. The walk now hands that text to the deny
rules before it tracks the directory.
