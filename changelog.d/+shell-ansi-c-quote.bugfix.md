`$'...'` ANSI-C quoted words now decode in shell tokenization, so command
words and `cd` targets are read as the shell runs them. This closes
bypasses such as `cd $'project' && make clean-all`.
