`tmp=`(umask 077 && mktemp -d "./confXXXXXX")`` hides `mktemp`
inside one word, so `rm -rf "$tmp"` was not the directory just made.
The group is read on its own. It is a subshell, not a file the line
runs. A temp created outside `/tmp` stays refused.
