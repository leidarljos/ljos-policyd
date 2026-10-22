`eval enable_$ac_useropt=no` assigns to a name built from a value the
line does not show, such as one `expr` or `sed` printed. That was an
unseen command, so `sh configure` lost the directory for the rest of
the script. An `eval` of anything other than lone `NAME=value` words,
or of a value with a substitution, still does.
