The pattern of `grep`, `egrep` and `fgrep`, the script of `sed`, `awk` and `gawk`, and the filter of `jq` and `yq` are no longer read as file paths, so `grep -rn '.netrc' src/` is allowed.
A pattern given with `-e` or `--regexp`, or a script with `-e` or `--expression`, leaves every operand a file.
The files they read still warn as `reads-credential`, including a `-f` pattern or program file and a `jq --rawfile` or `--slurpfile` file, so `grep x ~/.netrc` warns.
