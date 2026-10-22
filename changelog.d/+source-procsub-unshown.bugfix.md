`source <(cat x.sh)` and `. <(cat x.sh)` were allowed. A process
substitution, `/dev/stdin`, `/dev/fd/*` or `/proc/self/fd/*` is not a
file the guard can open, so that script is unshown.
