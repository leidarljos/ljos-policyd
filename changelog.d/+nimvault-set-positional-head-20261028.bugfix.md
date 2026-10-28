Nimvault hidden-head checks now track `set --` positional words, so later bare positional command heads like `"$@"` or `$1` are refused when they can run `nimvault get`.
