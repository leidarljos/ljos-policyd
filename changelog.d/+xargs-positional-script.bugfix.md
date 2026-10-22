A shell `-c` script that runs one of its positional parameters as code
(`eval "$1"`, `. "$1"`, `exec "$@"`) is now refused as
`xargs-script-unshown` when `xargs`, `parallel` or a variable read from
stdin fills those parameters.
