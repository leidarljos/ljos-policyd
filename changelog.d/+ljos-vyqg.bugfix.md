`exec` reads `block-on-warning` from the `--config` file, as `check --config` already does.
By default the setting is off, and `exec` prints the warning, runs the command, and exits with the command's status.
With it on, `exec` prints the warning, says on stderr that the command was not run, and exits 2.
