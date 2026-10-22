The command string `mapfile` or `readarray` runs with `-C` is now
judged, and one that takes the lines it reads as code (`mapfile -C eval
< cmds.txt`) is refused as `xargs-script-unshown`.
