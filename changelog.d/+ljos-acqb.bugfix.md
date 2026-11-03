When `exec` panics while reading its own flags, it runs the command.
It prints `allow`, `fail-open` and `user_allows` on stderr.
The line had been printed on stdout, and the command did not run.
