The relay could only run its secret through `python3 -c`, so its script
file had no way to read the token. It may now run
`nimvault run --env SECRET ENTRY python3 SCRIPT.py [args]`. The script
must be a regular file in the relay dir, reached with no symlink or `..`,
owned by the user and not group or world writable. Its text is judged by
the same rules as inline code, so printing the secret is refused and
sending it to the configured host is allowed.
