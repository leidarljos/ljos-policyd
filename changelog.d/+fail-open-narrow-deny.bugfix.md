When policyd hits an error or finds no config, it allows the call and names the reason.
A check that runs past one second also allows.
Hard denies remain only for these: removing a tree outside the temporary directory, `find -delete`, `find -exec rm`, `rsync --delete` outside the tree, a force-push, deleting a remote default branch, reading a credential file, and piping a download into a shell.
A `wc` count of a secrets path warns.
That count with `head -c` of at most 4 bytes of the same path warns too.
A longer `head -c`, `head -n`, plain `head`, `cat`, `tail`, `cp` or `base64` of that path still denies.
A history rewrite now warns, and so does every other hit.
A matching consent record or a user allow turns a deny into an allow.
Policyd names the process ancestry in the reason, but ancestry never changes the verdict.
