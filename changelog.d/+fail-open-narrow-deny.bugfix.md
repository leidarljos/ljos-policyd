When policyd hits an error or finds no config, it allows the call and names the reason.
Removing a tree outside the temporary directory, `find -delete`, `find -exec rm`, `rsync --delete` outside the tree, a force-push, deleting a remote default branch, reading a credential file, and piping a download into a shell each allow with a warning and add a line to the deny log.
A `wc` count of a secrets path warns.
That count with `head -c` of at most 4 bytes of the same path warns too.
A longer `head -c`, `head -n`, plain `head`, `cat`, `tail`, `cp` or `base64` of that path warns and adds a line to the deny log.
A history rewrite now warns, and so does every other hit.
For a hit the deny log records, a matching consent record or a user allow prints `allow consent` or `allow user-rule` in place of the warning, and the deny log gets no line.
Policyd names the process ancestry in the reason, but ancestry never changes the verdict.
