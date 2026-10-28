Deletion checks now have direct tests for `/tmp` symlinks: a link into a guarded home path is refused, and an ordinary temp path is allowed.
