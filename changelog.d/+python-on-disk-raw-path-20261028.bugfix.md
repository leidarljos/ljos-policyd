Python write-path checks now resolve on-disk paths from raw input except fd and device entries, so symlink-plus-`..` escapes and linked work-tree cwd writes are refused.
