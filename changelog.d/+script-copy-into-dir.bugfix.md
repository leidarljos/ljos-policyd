A `cp`, `mv`, `ln` or `install` into a directory now counts as writing
each source's name there, not the whole directory, so
`cp config.mk . && sh ./configure` is no longer refused. A recursive
copy still counts as writing all of the directory.
