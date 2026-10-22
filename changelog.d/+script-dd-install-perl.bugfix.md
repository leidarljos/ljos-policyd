`dd of=`, `install` and `perl -i` now count as writing their file, so a
script one of them writes and the same line then runs is refused.
