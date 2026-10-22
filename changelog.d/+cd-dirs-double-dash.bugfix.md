`dirs` stops reading options at `--`, so `dirs -- -c` no longer drops the stack the line built and a `popd` after it is followed back to where the `pushd` left.
