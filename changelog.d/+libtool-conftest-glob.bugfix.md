libtool removes `conftst*` after renaming a conftest object, and
`libconftest.dylib*` after the Apple single-module probe. Those are
scratch in the build directory, the same as `conftest*`. A parent
directory or `/` is still refused, and without the configure header
the names are not a pass.
