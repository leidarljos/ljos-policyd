`rm -rf conftest* confdefs.h` is configure deleting the header it
is about to write again. `confdefs.h` is scratch in the build
directory, like `conftest*`. `/`, a home directory, and `..` stay
refused. `a.out` still needs the generated-configure header.
