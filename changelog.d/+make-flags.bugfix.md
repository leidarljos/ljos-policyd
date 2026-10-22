`MAKEFLAGS`, `MFLAGS` and `GNUMAKEFLAGS` were ignored, in the
environment and on the line, so `-f`, `-C` and `--include-dir` there
did not choose the makefile make reads. They are parsed as make's own
options. A flag string that does not parse refuses the line.
