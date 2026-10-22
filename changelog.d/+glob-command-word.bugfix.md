A command word containing a glob and a slash was a program that might
write any file, so `/usr/bin/foo*` made a later script look written by
the line. A glob is not one program. A command the guard does not know,
with no glob in its name, may still write anything where it runs.
