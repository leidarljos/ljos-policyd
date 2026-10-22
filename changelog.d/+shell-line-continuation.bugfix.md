A backslash before a newline in a shell script now joins the two lines,
as the shell does, instead of keeping the newline in the next word. This
closes bypasses such as `cd project && \` followed by `make clean-all` on
the next line, which now reads the recipe in project.
