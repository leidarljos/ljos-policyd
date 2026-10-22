`include`, `-include` and `sinclude` were dropped, so a recipe that
lives in an included makefile was never judged. Includes are read
relative to the directory make runs in. A cycle, a nest past the
dependency bound, a missing required include, or a file that cannot
be read refuses the line.
