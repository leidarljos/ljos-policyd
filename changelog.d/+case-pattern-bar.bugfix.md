A `|` between `case` patterns was read as a pipeline, so `a | sh | b)`
was an unshown script on `sh`'s stdin. The pattern is not a command
either: `cd` or a glob there moved the shell or counted as a write.
A `|` in an arm body is still a pipeline, and the arm is still judged.
