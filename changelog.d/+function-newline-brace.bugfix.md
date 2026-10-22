A generated configure writes `name ()` and `{` on the next line. The
newline was a separator, so the body ran at the definition and `eval`
inside it dropped the directory. The brace still closes the
definition. A call of that function still runs the body.
