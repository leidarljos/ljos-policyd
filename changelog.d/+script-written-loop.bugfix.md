A write in a loop body, in a substitution of the same command, or by
the command that runs the script (`sh x.sh >> x.sh`) now counts for a
script the line runs, whatever the order the line shows them in, so
`for i in 1 2; do sh ok.sh; cp evil.sh ok.sh; done` is refused.
