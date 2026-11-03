On macOS, a check run under tmux, over ssh, or in a known terminal now adds `ancestry=person`, as on Linux.
Terminal and iTerm2 count as terminals.
Policyd had looked up the parent processes in /proc, which macOS does not have.
