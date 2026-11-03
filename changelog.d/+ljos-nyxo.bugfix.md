A check now reads every parent up to init to find a terminal, sshd or tmux.
In 0.7.0 it stopped after 64 parents.
A parent it cannot read also ends the walk, and so does a pid it has already read.
macOS chains and step cost were not measured.
