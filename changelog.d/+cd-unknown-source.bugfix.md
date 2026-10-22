A `cd` whose target the line does not resolve left the directory
untracked, so `cd "$X" && source .venv/bin/activate` was refused
unread even when that file was in the directory the line had just
left. The directory is unknown, and a relative `source` is read from
the last directory the walk could name. A runner there stays
untracked, and a file that is missing or unreadable stays unread.
