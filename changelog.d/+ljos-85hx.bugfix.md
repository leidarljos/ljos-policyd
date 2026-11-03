With no deny-log path set the old code printed nothing; the empty path came only from LJOS_POLICYD_DENY_LOG="".
Now, with no HOME, XDG_STATE_HOME or deny-log variable, every hit prints a new stderr line.
