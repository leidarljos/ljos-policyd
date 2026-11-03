A check no longer connects when `LJOS_POLICYD_DAEMON` is set.
The variable is not read, so a missing daemon does not add the connect timeout.
