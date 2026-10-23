A here-string overrides the pipe, and the last one wins. `read -u N` reads that descriptor. `read -t 0` assigns nothing, so the value this shell already holds stays.
