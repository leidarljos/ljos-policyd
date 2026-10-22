A `(...)` body was judged from `bash -c` and not from the words of the line, so an `rm` inside it was never seen. The value this shell already holds is the one that body uses.
