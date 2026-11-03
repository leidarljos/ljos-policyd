On macOS, a consent or `LJOS_USER_ALLOW` file the current user can write is now ignored, as on Linux.
It was honoured there because policyd read the user id from /proc, which macOS does not have.
