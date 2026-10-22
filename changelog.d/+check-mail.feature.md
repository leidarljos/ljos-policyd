`ljos-policyd check-mail` reads an RFC 5322 message on stdin and a config path, and prints a JSON allow or deny. Allow means this check found nothing to refuse. A send still needs its own grant.
