Tests and `cargo run` append denies to `target/test-deny.log` instead of the developer deny log.
The installed binary still uses `$XDG_STATE_HOME/ljos-policyd/deny.log`, or `~/.local/state/ljos-policyd/deny.log`.
