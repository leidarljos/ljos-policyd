# ljos-policyd

Argv law for the leiðarljós seat. One question: may this command line run?

This binary prints a verdict. It does not reload a pack. Reloading a
pack is not a check. The harness hook and `ljos policy` call this
binary when it is on `PATH` (or `POLICYD_BIN`). The model is not the
gate.

```console
$ cargo binstall ljos-policyd
$ ljos-policyd check -- cargo test
allow
$ ljos-policyd check -- sudo id
deny	sudo
```

`ljos-policyd exec -- argv` runs the line only if the verdict is
allow. A deny exits 2.

Writes stay out of this crate. Remember and Prefer belong to packset.
This crate is not a store.

The C Cap'n TCB used by some product seats is a different binary and
is not this crate.
