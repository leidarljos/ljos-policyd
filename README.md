# ljos-policyd

May this command line run? Argv law for the leiðarljós seat. One binary
prints a verdict. It does not reload a pack. It is not a store.

Docs: https://leidarljos.github.io/ljos-policyd/

| Page | What it answers |
|---|---|
| [Getting started](https://leidarljos.github.io/ljos-policyd/getting-started.html) | One allow, one deny, and an exec that did not run |
| [How-to](https://leidarljos.github.io/ljos-policyd/howto.html) | Hook, fail-closed, pack rules beside the TCB |
| [Reference](https://leidarljos.github.io/ljos-policyd/reference.html) | Verbs, denials, exit statuses |
| [Explanation](https://leidarljos.github.io/ljos-policyd/explanation.html) | Why a binary and not a prompt |

```console
$ cargo binstall ljos-policyd
$ ljos-policyd check -- cargo test
allow
$ ljos-policyd check -- sudo id
deny	sudo
```

`ljos-policyd exec -- argv` runs the line only if the verdict is
allow. A deny exits 2.

The harness hook and `ljos policy` call this binary when it is on
`PATH` (or `POLICYD_BIN`). The model is not the gate. Absence is not
a deny unless `POLICYD_REQUIRED=1`.

First matching deny wins: `sudo`/`doas`, `curl | sh`, `rm -rf` outside
`/tmp` and `/var/tmp`, `git push --force`. Pack rules can deny more.
They cannot allow what this binary denied.

Writes stay out of this crate. Remember and Prefer belong to packset.

The seat that sits is documented at https://leidarljos.github.io.
