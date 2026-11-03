A `block-on-warning true` line in the `check --config` file makes a warning block, and it is off by default.
With it on, a line that would warn prints `deny` with the same rule and warning, and `check` exits 2.
A check that fails open still allows.
