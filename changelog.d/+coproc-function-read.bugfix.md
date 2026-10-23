`coproc` runs in another shell, so its `read` does not assign here. A `read` in a function body counts only when a call in this shell runs it.
