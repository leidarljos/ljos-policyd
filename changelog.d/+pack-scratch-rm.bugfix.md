phronesis v0.2.5 refuses `rm -rf "$tmp"` after `mktemp`, and
`rm -rf conftest*`, because its recursive-delete rule has no binding
for a scratch variable and no configure scratch name. The host table
already allowed those operands. The line the pack judges names each
of them under `/tmp`, and every other word is unchanged, so a secret
beside that `rm` is still refused.
