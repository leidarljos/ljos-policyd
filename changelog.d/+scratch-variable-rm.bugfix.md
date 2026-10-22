`rm -rf "$tmp"` was refused whenever `tmp` was not a literal path
under `/tmp`, so a script that had just set `tmp` from `mktemp` or
from `${TMPDIR-/tmp}/name.$$` could not remove that directory. The
name is scratch when every assignment in the same script is, and a
later assignment to a real path poisons it. A variable the script
never sets stays refused.
