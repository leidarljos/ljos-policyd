A quote in a here-document ran on past the delimiter and hid every
command after it, so a force-push that followed help text was allowed.
The body is read on its own up to the delimiter line. A quote in the
body stops there, and the next command is still judged. A shell whose
script is the document is still judged on that text.
