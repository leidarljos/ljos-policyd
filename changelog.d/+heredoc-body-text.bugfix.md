A `cd` written in a here-document was run, so the commands after the
document were read in that directory. The body is text for anything
other than a shell. A shell that takes the document as its script
still runs it, and an expansion in an unquoted body still runs.
