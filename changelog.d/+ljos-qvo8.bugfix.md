A deny-log line written by this build starts with the word 'quoted', then the argv.
An older line has no such word.
A shell -c script on an older line stays one word, even when it holds a quote.
So bash -c cat '/a b' is still that script, not a command whose $0 is /a b.
