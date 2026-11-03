A command passed as one argv word is now read as a shell line when that word has whitespace or a shell operator in it.
`git push --force origin main` and `sudo id` passed that way warn, and a longer argv is unchanged.
