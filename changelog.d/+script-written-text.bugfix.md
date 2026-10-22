A script the line writes with `echo`, `printf` or a here-document whose
every word is literal, and then runs, is now judged on that text
instead of refused, so `echo 'echo ok' > build/run.sh && sh
build/run.sh` passes. Lines of a here-document something other than a
shell reads no longer count as commands that may write a script.
