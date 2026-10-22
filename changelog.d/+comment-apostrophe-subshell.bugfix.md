An apostrophe in a comment inside a subshell was read as a quote,
so the subshell ran on to the next one. configure's
`if ( # -L didn't work. )` then hid the assignments that show
`$ac_clean_files` is scratch, and its exit `rm` was refused.
