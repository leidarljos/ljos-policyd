Raw newline and carriage-return characters in shell script strings are
now treated as command separators. This closes bypasses such as
`bash -lc $'true\nrm -rf ~'`, which now splits and checks both commands.
