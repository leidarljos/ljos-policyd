# ljos-policyd

`check` prints `allow`. When a rule matches, the line is

    allow	warn	<rule>	<one warning>

The rule is the table's token, including a pack detail and an ancestry note. The warning is one line, so a caller can show it. Exit status is 0.

`exec` prints that warning on stderr and then runs the command. `capnp` writes decision allow, and puts `warn`, the rule, and the warning in the reason. `check-mail` prints `{"verdict":"allow",...}`. Each reason's code is the rule name and its detail is the warning. A missing `--config` is still a usage error and exits 2.

`LJOS_POLICYD_DAEMON` is not read. The table in this process is the answer.

The warnings are the rules in the README and in the reference. Keep them. This is not a security sandbox: a warning does not stop the command, and a path hidden from the line is outside what the table can see.
