A redirection standing before the command was taken as the command,
so `>conftest.c echo` counted as a program that might write any file.
The command is the word after the redirection. An unknown command
there may still write anything, and a script the redirection names is
still judged when a later command runs it.
