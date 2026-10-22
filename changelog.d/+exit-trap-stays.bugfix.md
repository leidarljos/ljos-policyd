An EXIT trap that changes directory was treated as moving every
command after it, so `make` following `trap 'cd /' EXIT` was refused
as untracked. The trap runs when the shell exits. Its action is still
judged. A trap on any other signal still moves the commands after it.
