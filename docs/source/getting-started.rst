A reader who has never used the binary can finish this page with one
allow, one warning, and an exec that ran.

1. Ask
======

.. code:: console

   $ ljos-policyd check -- uv run pytest
   allow
   $ ljos-policyd check -- sudo id
   allow   warn    sudo    a privilege runner is on the command

``uv run pytest`` is the line under test. A Janet pack
can name more after this verdict. The printed line stays allow.

Nothing is configured. The built-in warnings are the whole trusted computing base: nothing else decides.

2. See a warning
================

.. code:: console

   $ ljos-policyd check -- sudo id
   allow   warn    sudo    a privilege runner is on the command
   $ echo $?
   0

The first matching rule is the warning. The answer is allow. The rule
is a short token after ``warn`` (``sudo``, ``curl-pipe-shell``,
``git-force-push``, ``chmod-setuid``, ``raw-disk``, and more), then one line
a caller can show. The typed form is a Cap'n ``PolicyDecision`` with
decision allow:

.. code:: console

   $ ljos-policyd capnp -- true | wc -c
   40

3. Exec runs the program
========================

.. code:: console

   $ ljos-policyd exec -- true
   $ echo $?
   0
   $ ljos-policyd exec -- sudo id
   allow   warn    sudo    a privilege runner is on the command

``exec`` prints the warning on stderr and then runs the named program.
The exit status is that program's.

4. Point the seat at it
=======================

.. code:: console

   $ command -v ljos-policyd
   $ ljos doctor
   ok  policyd ljos-policyd
   $ ljos policy -- ls
   ls
   allow

``ljos policy`` prints the line, then the built-in verdict if the binary
answered, then any pack rule that matches. ``POLICYD_BIN`` names a
binary that is not on ``PATH``. ``POLICYD_REQUIRED=1`` is fail-closed:
a missing binary is then a deny.
