A reader who has never used the binary can finish this page with one
allow, one warning, and an exec that ran.

1. Ask
======

.. code:: console

   $ ljos-policyd check -- uv run pytest
   allow
   $ ljos-policyd check -- sudo id
   allow   warn    sudo    a privilege runner is on the command
   $ echo $?
   0

``uv run pytest`` is the line under test. A Janet pack
can name more after this verdict. The printed line stays allow.

Nothing is configured. The built-in warnings are the whole trusted computing base: nothing else decides.

2. See a warning
================

The first matching rule is the warning. The answer is allow. The rule
is a short token after ``warn`` (``sudo``, ``curl-pipe-shell``,
``git-force-push``, ``raw-disk``, and more), then one line
a caller can show. The typed form is a Cap'n ``PolicyDecision`` with
decision allow. The packed message for ``true`` is the byte count below.

.. code:: console

   $ ljos-policyd capnp -- true | wc -c
   48

3. Exec runs the program
========================

``exec`` prints the warning on stderr when a rule matches, then runs the
named program. The exit status is that program's. ``echo`` prints its
argument and matches no rule. ``find -delete`` outside the work tree
matches ``find-delete`` and, with this name, deletes nothing.

.. code:: console

   $ ljos-policyd exec -- echo ran
   ran
   $ echo $?
   0
   $ ljos-policyd exec -- find /tmp/ljos-policyd-doc-sample -name nosuch-policyd-doc -delete
   allow   warn    find-delete find -delete reaches outside /tmp and /var/tmp
   $ echo $?
   0

4. Point the seat at it
=======================

``ljos policy`` prints the line, then this verdict if the binary
answered, then any pack rule that matches. ``POLICYD_BIN`` names a
binary that is not on ``PATH``. ``POLICYD_REQUIRED=1`` is the seat's
fail-closed switch: the binary is not running, and the seat refuses
the command until it is installed. This binary does not read that
variable.
