A reader who has never used the binary can finish this page with one
allow, one deny, and an exec that did not run.

1. Ask with uv
==============

.. code:: console

   $ uvx ljos-policyd check -- uv run pytest
   allow
   $ uvx ljos-policyd check -- sudo id
   deny    sudo

``uvx`` runs the binary. ``uv run`` is the line under test. A Janet pack
can deny more after this verdict; it cannot allow what this binary
denied.

Nothing is configured. The built-in denials are the whole TCB.

2. See a deny
=============

.. code:: console

   $ ljos-policyd check -- sudo id
   deny    sudo
   $ echo $?
   2

First matching deny wins. The reason is a short token after a tab:
``sudo``, ``curl-pipe-shell``, ``rm-rf-outside-tmp``, ``git-force-push``, or
``empty argv``.

3. Exec only on allow
=====================

.. code:: console

   $ ljos-policyd exec -- true
   $ echo $?
   0
   $ ljos-policyd exec -- sudo id
   deny    sudo
   $ echo $?
   2

``exec`` prints the deny on stderr and does not spawn the process.

4. Point the seat at it
=======================

.. code:: console

   $ command -v ljos-policyd
   $ ljos doctor
   ok  policyd ljos-policyd
   $ ljos policy -- ls
   ls
   allow

``ljos policy`` prints the line, then the TCB verdict if the binary
answered, then any pack rule that matches. ``POLICYD_BIN`` names a
binary that is not on ``PATH``. ``POLICYD_REQUIRED=1`` is fail-closed:
a missing binary is then a deny.
