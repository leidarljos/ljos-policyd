A reader who has never used the binary can finish this page with one
allow, one deny, and an exec that did not run.

1. Install and ask
==================

.. code:: console

   $ cargo binstall ljos-policyd
   $ ljos-policyd version
   ljos-policyd 0.1.0
   $ ljos-policyd check -- ls
   allow

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
