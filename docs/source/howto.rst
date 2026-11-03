Check a line from a hook
========================

The harness hook should call the binary, not ask the model. Pipe is
not required; argv after ``--`` is the line.

.. code:: console

   $ ljos-policyd check -- git push origin main
   allow
   $ ljos-policyd check -- git push --force origin main
   allow   warn    git-force-push  a force push rewrites a published branch

The answer is allow, with the rule and one warning. Exit status is 0.
The hook can show the warning. It does not block the tool call.

Make a warning block
====================

.. code:: console

   $ echo 'block-on-warning true' > policyd.conf
   $ ljos-policyd check --config policyd.conf -- git push --force origin main
   deny    git-force-push  a force push rewrites a published branch
   $ echo $?
   2

This is off unless you turn it on. With the line
``block-on-warning true`` in the file ``--config`` names, a line that
would warn prints ``deny`` with the same rule and warning, and ``check``
exits 2. Without that line, a warning stays allow.
A check that fails open is still allow with the setting on: an
error, a missing config file, and a daemon that is missing or does
not answer.

Run only if allowed
===================

.. code:: console

   $ ljos-policyd exec -- uv run pytest

Same verdict as ``check``. ``exec`` prints a warning on stderr when a rule
matches, then replaces itself with the named program.

Name a binary that is not on PATH
=================================

.. code:: console

   $ export POLICYD_BIN=$HOME/.local/bin/ljos-policyd
   $ ljos policy -- rm -rf /tmp/scratch

``ljos`` looks at ``POLICYD_BIN`` first, then ``PATH``. Doctor names the
row either way.

Fail closed
===========

.. code:: console

   $ POLICYD_REQUIRED=1 ljos policy -- ls

Without this, a missing binary is reported and the line is not
denied. With it, absence is a deny. Use it on a seat that must not
run unchecked argv.

Write pack rules beside the TCB
===============================

Pack rules are memory. The binary prints a verdict:

.. code:: console

   $ ljos rule '*--force*' --verdict deny --why "Never force push."
   $ ljos policy -- git push --force

``ljos policy`` prints this verdict first, then the pack rule. This
verdict is allow, with the rule and a warning when one matches. Edit a
pack rule only when argv law itself changes.
Do not write dates, ticket ids, or sitting notes into it.

Emit the Cap'n verdict
======================

.. code:: console

   $ ljos-policyd capnp -- true | wc -c
   40

The hook still reads the text line from ``check``. Libraries read the
packed ``PolicyDecision``.
