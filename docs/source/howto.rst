Check a line from a hook
========================

The harness hook should call the binary, not ask the model. Pipe is
not required; argv after ``--`` is the line.

.. code:: console

   $ ljos-policyd check -- git push origin main
   allow
   $ ljos-policyd check -- git push --force origin main
   deny    git-force-push

A deny is exit 2. The hook turns that into a blocked tool call.

Run only if allowed
===================

.. code:: console

   $ ljos-policyd exec -- uv run pytest

Same verdict as ``check``. On allow, ``exec`` replaces itself with the
named program. On deny it prints the verdict and exits 2.

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

The binary does not load rules. Pack rules are memory:

.. code:: console

   $ ljos rule '*--force*' --verdict deny --why "Never force push."
   $ ljos policy -- git push --force

``ljos policy`` prints the TCB verdict first, then the pack rule. First
deny still wins. Edit a pack rule only when argv law itself changes.
Do not write dates, ticket ids, or sitting notes into it.
