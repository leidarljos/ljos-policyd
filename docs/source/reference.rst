Command line
============

``ljos-policyd check|exec|capnp|version -- argv...``

=========== ======================================================================================
Verb        Meaning
=========== ======================================================================================
``check``   print ``allow`` or ``deny<TAB>reason``; exit 2 on deny
``capnp``   write a packed Cap'n ``PolicyDecision`` to stdout; exit 2 on deny
``exec``    same text verdict; on allow, run argv; on deny, print the verdict on stderr and exit 2
``version`` print ``ljos-policyd <semver>``
=========== ======================================================================================

A leading ``--`` after the verb is optional and is stripped.

Built-in denials
================

First match wins. The head is the last path component of argv[0].

===================== ======================== ==============================
Token                 Cap'n PolicyReason       When
===================== ======================== ==============================
``empty argv``        ``emptyArgv``            no program
``sudo``              ``shellPrivilegeDenied`` privilege runner
``curl-pipe-shell``   ``shellRemoteExec``      fetcher piped to a shell
``rm-rf-outside-tmp`` ``rmRfOutsideTmp``       recursive delete off tmp
``git-force-push``    ``shellGitDangerous``    force push or force-with-lease
``chmod-setuid``      ``chmodSetuid``          setuid chmod
``raw-disk``          ``rawDisk``              dd to a device node, or mkfs
===================== ======================== ==============================

Anything else is ``allow``. ``python -c`` is allow. Schema: ``schema/policy.capnp``.

Environment the seat reads
==========================

These are not read by this binary. They are how ``ljos`` finds it.

==================== ===========================================
Variable             Meaning
==================== ===========================================
``POLICYD_BIN``      absolute path to this binary
``POLICYD_REQUIRED`` if set to ``1``, a missing binary is a deny
==================== ===========================================

Exit statuses
=============

===== ================================================
Code  Meaning
===== ================================================
0     allow, or ``exec`` of a process that exited 0
2     deny, missing verb, or empty usage
127   ``exec`` could not spawn the program
other ``exec`` of a process that exited with that code
===== ================================================

What this crate is
==================

-  Remember and Prefer stay in packset.
-  A check is the argv verdict. Pack rules stay in packset.
-  ``ljos policy`` prints the line and composes this verdict with pack
   rules.
