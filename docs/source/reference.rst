Command line
============

``ljos-policyd check|exec|capnp|check-mail|replay|version``

On ``check`` and ``exec``, ``--user-allow PATTERN`` and ``--config PATH`` are this binary's
flags, and only when they come before the command. A ``--`` ends them.
Nothing after it is read as a flag. A leading ``--`` after the verb is
optional and is stripped.

``check-mail --config PATH [--argv [--] RECIPIENT...]``
reads one RFC 5322 message on stdin. See "Outbound mail" below.

``replay [DENY_LOG]`` re-judges every row of a deny log.

============== ===================================================================================================================================================================================================================================================
Verb           Meaning
============== ===================================================================================================================================================================================================================================================
``check``      print one ``allow`` line; exit 0. With ``block-on-warning true`` in the ``--config`` file, a line that would warn prints ``deny<TAB>rule<TAB>warning``; exit 2
``capnp``      write a packed Cap'n ``PolicyDecision`` with decision allow; exit 0
``exec``       print a warning on stderr when a rule matches, then run argv. The exit status is the program's. With ``block-on-warning true`` in ``--config``, print the warning and ``exec: not run because block-on-warning is on``, and do not run argv; exit 2
``check-mail`` JSON ``verdict`` ``allow``; ``reasons`` carry the rule; exit 0. A missing ``--config`` exits 2
``replay``     one line per log row, then a count; exit 0. No log, or a log that cannot be read, exits 2
``version``    ``ljos-policyd <semver> (phronesis)`` or ``ljos-policyd <semver> (host table)``. ``--version`` prints the same line
============== ===================================================================================================================================================================================================================================================

Samples
=======

These lines are this binary. A release build prints ``phronesis`` in the
version parentheses. A source build without the library prints ``host table``.

.. code:: console

   $ ljos-policyd
   allow   fail-open   no args
   $ ljos-policyd nonesuch
   allow   fail-open   unknown verb
   $ ljos-policyd version
   ljos-policyd 0.7.0 (host table)
   $ ljos-policyd check -- git status
   allow
   $ ljos-policyd check -- sudo id
   allow   warn    sudo    a privilege runner is on the command
   $ ljos-policyd check -- chmod 4755 /tmp/x
   allow
   $ ljos-policyd check -- make clean-all
   allow
   $ ljos-policyd check -- sh -s
   allow
   $ ljos-policyd check -- git reflog expire --expire=now
   allow
   $ ljos-policyd check -- git push --force-with-lease origin feature
   allow   warn    git-force-push  a force push rewrites a published branch
   $ ljos-policyd check --user-allow 'rm -rf /home*' -- rm -rf /home
   allow   user-rule   rm -rf /home*
   $ ljos-policyd check --user-allow 'sudo *' -- sudo id
   allow   warn    sudo    a privilege runner is on the command
   $ ljos-policyd check --config /no/such-policyd.toml -- sudo id
   allow   fail-open   missing config
   $ ljos-policyd check-mail
   usage: ljos-policyd check|exec|capnp|version -- argv...
   usage: ljos-policyd check-mail --config PATH [--argv [--] RECIPIENT...]
   usage: ljos-policyd replay [DENY_LOG]
   $ echo $?
   2
   $ ljos-policyd replay /no/such-deny-log
   replay: /no/such-deny-log: No such file or directory (os error 2)
   $ echo $?
   2
   $ ljos-policyd check-mail --config mail.conf < message.eml
   {"verdict":"allow","reasons":[]}
   $ ljos-policyd check-mail --config mail.conf < blocked.eml
   {"verdict":"allow","reasons":[{"code":"recipient-domain-denied","detail":"to blocked.test"}]}
   $ ljos-policyd replay deny.log
   was deny    git-force-push  now allow   warn    git-force-push  a force push rewrites a published branch    git push --force origin main
   1 of 1 refused lines would run now
   $ ljos-policyd capnp -- true | wc -c
   48

Built-in warnings
=================

First match wins. The printed line is ``allow``. A rule hit is ``warn``,
the rule name, and one warning. A fault, a missing config, no
arguments, or an unknown verb is ``fail-open``. The command is not stopped.

The README table is the match list. A host-table build prints these
rule names: ``sudo``, ``curl-pipe-shell``, ``decoded-pipe-shell``,
``rm-rf-outside-tmp``, ``find-delete``, ``find-exec-rm``, ``feeder-rm``,
``rsync-delete-outside``, ``mv-tree-outside``, ``git-force-push``,
``git-push-delete``, ``git-reset-hard``, ``git-clean-force``,
``git-stash-drop``, ``git-stash-clear``, ``git-discard-worktree``,
``git-worktree-force-remove``, ``git-branch-force-delete``,
``git-history-rewrite``, ``git-update-ref-delete``, ``raw-disk``,
``reads-credential``, ``credential-mention``, ``seat-guard-path``, and
``exec-unresolved``.

A setuid or setgid mode, a recursive ``chmod`` or ``chown``, ``git reflog expire``, and ``find -fprint`` print ``allow``. A shell with no ``-c`` script
and no file (``sh -s``, a bare ``bash``) prints ``allow``. This binary does
not read that shell's stdin. A ``sh -c`` script, and a here-document
inside that script, is judged.

Task runners
============

Makefile, npm, pnpm, yarn, bun and just recipes are not read. The line
is judged as written. ``make clean-all`` is ``allow`` even when a recipe
on disk would delete a tree.

Argument limits
===============

A phronesis build hands each word to the pack whole. phronesis 0.2.3
keeps a word of up to 128 KiB (131072 bytes) and up to 32768 words. A
Cap'n command body over 512 KiB (524288 bytes) prints ``allow``,
``fail-open``, and ``field-too-long`` before the word count is checked.
Past a limit the printed line is ``allow``, ``fail-open``, and the reason:

======================================= ===============================================================================
Past                                    Answer
======================================= ===============================================================================
a word longer than 131072 bytes         ``allow``, ``fail-open``, ``field-too-long: argv word exceeds 131072 bytes``
more than 32768 words                   ``allow``, ``fail-open``, ``field-too-long: argv count exceeds 32768``
a command body longer than 524288 bytes ``allow``, ``fail-open``, ``field-too-long: command body exceeds 524288 bytes``
======================================= ===============================================================================

A blank reason is the name alone, ``field-too-long``. The limits are
``PHRONESIS_SHELL_WORD_MAX`` and ``PHRONESIS_SHELL_ARGV_MAX`` in phronesis
``src/internal.h``, and ``PHRONESIS_CAPNP_MAX_BODY`` in phronesis
``include/phronesis/supervisor.h``. phronesis 0.2.3 sets them to 131072,
32768 and 524288 and writes the reason strings above. This binary names
the code and keeps the reason. Release binaries link phronesis 0.2.5.
A build without the library uses the host table and does not apply
these limits.

Outbound mail
=============

``check-mail`` prints one JSON object. The verdict is ``allow``. Where this
section says a message is refused, that condition is a reason. The send
is not held. An empty reason list is not a grant to send.

The message on stdin is the whole input. A caller must pass no
recipient arguments to ``sendmail -t``: those addresses are not in
the message. Pass the same recipients to ``--argv`` and this check
names them in a reason, as it does a header recipient. ``--config`` comes before ``--argv``.

The config is lines of ``identity``, ``deny-file`` and ``pack-law``,
an optional ``subaddress`` line, and any number of ``alias`` lines. A
relative path is read from the config file's directory. ``identity`` is
the one address ``From`` must be, after ASCII case folding only. A
local part or domain that NFKC or the removal of a skipped
character would change is a refusal, including a zero-width
character or a fullwidth spelling. The mailbox is the address in
angle brackets, read from the raw unfolded value. A display-name encoded-word is decoded for display only, and
an encoded addr-spec is a refusal. A second ``From`` is a refusal.
A group in ``From`` is a refusal. A group in a recipient header
still contributes its mailboxes.
``Reply-To``, ``Sender``, ``Return-Path``, ``Errors-To``,
``Disposition-Notification-To``, ``Return-Receipt-To``,
``Delivery-Receipt-To``, ``Mail-Followup-To`` and ``Mail-Reply-To``
must stay clear of a deny-file identity (``address``, or a mailbox
at a ``domain``) and of a domain named by the pack-law file.
``Sender``, ``Errors-To`` and ``Return-Path``, when present, must
be the identity under the same rule as ``From``. An empty
``Return-Path`` is not that address. Any ``Resent-*`` header is a refusal, and so is
any ``Apparently-To``. ``To``, ``Cc`` and ``Bcc`` are refused when
the mailbox is an ``address`` line in the deny file, and when the
domain or a parent of it is named by the deny file or by a
``deny-domain`` line in the pack-law file. An ``address`` line is
that mailbox, not the whole domain. It also covers that local
part, one ``subaddress`` separator, and anything after the
separator. The separators are the ``subaddress`` line, or ``+-``
when the line is omitted. ``.``, ``@``, ``%`` and ``!`` are not
separators. An ``address`` rule is also compared by skeleton:
NFD, combining marks removed, case folded twice, combining marks
removed again, then NFC, with every ``.``, ``_``, ``-``, ``+`` and ``=``
removed and nothing cut. The second fold turns capital sharp s
into ss. The second removal drops the dot that case folding İ
produces, so İ and i are one skeleton, and a mark cannot compose
with the letter before it and escape the prefix. ``abc`` followed
by U+0301 and ``x`` is denied by ``abc``, and Lithuanian i + U+0307 +
U+0300 is the same skeleton as ì. A recipient whose skeleton starts with
the rule's skeleton, at the rule's domain or one in the same
alias family, is refused, and so is one the folding below
refuses. This over-blocks on purpose: a rule for ``john`` also
refuses ``johnny`` and ``jo.hn-x``, so a provider that ignores a
character no family lists cannot deliver a denied mailbox.
An address rule whose skeleton is empty refuses the deny file.
The error names the line and not the address. A deny file that
does not load refuses every send. A skeleton shorter than three
characters still matches that mailbox, its subaddresses and its
alias family, and does not use the prefix, so ``jo`` denies ``jo``
and ``jo+tag`` and not ``john``.
A provider alias family folds both the rule and the
recipient, and adds its separators to the ``subaddress`` line on
its domains. ``gmail.com`` and ``googlemail.com`` are one
domain, dots in the local part are ignored, and ``+`` is a
separator. On ``fastmail.com``, ``+`` is a separator and a
mailbox at ``<local>@<user>.fastmail.com`` is
``<user>+<local>@fastmail.com``. Every label in front of
``fastmail.com`` is the user, and a hyphen there is part of the
user name. A punycode user label is decoded to Unicode and folded as a
local part, so ``x@xn--bcher-kva.fastmail.com`` is
``bücher+x@fastmail.com``. ``proton.me``,
``protonmail.com``, ``protonmail.ch`` and ``pm.me`` are one
domain, and so are ``icloud.com``, ``me.com`` and ``mac.com``,
each with ``+``. ``outlook.*``, ``hotmail.*``, ``live.*`` and
``msn.*`` (every domain with that first label, whatever the
country suffix) are separate domains, each with ``+``. Exact and
subaddress matching stay on the domain the rule names. The
skeleton prefix still crosses that family, so a rule for
``john@outlook.com`` also denies ``john@hotmail.com``,
``john@live.com``, ``john@msn.com`` and ``john@outlook.de``. That
over-block is the prefix, not a shared mailbox. On
``yahoo.*``, ``ymail.*`` and ``rocketmail.com``, ``-`` is a
separator, and an address rule
is also cut at its first separator, so a rule for one disposable
address ``<base>-<keyword>`` covers ``<base>`` and every keyword.
An ``alias`` line adds a family to these:
``alias <domain>[,<domain>...] <separators> [flag...]``. A
domain may be ``<label>.*``, every domain whose first label is
``<label>``. The separators are checked as on the ``subaddress`` line, and the flags
are ``shared`` (the domains, and the same subdomain of each, are
one mailbox), ``dots`` (dots in the local part are ignored),
``subdomain`` (``<local>@<user>.<domain>`` is
``<user><sep><local>@<domain>``, ``<sep>`` being the line's first
separator, folded again so ``dots`` also reaches the user) and ``cut`` (the rule is also cut at its
first separator). An ``alias`` line cannot remove a built-in
family, and one that does not parse, or names one domain or flag
twice, refuses the config. A
``domain`` rule on a domain of a ``shared`` family covers every
domain of that family and their subdomains, so ``domain gmail.com``
also refuses ``googlemail.com``, ``domain pm.me`` the other Proton
domains, and ``domain icloud.com`` ``me.com`` and ``mac.com``.
``deny-domain`` in the pack-law file does the same. A ``domain``
or ``deny-domain`` value has to be a hostname after IDNA. A star,
a colon, a slash, an at-sign, whitespace, or anything else that
is not a hostname refuses the file. So does a domain a
recipient cannot have, such as an all-numeric one, in a
``domain``, ``deny-domain`` or ``address`` value. The detail is the
line number and not the value. A wildcard is not how to name
subdomains: ``domain example.test`` already covers
``a.example.test``. An ``address`` value with a star, or with a
character a parsed recipient cannot carry, is refused the same
way. ``From`` is
not matched this way. A domain literal (an address
at ``@[ ... ]``) in a watched header is a refusal. So is a domain
that is not a hostname after IDNA, such as one with an underscore,
a ``!`` or a ``+``, a label that starts or ends with a hyphen, a label
over 63 characters or a name over 253: no rule could name it. An
all-numeric domain is a refusal, judged after IDNA. That
includes a dotted quad, a shorter form ``inet_aton`` accepts, a
hex label (``0x``) and a label with a leading zero. U+3002 or
U+FF61 between the numbers is still that address. A source route
(``<@host:mailbox>``) is a refusal. ``@``, ``%`` or ``!`` in a local
part is a refusal, quoted or not, including a backslash escape
inside the quotes. A local part that NFKC changes into ASCII
punctuation, such as a fullwidth ``@``, ``%``, ``!`` or ``+``, is a
refusal. A local part that contains a default ignorable code point,
a noncharacter, an unassigned or private-use code point, a format
or control character, or a space separator is a refusal. A
zero-width space or a braille blank is still removed before the
address is compared.
A recipient domain, or a domain on a header checked against the
deny file, is refused when one label mixes Latin with Cyrillic or
Greek after NFKC and IDNA.

A deny-file domain compares a fullwidth spelling and the punycode
form as the same domain. A homoglyph that NFKC and IDNA leave alone
does not, and a label wholly in Cyrillic or Greek is not mapped to
the Latin it looks like. Case is folded as the address skeleton
folds it, so ß is ss and ı and İ are i, and a character a reader
skips is removed before that comparison. ``From`` is not compared that way. ``handle``, ``term`` and ``pair`` may share the deny file and
are ignored here. A pack-law line that would allow a domain refuses
the file. The detail of ``deny-file-invalid`` and ``pack-law-invalid``
is the line number, not the value. A message over 1 MiB, a control character in the header
block, U+0085, U+2028 or U+2029 in that block, a header line over
998 octets, a header block that mixes CRLF and a bare LF, or a
config that cannot be read is a refusal.

Each code is a reason. The JSON verdict on every row is ``allow``. The send is not held.

======================================== ================================================================================================================================
Code                                     When
======================================== ================================================================================================================================
``from-missing``                         no From
``duplicate-from``                       more than one From
``from-not-identity``                    From is not the configured identity
``from-unparsed``                        From does not parse as one mailbox
``from-group``                           From uses group syntax
``encoded-word``                         an encoded-word in a watched header did not decode
``reply-to-denied``                      Reply-To names a deny-file identity
``reply-to-unparsed``                    Reply-To does not parse
``sender-denied``                        Sender names a deny-file identity
``sender-unparsed``                      Sender does not parse
``sender-not-identity``                  Sender is present and is not the identity
``return-path-denied``                   Return-Path names a deny-file identity
``return-path-unparsed``                 Return-Path does not parse
``return-path-not-identity``             Return-Path is present and is not the identity
``errors-to-denied``                     Errors-To names a deny-file identity
``errors-to-unparsed``                   Errors-To does not parse
``errors-to-not-identity``               Errors-To is present and is not the identity
``disposition-notification-to-denied``   Disposition-Notification-To names a deny-file identity
``disposition-notification-to-unparsed`` Disposition-Notification-To does not parse
``return-receipt-to-denied``             Return-Receipt-To names a deny-file identity
``return-receipt-to-unparsed``           Return-Receipt-To does not parse
``delivery-receipt-to-denied``           Delivery-Receipt-To names a deny-file identity
``delivery-receipt-to-unparsed``         Delivery-Receipt-To does not parse
``mail-followup-to-denied``              Mail-Followup-To names a deny-file identity
``mail-followup-to-unparsed``            Mail-Followup-To does not parse
``mail-reply-to-denied``                 Mail-Reply-To names a deny-file identity
``mail-reply-to-unparsed``               Mail-Reply-To does not parse
``apparently-to``                        an Apparently-To header is present
``resent-header``                        a Resent-\* header is present
``mixed-script``                         a label mixes Latin with Cyrillic or Greek
``recipient-address-denied``             To, Cc or Bcc names a deny-file address
``recipient-domain-denied``              To, Cc or Bcc is at a denied domain
``recipient-unparsed``                   To, Cc or Bcc does not parse
``argv-recipient-denied``                an argv recipient is a denied address or domain
``argv-recipient-unparsed``              an argv recipient does not parse
``header-control``                       a control, or U+0085, U+2028 or U+2029
``header-line-ending``                   the header block mixes CRLF and a bare LF
``header-line-too-long``                 a header line is over 998 octets
``message-too-large``                    the message is over 1 MiB
``message-invalid``                      the bytes are not a header block
``config-unreadable``                    the config path cannot be read
``config-invalid``                       the config is missing a key or names an unknown one
``identity-invalid``                     the configured identity is not one mailbox
``deny-file-unreadable``                 the deny file cannot be read
``deny-file-invalid``                    a deny-file line is not a known kind, a domain is not a hostname, or an address skeleton is empty. The detail is the line number
``pack-law-unreadable``                  the pack-law file cannot be read
``pack-law-invalid``                     a pack-law line is not deny-domain, or the domain is not a hostname. The detail is the line number
======================================== ================================================================================================================================

Environment the seat reads
==========================

These are not read by this binary. They are how ``ljos`` finds it.

==================== ======================================================================================================================
Variable             Meaning
==================== ======================================================================================================================
``POLICYD_BIN``      absolute path to this binary
``POLICYD_REQUIRED`` if set to ``1``, the seat refuses every command until this binary is installed. This binary does not read the variable
==================== ======================================================================================================================

Exit statuses
=============

===== ===========================================================================================================================================================================
Code  Meaning
===== ===========================================================================================================================================================================
0     a check, capnp, check-mail, version, or ``exec`` of a process that exited 0
2     a ``check`` that printed ``deny``, an ``exec`` that did not run because block-on-warning is on, check-mail without ``--config``, or replay with no log or an unreadable log
127   ``exec`` could not spawn the program
other ``exec`` of a process that exited with that code
===== ===========================================================================================================================================================================

What this crate is
==================

- Remember and Prefer stay in packset.
- A check is the argv verdict. Pack rules stay in packset.
- ``ljos policy`` prints the line and composes this verdict with pack
  rules.
