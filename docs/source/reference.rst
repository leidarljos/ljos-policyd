Command line
============

``ljos-policyd check|exec|capnp|version -- argv...``

``ljos-policyd check-mail --config PATH`` reads one RFC 5322 message on
stdin. See "Outbound mail" below.

================ ========================================================================================
Verb             Meaning
================ ========================================================================================
``check``        print ``allow`` or ``deny<TAB>reason``; exit 2 on deny
``capnp``        write a packed Cap'n ``PolicyDecision`` to stdout; exit 2 on deny
``exec``         same text verdict; on allow, run argv; on deny, print the verdict on stderr and exit 2
``check-mail``   JSON ``allow`` or ``deny`` for one message on stdin; exit 2 when it refuses
``version``      print ``ljos-policyd <semver> (phronesis)`` or ``ljos-policyd <semver> (host table)``
================ ========================================================================================

A leading ``--`` after the verb is optional and is stripped.

Built-in denials
================

First match wins. The head is the last path component of argv[0].
Leading assignments, ``NAME=value`` or ``NAME+=value``, and runner words
such as ``env``, ``nice`` and ``timeout`` come off first, as does the head
of a ``case`` arm (``case $x in a)``, or ``b)`` after ``;;``). A ``trap``
action is judged as a script of its own. A shell with no ``-c`` script
and no file runs what it reads on stdin: the text of a here-string or
heredoc is judged as that script, and a pipe, a ``-s`` shell fed
neither, or a here-string holding an expansion is refused as
``shell-stdin-unshown``. A command word that an ``alias`` earlier on the
line names is read as the alias's body, since dash and zsh expand
aliases in a script and the line does not say which shell reads it.

===================== ======================== ============================
Token                 Cap'n PolicyReason       When
===================== ======================== ============================
``empty argv``        ``emptyArgv``            no program
``sudo``              ``shellPrivilegeDenied`` privilege runner
``curl-pipe-shell``   ``shellRemoteExec``      a download run as a program
``rm-rf-outside-tmp`` ``rmRfOutsideTmp``       recursive delete off tmp
``git-force-push``    ``shellGitDangerous``    force push or guarded lease
``chmod-setuid``      ``chmodSetuid``          setuid or setgid mode
``raw-disk``          ``rawDisk``              dd to a device node, or mkfs
===================== ======================== ============================

Anything else is ``allow``. ``python -c`` is allow. Schema: ``schema/policy.capnp``.

Task runners
============

A line that runs a task runner is also judged on what the target runs.
The recipe comes from the file the runner reads, in the directory it
runs in: the working directory, the one a ``cd`` or ``pushd`` earlier on
the line enters, the one ``env -C`` names for the command it runs, or
the one the runner's own ``-C``, ``--prefix`` or ``--cwd`` names.
``env`` reads its flags as GNU ``env`` does: short ones cluster
(``-iC DIR``, ``-uVAR -C DIR``) and a long one may be cut to a prefix that
names only it (``--ch DIR``), so these move the command as ``-C DIR``
does. ``-S STRING`` (or ``-iS STRING``) splits STRING into words that take
its place, so options in it (``env -S '-C dir' make``) and the words
after it are read too. The shell expands STRING first, so a ``$NAME`` or
``${NAME}`` in it that the line assigned one value earlier, and sets no
other way, is read as that value. A string that still holds a ``$`` after
that may run any command, so it is refused as
``env-split-string-unshown``.
Leading words that still run ``cd`` in this shell (``command``,
``builtin``, ``if``, ``while``, ``{`` and the other control keywords, a
``case`` arm's head, and
the ``time`` keyword with its ``-p``, which is a program after ``command``
or ``builtin``, where no word is a keyword)
are peeled before this check, as are assignments among them
(``if FOO=1 cd dir``), and a redirection among the words of a
``cd`` or ``pushd`` names neither the directory nor a ``pushd`` stack index.
One that closes a descriptor (``2>&-``, ``<&-``) is a whole word, so the
word after it is the target.

============================================ ==============================================================================================
Runner                                       File read
============================================ ==============================================================================================
``make``, ``gmake``                          ``GNUmakefile``, ``makefile`` or ``Makefile``, or ``-f FILE``, with the target's prerequisites
``just``                                     ``justfile``, ``Justfile`` or ``.justfile``
``cargo make``, ``makers``                   ``Makefile.toml``
``npm run``, ``pnpm``, ``yarn``, ``bun run`` the ``scripts`` of ``package.json``, with ``pre`` and ``post``
============================================ ==============================================================================================

Each recipe line is judged as a ``sh -c`` script, and a refusal names the
target and the line: :literal:`make clean-all runs \`rm -rf ~\`: rm-rf-outside-tmp`.
Nothing is spawned. A missing or unreadable file leaves the line
judged as written. A ``cd`` or ``pushd`` to a path the line does not show
(``cd "$X"``) leaves it in a directory it does not follow, so a runner
after it is refused. So does an ``eval``, a ``source`` or ``.`` whose file
the guard cannot read or whose text may move the shell or set one of
those, a command word the line does not show (``$c dir``), which may be
``cd``, as may an alias whose body the line does not show, and a ``trap``
whose action is one of those or a ``cd``, ``pushd`` or ``popd``, since a
``DEBUG`` trap runs before each command; after one ``HOME``, ``CDPATH`` and
``PWD`` are not followed either. A ``source`` or ``.`` of a literal path to
a regular file the guard can read, whose text does none of that, leaves
the line where it was. The text is read with the aliases the line
defined before the ``source`` expanded, as the shell that sources it
reads it.
Raw newlines and carriage returns split script commands, and ``$'...'``
ANSI-C quoted words are decoded before the line is judged. A backslash
before a newline joins the two lines, outside single quotes, as the
shell joins them.

A ``cd`` or ``pushd`` to a relative path whose first part is not ``.`` or
``..`` enters that path under the first ``CDPATH`` entry that holds it, an
empty or ``.`` entry being the working directory, so the runner after it
is read there, and in any entry before it the line does not show. A
``CDPATH`` set in
front of the ``cd`` (``CDPATH=dir cd x``), or of the shell that runs it, is
the one searched, as is one the line sets before it, alone or with
``export``, ``declare`` and the like (``export CDPATH=dir; cd x``), unless a
pipeline stage, a subshell or a list sent to the background set it.
One set where it may not run, past a ``&&`` or ``||``, is searched along
with the one before it. Another command that writes it in this shell
(``read CDPATH``, ``printf -v CDPATH``, ``${CDPATH:=dir}``, or an
assignment in front of a special builtin such as ``:``), or an entry with
``$``, a backquote or ``~`` in it, names no directory the line shows, so
a runner after the ``cd`` is refused. A word that only names it
(``grep CDPATH``, ``env CDPATH=dir cmd``) changes nothing.

``HOME`` is followed the same way: a bare ``cd`` enters the one set in
front of it (``HOME=dir cd``) or earlier on the line (``export HOME=dir;
cd``), and ``~`` expands from the one set before the command, as do
``$HOME`` and ``${HOME}`` at the head of a path. A ``HOME``
that may hold either of two values, or one the line does not show
(``HOME=$(mktemp -d) cd``), leaves the runner after the ``cd`` refused.
``$PWD`` in either value is the one directory the line is in, when it
shows that and does not set ``PWD`` (``export HOME="$PWD/.home"``).
With ``HOME`` unset, ``~`` is the home in the user's passwd entry, as in
bash, and a bare ``cd`` stays. With it unset or empty, ``$HOME/path`` is
the path from ``/``, as is ``~/path`` with it empty, while
``cd $HOME``, or ``cd ~`` with it empty, stays.
``~login`` expands from the password database and ``~+`` to where the
line is, while ``~-`` and a stack entry such as ``~1`` name a directory
that is not followed.

A ``cd`` or ``pushd`` takes ``..`` off the path by name, as the shell's
logical ``cd`` does, so ``cd lnk/..`` comes back to where it started even
when ``lnk`` is a symbolic link. Where that names no directory, the
line may instead be through the link, as bash then tries the path as
written (``cd lnk/../x`` with ``x`` only beside the link's target).
``cd -P``, the last of ``-L`` and ``-P`` winning, resolves the link
first, and after a ``set -P`` or ``set -o physical`` on the line, or a
``SHELLOPTS`` that may name ``physical`` for a bash the line starts, either
may hold. A ``source`` or ``.`` whose file runs ``set -P`` leaves the line in
a directory it does not follow. ``env -C`` resolves it, as ``chdir`` does.

``pushd`` and ``popd`` follow the directory stack. ``pushd -n`` stacks its
directory without entering it, ``pushd +N`` and ``-N`` enter the entry they
bring to the top, and a bare ``popd`` enters the entry under the top,
while ``popd -n``, ``popd +N`` and ``popd -N`` drop an entry and stay. An
index that counts past a ``pushd`` that may have failed may name any
directory on the stack. A ``popd`` that fails, on a word it does not take
(``popd x``) or with nothing left to pop (after ``dirs -c``), leaves the
line in a directory it does not follow. Under ``shopt -s lastpipe`` or
``set -o lastpipe``, alone or in an ``eval``, or a ``shopt`` with a word
the line does not show (``shopt -s $opt``), and in a shell the line
starts after setting ``BASHOPTS`` or ``SHELLOPTS`` to a value that names
``lastpipe`` or that it does not show, a
``cd``, ``pushd`` or ``popd`` in the last stage of a pipeline does the same,
and a ``dirs`` there leaves the stack not followed.

The line goes on past a ``cd`` that may fail, so the runner after it is
read in each directory the line may be in, up to sixteen. A ``cd`` into a
directory without the search bit moves nothing. A runner that may run
in a directory past those sixteen is refused, as
``make clean-all may run in an untracked directory``.

A ``cd -`` or ``pushd -`` enters ``OLDPWD``, which each ``cd``, ``pushd`` and
``popd`` on the line moves, and a script the line runs starts with the
one its command has. Without ``OLDPWD`` in the environment, and in a
recipe's line, where it is not followed, a runner after ``cd -`` is
refused the same way.

The words ``xargs`` adds from stdin can name any target, so a runner that
``xargs`` runs is refused, as ``xargs make may take a target from stdin``.

Argument limits
===============

A phronesis build hands each word to the pack whole. phronesis 0.2.3
keeps a word of up to 128 KiB (131072 bytes) and up to 32768 words. A
Cap'n command body over 512 KiB (524288 bytes) is refused before the
word count is checked. Past a limit the answer is ``field-too-long`` and
the host's reason:

======================================= =====================================================
Past                                    Answer
======================================= =====================================================
a word longer than 131072 bytes         ``field-too-long: argv word exceeds 131072 bytes``
more than 32768 words                   ``field-too-long: argv count exceeds 32768``
a command body longer than 524288 bytes ``field-too-long: command body exceeds 524288 bytes``
======================================= =====================================================

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

``check-mail`` prints one JSON object and only refuses. ``allow`` means
this check found nothing to refuse. A send still needs its own grant.

The config is lines of ``identity``, ``deny-file`` and ``pack-law``. A
relative path is read from the config file's directory. ``identity`` is
the one address ``From`` must be, after folding, encoded-word decoding,
NFKC and IDNA. A second ``From`` is a refusal. The mailbox is the
address in angle brackets. ``Reply-To``, ``Sender`` and ``Return-Path``
must stay clear of a deny-file identity (``address``, or a mailbox at a
``domain``). ``To``, ``Cc`` and ``Bcc`` are refused when the domain or a
parent of it is named by the deny file or by a ``deny-domain`` line in
the pack-law file.

A fullwidth spelling and the punycode form compare as the same domain.
A homoglyph that NFKC and IDNA leave alone does not. ASCII case is
folded, and a character a reader skips is removed before the
comparison. ``handle``, ``term`` and ``pair`` may share the deny file
and are ignored here. A pack-law line that would allow a domain refuses
the file. A message over 1 MiB, a control character in the header
block, or a config that cannot be read is a refusal.

=========================== =========================================================
Code                        When
=========================== =========================================================
``from-missing``            no From
``duplicate-from``          more than one From
``from-not-identity``       From is not the configured identity
``from-unparsed``           From does not parse as one mailbox
``encoded-word``            an encoded-word in a watched header did not decode
``reply-to-denied``         Reply-To names a deny-file identity
``sender-denied``           Sender names a deny-file identity
``return-path-denied``      Return-Path names a deny-file identity
``recipient-domain-denied`` To, Cc or Bcc is at a denied domain
``header-control``          a control character in the header block
``message-too-large``       the message is over 1 MiB
``message-invalid``         the bytes are not a header block
``config-unreadable``       the config path cannot be read
``config-invalid``          the config is missing a key or names an unknown one
``deny-file-invalid``       a deny-file line is not one of the known kinds
``pack-law-invalid``        the pack-law file has a line other than deny-domain
=========================== =========================================================

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

===== ==================================================================================
Code  Meaning
===== ==================================================================================
0     allow, check-mail with nothing to refuse, or ``exec`` of a process that exited 0
2     deny, a check-mail refusal, missing verb, or empty usage
127   ``exec`` could not spawn the program
other ``exec`` of a process that exited with that code
===== ==================================================================================

What this crate is
==================

-  Remember and Prefer stay in packset.
-  A check is the argv verdict. Pack rules stay in packset.
-  ``ljos policy`` prints the line and composes this verdict with pack
   rules.
