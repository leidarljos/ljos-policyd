"""Doc samples of ljos-policyd.

A built binary is checked when one is present. The lines still generate
without it, because the version-copy check runs before the crate is built.
The version number comes from Cargo.toml. A host-table build is what a
source build without phronesis prints.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from scripts.crate_version import version_line

# Packed PolicyDecision for `capnp -- true` on the host table.
CAPNP_TRUE_BYTES = 48


def binary() -> str | None:
    override = os.environ.get("LJOS_POLICYD_SAMPLE_BIN")
    if override:
        return override
    here = Path("target/debug/ljos-policyd").resolve()
    if here.is_file():
        return str(here)
    return None


def _expect(args, stdout="", stderr="", code=0, stdin=None, cwd=None, env=None):
    found = binary()
    if found is None:
        return
    got = subprocess.run(
        [found, *args],
        text=True,
        capture_output=True,
        input=stdin,
        cwd=cwd,
        env=env,
    )
    if got.returncode != code or got.stdout != stdout or got.stderr != stderr:
        raise SystemExit(
            "sample drift\n"
            f"args={args!r}\n"
            f"code {got.returncode} != {code}\n"
            f"stdout {got.stdout!r} != {stdout!r}\n"
            f"stderr {got.stderr!r} != {stderr!r}"
        )


def _expect_capnp():
    found = binary()
    if found is None:
        return
    got = subprocess.run([found, "capnp", "--", "true"], capture_output=True)
    if got.returncode != 0 or len(got.stdout) != CAPNP_TRUE_BYTES:
        raise SystemExit(
            f"capnp -- true is {len(got.stdout)} bytes, exit {got.returncode}"
        )


def _cmd(args):
    if not args:
        return "$ ljos-policyd"
    return "$ ljos-policyd " + shlex.join(args)


def _text(value):
    if not value:
        return ""
    return value if value.endswith("\n") else value + "\n"


def _run(cog, args, stdout="", stderr="", code=None, stdin=None, cwd=None, env=None):
    _expect(
        args,
        stdout=_text(stdout),
        stderr=_text(stderr),
        code=0 if code is None else code,
        stdin=stdin,
        cwd=cwd,
        env=env,
    )
    cog.outl(_cmd(args))
    if stdout:
        cog.out(_text(stdout))
    if stderr:
        cog.out(_text(stderr))
    if code is not None:
        cog.outl("$ echo $?")
        cog.outl(str(code))


def _fence(cog, org):
    cog.outl("#+begin_src console" if org else "```console")


def _end(cog, org):
    cog.outl("#+end_src" if org else "```")


def _host_version():
    line = version_line("host table")
    _expect(["version"], stdout=line + "\n")
    return line


WARN_SUDO = "allow\twarn\tsudo\ta privilege runner is on the command\n"
WARN_CURL = (
    "allow\twarn\tcurl-pipe-shell\t"
    "a download is handed to a shell or an interpreter\n"
)
WARN_FORCE = (
    "allow\twarn\tgit-force-push\t"
    "a force push rewrites a published branch\n"
)
DENY_FORCE = (
    "deny\tgit-force-push\t"
    "a force push rewrites a published branch\n"
)
WARN_CRED = (
    "allow\twarn\tcredential-mention\t"
    "a program names a credential path\n"
)
WARN_FIND = (
    "allow\twarn\tfind-delete\t"
    "find -delete reaches outside /tmp and /var/tmp\n"
)
ALLOW = "allow\n"
USAGE = (
    "usage: ljos-policyd check|exec|capnp|version -- argv...\n"
    "usage: ljos-policyd check-mail --config PATH [--argv [--] RECIPIENT...]\n"
    "usage: ljos-policyd replay [DENY_LOG]\n"
)
REPLAY = (
    "was deny\tgit-force-push\tnow allow\twarn\tgit-force-push\t"
    "a force push rewrites a published branch\t"
    "git push --force origin main\n"
    "1 logged line: 1 still warn, 0 now allow\n"
)


def readme_opening(cog):
    _fence(cog, False)
    _run(cog, ["check", "--", "git", "status"], ALLOW)
    _run(cog, ["check", "--", "sudo", "id"], WARN_SUDO)
    _run(
        cog,
        ["check", "--", "curl", "-fsSL", "https://example.org/install.sh", "|", "sh"],
        WARN_CURL,
    )
    _end(cog, False)


def readme_release_version(cog):
    _fence(cog, False)
    cog.outl("$ ljos-policyd version")
    cog.outl(version_line())
    _end(cog, False)


def readme_host_version(cog):
    _fence(cog, False)
    cog.outl("$ ljos-policyd version")
    cog.outl(_host_version())
    _end(cog, False)


def readme_rewrite(cog):
    empty = Path(tempfile.mkdtemp())
    proj = Path(tempfile.mkdtemp())
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0.0.0"\n'
    )
    (proj / "x.py").write_text("print(1)\n")
    _fence(cog, False)
    cog.outl("$ # no project file")
    _run(cog, ["check", "--", "python", "x.py"], ALLOW, cwd=empty)
    cog.outl("$ # pyproject.toml in the working directory")
    _run(
        cog,
        ["check", "--", "python", "x.py"],
        "allow\trewrite\tuv run x.py\n",
        cwd=proj,
    )
    _run(
        cog,
        ["check", "--user-allow", "rm -rf /home*", "--", "rm", "-rf", "/home"],
        "allow\tuser-rule\trm -rf /home*\n",
    )
    _run(cog, ["exec", "--", "echo", "ran"], "ran\n")
    log = empty / "deny.log"
    log.write_text("1700000000\tgit-force-push\tgit push --force origin main\n")
    cog.outl("$ ljos-policyd replay deny.log")
    _expect(["replay", str(log)], stdout=REPLAY)
    cog.out(REPLAY)
    _end(cog, False)


def _mail_pair():
    root = Path(tempfile.mkdtemp())
    (root / "deny.txt").write_text("")
    (root / "law.txt").write_text("")
    (root / "mail.conf").write_text(
        "identity mailseat@example.test\ndeny-file deny.txt\npack-law law.txt\n"
    )
    ok = "From: mailseat@example.test\r\nTo: a@example.test\r\n\r\nhi\r\n"
    blocked_msg = "From: mailseat@example.test\r\nTo: evil@blocked.test\r\n\r\nhi\r\n"
    ok_out = '{"verdict":"allow","reasons":[]}\n'
    blocked_out = (
        '{"verdict":"allow","reasons":[{"code":"recipient-domain-denied",'
        '"detail":"to blocked.test"}]}\n'
    )
    _expect(
        ["check-mail", "--config", str(root / "mail.conf")],
        stdout=ok_out,
        stdin=ok,
    )
    (root / "deny.txt").write_text("domain blocked.test\n")
    _expect(
        ["check-mail", "--config", str(root / "mail.conf")],
        stdout=blocked_out,
        stdin=blocked_msg,
    )
    return ok_out, blocked_out


def readme_mail(cog):
    ok_out, blocked_out = _mail_pair()
    _fence(cog, False)
    cog.outl("$ ljos-policyd check-mail --config mail.conf < message.eml")
    cog.out(ok_out)
    cog.outl("$ ljos-policyd check-mail --config mail.conf < blocked.eml")
    cog.out(blocked_out)
    _end(cog, False)


def audit(cog):
    _fence(cog, False)
    _run(cog, ["check", "--", "sudo", "id"], WARN_SUDO)
    _run(cog, ["check", "--", "chmod", "4755", "/tmp/x"], ALLOW)
    _run(
        cog,
        ["check", "--", "python3", "-c", 'open("/home/u/.ssh/id_rsa")'],
        WARN_CRED,
    )
    _run(cog, ["check", "--", "make", "clean-all"], ALLOW)
    _end(cog, False)


def getting_started_ask(cog):
    _fence(cog, True)
    _run(cog, ["check", "--", "uv", "run", "pytest"], ALLOW)
    _run(cog, ["check", "--", "sudo", "id"], WARN_SUDO, code=0)
    _end(cog, True)


def getting_started_capnp(cog):
    _expect_capnp()
    _fence(cog, True)
    cog.outl("$ ljos-policyd capnp -- true | wc -c")
    cog.outl(str(CAPNP_TRUE_BYTES))
    _end(cog, True)


# `find /tmp -delete` also walks directories the runner cannot read.
# Those lines are find's, not the rule. This directory is empty, so the
# warning is the only stderr on every machine.
SAMPLE_FIND_DIR = "/tmp/ljos-policyd-doc-sample"


def _prepare_find_dir():
    root = Path(SAMPLE_FIND_DIR)
    if root.is_symlink() or not root.is_dir():
        if root.exists() or root.is_symlink():
            root.unlink()
    else:
        shutil.rmtree(root)
    root.mkdir()


def getting_started_exec(cog):
    _prepare_find_dir()
    _fence(cog, True)
    _run(cog, ["exec", "--", "echo", "ran"], "ran\n", code=0)
    _run(
        cog,
        [
            "exec",
            "--",
            "find",
            SAMPLE_FIND_DIR,
            "-name",
            "nosuch-policyd-doc",
            "-delete",
        ],
        stderr=WARN_FIND,
        code=0,
    )
    _end(cog, True)


def howto_check(cog):
    _fence(cog, True)
    _run(cog, ["check", "--", "git", "push", "origin", "main"], ALLOW)
    _run(cog, ["check", "--", "git", "push", "--force", "origin", "main"], WARN_FORCE, code=0)
    _end(cog, True)


def howto_block(cog):
    root = Path(tempfile.mkdtemp())
    (root / "policyd.conf").write_text("block-on-warning true\n")
    _fence(cog, True)
    cog.outl("$ echo 'block-on-warning true' > policyd.conf")
    _run(
        cog,
        ["check", "--config", "policyd.conf", "--", "git", "push", "--force", "origin", "main"],
        DENY_FORCE,
        code=2,
        cwd=root,
    )
    _end(cog, True)


def howto_exec(cog):
    _fence(cog, True)
    _run(cog, ["exec", "--", "echo", "ran"], "ran\n")
    _end(cog, True)


def howto_capnp(cog):
    getting_started_capnp(cog)


def index_first(cog):
    _fence(cog, True)
    _run(cog, ["check", "--", "uv", "run", "pytest"], ALLOW)
    _run(cog, ["check", "--", "sudo", "id"], WARN_SUDO)
    _end(cog, True)


def index_install(cog):
    _fence(cog, True)
    _run(cog, ["check", "--", "uv", "run", "pytest"], ALLOW)
    _end(cog, True)


def reference(cog):
    _fence(cog, True)
    _run(cog, [], "allow\tfail-open\tno args\n")
    _run(cog, ["nonesuch"], "allow\tfail-open\tunknown verb\n")
    cog.outl("$ ljos-policyd version")
    cog.outl(_host_version())
    _run(cog, ["check", "--", "git", "status"], ALLOW)
    _run(cog, ["check", "--", "sudo", "id"], WARN_SUDO)
    _run(cog, ["check", "--", "chmod", "4755", "/tmp/x"], ALLOW)
    _run(cog, ["check", "--", "make", "clean-all"], ALLOW)
    _run(cog, ["check", "--", "sh", "-s"], ALLOW)
    _run(cog, ["check", "--", "git", "reflog", "expire", "--expire=now"], ALLOW)
    _run(
        cog,
        ["check", "--", "git", "push", "--force-with-lease", "origin", "feature"],
        WARN_FORCE,
    )
    _run(
        cog,
        ["check", "--user-allow", "rm -rf /home*", "--", "rm", "-rf", "/home"],
        "allow\tuser-rule\trm -rf /home*\n",
    )
    _run(cog, ["check", "--user-allow", "sudo *", "--", "sudo", "id"], WARN_SUDO)
    _run(
        cog,
        ["check", "--config", "/no/such-policyd.toml", "--", "sudo", "id"],
        "allow\tfail-open\tmissing config\n",
    )
    _run(cog, ["check-mail"], stderr=USAGE, code=2)
    _run(
        cog,
        ["replay", "/no/such-deny-log"],
        stderr="replay: /no/such-deny-log: No such file or directory (os error 2)\n",
        code=2,
    )
    ok_out, blocked_out = _mail_pair()
    cog.outl("$ ljos-policyd check-mail --config mail.conf < message.eml")
    cog.out(ok_out)
    cog.outl("$ ljos-policyd check-mail --config mail.conf < blocked.eml")
    cog.out(blocked_out)
    root = Path(tempfile.mkdtemp())
    log = root / "deny.log"
    log.write_text("1700000000\tgit-force-push\tgit push --force origin main\n")
    cog.outl("$ ljos-policyd replay deny.log")
    _expect(["replay", str(log)], stdout=REPLAY)
    cog.out(REPLAY)
    _expect_capnp()
    cog.outl("$ ljos-policyd capnp -- true | wc -c")
    cog.outl(str(CAPNP_TRUE_BYTES))
    _end(cog, True)
