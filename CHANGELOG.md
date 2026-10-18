# Changelog

<!-- towncrier release notes start -->

## Unreleased

## 0.4.4 (2026-10-18)

### Features

- A phronesis refusal reads as the code's name, then the pack's own text (`path-outside-workspace: path outside workspace`). A pack that wrote no text still names its code instead of the bare word `phronesis`.

### Fixes

- Concurrent checks that share a state directory no longer unset the embedded pack. Each check used to delete `pack-<hash>` and rename its own copy into place, so the one that lost the race loaded nothing and answered `deny` with an empty reason (`deny\tphronesis`) for a harmless line such as `git add slug.py test_slug.py`. The pack is now written to a private directory and renamed into place while a lock is held, a pack of the same content hash that is already there is left as it is, and a seat that still cannot load its pack answers `deny\tpack-unavailable`. Checks in one workspace retry a torn read of the shared seat slot instead of answering `bind-failed`.
- A long argument is judged on what it says. A word of 512 bytes or more was refused before the pack read it, so `echo` of a long program was denied with no reason of its own. Release and test builds link phronesis v0.2.3, which keeps each word up to 128 KiB and up to 32768 words. Past those limits, or a command body over 512 KiB, the line is `field-too-long` and the host's reason, as in `field-too-long: argv word exceeds 131072 bytes`.

## 0.4.3 (2026-10-17)

### Fixes

- The crate version reads 0.4.3, so `ljos-policyd --version` and the binstall archive name match the release tag; the v0.4.2 archives still called themselves 0.4.1.

## 0.4.2 (2026-10-14)

### Miscellaneous

- Release binaries link phronesis v0.2.2, whose generated schema C builds under `-Werror` on current macOS clang. The Intel macOS cross file names a C++ compiler, which c-capnproto's meson build now asks for. A manual run of the release workflow builds every target on a branch and publishes nothing; only a `v*` tag publishes.

## 0.4.1 (2026-10-13)

- A phronesis build embeds the compiled images phronesis installs beside its packs (`shell.jimage`, `seat.jimage`) and unpacks them with the sources. phronesis then loads the law from the image and skips the Janet boot image and compiler, so an allowed line takes about 2.3 ms instead of 7.3 ms. With a phronesis that ships no images, the build embeds only the sources and phronesis compiles them as before.
- A line that runs a task runner is judged on what the target runs. `make <target>` reads the Makefile in the working directory (or the one `-C` and `-f` name) and follows the target's prerequisites up to eight levels; `npm run`, `pnpm`, `yarn` and a bare `npm <script>` read the `scripts` of `package.json`, with its `pre` and `post` scripts; `just` and `cargo make` read their recipe files. Each recipe line is judged by the table and phronesis, so `make clean-all` whose recipe runs `rm -rf ~` and `npm run nuke` whose script runs `rm -rf ~/` are refused, and `make test` and `npm run build` still run. A missing or unreadable file leaves the verdict as before. Files are read in-process and cached by mtime and size; nothing is spawned.
- More ways to delete a tree are refused. `rm-rf-outside-tmp` covers a recursive `rm` without `-f` and the trash commands (`rtrash -r`, `trash`, `trash-put`, `gtrash`, `rmtrash`, `gio trash`) given the root, a home directory or a system tree; `rtrash -r /etc` and `trash-put ~` were allowed. `mv-to-dev-null` refuses `mv` into `/dev/null`, and `rsync-delete-root-tree` refuses an `rsync` with a `--delete` flag into the root, a home directory or a system tree. A recursive `setfacl` that strips every entry (`-b`, `-k`) or gives everyone write meets `recursive-chmod-chown` wherever it starts outside `/tmp`, as a sweeping `chmod` does. The command a `docker run`, `podman run` or `nerdctl run` passes the container is judged with each path under a bind mount read as the host path it reaches, so `docker run --rm -v $HOME:/h alpine rm -rf /h/projects` is refused and `docker run --rm alpine rm -rf /app/build` still runs.
- `find-delete-outside-tmp` allows a cleanup of files a tool writes again inside the tree, such as `find . -name '*.pyc' -delete` and `find . -name .DS_Store -delete`. Every starting point is `.` or a plain relative path outside `.git`, and every `-name`, `-iname` or `-path` test names bytecode, objects, patch leftovers, editor swap files or folder metadata from the list in the source. `find . -delete`, `find . -name '*.rs' -delete`, a home, absolute or `..` start, an `-o`, `!` or `-not` in the expression, and a line whose `cd` can leave the tree are still refused.
- `rm-rf-outside-tmp` allows a recursive delete of a top-level scratch directory named as a plain relative path, `tmp`, `.tmp` or `temp`, or a path under one, such as `rm -rf ./tmp/test-output`. `rm -rf ./src`, `src/tmp`, `tmp/../src` and `tmp/.git` are still refused.
- Both need phronesis 0.2.1 or later in a phronesis build, whose default pack makes the same two allowances; phronesis 0.2.0 still refuses these lines after the table allows them.

## 0.4.0 (2026-10-11)

- A phronesis build links phronesis 0.2 and the Cap'n Proto C runtime statically, with no runtime path, and embeds phronesis's default pack. The binary runs on a host with no phronesis install. `build.rs` finds the library under `lib`, `lib64` or `lib/<multiarch>`, and the `pkg-config` route compiles the ShellCheck shim as the `PHRONESIS_DIR` route does.
- phronesis judges every command the table reads inside a line (past wrappers, inside `sh -c` scripts and substitutions), not only the outer line. Its refusal prints the pack's reason after the tab; every phronesis refusal used to read `banned-runner`.
- phronesis state lives under one directory per workspace, so a check in a second workspace is judged like one in the first. With one shared directory phronesis kept the first workspace and refused every line outside it.
- `LJOS_POLICYD_PACK=seat` loads phronesis's seat pack, which adds uv-only Python and the package-manager refusals. The default pack no longer has them.
- The release workflow builds phronesis from source on all four targets, so the release binaries report `(phronesis)`. CI tests a phronesis build beside the table-only one.
- `raw-disk` covers the other ways to wipe a disk: `wipefs -a`, `sgdisk`, `sfdisk`, `fdisk`, `parted`, `blkdiscard`, `mkswap` and `shred` given a block device, `cryptsetup luksFormat`, `badblocks -w`, and a `>` redirection into a block device. Each tool's listing flags stay allowed. `mkfs` on an image file and `dd of=/dev/null` are no longer refused; only a block device is a disk.
- `recursive-chmod-chown` refuses a recursive `chmod`, `chown`, `chgrp` or `setfacl` that starts at `/`, a home directory or a system tree, and a recursive `chmod` that removes every permission or gives everyone write. `chmod -R 777 /` and `chown -R nobody ~` were allowed before.
- `decoded-pipe-shell` refuses a decoder's output handed to a shell: `base64 -d`, `xxd -r`, `openssl base64 -d`, `zcat`, `rev` and the other decoders piped into `sh` or `bash`, or run inside a shell's `$(...)`, `<(...)` or backticks. `echo ... | base64 -d | sh` was allowed before; the table cannot read what such a script runs.
- A function definition's body is judged: `f(){ git push -f; }; f` and `function f { rm -rf ~/x; }` were allowed before.
- More git calls that lose work are refused: `git-push-delete` for `push --delete`, `push -d` and an empty-source refspec such as `:main` or `:refs/tags/v1.0`, `git-branch-force-delete` for `branch -D`, `git-reflog-expire` for `reflog expire --expire=now` and `reflog delete`, `git-history-rewrite` for `filter-branch` and `filter-repo`, `git-update-ref-delete` and `git-worktree-force-remove`. `branch -d`, `reflog expire` with a date and `worktree remove` without `--force` stay allowed, and so does `stash drop`, as before.
- A `-c` on the git line no longer hides what runs. `git -c alias.p='push -f' p` is judged as `git push -f`, an alias that starts with `!` is judged as a shell line, and so is the value of a key git runs as a command, such as `core.sshCommand`, `core.pager` or `credential.helper`.
- `find -exec rm`, `-execdir rm`, `-ok rm`, and `shred` or `unlink` in their place, meet the same starting-point rule as `find -delete`. `busybox` and `toybox` run the applet after them, so `busybox rm -rf ~/x` meets the `rm` rule.
- `rm-rf-outside-tmp` allows a recursive delete of a build output directory named as a plain relative path: `node_modules`, `target`, `dist`, `build`, `.venv`, `__pycache__`, `.next` and the other tool caches listed in the source, or a path under one. A path with `..`, `~`, `$`, a glob, an absolute start or a `.` part is still refused, and so is the whole line when a `cd` or `pushd` on it can leave the tree. `rm -rf node_modules` and `rm -rf target/` were refused before.

## 0.3.0 (2026-10-10)

- `git push --force-with-lease`, in any form, and `--force-if-includes` are allowed. The remote refuses them when it holds commits the pusher has not fetched, so they are the safe way to rewrite a branch. Adding `--force`, `-f` or a `+` refspec is still refused.
- New refusals for git calls that drop uncommitted work: `git-reset-hard`, `git-clean-force` (`-f`, `-fd`, `-fdx`), `git-stash-clear`, and `git-discard-worktree` for `checkout -- .`, `checkout .`, `restore .` and `restore` with no path. `find-delete-outside-tmp` refuses `find -delete` outside `/tmp`.
- An inline program is read: the strings `python -c`, `node -e`, `perl -e` and `ruby -e` code hands to `os.system`, `subprocess.*`, `execSync` or `system` are judged as shell lines, and a recursive tree delete outside `/tmp` (`shutil.rmtree`, `rmSync` with `recursive`, `rm_rf`) is `rm-rf-outside-tmp`.
- A variable command word does not hide git: `g=git; $g push -f` reads `$g` from the assignment, and `$GIT push -f` with no assignment meets the git rules.
- A test runs the 24 lines of the launch comparison through the table.
- A script the table reads also runs the commands inside its `$(...)`, backticks, `<(...)`, `>(...)` and `( ... )` subshells, nested to four levels, and the table judges each. `eval ARGS` is read as a script, and the command after `if`, `then`, `do`, `{`, `!` and `coproc` is the one judged. A substitution is one word of its command, so a `;` inside it no longer cuts the script. `sh -c 'echo $(git push -f)'` was allowed before. Single quotes and an escaped `$` stay text.
- `cargo binstall ljos-policyd` builds from source on a target with no release tarball, such as Windows or musl Linux. The `compile` strategy was off, so binstall failed there. cargo-quickinstall stays off.
- The table judges every command a line runs through a wrapper or a shell. `env`, `nice`, `nohup`, `time`, `exec`, `command`, `timeout`, `xargs`, `setsid`, `stdbuf`, `ionice` and leading `NAME=value` words are taken off, with their flags, and a shell's `-c` script (`sh -c`, `bash -lc`, `sh -c -- SCRIPT`, `bash -o pipefail -c`) is read as its own line. So is the string `env -S`, `flock FILE -c` and `watch` hand to a shell. `env git push -f` and `sh -c "git push -f"` were allowed before, and so was every hook that asks this binary.

## 0.2.6 (2026-10-10)

- `git-force-push` refuses every push that can overwrite the remote: a `+` refspec
  (`git push origin +main`), `--force-with-lease=REF`, `-f` inside a flag
  cluster such as `-fu`, and `--mirror`. Only the bare words `--force`, `-f`
  and `--force-with-lease` were refused before.
- `rm-rf-outside-tmp` reads a `..` in an operand as outside `/tmp`, so
  `rm -rf /tmp/../home/u` is refused.
- The explanation says why a model cannot mediate. An unmatched command
  is an allow. Fail-closed is `POLICYD_REQUIRED`, and it covers a
  missing binary.

## 0.2.5 (2026-10-04)

- A phronesis build runs the built-in table first and keeps its refusals,
  so it refuses `rm -rf` outside `/tmp`, setuid `chmod` and raw-disk
  writes as the table build does; phronesis adds its own refusals after.
- `ljos-policyd version` names the backend: `phronesis` or `host table`.
- The README says what is refused, in what order, and how to tell which
  backend a binary uses.

## 0.2.4 (2026-10-04)

- The recursive-delete rule judges each `rm` or `rtrash` on a hooked line
  by its own operands. Redirections, separators and later commands no
  longer count as delete targets, and a second delete after `;`, `&&`,
  `||` or `|` is judged too.
- Everything in 0.2.3, which was published without the line above and is
  yanked.

## 0.2.3 (2026-10-04, yanked)

- `curl-pipe-shell` refuses a download handed to a shell: a fetching stage
  piped into a shell stage, or a shell running a download through `$( )`,
  `<( )`, backticks or `-c`. A line that names a download tool and a shell
  without that (`git fetch`, then `bash build.sh`; a pattern `curl|shell`)
  is no longer refused.
- `PHRONESIS_DIR` / `pkg-config phronesis` enables `phronesis_check_shell`
  as the check. Missing library still compiles (host argv table).
- A seated check binds the host slot to the process cwd and loads the
  Janet pack from `$PHRONESIS_PREFIX/share/phronesis/policy/shell.janet`.

## 0.2.2 (2026-09-15)

- README names the `capnp` verb.

## 0.2.1 (2026-09-15)

- Usage names `check|exec|capnp|version`. A missing or unknown verb
  no longer pretends the binary is check and exec only.

## 0.2.0 (2026-09-15)

- Cap'n `PolicyDecision` / `Decision` / `checkShell(argv)` as the typed
  API, derived from phronesis (Ali Akber Saifee / indynull, HaoZeke;
  MIT). Seat, model, and audio planes stay out.
- `ljos-policyd capnp -- argv` writes a packed PolicyDecision.
- 0.1.1 argv classes (privilege, remote-exec, setuid, raw disk, force
  with lease) are the phronesis shell-danger table, same authors.


## 0.1.1 (2026-09-15)

- Privilege runners include `su`, `pkexec`, `run0`.
- Remote-exec covers wget and fetch as well as curl.
- `chmod` setuid and `dd`/`mkfs` to raw disks are deny.
- `git push --force-with-lease` is deny.
- `python -c` stays allow: this hook sits on a general agent shell.

## 0.1.0

First public release.
