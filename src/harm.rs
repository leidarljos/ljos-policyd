//! Small tables for destructive commands. Each row is a shape on the
//! words the lexer already split. Nothing here walks a directory or a
//! recipe.

use std::borrow::Cow;

use super::{
    base_of, commands, git_subcommand, is_assignment, shell_script, shell_words, whole_tree, SHELLS,
};

pub(crate) const RM_LONG: &[&str] = &[
    "--recursive",
    "--force",
    "--dir",
    "--verbose",
    "--interactive",
    "--one-file-system",
    "--preserve-root",
    "--no-preserve-root",
    "--help",
    "--version",
];

pub(crate) const GIT_PUSH_LONG: &[&str] = &[
    "--all",
    "--atomic",
    "--delete",
    "--dry-run",
    "--exec",
    "--follow-tags",
    "--force",
    "--force-if-includes",
    "--force-with-lease",
    "--mirror",
    "--no-force-with-lease",
    "--no-thin",
    "--no-verify",
    "--porcelain",
    "--progress",
    "--prune",
    "--push-option",
    "--quiet",
    "--receive-pack",
    "--recurse-submodules",
    "--repo",
    "--set-upstream",
    "--signed",
    "--tags",
    "--thin",
    "--verbose",
];

pub(crate) const GIT_RESET_LONG: &[&str] = &[
    "--hard", "--soft", "--mixed", "--merge", "--keep", "--quiet", "--patch",
];

pub(crate) const GIT_CONFIG_LONG: &[&str] = &[
    "--add",
    "--bool",
    "--default",
    "--edit",
    "--file",
    "--get",
    "--get-all",
    "--get-regexp",
    "--global",
    "--includes",
    "--int",
    "--list",
    "--local",
    "--name-only",
    "--no-includes",
    "--null",
    "--replace-all",
    "--show-origin",
    "--show-scope",
    "--system",
    "--type",
    "--unset",
    "--unset-all",
];

pub(crate) const GIT_CLEAN_LONG: &[&str] = &[
    "--directories",
    "--dry-run",
    "--exclude",
    "--force",
    "--interactive",
    "--quiet",
];

pub(crate) const GIT_SWITCH_LONG: &[&str] = &[
    "--conflict",
    "--create",
    "--detach",
    "--discard-changes",
    "--force",
    "--guess",
    "--ignore-other-worktrees",
    "--merge",
    "--no-guess",
    "--no-progress",
    "--no-track",
    "--orphan",
    "--progress",
    "--quiet",
    "--recurse-submodules",
    "--track",
];

pub(crate) const GIT_RESTORE_LONG: &[&str] = &[
    "--conflict",
    "--ignore-skip-worktree-bits",
    "--ignore-unmerged",
    "--merge",
    "--ours",
    "--overlay",
    "--patch",
    "--quiet",
    "--source",
    "--staged",
    "--theirs",
    "--worktree",
];

/// A unique prefix of one long option becomes that option. An exact name
/// wins, so `--force` is not `--force-with-lease`.
pub(crate) fn expand_long<'a>(word: &'a str, options: &[&str]) -> Cow<'a, str> {
    let (name, eq) = match word.split_once('=') {
        Some((n, v)) if n.starts_with("--") => (n, Some(v)),
        _ => (word, None),
    };
    if !name.starts_with("--") || name == "--" {
        return Cow::Borrowed(word);
    }
    let chosen = if options.contains(&name) {
        name
    } else {
        let mut hits = options.iter().copied().filter(|o| o.starts_with(name));
        match (hits.next(), hits.next()) {
            (Some(one), None) => one,
            _ => return Cow::Borrowed(word),
        }
    };
    match eq {
        Some(v) => Cow::Owned(format!("{chosen}={v}")),
        None if chosen == word => Cow::Borrowed(word),
        None => Cow::Owned(chosen.to_string()),
    }
}

fn git_words(sub: &str, rest: &[String]) -> Vec<String> {
    let table: &[&str] = match sub {
        "push" => GIT_PUSH_LONG,
        "reset" => GIT_RESET_LONG,
        "clean" => GIT_CLEAN_LONG,
        "switch" => GIT_SWITCH_LONG,
        "restore" | "checkout" => GIT_RESTORE_LONG,
        "config" => GIT_CONFIG_LONG,
        _ => &[],
    };
    rest.iter()
        .map(|w| expand_long(w, table).into_owned())
        .collect()
}

/// Local git that drops uncommitted work. An ask, not a deny: the person
/// can still let it through. A force push stays a deny in the git table.
pub(crate) fn git_lost_work(argv: &[String]) -> Option<&'static str> {
    let (sub, rest) = git_subcommand(argv)?;
    let owned = git_words(sub, rest);
    let rest: Vec<&str> = owned.iter().map(String::as_str).collect();
    let short = |c: char| {
        rest.iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains(c))
    };
    let has = |f: &str| rest.contains(&f);
    let dry = has("--dry-run") || short('n');
    if dry {
        return None;
    }
    match sub {
        "reset" if has("--hard") => Some("git-reset-hard"),
        "clean" if clean_fd(&owned) => Some("git-clean-force"),
        "stash"
            if rest
                .iter()
                .find(|a| !a.starts_with('-'))
                .is_some_and(|a| *a == "clear" || *a == "drop") =>
        {
            Some(if rest.contains(&"drop") {
                "git-stash-drop"
            } else {
                "git-stash-clear"
            })
        }
        "checkout" | "switch" if has("--force") || short('f') || has("--discard-changes") => {
            Some("git-discard-worktree")
        }
        "checkout" | "restore" if discards_tree(&owned) => Some("git-discard-worktree"),
        _ => None,
    }
}

/// `clean -fd` and `clean -fdx`: force and directories, in one cluster
/// or as separate flags. A dry run (`-n`) is not this.
fn clean_fd(rest: &[String]) -> bool {
    if rest.iter().any(|a| a == "--dry-run" || a == "-n") {
        return false;
    }
    let mut force = false;
    let mut dirs = false;
    for a in rest {
        if a == "--force" || a == "-f" {
            force = true;
        }
        if a == "--directories" || a == "-d" {
            dirs = true;
        }
        if let Some(c) = a.strip_prefix('-').filter(|c| !c.starts_with('-')) {
            if c.contains('n') {
                return false;
            }
            if c.contains('f') {
                force = true;
            }
            if c.contains('d') {
                dirs = true;
            }
        }
    }
    force && dirs
}

/// `checkout -- .` and `restore .`. A named file, a new branch, or a
/// patch is not the whole tree.
fn discards_tree(rest: &[String]) -> bool {
    let staged = rest.iter().any(|a| a == "--staged");
    let worktree = rest.iter().any(|a| a == "--worktree");
    if staged && !worktree {
        return false;
    }
    if rest
        .iter()
        .any(|a| matches!(a.as_str(), "-b" | "-B" | "--patch" | "-p"))
    {
        return false;
    }
    let mut paths = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if matches!(a.as_str(), "-s" | "--source") {
            it.next();
        } else if !a.starts_with('-') {
            paths.push(a.as_str());
        }
    }
    paths.iter().any(|p| whole_tree(p))
}

/// `find -delete`, `find -exec rm`, and `xargs` or `parallel` whose
/// command is `rm`. The path arrives from the feeder, so the `rm` rule
/// on a written operand never sees it.
pub(crate) fn around_rm(argv: &[String]) -> Option<&'static str> {
    for cmd in commands(argv) {
        if let Some(token) = one_around(&cmd) {
            return Some(token);
        }
    }
    None
}

fn one_around(cmd: &[&str]) -> Option<&'static str> {
    let head_at = cmd
        .iter()
        .position(|w| !is_assignment(w) && !w.starts_with('<') && !w.starts_with('>'))?;
    let head = base_of(cmd[head_at]);
    if head == "find" {
        if find_delete_hit(cmd) {
            return Some("find-delete");
        }
        let mut i = 0;
        while i < cmd.len() {
            if matches!(cmd[i], "-exec" | "-execdir" | "-ok" | "-okdir") {
                let payload = &cmd[i + 1..];
                let end = payload
                    .iter()
                    .position(|w| matches!(*w, ";" | "+" | "\\;" | "\\+"))
                    .unwrap_or(payload.len());
                if deletes_command(&payload[..end]) {
                    return Some("find-exec-rm");
                }
            }
            i += 1;
        }
    }
    if matches!(head, "xargs" | "parallel") {
        if let Some(at) = command_at(cmd, head_at) {
            if deletes_command(&cmd[at..]) {
                return Some("feeder-rm");
            }
        }
    }
    None
}

/// A filtered `find -delete` whose starting points stay in the work tree
/// is cleanup. An unfiltered `-delete`, or one aimed at `/`, `~`, or a
/// parent of the tree, is a delete.
fn find_delete_hit(cmd: &[&str]) -> bool {
    if !cmd.contains(&"-delete") {
        return false;
    }
    let filtered = cmd.iter().any(|w| {
        matches!(
            *w,
            "-name"
                | "-iname"
                | "-path"
                | "-ipath"
                | "-regex"
                | "-iregex"
                | "-wholename"
                | "-iwholename"
        )
    });
    let starts = find_starts(cmd);
    if starts.iter().copied().any(find_start_leaves) {
        return true;
    }
    !filtered
}

/// Path operands before the expression. No path means the current directory.
fn find_starts<'a>(cmd: &'a [&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 1;
    while i < cmd.len() {
        let a = cmd[i];
        if matches!(a, "-H" | "-L" | "-P") {
            i += 1;
            continue;
        }
        if a.starts_with('-') || a == "(" || a == "!" {
            break;
        }
        out.push(a);
        i += 1;
    }
    out
}

fn find_start_leaves(start: &str) -> bool {
    start == "/"
        || start.starts_with('/')
        || start.starts_with('~')
        || start.starts_with('$')
        || start == ".."
        || start.starts_with("../")
}

/// The same wrapper walk the rest of the checker uses, then `rm` or
/// `unlink`, or a script or `eval` string whose command is.
fn deletes_command(words: &[&str]) -> bool {
    let owned: Vec<String> = words.iter().map(|s| (*s).to_string()).collect();
    let (run, handed) = super::unwrap_wrappers(&owned);
    if let Some(script) = handed {
        let inner = shell_words(script);
        return commands(&inner).iter().any(|c| deletes_command(c));
    }
    let Some(head) = run.first() else {
        return false;
    };
    let b = base_of(head);
    if matches!(b, "rm" | "unlink") {
        return true;
    }
    if b == "eval" {
        let joined = run[1..].join(" ");
        let inner = shell_words(&joined);
        return commands(&inner).iter().any(|c| deletes_command(c));
    }
    if SHELLS.contains(&b) {
        if let Some(script) = shell_script(run) {
            let inner = shell_words(script);
            return commands(&inner).iter().any(|c| deletes_command(c));
        }
    }
    false
}

fn command_at(cmd: &[&str], at: usize) -> Option<usize> {
    const VALUED: &[&str] = &[
        "-I",
        "-J",
        "-L",
        "-n",
        "-s",
        "-P",
        "-a",
        "-E",
        "-e",
        "-d",
        "-R",
        "-S",
        "-j",
        "--jobs",
        "--arg-sep",
        "--replace",
        "--max-args",
        "--max-chars",
        "--max-procs",
        "--delimiter",
        "--arg-file",
        "--eof",
    ];
    let mut i = at + 1;
    while i < cmd.len() {
        let a = cmd[i];
        if a == ":::" || a == "::::" {
            return None;
        }
        if a == "--" {
            return Some(i + 1).filter(|n| *n < cmd.len());
        }
        if a.starts_with('-') && a != "-" {
            let takes = VALUED.contains(&a) && !a.contains('=');
            i += if takes { 2 } else { 1 };
            continue;
        }
        return Some(i);
    }
    None
}

/// `mv` onto `/dev/null` or another whole tree outside the work tree,
/// and `rsync --delete` over such a tree. A relative destination stays
/// in the work tree.
pub(crate) fn tree_outside(
    argv: &[String],
    work: Option<&std::path::Path>,
) -> Option<&'static str> {
    for cmd in commands(argv) {
        let Some(head) = cmd.first() else {
            continue;
        };
        match base_of(head) {
            "mv" => {
                if mv_dest(&cmd).is_some_and(|d| outside_tree(d, work)) {
                    return Some("mv-tree-outside");
                }
            }
            "rsync"
                if rsync_deletes(&cmd)
                    && !rsync_dry(&cmd)
                    && rsync_dest(&cmd).is_some_and(|d| outside_tree(d, work)) =>
            {
                return Some("rsync-delete-outside");
            }
            _ => {}
        }
    }
    None
}

fn mv_dest<'a>(cmd: &[&'a str]) -> Option<&'a str> {
    let mut i = 1;
    let mut dest = None;
    while i < cmd.len() {
        let a = cmd[i];
        if a == "-t" || a == "--target-directory" {
            return cmd.get(i + 1).copied();
        }
        if let Some(v) = a.strip_prefix("--target-directory=") {
            return Some(v);
        }
        if a.starts_with('-') && a != "-" {
            i += 1;
            continue;
        }
        dest = Some(a);
        i += 1;
    }
    dest
}

fn rsync_deletes(cmd: &[&str]) -> bool {
    cmd.iter().any(|a| {
        matches!(
            *a,
            "--delete"
                | "--del"
                | "--delete-before"
                | "--delete-during"
                | "--delete-delay"
                | "--delete-after"
                | "--delete-excluded"
        )
    })
}

fn rsync_dry(cmd: &[&str]) -> bool {
    cmd.iter().any(|a| {
        *a == "--dry-run"
            || *a == "-n"
            || (a.starts_with('-') && !a.starts_with("--") && a.contains('n'))
    })
}

fn rsync_dest<'a>(cmd: &[&'a str]) -> Option<&'a str> {
    const VALUED: &[&str] = &[
        "-e",
        "--rsh",
        "--exclude",
        "--include",
        "--filter",
        "-f",
        "--exclude-from",
        "--include-from",
        "--files-from",
        "--chmod",
        "--chown",
        "--max-size",
        "--min-size",
        "--backup-dir",
        "--suffix",
        "--partial-dir",
        "--compare-dest",
        "--copy-dest",
        "--link-dest",
        "--log-file",
        "--out-format",
        "--temp-dir",
        "-T",
        "--password-file",
        "--bwlimit",
        "--info",
        "--debug",
        "--rsync-path",
        "--address",
        "--port",
        "--timeout",
        "--contimeout",
    ];
    let mut i = 1;
    let mut pos = Vec::new();
    while i < cmd.len() {
        let a = cmd[i];
        if a == "--" {
            pos.extend(cmd[i + 1..].iter().copied());
            break;
        }
        if a.starts_with('-') && a != "-" {
            let takes = VALUED.contains(&a) && !a.contains('=');
            i += if takes { 2 } else { 1 };
            continue;
        }
        pos.push(a);
        i += 1;
    }
    pos.last().copied()
}

/// A destination that is a whole tree and not inside `work`.
fn outside_tree(dest: &str, work: Option<&std::path::Path>) -> bool {
    let dest = tidy_dest(dest);
    if dest.is_empty() || !whole_outside(&dest, work) {
        return false;
    }
    is_tree(&dest)
}

fn tidy_dest(dest: &str) -> String {
    let dest = dest.trim_matches(|c| c == '"' || c == '\'');
    let tilde = dest.starts_with('~');
    let abs = dest.starts_with('/');
    let body = if tilde {
        dest.trim_start_matches('~').trim_start_matches('/')
    } else {
        dest.trim_start_matches('/')
    };
    let mut parts: Vec<&str> = Vec::new();
    for p in body.split('/') {
        if p.is_empty() || p == "." {
            continue;
        }
        if p == ".." {
            parts.pop();
            continue;
        }
        parts.push(p);
    }
    if tilde {
        if parts.is_empty() {
            "~".into()
        } else {
            format!("~/{}", parts.join("/"))
        }
    } else if abs {
        if parts.is_empty() {
            "/".into()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else {
        parts.join("/")
    }
}

fn whole_outside(dest: &str, work: Option<&std::path::Path>) -> bool {
    if dest.starts_with('~')
        || dest.starts_with("$HOME")
        || dest.starts_with("${HOME}")
        || dest == "/dev/null"
        || dest.contains(':')
    {
        return true;
    }
    if !dest.starts_with('/') {
        return false;
    }
    let Some(work) = work.and_then(|p| p.to_str()) else {
        return true;
    };
    let work = work.trim_end_matches('/');
    dest != work && !dest.starts_with(&format!("{work}/"))
}

fn is_tree(dest: &str) -> bool {
    if matches!(
        dest,
        "/" | "~" | "$HOME" | "${HOME}" | "/dev/null" | "/home" | "/root"
    ) {
        return true;
    }
    let name = dest.rsplit(['/', ':']).next().unwrap_or(dest);
    !name.is_empty() && !name.contains('.')
}
