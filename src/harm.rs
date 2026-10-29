//! Small tables for destructive commands. Each row is a shape on the
//! words the lexer already split. Nothing here walks a directory or a
//! recipe.

use super::{base_of, commands, git_subcommand, whole_tree};

/// Local git that drops uncommitted work. An ask, not a deny: the person
/// can still let it through. A force push stays a deny in the git table.
pub(crate) fn git_lost_work(argv: &[String]) -> Option<&'static str> {
    let (sub, rest) = git_subcommand(argv)?;
    let short = |c: char| {
        rest.iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains(c))
    };
    let has = |f: &str| rest.iter().any(|a| a.as_str() == f);
    match sub {
        "reset" if has("--hard") => Some("git-reset-hard"),
        "clean" if clean_fd(rest) => Some("git-clean-force"),
        "stash"
            if rest
                .iter()
                .find(|a| !a.starts_with('-'))
                .is_some_and(|a| a.as_str() == "clear" || a.as_str() == "drop") =>
        {
            Some(if rest.iter().any(|a| a == "drop") {
                "git-stash-drop"
            } else {
                "git-stash-clear"
            })
        }
        "checkout" | "restore" if discards_tree(rest) && !short('b') && !has("-b") && !has("-B") => {
            Some("git-discard-worktree")
        }
        _ => None,
    }
}

/// `clean -fd` and `clean -fdx`: force and directories, in one cluster
/// or as separate flags. A dry run (`-n`) is not this.
fn clean_fd(rest: &[String]) -> bool {
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
    if rest.iter().any(|a| matches!(a.as_str(), "-b" | "-B" | "--patch" | "-p")) {
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
    let find = cmd.iter().any(|w| base_of(w) == "find");
    if find && cmd.iter().any(|w| *w == "-delete") {
        return Some("find-delete");
    }
    if find {
        for (i, w) in cmd.iter().enumerate() {
            if matches!(*w, "-exec" | "-execdir" | "-ok" | "-okdir")
                && cmd.get(i + 1).is_some_and(|n| base_of(n) == "rm")
            {
                return Some("find-exec-rm");
            }
        }
    }
    for (i, w) in cmd.iter().enumerate() {
        if matches!(base_of(w), "xargs" | "parallel")
            && command_after(cmd, i).is_some_and(|c| base_of(c) == "rm")
        {
            return Some("feeder-rm");
        }
    }
    None
}

/// The program `xargs` or `parallel` runs: the first word that is not
/// one of its flags. `:::` starts the inputs, so the program was earlier.
fn command_after<'a>(cmd: &[&'a str], at: usize) -> Option<&'a str> {
    const VALUED: &[&str] = &[
        "-I", "-J", "-L", "-n", "-s", "-P", "-a", "-E", "-e", "-d", "-R", "-S", "-j", "--jobs",
        "--arg-sep", "--replace", "--max-args", "--max-chars", "--max-procs", "--delimiter",
        "--arg-file", "--eof",
    ];
    let mut i = at + 1;
    while i < cmd.len() {
        let a = cmd[i];
        if a == ":::" || a == "::::" {
            return None;
        }
        if a == "--" {
            return cmd.get(i + 1).copied();
        }
        if a.starts_with('-') && a != "-" {
            let takes = VALUED.iter().any(|f| a == *f) && !a.contains('=');
            i += if takes { 2 } else { 1 };
            continue;
        }
        return Some(a);
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
            "rsync" if rsync_deletes(&cmd) => {
                if rsync_dest(&cmd).is_some_and(|d| outside_tree(d, work)) {
                    return Some("rsync-delete-outside");
                }
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

fn rsync_dest<'a>(cmd: &[&'a str]) -> Option<&'a str> {
    cmd.iter()
        .rev()
        .find(|a| !a.starts_with('-'))
        .copied()
        .filter(|a| base_of(a) != "rsync")
}

/// A destination that is a whole tree and not inside `work`.
fn outside_tree(dest: &str, work: Option<&std::path::Path>) -> bool {
    let dest = dest
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_end_matches('/');
    if dest.is_empty() || !whole_outside(dest, work) {
        return false;
    }
    is_tree(dest)
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

