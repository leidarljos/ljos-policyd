//! Git calls that throw away work: force pushes, lease pushes, remote
//! deletes, and config that runs a command.

use std::borrow::Cow;

use super::{
    climbs, disk, harm, host_argv_table_at, open, quoted_body, shell_words, Decision, Scratch,
};

/// True when any `rm` or `rtrash` on the line deletes recursively with an
/// operand outside `/tmp` or `/var/tmp`. Flags and redirections are not
/// operands; every command on the line is judged.
/// A `git push` that can overwrite or drop history on the remote with no
/// check: `--force`, a short flag cluster holding `f` (`-fu`), `--mirror`,
/// or a refspec that starts with `+`. A `--force-with-lease` push is
/// judged by [`lease_push_guarded`].
fn force_push(argv: &[String]) -> bool {
    let Some(at) = argv.iter().position(|a| a == "push") else {
        return false;
    };
    argv[at + 1..].iter().any(|a| {
        let a = harm::expand_long(a, harm::GIT_PUSH_LONG);
        let a = a.as_ref();
        a == "--force"
            || a == "--mirror"
            || (a.starts_with('-') && !a.starts_with("--") && a.len() > 1 && a[1..].contains('f'))
            || (a.starts_with('+') && a.len() > 1)
    })
}

/// `git push` options that take the next word as their value.
const PUSH_VALUED: &[&str] = &["-o", "--push-option", "--receive-pack", "--exec", "--repo"];

/// `--force-with-lease`, bare or with `=REF` or `=REF:SHA`.
fn lease_flag(a: &str) -> bool {
    a == "--force-with-lease" || a.starts_with("--force-with-lease=")
}

fn has_lease_push(argv: &[String]) -> bool {
    let Some(at) = argv.iter().position(|a| a == "push") else {
        return false;
    };
    argv[at + 1..].iter().any(|a| lease_flag(a))
}

/// The branch a name means on the remote: `refs/heads/` taken off.
/// `None` when the words do not say: empty, `HEAD`, or a word the shell
/// still expands or globs (`$b`, `*`).
fn lease_branch(name: &str) -> Option<String> {
    let name = name.strip_prefix("refs/heads/").unwrap_or(name);
    if name.is_empty() || name == "HEAD" || name.contains(['$', '`', '*', '?', '[']) {
        return None;
    }
    Some(name.to_string())
}

/// The branch a refspec writes on the remote: the `dst` of `src:dst`,
/// else the refspec itself, a leading `+` taken off.
fn refspec_branch(spec: &str) -> Option<String> {
    let spec = spec.strip_prefix('+').unwrap_or(spec);
    lease_branch(spec.split_once(':').map_or(spec, |(_, dst)| dst))
}

/// A `--force-with-lease` push (any form, with `--force-if-includes` or
/// not) whose destination is main, master or develop, or that its words do
/// not name: no refspec, `HEAD`, a wildcard, `--all` or `--branches`. The
/// destination is each refspec's branch on the remote, and a ref the lease
/// names (`--force-with-lease=main:abc123`) counts too. The first word past
/// the options is the remote. A lease push to any other branch is allowed:
/// the remote refuses it when it holds commits the pusher has not seen.
fn lease_push_guarded(argv: &[String]) -> bool {
    let Some(at) = argv.iter().position(|a| a == "push") else {
        return false;
    };
    let rest = &argv[at + 1..];
    if !rest.iter().any(|a| lease_flag(a)) {
        return false;
    }
    let mut words: Vec<&str> = Vec::new();
    let mut named: Vec<Option<String>> = Vec::new();
    let mut every = false;
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        i += 1;
        if a == "--" {
            words.extend(rest[i..].iter().map(String::as_str));
            break;
        }
        if PUSH_VALUED.contains(&a) {
            i += 1;
            continue;
        }
        if matches!(a, "--all" | "--branches") {
            every = true;
            continue;
        }
        if let Some(value) = a.strip_prefix("--force-with-lease=") {
            let name = value.split_once(':').map_or(value, |(name, _)| name);
            if !name.is_empty() {
                named.push(lease_branch(name));
            }
            continue;
        }
        if !a.starts_with('-') {
            words.push(a);
        }
    }
    let specs = words.get(1..).unwrap_or(&[]);
    if every || specs.is_empty() {
        return true;
    }
    let remote = words.first().copied().unwrap_or("origin");
    let head = open::remote_head(git_c_dir(argv).as_deref(), remote);
    specs
        .iter()
        .map(|s| refspec_branch(s))
        .chain(named)
        .any(|branch| match branch {
            Some(b) => push_is_default(&b, head.as_deref()),
            None => true,
        })
}

/// A command word that is still a parameter expansion (`$g`, `${GIT}`).
pub(crate) fn unresolved(base: &str) -> bool {
    quoted_body(base).starts_with('$')
}

/// Git's subcommand and the words after it, past global options such as
/// `-C DIR`, `-c KEY=VALUE` and `--git-dir=DIR`.
pub(crate) fn git_subcommand(argv: &[String]) -> Option<(&str, &[String])> {
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if matches!(a, "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace") {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            return Some((a, &argv[i + 1..]));
        }
    }
    None
}

/// Pathspecs that name the whole tree.
pub(crate) fn whole_tree(p: &str) -> bool {
    matches!(p, "." | "./" | ":/" | ":" | "*" | "-A")
}

/// Config keys whose value git runs as a command.
const GIT_COMMAND_KEYS: &[&str] = &[
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.fsmonitor",
    "core.askpass",
    "sequence.editor",
    "diff.external",
    "gpg.program",
    "credential.helper",
];

/// The `-c KEY=VALUE` pairs given before git's subcommand, key lowercased.
pub(crate) fn git_configs(argv: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "-c" {
            if let Some((k, val)) = argv.get(i + 1).and_then(|kv| kv.split_once('=')) {
                out.push((
                    k.to_ascii_lowercase(),
                    val.trim_matches(['"', '\'']).to_string(),
                ));
            }
            i += 2;
        } else if matches!(a, "-C" | "--git-dir" | "--work-tree" | "--namespace") {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            break;
        }
    }
    out
}

/// The table's verdict on a string git hands to a shell. Git can run it
/// from another directory, so a relative build output path is not allowed
/// to pass there.
fn git_shell_value(value: &str) -> Option<&'static str> {
    let argv = ["sh", "-c", value].map(String::from);
    let c = host_argv_table_at(&argv, 1, true, &Scratch::default());
    // The table's tokens are all static; only phronesis writes its own.
    (c.decision != Decision::Allow).then_some(match c.token {
        Cow::Borrowed(t) => t,
        Cow::Owned(_) => "git-shell-value",
    })
}

/// A refspec or flag on `git push` that deletes a remote ref: `--delete`,
/// `-d` in a short cluster, or a refspec with an empty source (`:main`).
fn push_delete(rest: &[String]) -> bool {
    rest.iter().any(|a| {
        a == "--delete"
            || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('d'))
            || (a.starts_with(':') && a.len() > 1)
    })
}

/// A git call that throws away work no commit holds: a force push, a
/// remote ref delete, `reset --hard` (or `--merge`/`--keep` are fine),
/// `clean` with `-f`, `stash clear`, `branch -D`, `reflog expire`
/// to now, `filter-branch`, `update-ref -d`, `worktree remove --force`,
/// `checkout` of the whole tree, or `restore` of the whole tree or with no
/// path at all. An alias given with `-c alias.NAME=...` is judged as what
/// it runs, and so is a `-c` value git runs as a command.
pub(crate) enum GitHit {
    Deny(&'static str),
    Warn(&'static str),
}

fn git_hit(token: &'static str) -> GitHit {
    if open::irreversible(token) {
        GitHit::Deny(token)
    } else {
        GitHit::Warn(token)
    }
}

pub(crate) fn git_dangerous(argv: &[String]) -> Option<GitHit> {
    if has_lease_push(argv) {
        return Some(if lease_push_guarded(argv) {
            GitHit::Deny("git-force-push")
        } else {
            GitHit::Warn("git-force-push")
        });
    }
    if force_push(argv) {
        return Some(if push_rewrites_default(argv) {
            GitHit::Deny("git-force-push")
        } else {
            GitHit::Warn("git-force-push")
        });
    }
    let configs = git_configs(argv);
    for (k, val) in &configs {
        if val.is_empty() {
            continue;
        }
        if GIT_COMMAND_KEYS.contains(&k.as_str()) {
            if let Some(token) = git_shell_value(val.trim_start_matches('!')) {
                return Some(git_hit(token));
            }
        }
    }
    let (sub, rest) = git_subcommand(argv)?;
    if let Some((_, val)) = configs
        .iter()
        .find(|(k, _)| k.strip_prefix("alias.") == Some(&sub.to_ascii_lowercase()))
    {
        if let Some(script) = val.strip_prefix('!') {
            return git_shell_value(script).map(git_hit);
        }
        let mut expanded = vec!["git".to_string()];
        expanded.extend(shell_words(val));
        expanded.extend(rest.iter().cloned());
        if expanded.get(1).map(String::as_str) != Some(sub) {
            return git_dangerous(&expanded);
        }
    }
    let short = |c: char| {
        rest.iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains(c))
    };
    match sub {
        "push" if push_delete(rest) => Some(if delete_hits_default(rest) {
            GitHit::Deny("git-push-delete")
        } else {
            GitHit::Warn("git-push-delete")
        }),
        "filter-branch" | "filter-repo" => Some(GitHit::Warn("git-history-rewrite")),
        "update-ref" if short('d') => Some(GitHit::Warn("git-update-ref-delete")),
        _ => None,
    }
}

/// A force or lease push whose remote side is `main`, `master`, or
/// `develop`, a mirror, or a push that names no other branch while the
/// checkout is on a default branch.
fn push_rewrites_default(argv: &[String]) -> bool {
    let Some(at) = argv.iter().position(|a| a == "push") else {
        return false;
    };
    let rest = &argv[at + 1..];
    if rest
        .iter()
        .any(|a| harm::expand_long(a, harm::GIT_PUSH_LONG).as_ref() == "--mirror")
    {
        return true;
    }
    let dests = explicit_push_dests(rest);
    let remote = push_remote_word(rest);
    let head = open::remote_head(git_c_dir(argv).as_deref(), remote);
    if dests.iter().any(|d| {
        let bare = d.strip_prefix("refs/heads/").unwrap_or(d);
        bare == "develop" || push_is_default(d, head.as_deref())
    }) {
        return true;
    }
    dests.is_empty() && unnamed_is_default(git_c_dir(argv))
}

/// The first push word that names the remote, or `origin`.
fn push_remote_word(rest: &[String]) -> &str {
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        i += 1;
        if a == "--" {
            break;
        }
        if PUSH_VALUED.contains(&a) || lease_flag(a) {
            if PUSH_VALUED.contains(&a) {
                i += 1;
            }
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        return a;
    }
    "origin"
}

/// An unnamed push lands on the checkout. A detached checkout is `HEAD`,
/// which is not a branch we can call safe, so it stays a deny. A missing
/// `git -C` directory has no name and is not this case.
fn unnamed_is_default(dir: Option<std::path::PathBuf>) -> bool {
    matches!(
        open::head_name(dir.as_deref()).as_deref(),
        Some("main" | "master" | "develop" | "HEAD")
    )
}

/// `main` and `master` are defaults on their own. Any other name, including
/// `develop`, is a default only when it is the remote HEAD in the checkout.
fn push_is_default(name: &str, remote_head: Option<&str>) -> bool {
    let name = name.strip_prefix("refs/heads/").unwrap_or(name);
    if matches!(name, "main" | "master") {
        return true;
    }
    remote_head.is_some_and(|head| head == name)
}

fn is_default_branch(name: &str) -> bool {
    let name = name.strip_prefix("refs/heads/").unwrap_or(name);
    matches!(name, "main" | "master" | "develop")
}

fn git_c_dir(argv: &[String]) -> Option<std::path::PathBuf> {
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "-C" {
            return argv.get(i + 1).map(std::path::PathBuf::from);
        }
        if argv[i] == "push" {
            break;
        }
        i += 1;
    }
    None
}

fn explicit_push_dests(rest: &[String]) -> Vec<String> {
    let mut words = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let raw = rest[i].as_str();
        let expanded = harm::expand_long(raw, harm::GIT_PUSH_LONG);
        let a = expanded.as_ref();
        i += 1;
        if a == "--" {
            words.extend(rest[i..].iter().cloned());
            break;
        }
        if PUSH_VALUED.contains(&a) {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        words.push(raw.to_string());
    }
    let specs: &[String] = if words
        .first()
        .is_some_and(|w| !w.contains(':') && !w.starts_with('+') && !w.starts_with(':'))
    {
        &words[1..]
    } else {
        words.as_slice()
    };
    specs
        .iter()
        .filter_map(|spec| refspec_dest_name(spec))
        .collect()
}

fn refspec_dest_name(spec: &str) -> Option<String> {
    let spec = spec.strip_prefix('+').unwrap_or(spec);
    let dest = spec.split_once(':').map_or(spec, |(_, dest)| dest);
    if dest.is_empty() || dest == "HEAD" || dest.contains(['$', '`', '*', '?', '[']) {
        return None;
    }
    Some(dest.trim_start_matches("refs/heads/").to_string())
}

fn delete_hits_default(rest: &[String]) -> bool {
    let mut delete_flag = false;
    for a in rest {
        if a == "--delete" || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('d')) {
            delete_flag = true;
            continue;
        }
        if let Some(name) = a.strip_prefix(':').filter(|n| !n.is_empty()) {
            let name = name.split(':').next().unwrap_or(name);
            if is_default_branch(name) {
                return true;
            }
        }
        if delete_flag && !a.starts_with('-') {
            if is_default_branch(a) {
                return true;
            }
            delete_flag = false;
        }
    }
    false
}

/// A path that stays under `/tmp` or `/var/tmp`.
pub(crate) fn under_tmp(p: &str) -> bool {
    if climbs(p) {
        return false;
    }
    let lexical =
        p == "/tmp" || p.starts_with("/tmp/") || p == "/var/tmp" || p.starts_with("/var/tmp/");
    if !lexical {
        return false;
    }
    let disk = disk::on_disk(std::path::Path::new(p));
    disk.starts_with("/tmp") || disk.starts_with("/var/tmp")
}
