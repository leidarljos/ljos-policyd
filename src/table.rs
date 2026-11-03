//! The host argv table: the walk over a line and the commands inside it, and
//! the rules each one meets.

use std::borrow::Cow;

use super::{
    ask, base_of, brace_expands, command_roots, commands, credential_read, decoded_exec,
    deletes_a_root_tree, disk, ended_commands, expand_aliases, git_dangerous, harm, hidden_moves,
    inner_commands, inner_commands_expanded, interpreter_rmtree, is_assignment, is_privilege,
    is_redirection, lexical_norm, note_cap_label, open, peel_cd_command_word, phase, piece_base,
    python_pipe, quoted_body, raw_disk, recursive_delete_off_tmp, remote_exec, runs_fresh,
    seat_guard_denial, under_tmp, unquote, unresolved, unwrap_wrappers, writes_block_device,
    Checked, CredRead, Decision, GitHit, PolicyReason, Scratch, DECODERS, DISK_WRITERS, FETCHERS,
    SHELLS, TRASHERS,
};

/// How many steps the walk reads past the line.
///
/// The line is step 0. Each nested script, substitution or `find
/// -exec` payload is one more step. A command at step 4 is judged,
/// so four nested `sh -c` calls still show the command they run.
/// The next step is not read. The line stays allow, and the label
/// is `nesting-unread`.
pub(crate) const MAX_DEPTH: usize = 4;

/// Programs the deny rules do not read. A second command, a substitution,
/// a brace or a privilege word is not in this set: the table still walks
/// those. A wrapper is not here, and neither is a `$name`. A program that
/// writes a file is not here either: `cp`, `ln`, `mv`, `install`, `tee`
/// and `dd` overwrite whatever path they are given. `export`, `readonly`,
/// `declare`, `typeset`, `local`, `alias` and `unalias` change what a
/// later command runs.
fn inert_program(base: &str) -> bool {
    matches!(
        base,
        "echo"
            | "printf"
            | "mkdir"
            | "cat"
            | "true"
            | "false"
            | "test"
            | "["
            | "[["
            | "return"
            | ":"
            | "pwd"
            | "basename"
            | "dirname"
            | "date"
            | "id"
            | "uname"
            | "hostname"
            | "sleep"
            | "touch"
            | "ls"
            | "stat"
            | "readlink"
            | "realpath"
            | "mktemp"
    )
}

/// `argv` is one inert program and nothing the table has to open: no
/// second command, no `$(...)`, no backtick, no process substitution,
/// no brace expansion and no redirection. A `$name` in an argument stays,
/// because these programs are not `rm`.
fn inert_argv(argv: &[String]) -> bool {
    // `echo x > /dev/sda` and `echo x > file` both write. The program
    // name does not say so, so any redirection takes the full table.
    if writes_block_device(argv) || argv.iter().any(|w| is_redirection(w)) {
        return false;
    }
    let mut head = "";
    let mut saw = false;
    for w in argv {
        if matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&") || w.ends_with(';') {
            return false;
        }
        if is_privilege(base_of(w)) {
            return false;
        }
        if w.contains('`')
            || w.contains("$(")
            || w.contains("<(")
            || w.contains(">(")
            || w.contains('\n')
            || (w.contains('{') && brace_expands(w))
        {
            return false;
        }
        if !saw && !is_assignment(w) && !is_redirection(w) {
            head = base_of(w);
            saw = true;
        }
    }
    saw && inert_program(head)
}

/// Words past this stay out of the reuse map. The long script is one argv;
/// its commands are the short ones worth keeping.
pub(crate) fn host_argv_table_at(
    argv: &[String],
    depth: usize,
    moved: bool,
    parent: &Scratch,
) -> Checked {
    host_argv_table_run(argv, depth, moved, parent)
}

fn host_argv_table_run(argv: &[String], depth: usize, moved: bool, parent: &Scratch) -> Checked {
    let _span = phase::enter(phase::TABLE);
    let mut bound = parent.clone();
    bound.observe(argv);
    match credential_read(argv) {
        CredRead::Deny(by, path) => {
            return Checked {
                decision: Decision::Deny,
                code: PolicyReason::PathSensitiveDeny,
                token: Cow::Owned(format!("reads-credential: {by} with {path}")),
            };
        }
        // `wc -c`, `-l`, `-m` or `-w` prints a count, not the file.
        // The same warning covers that count with `head -c` of at most
        // 4 bytes of the same path. Any other content read still denies.
        CredRead::Count(by, path) => {
            return open::warn_checked(&format!("reads-credential: {by} with {path}"));
        }
        CredRead::None => {}
    }
    // `touch` and `mkdir` write a path and still return here. The seat
    // files are checked first, so a plain `echo` does not pay for that.
    if inert_argv(argv) {
        if let Some(c) = seat_guard_denial(argv, bound.root.as_deref()) {
            return c;
        }
        return Checked {
            decision: Decision::Allow,
            code: PolicyReason::Unspecified,
            token: Cow::Borrowed("allow"),
        };
    }
    let own = {
        let _span = phase::enter(phase::RULES);
        host_argv_rules(argv, moved, &bound)
    };
    if own.decision != Decision::Allow {
        return own;
    }
    // Past the cap the inner command is not read. The line stays the
    // allow already decided, and the label names the stop.
    if depth >= MAX_DEPTH {
        if unwalked_line(argv) {
            note_cap_label("nesting-unread");
        }
        return own;
    }
    let mut warned = open::noted(&own.token).is_some().then(|| own.clone());
    if let Some(c) = find_exec_line(argv, depth, moved, &bound) {
        if c.decision != Decision::Allow {
            return c;
        }
        if warned.is_none() {
            warned = Some(c);
        }
    }
    // A later command runs where `cd` left it. Judging the `rm` on its
    // own from the starting directory would see the wrong parent.
    {
        let span = phase::enter(phase::INNER);
        let expanded = expand_aliases(argv);
        let roots = command_roots(&expanded, bound.root.clone());
        let inners = inner_commands_expanded(&expanded);
        drop(span);
        let cmds = commands(&expanded);
        let hidden = hidden_moves(&cmds, &inners);
        for (i, inner) in inners {
            if inner.as_slice() == argv {
                continue;
            }
            let mut next = bound.clone();
            if let Some(root) = roots.get(i) {
                next.root = root.clone();
            }
            next.placed = bound.placed && (!hidden || runs_fresh(cmds.get(i), &inner));
            let c = host_argv_table_at(&inner, depth + 1, moved, &next);
            if c.decision != Decision::Allow {
                return c;
            }
            if warned.is_none() && open::noted(&c.token).is_some() {
                warned = Some(c);
            }
        }
    }
    warned.unwrap_or(own)
}

/// A command the walk would open and does not, once [`MAX_DEPTH`] is
/// spent. The line's own words are not that command.
fn unwalked_line(argv: &[String]) -> bool {
    if !find_payloads(argv).is_empty() {
        return true;
    }
    inner_commands(argv)
        .iter()
        .any(|inner| inner.as_slice() != argv)
}

/// Each `find -exec`, `-execdir`, `-ok` and `-okdir` payload is a command
/// line. It goes through the same wrapper walk and the same checks as a
/// command typed on its own. A command word that walk cannot name asks.
fn find_exec_line(argv: &[String], depth: usize, moved: bool, bound: &Scratch) -> Option<Checked> {
    let mut warned = None;
    for payload in find_payloads(argv) {
        if exec_word_unresolved(&payload) {
            return Some(Checked {
                decision: Decision::Prompt,
                code: PolicyReason::HighRiskPrompt,
                token: Cow::Borrowed("exec-unresolved"),
            });
        }
        let c = host_argv_table_at(&payload, depth + 1, moved, bound);
        if c.decision != Decision::Allow {
            return Some(c);
        }
        if warned.is_none() && open::noted(&c.token).is_some() {
            warned = Some(c);
        }
    }
    warned
}

fn find_payloads(argv: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for cmd in commands(argv) {
        let head = cmd.iter().find(|w| !is_assignment(w));
        if head.is_none_or(|w| base_of(w) != "find") {
            continue;
        }
        let mut i = 0;
        while i < cmd.len() {
            if matches!(cmd[i], "-exec" | "-execdir" | "-ok" | "-okdir") {
                let rest = &cmd[i + 1..];
                let end = rest
                    .iter()
                    .position(|w| matches!(*w, ";" | "+" | "\\;" | "\\+"))
                    .unwrap_or(rest.len());
                if end > 0 {
                    out.push(rest[..end].iter().map(|s| (*s).to_string()).collect());
                }
                i += 1 + end;
                continue;
            }
            i += 1;
        }
    }
    out
}

/// `{}` and an unsubstituted `$cmd` are not a program the walk can name.
/// `eval` and a shell `-c` / `-lc` are: their string is lexed on the way in.
fn exec_word_unresolved(payload: &[String]) -> bool {
    let (run, handed) = unwrap_wrappers(payload);
    if handed.is_some() {
        return false;
    }
    let Some(head) = run.first() else {
        return true;
    };
    let b = base_of(head);
    if b == "eval" || SHELLS.contains(&b) {
        return false;
    }
    let bare = quoted_body(head);
    bare.is_empty() || bare == "{}" || bare.contains("{}") || unresolved(bare)
}

const RULE_REMOTE: u32 = 1 << 0;
const RULE_DECODE: u32 = 1 << 1;
const RULE_DISK: u32 = 1 << 3;
const RULE_DELETE: u32 = 1 << 5;

/// Programs named on the line. A scanner whose program is absent cannot
/// match, so it is not run. A command word left as `$name` can be any
/// program, and then every scanner runs.
fn rule_mask(argv: &[String]) -> u32 {
    let mut mask = 0u32;
    for (cmd, _) in ended_commands(argv) {
        let head = peel_cd_command_word(&cmd);
        if let Some(w) = head.first() {
            let b = base_of(w);
            if unresolved(b) {
                return u32::MAX;
            }
            mask |= rule_bits(b);
        }
        for w in &cmd {
            if w.contains("/dev/") {
                mask |= RULE_DISK;
            }
            if w.contains("$(") || w.contains('`') || w.contains("<(") {
                mask |= rule_subst_bits(w);
            }
            // `timeout 30 curl` names curl in its own word, not as the head.
            mask |= rule_bits(piece_base(w));
            if !w.contains(char::is_whitespace) {
                continue;
            }
            for p in w.split(char::is_whitespace) {
                if !p.is_empty() {
                    mask |= rule_bits(piece_base(p));
                }
            }
        }
    }
    mask
}

fn rule_bits(b: &str) -> u32 {
    let mut mask = 0u32;
    if FETCHERS.contains(&b) {
        mask |= RULE_REMOTE;
    }
    if DECODERS.contains(&b) {
        mask |= RULE_DECODE;
    }
    if matches!(b, "rm" | "srm" | "wipe" | "rmdir" | "unlink" | "shred")
        || TRASHERS.contains(&b)
        || b == "gio"
    {
        mask |= RULE_DELETE;
    }
    if b == "dd"
        || b == "cryptsetup"
        || b.starts_with("mkfs")
        || DISK_WRITERS.iter().any(|(n, _)| *n == b)
    {
        mask |= RULE_DISK;
    }
    mask
}

/// A download or a decoder inside `$(...)`, backticks or `<(...)`.
fn rule_subst_bits(w: &str) -> u32 {
    let mut mask = 0u32;
    for name in FETCHERS {
        if subst_names_tool(w, name) {
            mask |= RULE_REMOTE;
        }
    }
    for name in DECODERS {
        if subst_names_tool(w, name) {
            mask |= RULE_DECODE;
        }
    }
    mask
}

fn subst_names_tool(w: &str, name: &str) -> bool {
    let mut rest = w;
    while let Some(i) = rest.find(['$', '`', '<']) {
        let after = &rest[i..];
        let body = if let Some(b) = after
            .strip_prefix("$(")
            .or_else(|| after.strip_prefix("<("))
        {
            b
        } else if let Some(b) = after.strip_prefix('`') {
            b
        } else {
            rest = &rest[i + 1..];
            continue;
        };
        if let Some(tail) = body.strip_prefix(name) {
            let boundary = tail.chars().next().unwrap_or(' ');
            if !boundary.is_ascii_alphanumeric() && boundary != '_' && boundary != '-' {
                return true;
            }
        }
        rest = &rest[i + 1..];
    }
    false
}

fn host_argv_rules(argv: &[String], moved: bool, bound: &Scratch) -> Checked {
    if argv.is_empty() {
        // A file write with no command words is not a shell action.
        return Checked {
            decision: Decision::Allow,
            code: PolicyReason::Unspecified,
            token: Cow::Borrowed("allow"),
        };
    }
    // A privilege word is a warning. The command after it is judged on
    // its own, so `sudo rm -rf /home` is still the delete.
    if let Some(inner) = peel_privilege(argv) {
        if inner.is_empty() {
            return open::warn_checked("sudo");
        }
        let hit = host_argv_rules(&inner, moved, bound);
        if hit.decision != Decision::Allow || open::noted(&hit.token).is_some() {
            return hit;
        }
        return open::warn_checked("sudo");
    }
    let base = base_of(&argv[0]);
    let mask = rule_mask(argv);
    let mut notes: Vec<String> = Vec::new();
    // Irreversible hits deny. Everything else is a warning.
    if mask & RULE_REMOTE != 0 && remote_exec(argv) {
        return deny_shell(PolicyReason::ShellRemoteExec, "curl-pipe-shell");
    }
    if mask & RULE_REMOTE != 0 && python_pipe(argv) {
        notes.push("curl-pipe-shell".to_string());
    }
    if mask & RULE_DELETE != 0 && recursive_delete_off_tmp(argv, moved, bound) {
        return deny_shell(PolicyReason::ShellDangerousRunner, "rm-rf-outside-tmp");
    }
    if interpreter_rmtree(argv) || deletes_a_root_tree(argv) {
        return deny_shell(PolicyReason::ShellDangerousRunner, "rm-rf-outside-tmp");
    }
    if let Some(token) = harm::around_rm(argv) {
        if token != "feeder-rm" && find_delete_outside(argv, bound) {
            return deny_shell(PolicyReason::ShellDangerousRunner, token);
        }
        notes.push(token.to_string());
    }
    if let Some(token) = harm::tree_outside(argv, bound.work.as_deref()) {
        if token == "rsync-delete-outside" {
            return deny_shell(PolicyReason::ShellDangerousRunner, token);
        }
        notes.push(token.to_string());
    }
    if base == "git-filter-repo" || base == "git-filter-branch" {
        notes.push("git-history-rewrite".to_string());
    }
    // A command word left as `$g` or `${GIT}` could be git: the git rules
    // read it as git rather than let the variable hide the call.
    if base == "git" || unresolved(base) {
        if let Some(hit) = git_dangerous(argv) {
            match hit {
                GitHit::Deny(token) => {
                    return deny_shell(PolicyReason::ShellGitDangerous, token);
                }
                GitHit::Warn(token) => notes.push(token.to_string()),
            }
        } else if let Some(token) = harm::git_lost_work(argv) {
            return Checked {
                decision: Decision::Prompt,
                code: PolicyReason::HighRiskPrompt,
                token: Cow::Borrowed(token),
            };
        }
    }
    if is_privilege(base) || argv.iter().any(|t| is_privilege(base_of(t))) {
        notes.push("sudo".to_string());
    }
    if mask & RULE_DECODE != 0 && decoded_exec(argv) {
        notes.push("decoded-pipe-shell".to_string());
    }
    if let Some(hit) = seat_guard_denial(argv, bound.root.as_deref()) {
        notes.push(hit.token.into_owned());
    }
    if mask & RULE_DISK != 0 && raw_disk(argv) {
        notes.push("raw-disk".to_string());
    }
    if let Some(c) = ask::credential_mention(argv) {
        return c;
    }
    if let Some(note) = notes.into_iter().next() {
        return open::warn_checked(&note);
    }
    Checked {
        decision: Decision::Allow,
        code: PolicyReason::Unspecified,
        token: Cow::Borrowed("allow"),
    }
}

/// The argv after a leading `sudo`, `doas`, `su`, `pkexec`, or `run0`
/// and the flags that belong to it. `None` when the line does not start
/// that way.
fn peel_privilege(argv: &[String]) -> Option<Vec<String>> {
    let mut cur = argv.to_vec();
    let mut saw = false;
    loop {
        let mut i = 0;
        while i < cur.len() && is_assignment(&cur[i]) {
            i += 1;
        }
        if !cur.get(i).is_some_and(|w| is_privilege(base_of(w))) {
            break;
        }
        saw = true;
        i += 1;
        while i < cur.len() {
            let a = cur[i].as_str();
            if a == "--" {
                i += 1;
                break;
            }
            if a.starts_with('-') && a != "-" {
                let valued = matches!(
                    a,
                    "-u" | "-g"
                        | "-h"
                        | "-p"
                        | "-C"
                        | "-D"
                        | "-R"
                        | "-T"
                        | "-a"
                        | "--user"
                        | "--group"
                        | "--host"
                        | "--prompt"
                        | "--chdir"
                        | "--role"
                        | "--type"
                        | "--close-from"
                ) && !a.contains('=');
                i += if valued { 2 } else { 1 };
                continue;
            }
            break;
        }
        if i > cur.len() {
            i = cur.len();
        }
        cur = cur[i..].to_vec();
    }
    saw.then_some(cur)
}

fn deny_shell(code: PolicyReason, token: &'static str) -> Checked {
    Checked {
        decision: Decision::Deny,
        code,
        token: Cow::Borrowed(token),
    }
}

/// A `find` delete whose starting point is outside the work tree and
/// outside `/tmp`. No starting point is the current directory. A feeder
/// whose paths are not on the line is not this.
fn find_delete_outside(argv: &[String], bound: &Scratch) -> bool {
    let cwd = bound
        .root
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    for cmd in commands(argv) {
        let Some(head_at) = cmd.iter().position(|w| base_of(w) == "find") else {
            continue;
        };
        let mut starts = Vec::new();
        for w in cmd.iter().skip(head_at + 1).copied() {
            if matches!(w, "-H" | "-L" | "-P") {
                continue;
            }
            if w.starts_with('-') || matches!(w, "(" | "!" | ";") {
                break;
            }
            starts.push(w);
        }
        if starts.is_empty() {
            starts.push(".");
        }
        for start in starts {
            if under_tmp(start) || (start == "." && path_under_tmp(&cwd)) {
                continue;
            }
            if path_in_work(start, &cwd) {
                continue;
            }
            let relative = !start.starts_with('/')
                && !start.starts_with('~')
                && !start.starts_with('$')
                && !start.contains("..");
            if relative && (open::work_tree(&cwd).is_some() || path_under_tmp(&cwd)) {
                continue;
            }
            return true;
        }
    }
    false
}

fn path_under_tmp(path: &std::path::Path) -> bool {
    let text = path.to_string_lossy();
    under_tmp(&text) || text == "/tmp" || text.starts_with("/tmp/")
}

/// `p` lands inside the git work tree that contains `cwd`. A missing
/// path is judged by the spelling. A variable, a glob, or `~` is not.
pub(crate) fn path_in_work(p: &str, cwd: &std::path::Path) -> bool {
    let raw = unquote(p).trim_end_matches('/');
    if raw.is_empty() || raw.contains(['$', '`', '*', '?', '[', '~']) {
        return false;
    }
    let Some(top) = open::work_tree(cwd) else {
        return false;
    };
    let abs = if raw.starts_with('/') {
        std::path::PathBuf::from(lexical_norm(raw))
    } else {
        std::path::PathBuf::from(lexical_norm(&format!(
            "{}/{}",
            lexical_norm(&cwd.to_string_lossy()),
            raw.trim_start_matches("./")
        )))
    };
    if !abs.starts_with(&top) {
        return false;
    }
    if abs.exists() {
        return disk::on_disk(&abs).starts_with(&top);
    }
    true
}
