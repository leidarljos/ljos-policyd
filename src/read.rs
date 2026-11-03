//! Compound commands, the shell each command runs in, and the values `read`
//! and `mapfile` take.

use super::{
    base_of, command_after_keywords, commands, ended_owned, fed_sensitive, here_string,
    is_assignment, is_name, may_set, may_set_lastpipe, mentions, producer_text, split_env_strings,
    under_tmp, unwrap_wrappers,
};

/// Which compound a command word opens or closes. `do` and `then` are
/// the body, not another compound.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nest {
    Loop,
    If,
    Case,
    Brace,
    Paren,
}

fn nest_event(cmd: &[String]) -> Option<(bool, Nest)> {
    let w = cmd.iter().map(String::as_str).find(|w| !is_assignment(w))?;
    Some(match w {
        "while" | "until" | "for" | "select" => (true, Nest::Loop),
        "if" => (true, Nest::If),
        "case" => (true, Nest::Case),
        "{" => (true, Nest::Brace),
        "(" => (true, Nest::Paren),
        "done" => (false, Nest::Loop),
        "fi" => (false, Nest::If),
        "esac" => (false, Nest::Case),
        "}" => (false, Nest::Brace),
        ")" => (false, Nest::Paren),
        _ => return None,
    })
}

fn nest_bump(kind: Nest, open: bool, depth: &mut [i32; 5]) {
    let i = match kind {
        Nest::Loop => 0,
        Nest::If => 1,
        Nest::Case => 2,
        Nest::Brace => 3,
        Nest::Paren => 4,
    };
    if open {
        depth[i] += 1;
    } else if depth[i] > 0 {
        depth[i] -= 1;
    }
}

/// Whether `cmd` is a `case` arm's patterns and not the command the arm
/// runs. The `|` after it separates patterns (`case z in a | b)`), so it
/// is not the pipeline a `{ printf | read` opener starts.
fn pure_case_pattern(cmd: &[String]) -> bool {
    let closes = |p: &str| {
        p == ")"
            || (p.ends_with(')') && p.matches(')').count() > p.matches('(').count())
            || (p.starts_with('(') && !p.starts_with("((") && p.ends_with(')'))
    };
    let mut saw_case = false;
    let mut await_in = false;
    let mut pattern = false;
    let mut body = false;
    for (wi, w) in cmd.iter().enumerate() {
        let w = w.as_str();
        if !saw_case {
            if is_assignment(w) {
                continue;
            }
            if w != "case" {
                return false;
            }
            saw_case = true;
            await_in = true;
            continue;
        }
        if pattern {
            if closes(w) {
                pattern = false;
                if wi + 1 < cmd.len() {
                    body = true;
                }
            }
            continue;
        }
        if w == "in" && await_in {
            await_in = false;
            pattern = true;
        }
    }
    saw_case && pattern && !body
}

/// The command that closes the compound `ended[i]` opens, or `i` when
/// it is a simple command. The scan stays inside `[i, hi)`.
fn compound_end(ended: &[(Vec<String>, String)], i: usize, hi: usize) -> usize {
    let Some((true, kind)) = nest_event(&ended[i].0) else {
        return i;
    };
    let mut depth = [0; 5];
    nest_bump(kind, true, &mut depth);
    for (j, cmd) in ended.iter().enumerate().take(hi).skip(i + 1) {
        if let Some((open, k)) = nest_event(&cmd.0) {
            nest_bump(k, open, &mut depth);
        }
        if depth.iter().all(|d| *d == 0) {
            return j;
        }
    }
    hi.saturating_sub(1)
}

/// The shell each command writes. A pipeline stage is its own shell.
/// The last stage is this shell only after `lastpipe` may be on. A
/// `(...)` group and a command ended by `&` are their own shell too.
/// The body of `while` stays in the shell that runs the `while`.
/// A compound opener is the first stage when its separator is `|`
/// (`{ printf | read`), so that stage's successor stays in its own shell.
fn command_shells(ended: &[(Vec<String>, String)]) -> Vec<u32> {
    let n = ended.len();
    let mut shells = vec![0u32; n];
    let mut lastpipe = vec![false; n];
    let mut on = false;
    for (i, (cmd, _)) in ended.iter().enumerate() {
        lastpipe[i] = on;
        let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
        if may_set_lastpipe(&refs) {
            on = true;
        }
    }
    let mut next = 1u32;
    walk_shells(ended, 0, n, 0, &mut shells, &mut next, &lastpipe);
    shells
}

fn walk_shells(
    ended: &[(Vec<String>, String)],
    lo: usize,
    hi: usize,
    shell: u32,
    shells: &mut [u32],
    next: &mut u32,
    lastpipe: &[bool],
) {
    let mut i = lo;
    while i < hi {
        let end = compound_end(ended, i, hi).min(hi.saturating_sub(1));
        // The first command of a compound body still has a separator.
        // The opener is the command before it (`{ printf`, `if printf`,
        // `while printf`, `case … printf`), and a trailing `|` is the
        // pipeline that command started. Dropping it put `read` back in
        // the shell that follows the group. A `|` that only splits `case`
        // patterns is not a pipeline. The top of the line has nothing
        // before it. `!`, `time` and `&&` / `||` do not open a body, so
        // their `|` is already the separator of the command it follows.
        let sep_before = if i > lo || (lo > 0 && i == lo && !pure_case_pattern(&ended[i - 1].0)) {
            ended[i - 1].1.as_str()
        } else {
            ""
        };
        let sep_after = ended[end].1.as_str();
        let in_pipe = sep_before == "|" || sep_after == "|";
        let last = in_pipe && sep_after != "|";
        let paren = nest_event(&ended[i].0).is_some_and(|(open, k)| open && k == Nest::Paren);
        let fresh = paren || sep_after == "&" || (in_pipe && !(last && lastpipe[i]));
        let stage = if fresh {
            let id = *next;
            *next += 1;
            id
        } else {
            shell
        };
        shells[i] = stage;
        if end > i {
            shells[end] = stage;
            if i + 1 < end {
                walk_shells(ended, i + 1, end, stage, shells, next, lastpipe);
            }
        }
        i = end + 1;
    }
}

/// A `read` at `set_at` is the value a later command sees. It has to
/// run in that command's shell, and before it. The last stage of a
/// pipeline is a subshell until `lastpipe` is on, so it does not.
fn read_reaches(shells: &[u32], set_at: usize, use_at: usize) -> bool {
    set_at < use_at && shells.get(set_at) == shells.get(use_at)
}

struct ReadHit {
    name: String,
    /// The field this name took from each line. The last name keeps the
    /// rest of the line. `None` when that text is not on the line.
    values: Option<Vec<String>>,
    at: usize,
}

fn read_command(cmd: &[String]) -> Option<Vec<String>> {
    let owned = split_env_strings(cmd).into_owned();
    let run = unwrap_wrappers(&owned).0;
    let refs: Vec<&str> = run.iter().map(String::as_str).collect();
    let tail: Vec<String> = command_after_keywords(&refs)
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    tail.first()
        .is_some_and(|w| matches!(base_of(w), "read" | "mapfile" | "readarray"))
        .then_some(tail)
}

pub(crate) fn read_text(
    ended: &[(Vec<String>, String)],
    i: usize,
    cmd: &[String],
) -> Option<String> {
    if let Some(p) = i.checked_sub(1).filter(|&p| ended[p].1 == "|") {
        producer_text(&ended[p].0)
    } else {
        here_string(cmd)
    }
}

fn read_lines(text: &str) -> Vec<String> {
    // A trailing newline ends the last record. It is not another line.
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() {
        return vec![String::new()];
    }
    body.split('\n').map(|s| s.to_string()).collect()
}

/// `IFS` after the pure assignments this shell has run. A prefix on
/// `read` does not remain: `read` is not a special builtin.
fn shell_ifs(ended: &[(Vec<String>, String)], shells: &[u32], at: usize) -> String {
    let mut ifs = " \t\n".to_string();
    let Some(&shell) = shells.get(at) else {
        return ifs;
    };
    for (i, (cmd, _)) in ended.iter().enumerate().take(at) {
        if shells.get(i) != Some(&shell) || cmd.is_empty() {
            continue;
        }
        if !cmd.iter().all(|w| is_assignment(w)) {
            continue;
        }
        for w in cmd {
            apply_ifs_assign(w, &mut ifs);
        }
    }
    ifs
}

/// `IFS=` replaces the value. `IFS+=` appends. Anything else is left.
fn apply_ifs_assign(w: &str, ifs: &mut String) -> bool {
    if let Some(v) = w.strip_prefix("IFS=") {
        *ifs = v.to_string();
        true
    } else if let Some(v) = w.strip_prefix("IFS+=") {
        ifs.push_str(v);
        true
    } else {
        false
    }
}

/// The `IFS` `read` splits on: this shell's value, then a prefix
/// assignment on the `read` itself (`while IFS=: read x y`).
fn read_input_ifs(
    ended: &[(Vec<String>, String)],
    shells: &[u32],
    at: usize,
    cmd: &[String],
) -> String {
    let mut ifs = shell_ifs(ended, shells, at);
    let run = unwrap_wrappers(cmd).0;
    let Some(head) = run.first() else {
        return ifs;
    };
    if !matches!(base_of(head), "read" | "mapfile" | "readarray") {
        return ifs;
    }
    if let Some(read_at) = cmd.iter().position(|w| std::ptr::eq(w, head)) {
        for w in &cmd[..read_at] {
            apply_ifs_assign(w, &mut ifs);
        }
    }
    ifs
}

/// One field per name, the way `read` assigns them. Leading and trailing
/// IFS whitespace is dropped. Each name but the last takes the text up to
/// the next IFS character; a whitespace delimiter swallows the run after
/// it, and any other delimiter is one character. The last name keeps the
/// rest, delimiters included.
fn read_fields(line: &str, nvars: usize, ifs: &str) -> Vec<String> {
    if nvars == 0 {
        return Vec::new();
    }
    let ws: Vec<char> = ifs.chars().filter(|c| c.is_whitespace()).collect();
    let is_ws = |c: char| ws.contains(&c);
    let is_ifs = |c: char| ifs.contains(c);
    let chars: Vec<char> = line.chars().collect();
    let mut end = chars.len();
    while end > 0 && is_ws(chars[end - 1]) {
        end -= 1;
    }
    let mut i = 0;
    while i < end && is_ws(chars[i]) {
        i += 1;
    }
    let mut fields = Vec::with_capacity(nvars);
    for var_i in 0..nvars {
        if var_i + 1 == nvars {
            fields.push(chars[i..end].iter().collect());
            break;
        }
        if i >= end {
            fields.push(String::new());
            continue;
        }
        let start = i;
        while i < end && !is_ifs(chars[i]) {
            i += 1;
        }
        fields.push(chars[start..i].iter().collect());
        if i >= end {
            continue;
        }
        if is_ws(chars[i]) {
            while i < end && is_ws(chars[i]) {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    fields
}

fn read_hits(ended: &[(Vec<String>, String)]) -> Vec<ReadHit> {
    let shells = command_shells(ended);
    let mut out = Vec::new();
    for (i, (cmd, _)) in ended.iter().enumerate() {
        let Some(tail) = read_command(cmd) else {
            continue;
        };
        let names = read_var_names(&tail);
        if names.is_empty() {
            continue;
        }
        let cols = read_text(ended, i, cmd).map(|t| {
            let ifs = read_input_ifs(ended, &shells, i, cmd);
            let mut cols = vec![Vec::new(); names.len()];
            for line in read_lines(&t) {
                let fields = read_fields(&line, names.len(), &ifs);
                for (k, field) in fields.into_iter().enumerate() {
                    if let Some(col) = cols.get_mut(k) {
                        col.push(field);
                    }
                }
            }
            cols
        });
        for (k, name) in names.into_iter().enumerate() {
            out.push(ReadHit {
                name,
                values: cols.as_ref().map(|c| c.get(k).cloned().unwrap_or_default()),
                at: i,
            });
        }
    }
    out
}

/// Names a `read` takes from a `printf` or `echo` of paths under `/tmp`,
/// when that `read` runs in the same shell and before the use, and the
/// names a reaching `read` sets to something else. A name a later
/// command still holds from an earlier assignment is in neither.
pub(crate) fn shown_temp_reads(argv: &[String]) -> (Vec<String>, Vec<String>) {
    if !mentions(argv, &["read", "mapfile", "readarray"]) {
        return (Vec::new(), Vec::new());
    }
    let ended = ended_owned(argv);
    let shells = command_shells(&ended);
    let hits = read_hits(&ended);
    let mut good = Vec::new();
    let mut bad = Vec::new();
    let mut uncovered = false;
    for (use_at, (cmd, _)) in ended.iter().enumerate() {
        let owned = split_env_strings(cmd).into_owned();
        let run = unwrap_wrappers(&owned).0.to_vec();
        if !fed_sensitive(&run) {
            continue;
        }
        let names: Vec<String> = hits
            .iter()
            .map(|h| h.name.clone())
            .filter(|n| run.iter().any(|w| expands(w, n)))
            .collect();
        let mut seen = Vec::new();
        for name in names {
            if seen.iter().any(|s| s == &name) {
                continue;
            }
            seen.push(name.clone());
            let reaching = hits
                .iter()
                .filter(|h| h.name == name && read_reaches(&shells, h.at, use_at));
            let Some(hit) = reaching.max_by_key(|h| h.at) else {
                // This use still has the assignment. A temp from another
                // shell must not cover it.
                uncovered = true;
                continue;
            };
            let temp = hit
                .values
                .as_ref()
                .is_some_and(|lines| !lines.is_empty() && lines.iter().all(|l| under_tmp(l)));
            if temp {
                good.push(name);
            } else {
                bad.push(name);
            }
        }
    }
    if uncovered {
        good.clear();
    }
    good.retain(|n| !bad.iter().any(|b| b == n));
    bad.retain(|n| good.iter().all(|g| g != n));
    (good, bad)
}

fn read_var_names(run: &[String]) -> Vec<String> {
    let all = read_names(run);
    let named: Vec<String> = all
        .iter()
        .filter(|n| n.as_str() != "REPLY" && n.as_str() != "MAPFILE")
        .cloned()
        .collect();
    if named.is_empty() {
        all
    } else {
        named
    }
}

/// The command string a `mapfile` or `readarray` call runs with `-C`,
/// alone or at the end of a cluster, or glued (`-Ccb`).
pub(crate) fn mapfile_callback(run: &[String]) -> Option<&str> {
    if !matches!(base_of(run.first()?), "mapfile" | "readarray") {
        return None;
    }
    let mut words = run[1..].iter().map(String::as_str);
    while let Some(a) = words.next() {
        let flags = a.strip_prefix('-').filter(|f| !f.is_empty() && *f != "-")?;
        for (k, c) in flags.char_indices() {
            if "dnOsucC".contains(c) {
                let rest = &flags[k + 1..];
                let value = if rest.is_empty() { words.next()? } else { rest };
                if c == 'C' {
                    return Some(value);
                }
                break;
            }
        }
    }
    None
}

/// The variables a `read`, `mapfile` or `readarray` call fills: its
/// name operands, or `REPLY` and `MAPFILE` when it names none.
fn read_names(run: &[String]) -> Vec<String> {
    let Some((head, args)) = run.split_first() else {
        return Vec::new();
    };
    let (default, valued): (_, &[&str]) = match base_of(head) {
        "read" => ("REPLY", &["-d", "-n", "-N", "-p", "-t", "-u", "-i"]),
        "mapfile" | "readarray" => ("MAPFILE", &["-d", "-n", "-O", "-s", "-u", "-C", "-c"]),
        _ => return Vec::new(),
    };
    let mut out = vec![default.to_string()];
    let mut words = args.iter();
    while let Some(a) = words.next() {
        if valued.contains(&a.as_str()) {
            words.next();
        } else if is_name(a) {
            out.push(a.clone());
        }
    }
    out
}

/// Whether the word `w` expands the variable `name`: `$name` or
/// `${name...}` with no more of a name after it.
pub(crate) fn expands(w: &str, name: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    ["$", "${", "${!"].iter().any(|open| {
        w.match_indices(&format!("{open}{name}"))
            .any(|(i, m)| !w[i + m.len()..].starts_with(ident))
    })
}

/// The script `trap` runs on each signal it names: its first operand,
/// past `-l`, `-p` and `--`.
pub(crate) fn trap_action<S: AsRef<str>>(run: &[S]) -> Option<&str> {
    let (first, args) = run.split_first()?;
    if base_of(first.as_ref()) != "trap" {
        return None;
    }
    args.iter()
        .map(AsRef::as_ref)
        .find(|a| !(a.starts_with('-') && a.len() > 1))
}

/// `w` with each `$NAME` and `${NAME}` whose value the line shows read as
/// that value: `names` holds one value for it, and no other command on
/// `argv` may set it. Any other is left as written.
pub(crate) fn with_names(w: &str, names: &[(String, String)], argv: &[String]) -> String {
    let known = |name: &str| {
        let mut vals = names.iter().filter(|(k, _)| k == name).map(|(_, v)| v);
        let v = vals.next()?;
        let elsewhere = commands(argv)
            .iter()
            .filter(|c| !c.iter().all(|w| is_assignment(w)))
            .any(|c| c.iter().any(|w| may_set(w, name)));
        (vals.all(|o| o == v) && !elsewhere).then_some(v)
    };
    let mut out = String::new();
    let mut rest = w;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let (name, len) = match rest.strip_prefix('{') {
            Some(b) => b.find('}').map_or(("", 0), |j| (&b[..j], j + 2)),
            None => {
                let n = rest
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                (&rest[..n], n)
            }
        };
        match known(name).filter(|_| !name.is_empty()) {
            Some(v) => {
                out.push_str(v);
                rest = &rest[len..];
            }
            None => out.push('$'),
        }
    }
    out.push_str(rest);
    out
}
