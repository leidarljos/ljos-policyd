//! Where each command on a line runs: `cd`, `pushd`, `~`, `env -C`, and the
//! paths the line made.

use std::borrow::Cow;

use super::{
    base_of, brace_expands, case_head, commands, ended_commands, inner_commands, is_assignment,
    keyword_at, operands, output_target, peeled, plain_relative, quoted_body, shell_script,
    shell_words, KEYWORDS, MAX_DEPTH,
};

/// How many directories the commands after a `cd` that may have failed
/// are read in. Past this, a further `cd` leaves the ones it drops
/// untracked.
const UNTRACKED: &str = "/\0";

/// A `cd` or `pushd` whose target the line does not resolve. It is not a
/// directory the walk can name, so a runner there is refused as
/// [`UNTRACKED`] is, but it is not the same loss: a relative `source` is
/// still read from the last directory the walk knew, when that file is
/// there at check time.
pub(crate) fn is_untracked(d: &std::path::Path) -> bool {
    d.as_os_str().as_encoded_bytes().contains(&0)
}

/// The directories `cd` or `pushd` with `args` may enter from `dir`: a
/// path, `~` or `~/path` from `home`, the `HOME` of `set` for a bare `cd`,
/// `old` for `-`, and for a relative path whose first part is not `.` or
/// `..`, each entry of the `CDPATH` of `set` that holds it. `set` holds
/// the command's own assignments, which `~` does not see. A bare `pushd`
/// or a stack index names nothing, so the caller keeps the directory it
/// has; a path the line does not show, through a variable, a substitution
/// or `~user`, may be any. That is [`UNKNOWN`]: not a directory the walk
/// can name, and not the same as losing the one it had.
fn logical(path: &std::path::Path) -> std::path::PathBuf {
    if is_untracked(path) {
        return path.to_path_buf();
    }
    let mut out = std::path::PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// Whether `a` is a `pushd` stack index, `+N` or `-N`.
fn stack_index(a: &str) -> bool {
    a.len() > 1 && a.starts_with(['+', '-']) && a[1..].bytes().all(|c| c.is_ascii_digit())
}

/// `stack` after `pushd` brings entry `index` to the top: `+N` counts from
/// the top and `-N` from the bottom, and a bare `pushd` swaps the top two.
/// None when the stack is too short. An entry the index counts past may
/// be missing, so the one it names may be another and the top may then be
/// any directory on the stack.
fn home_from(home: Option<&str>, dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let h = home.filter(|h| !h.is_empty())?;
    Some(if h.contains(['$', '`']) {
        UNTRACKED.into()
    } else {
        dir.join(h)
    })
}

/// What `~` expands to with `HOME` at `home`: that value, or with `HOME`
/// unset the home in the user's passwd entry, as bash takes it. A user
/// with no entry names no directory the line shows.
pub(crate) fn tilde_home(home: Option<&str>) -> Cow<'_, str> {
    if let Some(h) = home {
        return Cow::Borrowed(h);
    }
    // SAFETY: getpwuid returns null or a record that stays valid until the
    // next lookup, and pw_dir is copied out before this returns.
    let dir = unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() || (*pw).pw_dir.is_null() {
            return Cow::Borrowed("$");
        }
        std::ffi::CStr::from_ptr((*pw).pw_dir)
    };
    Cow::Owned(dir.to_string_lossy().into_owned())
}

/// Where the path word `to` lands from `dir`: `~` at its head as
/// [`tilde_home`] reads it, `$HOME` and `${HOME}` from `home`, either
/// from `/` when it is unset or empty and a path follows, `~login`
/// from the password database, `~+` at `dir`, anything else joined onto
/// `dir`. Another variable or a substitution names no directory the line
/// shows, and `~-` or a stack entry (`~1`) one the line does not follow.
fn path_from(to: &str, dir: &std::path::Path, home: Option<&str>) -> Option<std::path::PathBuf> {
    // `"$HOME"` is `$HOME`. The quotes only say the expansion is one word.
    let to = quoted_body(to);
    // `{sub,}`, `su?` and `su[b]` are not directories. The shell expands
    // them before `cd`, and the walk does not follow that expansion.
    if brace_expands(to) || to.contains(['*', '?', '[']) {
        return None;
    }
    let (head, rest) = to.split_once('/').unwrap_or((to, ""));
    if rest.contains(['$', '`']) {
        return None;
    }
    let base = match head {
        "~" | "$HOME" | "${HOME}" => {
            let h = if head == "~" {
                Some(tilde_home(home))
            } else {
                home.map(Cow::Borrowed)
            };
            match home_from(h.as_deref(), dir) {
                Some(h) => h,
                // Unset or empty, it leaves the rest of the word, and a
                // word of it alone leaves the line where it is.
                None if to.contains('/') => "/".into(),
                None => dir.to_path_buf(),
            }
        }
        "~+" => dir.to_path_buf(),
        _ if head.contains(['$', '`']) => return None,
        _ => match head.strip_prefix('~') {
            Some(n) if n.starts_with(['+', '-']) || n.bytes().all(|b| b.is_ascii_digit()) => {
                UNTRACKED.into()
            }
            Some(name) => user_home(name).unwrap_or_else(|| dir.join(head)),
            None => return Some(dir.join(to)),
        },
    };
    Some(base.join(rest))
}

/// The home directory of the login `name` in the password database.
#[cfg(unix)]
fn user_home(name: &str) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: an all-zero passwd is valid, and getpwnam_r fills it with
    // pointers into `buf`, which outlives every read of them below.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
    Some(std::ffi::OsStr::from_bytes(dir.to_bytes()).into())
}

#[cfg(not(unix))]
fn user_home(_: &str) -> Option<std::path::PathBuf> {
    None
}

/// What the `env` option word `a`, with `next` after it, does: how many
/// words it takes, and the letter and value of the one it holds that
/// takes a value (`-u NAME`, `-C DIR`, `-S STRING`, or the long forms).
/// Short options cluster, and the first that takes a value takes the
/// rest of the word, or the next word when nothing is left: `-iC DIR`,
/// `-iCDIR`, `-uVAR`. A long option may be cut to any prefix that names
/// only it: `--ch DIR`.
pub(crate) fn env_flag<'a>(a: &'a str, next: Option<&'a str>) -> (usize, Option<(char, &'a str)>) {
    const LONG: [(&str, Option<char>); 12] = [
        ("block-signal", None),
        ("chdir", Some('C')),
        ("debug", None),
        ("default-signal", None),
        ("help", None),
        ("ignore-environment", None),
        ("ignore-signal", None),
        ("list-signal-handling", None),
        ("null", None),
        ("split-string", Some('S')),
        ("unset", Some('u')),
        ("version", None),
    ];
    if let Some(long) = a.strip_prefix("--") {
        let (name, value) = long
            .split_once('=')
            .map_or((long, None), |(n, v)| (n, Some(v)));
        let named: Vec<_> = LONG.iter().filter(|(n, _)| n.starts_with(name)).collect();
        let [&(_, Some(key))] = named[..] else {
            return (1, None);
        };
        return match value {
            Some(v) => (1, Some((key, v))),
            None => (2, next.map(|v| (key, v))),
        };
    }
    let flags = a.strip_prefix('-').unwrap_or(a);
    for (i, c) in flags.char_indices() {
        if matches!(c, 'u' | 'C' | 'S') {
            let rest = &flags[i + 1..];
            return if rest.is_empty() {
                (2, next.map(|v| (c, v)))
            } else {
                (1, Some((c, rest)))
            };
        }
    }
    (1, None)
}

/// The directory a command runs in from `dir` after the runner words
/// `wrappers` in front of it: the one an `env` `-C` or `--chdir` names, in
/// any form [`env_flag`] reads, with `~` from `home`, or `dir`. The last
/// of an `env`'s flags wins, from where that `env` starts.
pub(crate) fn peel_cd_command_word<'a>(mut words: &'a [&'a str]) -> &'a [&'a str] {
    // After `command` or `builtin` no word is a keyword: `command time`
    // runs the time program.
    let mut looked_up = false;
    loop {
        let Some((w, rest)) = words.split_first() else {
            return words;
        };
        let head = case_head(words);
        if head > 0 && !looked_up {
            words = &words[head..];
            continue;
        }
        if is_assignment(w) {
            words = rest;
            continue;
        }
        match base_of(w) {
            "command" => {
                looked_up = true;
                words = rest;
                while let Some((a, tail)) = words.split_first() {
                    if *a == "--" {
                        words = tail;
                        break;
                    }
                    if *a == "-p" {
                        words = tail;
                        continue;
                    }
                    break;
                }
            }
            "builtin" => {
                looked_up = true;
                words = rest;
                if let Some((a, tail)) = words.split_first() {
                    if *a == "--" {
                        words = tail;
                    }
                }
            }
            // `/usr/bin/time` is a program, and runs `cd` in a child.
            "time" if *w != "time" || looked_up => return words,
            k if KEYWORDS.contains(&k) && !looked_up => {
                words = rest;
                if k == "time" && words.first() == Some(&"-p") {
                    words = &words[1..];
                }
            }
            _ => return words,
        }
    }
}

/// A `cd`, `pushd` or `popd` that can leave the working tree: an absolute
/// target, `~`, `-`, `..`, a variable, or none at all (home).
pub(crate) fn leaves_tree(argv: &[String], depth: usize) -> bool {
    let here = commands(argv).iter().any(|cmd| {
        let b = base_of(cmd[0]);
        if b == "popd" {
            return true;
        }
        if b != "cd" && b != "pushd" {
            return false;
        }
        match cmd[1..].iter().find(|a| !a.starts_with('-') || **a == "-") {
            Some(t) => !plain_relative(t),
            None => true,
        }
    });
    here || (depth < MAX_DEPTH
        && inner_commands(argv)
            .iter()
            .any(|inner| inner.as_slice() != argv && leaves_tree(inner, depth + 1)))
}

/// The directory a command on the line runs in, and the paths the line
/// has already created there. `open` is a created path whose name the
/// line does not show: a later relative parent may be that path.
pub(crate) struct Place {
    root: Option<std::path::PathBuf>,
    made: Vec<std::path::PathBuf>,
    open: bool,
    /// A `cd` to a path that is not there, and that the line did not
    /// make, leaves the directory unknown: it may be made in a way the
    /// walk does not read.
    strict: bool,
}

impl Place {
    pub(crate) fn new(root: Option<std::path::PathBuf>) -> Self {
        Self {
            root,
            made: Vec::new(),
            open: false,
            strict: false,
        }
    }

    /// Move for a literal `cd` or `pushd`, then record what this command
    /// creates. A pipeline stage does not move the shell that follows it.
    pub(crate) fn finish(&mut self, cmd: &[&str], in_pipe: bool) {
        if !in_pipe {
            self.apply_cd(cmd);
        }
        self.note_created(cmd);
    }

    fn apply_cd(&mut self, cmd: &[&str]) {
        let (name, args) = command_verb(cmd);
        if name == "popd" {
            // The stack below this line is not the one `popd` reads.
            // `-n` only rotates that stack and leaves the directory.
            if !args.iter().any(|a| a == "-n") {
                self.root = None;
            }
            return;
        }
        if name != "cd" && name != "pushd" {
            return;
        }
        // `pushd -n` changes the stack and leaves the directory.
        if name == "pushd" && args.iter().any(|a| a == "-n") {
            return;
        }
        let args: Vec<&str> = args
            .iter()
            .filter(|a| a.as_str() != "-n")
            .map(String::as_str)
            .collect();
        let target = args
            .iter()
            .copied()
            .find(|a| !a.starts_with('-') || *a == "-");
        if name == "pushd" && target.is_none_or(stack_index) {
            self.root = None;
            return;
        }
        let Some(to) = target else {
            self.root = None;
            return;
        };
        if to == "-" {
            self.root = None;
            return;
        }
        let Some(root) = self.root.clone() else {
            return;
        };
        let Some(next) = path_from(to, &root, None) else {
            self.root = None;
            return;
        };
        match std::fs::symlink_metadata(&next) {
            Ok(m) if m.file_type().is_symlink() => self.root = None,
            Ok(m) if m.is_dir() => self.root = Some(next),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !self.strict => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.made.contains(&next) => {
                self.root = Some(next);
            }
            Err(_) => self.root = None,
        }
    }

    fn note_created(&mut self, cmd: &[&str]) {
        let (name, args) = command_verb(cmd);
        let mut dests: Vec<&str> = Vec::new();
        match name.as_str() {
            "mkdir" => dests.extend(positionals(&args)),
            "ln" | "cp" | "mv" | "install" => {
                if let Some(last) = positionals(&args).last().copied() {
                    dests.push(last);
                }
            }
            _ => {}
        }
        dests.extend(command_output_targets(cmd));
        if dests.is_empty() {
            return;
        }
        let Some(root) = self.root.clone() else {
            self.open = true;
            return;
        };
        for d in dests {
            match concrete_path(d, &root) {
                Some(p) => self.made.push(p),
                None => self.open = true,
            }
        }
    }
}

/// Whether a `cd`, `pushd` or `popd` the line runs is not one of the
/// commands [`command_roots`] follows, as in a subshell or a function.
pub(crate) fn hidden_moves(cmds: &[Vec<&str>], inners: &[(usize, Vec<String>)]) -> bool {
    let moves = |w: Option<&str>| w.is_some_and(|w| matches!(base_of(w), "cd" | "pushd" | "popd"));
    let shown = cmds.iter().filter(|c| moves(c.first().copied())).count();
    let all = inners
        .iter()
        .filter(|(_, c)| moves(c.first().map(String::as_str)))
        .count();
    all != shown
}

/// Whether `inner` is the whole script a shell's `-c` runs for `cmd`. It
/// starts where `cmd` does, whatever `cd` the script itself runs.
pub(crate) fn runs_fresh(cmd: Option<&Vec<&str>>, inner: &[String]) -> bool {
    let Some(cmd) = cmd else {
        return false;
    };
    let owned: Vec<String> = cmd.iter().map(|s| (*s).to_string()).collect();
    shell_script(peeled(&owned)).is_some_and(|s| shell_words(s) == inner)
}

/// Where each command of `argv` runs, in order. The entry is the directory
/// before that command, so a `cd` moves the ones after it.
pub(crate) fn command_roots(
    argv: &[String],
    start: Option<std::path::PathBuf>,
) -> Vec<Option<std::path::PathBuf>> {
    command_roots_with(argv, Place::new(start))
}

fn command_roots_with(argv: &[String], mut place: Place) -> Vec<Option<std::path::PathBuf>> {
    let mut prev = "";
    let mut roots = Vec::new();
    for (cmd, end) in ended_commands(argv) {
        let in_pipe = end == "|" || prev == "|";
        roots.push(place.root.clone());
        place.finish(&cmd, in_pipe);
        prev = end;
    }
    roots
}

/// The command word and the words after it.
fn command_verb(cmd: &[&str]) -> (String, Vec<String>) {
    let words = operands(cmd);
    let front = (0..words.len())
        .take_while(|&i| is_assignment(words[i]) || keyword_at(&words, i))
        .count();
    let rest = peel_cd_command_word(&words[front..]);
    let name = rest
        .first()
        .map(|w| base_of(w).to_string())
        .unwrap_or_default();
    let args = rest
        .get(1..)
        .unwrap_or(&[])
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    (name, args)
}

/// Operands that are not flags. `--` ends the flags.
fn positionals(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut bare = false;
    for a in args {
        if a == "--" {
            bare = true;
            continue;
        }
        if !bare && a.starts_with('-') {
            continue;
        }
        out.push(a.as_str());
    }
    out
}

/// Files a command's output redirections name.
fn command_output_targets<'a>(cmd: &'a [&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < cmd.len() {
        let next = cmd.get(i + 1).copied();
        if let Some((target, ate)) = output_target(cmd[i], next) {
            out.push(target);
            if ate {
                i += 1;
            }
        }
        i += 1;
    }
    out
}

/// `p` joined onto `root`, when every part of it is written out. A
/// variable, a glob, a brace or `~` is not a path the line shows.
fn concrete_path(p: &str, root: &std::path::Path) -> Option<std::path::PathBuf> {
    let p = p.trim_matches(|c| c == '\'' || c == '"');
    if p.is_empty()
        || p.contains(['$', '`', '*', '?', '['])
        || p.starts_with('~')
        || brace_expands(p)
    {
        return None;
    }
    let p = p.trim_end_matches('/');
    if p.is_empty() {
        return None;
    }
    let joined = if p.starts_with('/') {
        std::path::PathBuf::from(p)
    } else {
        root.join(p)
    };
    Some(logical(&joined))
}
