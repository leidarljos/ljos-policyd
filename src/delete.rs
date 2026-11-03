//! Recursive deletes and disk wipes, and the scratch paths a script may
//! delete.

use super::{
    base_of, command_parts, command_sets_ifs, commands, harm, inline_program, interpreter_flag,
    is_assignment, is_name, is_redirection, lexical_norm, opaque_bound, path_in_work, phase,
    quoted_strings, shell_words, shown_temp_reads, temp_fed_marks, under_tmp, unquote,
};

/// An inline program that deletes a tree recursively outside `/tmp`:
/// Python's `shutil.rmtree`, Node's `rmSync`/`rm` with `recursive`, Ruby's
/// `FileUtils.rm_rf`/`rm_r`, Perl's `remove_tree`/`rmtree`.
pub(crate) fn interpreter_rmtree(argv: &[String]) -> bool {
    if !argv.iter().any(|w| {
        w.split(char::is_whitespace)
            .any(|p| !p.is_empty() && interpreter_flag(base_of(p)).is_some())
    }) {
        return false;
    }
    commands(argv).iter().any(|cmd| {
        let owned: Vec<String> = cmd.iter().map(|s| (*s).to_string()).collect();
        let Some(code) = inline_program(&owned) else {
            return false;
        };
        let mut hit = false;
        for call in [
            "rmtree(",
            "rm_rf(",
            "rm_r(",
            "remove_tree(",
            "rmSync(",
            "rimraf(",
        ] {
            let mut from = 0;
            while let Some(at) = code[from..].find(call) {
                let start = from + at + call.len();
                from = start;
                let rest = &code[start..];
                if call == "rmSync(" && !rest.split(')').next().unwrap_or("").contains("recursive")
                {
                    continue;
                }
                let target = quoted_strings(rest.split(')').next().unwrap_or(""))
                    .into_iter()
                    .next();
                if target.as_ref().is_some_and(|t| home_or_root_operand(t)) {
                    hit = true;
                }
            }
        }
        hit
    })
}

/// Whether a path names a parent directory anywhere, so a `/tmp/` prefix
/// says nothing about where it lands.
pub(crate) fn climbs(path: &str) -> bool {
    path.split('/').any(|part| part == "..")
}

/// A path written out in plain characters that stays below the working
/// directory: not absolute, no `~`, no `$`, no glob, no `..` and no `.`
/// part. A leading `./` and a trailing `/` are allowed.
pub(crate) fn plain_relative(p: &str) -> bool {
    let mut rest = p;
    while let Some(r) = rest.strip_prefix("./") {
        rest = r;
    }
    let rest = rest.trim_end_matches('/');
    !rest.is_empty()
        && !rest.starts_with('-')
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@' | '/'))
        && rest
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// A redirection to configure's unshown scratch file: `conftest.$ac_ext`,
/// `conftest*`. The `$` or `*` is an extension, not a path the line could
/// point at an arbitrary script. A literal name (`conftest.in`) is a real
/// file. A slash would let it name another directory.
fn configure_scratch(p: &str) -> bool {
    if p.ends_with('/') {
        return false;
    }
    let (dir, name) = p.rsplit_once('/').unwrap_or(("", p));
    (dir.is_empty() || dir == "." || plain_relative(dir))
        && (matches!(name, "conftest*" | "conftest.*")
            || (plain_relative(name)
                && (name == "conftest"
                    || name.starts_with("conftest.")
                    || name == "autom4te.cache")))
}

/// What a variable holds, when every assignment the script shows is of
/// that kind. A temp may be removed. A root is only a prefix
/// (`${TMPDIR-/tmp}`), and removing it would clear the temp directory.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hold {
    Temp,
    Root,
}

/// Variables a script assigns to scratch, so `rm -rf "$tmp"` is the
/// directory `mktemp` just made and not a path the line does not show.
/// One assignment that is not scratch poisons the name.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct Scratch {
    pub(crate) vars: std::collections::HashMap<String, Option<Hold>>,
    /// True while every assignment is a suffix with no `/` and no `..`.
    pub(crate) suffixes: std::collections::HashMap<String, bool>,
    /// Set when the leading comment carries the autoconf marker. A hint
    /// for the temps a generated `configure` removes, not a pass.
    pub(crate) autoconf: bool,
    /// Directory a relative scratch path is judged in. `None` when that
    /// directory is not a single tracked one: a symlink there would be
    /// followed, so the name is refused.
    pub(crate) root: Option<std::path::PathBuf>,
    /// The tree the line was started in. Set for the line's own words,
    /// and `None` for a script file it runs, whose writes are its own.
    pub(crate) work: Option<std::path::PathBuf>,
    /// `root` is where these words run: no `cd` the walk does not follow
    /// came before them on the line.
    pub(crate) placed: bool,
    /// `IFS` was assigned or `eval` ran. A variable suffix can split.
    pub(crate) ifs_assigned: bool,
    /// An `xargs -I` mark whose shown inputs are all under `/tmp`. The
    /// pack still sees the mark, and its older rule refuses that word.
    pub(crate) fed_marks: Vec<String>,
}

impl Scratch {
    pub(crate) fn observe(&mut self, argv: &[String]) {
        let _span = phase::enter(phase::OBSERVE);
        for cmd in commands(argv) {
            for w in &cmd {
                self.observe_word(w);
            }
            if command_sets_ifs(&cmd) {
                self.ifs_assigned = true;
            }
            for name in opaque_bound(&cmd) {
                self.poison(&name);
            }
            if command_parts(&cmd).1 == "eval" {
                self.poison_all();
            }
        }
        // `read x` from a `printf` of `/tmp/...` holds that path. The pack
        // still sees `$x`, and its older rule refuses the name. A `read`
        // in another shell does not, and neither does one that comes later.
        let (temps, other) = shown_temp_reads(argv);
        for name in other {
            self.poison(&name);
        }
        for name in temps {
            // `read` poisons the name: stdin is not an assignment. The
            // producer on this line is the value, so the poison is wrong.
            self.vars.insert(name, Some(Hold::Temp));
        }
        for mark in temp_fed_marks(argv) {
            if !self.fed_marks.iter().any(|m| m == &mark) {
                self.fed_marks.push(mark);
            }
        }
    }

    /// The name no longer has a value the script shows.
    fn poison(&mut self, name: &str) {
        self.vars.insert(name.to_string(), None);
        self.suffixes.insert(name.to_string(), false);
    }

    /// `eval` can change every name, and `IFS`.
    fn poison_all(&mut self) {
        for v in self.vars.values_mut() {
            *v = None;
        }
        for s in self.suffixes.values_mut() {
            *s = false;
        }
        self.ifs_assigned = true;
    }

    fn observe_word(&mut self, w: &str) {
        if let Some((name, value, append)) = assignment_of(w) {
            if w[name.len()..].starts_with('[') {
                self.vars.insert(name.to_string(), None);
                self.suffixes.insert(name.to_string(), false);
            } else {
                self.note(name, value, append);
            }
        }
        self.observe_defaults(w);
    }

    fn note(&mut self, name: &str, value: &str, append: bool) {
        let hold = self.classify(value, name);
        let next = match (self.vars.get(name).copied(), hold, append) {
            (Some(None), _, _) => None,
            (None, hold, false) => hold,
            (Some(Some(Hold::Temp)), Some(Hold::Temp), _) => Some(Hold::Temp),
            (Some(Some(Hold::Root)), Some(Hold::Root), false) => Some(Hold::Root),
            _ => None,
        };
        self.vars.insert(name.to_string(), next);
        let suffix = self.safe_suffix(value);
        let kept = self.suffixes.get(name).copied().unwrap_or(true) && suffix;
        self.suffixes.insert(name.to_string(), kept);
    }

    fn classify(&self, value: &str, self_name: &str) -> Option<Hold> {
        if value.is_empty() {
            return Some(Hold::Temp);
        }
        if let Some(body) = command_body(value) {
            return self.cmdsub(body);
        }
        if let Some(name) = bare_var(value) {
            return self.held(name, self_name);
        }
        if temp_root(value) {
            return Some(Hold::Root);
        }
        if self.pid_temp(value) || self.literal_temp(value) {
            return Some(Hold::Temp);
        }
        if value.contains(char::is_whitespace) {
            return value
                .split_whitespace()
                .all(|part| self.classify(part, self_name) == Some(Hold::Temp))
                .then_some(Hold::Temp);
        }
        None
    }

    /// The hold recorded for `name`. A reference to the variable being
    /// assigned reads the hold from before this assignment, which is the
    /// same map: this assignment is not recorded yet.
    fn held(&self, name: &str, _self_name: &str) -> Option<Hold> {
        self.vars.get(name).copied().flatten()
    }

    /// A command substitution that only makes a temp directory.
    fn cmdsub(&self, body: &str) -> Option<Hold> {
        let words = command_words(body);
        if !words
            .iter()
            .any(|w| matches!(base_of(w), "mktemp" | "tempfile"))
        {
            return None;
        }
        words
            .iter()
            .all(|w| !climbs(w) && (!w.starts_with('/') || under_tmp(w)) && self.expansion_safe(w))
            .then_some(Hold::Temp)
    }

    fn literal_temp(&self, p: &str) -> bool {
        under_tmp(p) || configure_scratch(p) || (self.autoconf && autoconf_operand(p, self))
    }

    fn pid_temp(&self, value: &str) -> bool {
        if climbs(value) || !has_pid(value) {
            return false;
        }
        if let Some(rest) = strip_temp_root(value) {
            return !rest.is_empty() && self.expansion_safe(rest);
        }
        if value.strip_prefix("./conf$$").is_some() || value.strip_prefix("conf$$").is_some() {
            return self.expansion_safe(value);
        }
        let Some((head, rest)) = value.split_once('/') else {
            return false;
        };
        let Some(name) = bare_var(head) else {
            return false;
        };
        !rest.is_empty() && self.held(name, "") == Some(Hold::Root) && self.expansion_safe(rest)
    }

    fn expansion_safe(&self, s: &str) -> bool {
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'$' {
                i += 1;
                continue;
            }
            if matches!(b.get(i + 1), Some(&b'$' | &b'!')) {
                i += 2;
                continue;
            }
            if b.get(i + 1) == Some(&b'{') {
                let Some(end) = s[i + 2..].find('}') else {
                    return false;
                };
                let body = &s[i + 2..i + 2 + end];
                if !self.brace_safe(body) {
                    return false;
                }
                i += end + 3;
                continue;
            }
            let rest = &s[i + 1..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() || !self.name_in_temp(&name) {
                return false;
            }
            i += 1 + name.len();
        }
        true
    }

    fn brace_safe(&self, body: &str) -> bool {
        if matches!(body, "$" | "RANDOM" | "PPID" | "BASHPID") || temp_root(&format!("${{{body}}}"))
        {
            return true;
        }
        match body.split_once('=') {
            Some((name, _)) if name.ends_with(':') || is_name(name) => {
                self.name_in_temp(name.trim_end_matches(':'))
            }
            None => self.name_in_temp(body),
            Some(_) => false,
        }
    }

    fn name_in_temp(&self, name: &str) -> bool {
        matches!(name, "RANDOM" | "PPID" | "BASHPID")
            || self.suffixes.get(name) == Some(&true)
            || self.vars.get(name).copied().flatten() == Some(Hold::Root)
    }

    fn safe_suffix(&self, value: &str) -> bool {
        if value.is_empty() {
            return true;
        }
        if command_body(value).is_some() {
            // The output is not a value the line shows.
            return false;
        }
        if let Some(name) = bare_var(value) {
            return self.suffixes.get(name) == Some(&true);
        }
        !value.contains(['/', '$', '`']) && !value.contains(char::is_whitespace) && !climbs(value)
    }

    fn observe_defaults(&mut self, w: &str) {
        let bytes = w.as_bytes();
        let mut i = 0;
        while i + 2 < bytes.len() {
            if bytes[i] == b'$' && bytes[i + 1] == b'{' {
                if let Some(end) = w[i + 2..].find('}') {
                    let body = &w[i + 2..i + 2 + end];
                    if let Some((name, _)) = default_assign(body) {
                        // `${name:=value}` assigns when the name is unset.
                        // The line does not show that it was unset.
                        self.poison(name);
                    }
                    i += end + 3;
                    continue;
                }
            }
            i += 1;
        }
    }
}

/// `NAME=value` or `NAME+=value`, the name without a subscript.
pub(crate) fn assignment_of(w: &str) -> Option<(&str, &str, bool)> {
    if !is_assignment(w) {
        return None;
    }
    let end = w
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(w.len());
    if end == 0 {
        return None;
    }
    let mut rest = &w[end..];
    if let Some(body) = rest.strip_prefix('[') {
        let mut depth = 1;
        let close = body.char_indices().find(|&(_, c)| {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            }
            depth == 0
        })?;
        rest = &body[close.0 + 1..];
    }
    if let Some(value) = rest.strip_prefix("+=") {
        return Some((&w[..end], value, true));
    }
    rest.strip_prefix('=')
        .map(|value| (&w[..end], value, false))
}

/// `${NAME=value}` or `${NAME:=value}` assigns when the name is unset.
pub(crate) fn default_assign(body: &str) -> Option<(&str, &str)> {
    let end = body
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(body.len());
    if end == 0 || !is_name(&body[..end]) {
        return None;
    }
    let rest = &body[end..];
    let value = rest.strip_prefix(":=").or_else(|| rest.strip_prefix('='))?;
    Some((&body[..end], value))
}

/// Words of a command substitution, with a parenthesised group opened.
/// `$( (umask 077 && mktemp -d dir) )` hides `mktemp` inside one word
/// until the group is read on its own.
pub(crate) fn command_words(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    flatten_commands(&shell_words(body), 0, &mut out);
    out
}

fn flatten_commands(words: &[String], depth: usize, out: &mut Vec<String>) {
    for w in words {
        if depth < 4 {
            if let Some(inner) = w.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
                flatten_commands(&shell_words(inner), depth + 1, out);
                continue;
            }
        }
        out.push(w.clone());
    }
}

/// The whole value is `$(...)` or a backtick command.
fn command_body(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix("$(") {
        return rest.strip_suffix(')');
    }
    if value.starts_with('`') && value.ends_with('`') && value.len() >= 2 {
        let body = &value[1..value.len() - 1];
        return (!body.contains('`')).then_some(body);
    }
    None
}

/// `$name` or `${name}`, and not `${name:-default}`.
/// `"$name"` with the quotes `shell_words` kept around a `$`.
pub(crate) fn quoted_body(w: &str) -> &str {
    w.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .filter(|s| !s.is_empty() && !s.contains('"'))
        .unwrap_or(w)
}

fn bare_var(w: &str) -> Option<&str> {
    let w = quoted_body(w);
    let w = w.strip_prefix('$')?;
    if let Some(name) = w.strip_prefix('{') {
        let name = name.strip_suffix('}')?;
        return is_name(name).then_some(name);
    }
    is_name(w).then_some(w)
}

fn temp_root(value: &str) -> bool {
    matches!(
        value,
        "${TMPDIR-/tmp}"
            | "${TMPDIR:-/tmp}"
            | "${TMPDIR-/var/tmp}"
            | "${TMPDIR:-/var/tmp}"
            | "/tmp"
            | "/var/tmp"
            | "/tmp/"
            | "/var/tmp/"
    )
}

fn strip_temp_root(value: &str) -> Option<&str> {
    const ROOTS: &[&str] = &[
        "${TMPDIR:-/var/tmp}/",
        "${TMPDIR-/var/tmp}/",
        "${TMPDIR:-/tmp}/",
        "${TMPDIR-/tmp}/",
        "/var/tmp/",
        "/tmp/",
    ];
    ROOTS.iter().find_map(|root| value.strip_prefix(root))
}

fn has_pid(s: &str) -> bool {
    s.contains("$$")
        || s.contains("$RANDOM")
        || s.contains("${RANDOM}")
        || s.contains("$!")
        || s.contains("$PPID")
}

/// A name a generated `configure` removes. The header is required; the
/// name alone is not a pass for `/` or a home directory.
fn autoconf_operand(p: &str, bound: &Scratch) -> bool {
    if climbs(p) || p.contains('~') || p.ends_with('/') {
        return false;
    }
    if configure_scratch(p) {
        return true;
    }
    // Only the current directory. `src/core` and `packages/a.out` are
    // real trees. `core`, `a.out`, `b.out` and `config.status` are not
    // recursive temps: configure removes those with `rm -f`, in this
    // directory, and a recursive delete of them is refused.
    let name = match p.rsplit_once('/') {
        Some((".", name) | ("", name)) => name,
        Some(_) => return false,
        None => p,
    };
    const NAMES: &[&str] = &[
        "confdefs",
        "confdefs.h",
        "confdefs*",
        ".tst",
        "a.exe",
        "a.out.dSYM",
        "conf$$*",
    ];
    if NAMES.contains(&name) {
        return true;
    }
    // `$$` is the pid. Anything after it is a suffix, same as `conftest`.
    if let Some(rest) = name.strip_prefix("conf$$") {
        return operand_suffix_ok(rest, bound);
    }
    // libtool's renamed object (`mv conftest.$ac_objext conftstm.$ac_objext`,
    // then `rm -rf conftst*`) and the Apple `-single_module` probe
    // (`libconftest.dylib*`). Same scratch as `conftest`, still not `/`.
    if let Some(rest) = name
        .strip_prefix("conftst")
        .or_else(|| name.strip_prefix("libconftest"))
    {
        return operand_suffix_ok(rest, bound);
    }
    let Some(rest) = name.strip_prefix("conftest") else {
        return false;
    };
    operand_suffix_ok(rest, bound)
}

/// A scratch suffix is literal text, or one variable whose value the
/// script shows is a single path piece. `$IFS`, `$(...)` and a backtick
/// split the word or name another directory.
fn operand_suffix_ok(rest: &str, bound: &Scratch) -> bool {
    if rest.contains('/')
        || climbs(rest)
        || rest.contains('`')
        || rest.contains("$(")
        || rest.contains(char::is_whitespace)
    {
        return false;
    }
    if !rest.contains('$') {
        return true;
    }
    // `IFS=:` makes `conftst$x` with `x=a:..` into `conftsta` and `..`.
    if bound.ifs_assigned {
        return false;
    }
    bare_var(rest).is_some_and(|n| bound.suffixes.get(n) == Some(&true))
}

/// True when any `rm` or `rtrash` on the line deletes recursively with an
/// operand that is neither under `/tmp` or `/var/tmp`, nor a build output
/// directory or a top-level scratch directory ([`SCRATCH_DIRS`]) named as a
/// plain relative path, nor a variable the same script assigns only to
/// scratch. When the line can `cd` out of the working tree, a relative
/// `rm -rf` of `/`, of `~` or `$HOME`, or of `/home/<user>` or `/root`.
/// A project directory, `/tmp` and `/var` are not that.
fn home_or_root_operand(p: &str) -> bool {
    let p = lexical_norm(unquote(p).trim_end_matches('/'));
    let p = p.trim_end_matches('/');
    if p.is_empty() || p == "/" || p == "/*" || p == "/." {
        return true;
    }
    if matches!(p, "~" | "$HOME" | "${HOME}" | "/home" | "/root" | "/Users") {
        return true;
    }
    if let Some(rest) = p
        .strip_prefix("/home/")
        .or_else(|| p.strip_prefix("/Users/"))
    {
        return !rest.is_empty() && !rest.contains('/');
    }
    false
}

/// A recursive `rm` of a tree that is not `/tmp`, `/var/tmp`, or a
/// regenerable build directory. Abbreviated long options count.
pub(crate) fn recursive_delete_off_tmp(argv: &[String], _moved: bool, bound: &Scratch) -> bool {
    commands(argv).iter().any(|cmd| {
        let expanded: Vec<String> = std::iter::once(cmd[0].to_string())
            .chain(
                cmd.iter()
                    .skip(1)
                    .map(|a| harm::expand_long(a, harm::RM_LONG).into_owned()),
            )
            .collect();
        let refs: Vec<&str> = expanded.iter().map(String::as_str).collect();
        rm_recursive(&refs)
            && refs
                .iter()
                .skip(1)
                .filter(|a| rm_operand(a))
                .any(|p| !safe_rm_path(p, bound))
    })
}

/// `/tmp` and the build directories a project deletes on purpose.
fn rm_operand(a: &str) -> bool {
    if a.starts_with('-') || is_redirection(a) || a.starts_with('>') || a.contains(">&") {
        return false;
    }
    a.contains('/') || a.starts_with('~') || a.starts_with('.') || a.starts_with('$')
}

/// `/tmp`, a regenerable build directory, or a variable this script
/// assigns only to a temp (`tmp=$(mktemp -d)`). A bare `$HOME` is not
/// that variable.
fn safe_rm_path(p: &str, bound: &Scratch) -> bool {
    let raw = unquote(p).trim_end_matches('/');
    if bare_var(raw).is_some_and(|name| bound.vars.get(name).copied().flatten() == Some(Hold::Temp))
    {
        return true;
    }
    // `./src` is still the source tree. Stripping the dot would make it
    // look like any other in-tree path and allow the delete.
    let spelled_dot = raw.starts_with("./");
    let p = lexical_norm(raw);
    if under_tmp(&p) {
        return true;
    }
    if !spelled_dot {
        if let Some(root) = bound.root.as_deref() {
            if path_in_work(&p, root) {
                return true;
            }
        }
    }
    let rel = p.trim_start_matches("./");
    const REGEN: &[&str] = &[
        "target",
        "node_modules",
        "dist",
        "build",
        ".venv",
        "__pycache__",
        ".next",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "web/node_modules",
    ];
    REGEN
        .iter()
        .any(|n| rel == *n || rel.starts_with(&format!("{n}/")))
}

/// `rm` or `rtrash` deleting recursively. The same flag test as
/// [`recursive_delete_off_tmp`].
pub(crate) fn rm_recursive(cmd: &[&str]) -> bool {
    let Some(head) = cmd.first() else {
        return false;
    };
    let b = base_of(head);
    if b != "rm" && b != "rtrash" && b != "srm" && b != "wipe" {
        return false;
    }
    cmd.iter().skip(1).any(|a| {
        let a = harm::expand_long(a, harm::RM_LONG);
        let a = a.as_ref();
        (a.starts_with('-') && !a.starts_with("--") && a.contains('r') && a.contains('f'))
            || a == "--recursive"
            || a == "-r"
            || a == "-R"
    }) && cmd.iter().skip(1).any(|a| {
        let a = harm::expand_long(a, harm::RM_LONG);
        let a = a.as_ref();
        (a.starts_with('-') && !a.starts_with("--") && a.contains('f') && !a.contains('r'))
            || a == "--force"
            || a == "-f"
            || (a.starts_with('-') && !a.starts_with("--") && a.contains('r') && a.contains('f'))
    })
}

/// A block device: a whole disk, a partition, or a mapped or RAID volume.
/// `/dev/null`, `/dev/zero` and the other character devices are not one.
fn block_device(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/dev/") else {
        return false;
    };
    [
        "sd", "hd", "vd", "xvd", "nvme", "mmcblk", "disk", "md", "dm-", "mapper/", "loop", "rbd",
        "nbd", "zd",
    ]
    .iter()
    .any(|p| name.starts_with(p))
}

/// A redirection on the line that writes to a block device: `> /dev/sda`,
/// `>/dev/sda`, `1>> /dev/nvme0n1`.
pub(crate) fn writes_block_device(argv: &[String]) -> bool {
    argv.iter().enumerate().any(|(i, a)| {
        let rest = a.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
        let Some(target) = rest.strip_prefix('>') else {
            return false;
        };
        let target = target.trim_start_matches(['>', '|']);
        if target.is_empty() {
            argv.get(i + 1).is_some_and(|t| block_device(t))
        } else {
            block_device(target)
        }
    })
}

/// Tools that rewrite a partition table, a filesystem signature or a whole
/// block device, each with the flags that only read. Such a tool given a
/// block device and none of its read-only flags is a write.
pub(crate) const DISK_WRITERS: &[(&str, &[&str])] = &[
    ("wipefs", &["-n", "--no-act", "-h", "--help"]),
    (
        "sgdisk",
        &[
            "-p", "--print", "-v", "--verify", "-i", "--info", "-h", "--help",
        ],
    ),
    (
        "sfdisk",
        &[
            "-l",
            "--list",
            "-d",
            "--dump",
            "-J",
            "--json",
            "-s",
            "--show-size",
            "-V",
            "--verify",
            "-h",
            "--help",
        ],
    ),
    ("fdisk", &["-l", "--list", "-h", "--help"]),
    ("gdisk", &["-l", "-h", "--help"]),
    ("cfdisk", &["-h", "--help"]),
    ("parted", &["-l", "--list", "print", "-h", "--help"]),
    ("blkdiscard", &["-h", "--help"]),
    ("mkswap", &["-h", "--help"]),
    ("shred", &["-h", "--help"]),
    ("badblocks", &[]),
];

/// A command that overwrites a disk: `mkfs` on a device (or with no target
/// named), `dd` writing to a block device, a partitioning or wiping tool
/// on a block device, `cryptsetup` formatting or erasing one, `badblocks
/// -w`, or a redirection into one. `mkfs.ext4 -F disk.img` formats a file
/// and `dd of=/dev/null` writes nowhere, so neither is refused.
pub(crate) fn raw_disk(argv: &[String]) -> bool {
    if writes_block_device(argv) {
        return true;
    }
    let b = base_of(&argv[0]);
    let operands: Vec<&str> = argv[1..]
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    if b.starts_with("mkfs") {
        // `mkfs -t xfs DEV`: the value of -t is not the target.
        let mut targets = Vec::new();
        let mut skip = false;
        for a in &argv[1..] {
            if skip {
                skip = false;
            } else if matches!(
                a.as_str(),
                "-t" | "--type" | "-L" | "-b" | "-O" | "-E" | "-m"
            ) {
                skip = true;
            } else if !a.starts_with('-') {
                targets.push(a.as_str());
            }
        }
        return targets.is_empty()
            || targets
                .iter()
                .any(|t| t.starts_with("/dev/") || t.contains('$'));
    }
    if b == "dd" {
        return argv
            .iter()
            .filter_map(|a| a.strip_prefix("of="))
            .any(|t| block_device(t) || t.contains('$'));
    }
    if b == "cryptsetup" {
        return operands
            .iter()
            .any(|a| matches!(*a, "luksFormat" | "erase" | "luksErase" | "reencrypt"));
    }
    if b == "wipefs"
        && !argv[1..].iter().any(|a| {
            matches!(a.as_str(), "--all" | "--offset")
                || a.starts_with("--offset=")
                || (a.starts_with('-')
                    && !a.starts_with("--")
                    && (a.contains('a') || a.contains('o')))
        })
    {
        // With neither -a nor -o, wipefs only lists the signatures it finds.
        return false;
    }
    if b == "badblocks" {
        return argv.iter().any(|a| a == "-w") && operands.iter().any(|a| block_device(a));
    }
    let Some((_, reads)) = DISK_WRITERS.iter().find(|(n, _)| *n == b) else {
        return false;
    };
    operands.iter().any(|a| block_device(a))
        && !argv[1..].iter().any(|a| reads.contains(&a.as_str()))
}

/// Commands that send a path to the trash; the trash keeps it only until
/// it is emptied, and a whole tree there is still gone from where it ran.
pub(crate) const TRASHERS: &[&str] = &["rtrash", "trash", "trash-put", "gtrash", "rmtrash"];

/// A recursive `rm` (with or without `-f`), or a trash command, given the
/// root, a home directory or a system tree. `rm -r /etc` and `rtrash -r
/// /etc` were allowed because only `-rf` counted as recursive.
pub(crate) fn deletes_a_root_tree(argv: &[String]) -> bool {
    commands(argv).iter().any(|cmd| {
        let b = base_of(cmd[0]);
        let gio = b == "gio" && cmd.get(1) == Some(&"trash");
        let recursive = cmd[1..].iter().any(|a| {
            *a == "--recursive"
                || (a.starts_with('-')
                    && !a.starts_with("--")
                    && (a.contains('r') || a.contains('R')))
        });
        if !(gio || TRASHERS.contains(&b) || (matches!(b, "rm" | "srm" | "wipe") && recursive)) {
            return false;
        }
        let from = usize::from(gio) + 1;
        cmd[from..]
            .iter()
            .filter(|a| !a.starts_with('-') && !is_redirection(a))
            .any(|p| home_or_root_operand(p))
    })
}
