//! What a python program may do, read from its text.
//!
//! The text is split into names, strings and marks the way python reads
//! it. Each name is taken through the program's imports, so after
//! `import os as o`, `o.system` is `os.system`. Strings are decoded as
//! python decodes them, and an f-string's fields are read as code. A
//! program the reader cannot split is refused.

use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;

use crate::policy_capnp::PolicyReason;

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Name(String),
    Str(String),
    Mark(char),
}

/// How deep an f-string field or the literal text of an `exec` is read.
const DEPTH: usize = 8;

/// Where an f-string field goes in the string's text. Its value is not
/// known, so a string that holds it is not a literal.
const FIELD: char = '\0';

fn name_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn name_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

fn string_prefix(w: &str) -> bool {
    matches!(
        w.to_ascii_lowercase().as_str(),
        "r" | "u" | "b" | "f" | "t" | "br" | "rb" | "fr" | "rf" | "tr" | "rt"
    )
}

fn lex(src: &[char], depth: usize, out: &mut Vec<Tok>) -> Option<()> {
    if depth > DEPTH {
        return None;
    }
    let mut i = 0;
    let mut nest = 0usize;
    while let Some(&c) = src.get(i) {
        if c == '#' {
            while src.get(i).is_some_and(|&c| c != '\n') {
                i += 1;
            }
        } else if c == '\\' && src.get(i + 1) == Some(&'\n') {
            i += 2;
        } else if c == ';' || (c == '\n' && nest == 0) {
            out.push(Tok::Mark(';'));
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if name_start(c) {
            let s = i;
            while src.get(i).copied().is_some_and(name_char) {
                i += 1;
            }
            let word: String = src[s..i].iter().collect();
            if matches!(src.get(i), Some('\'' | '"')) && string_prefix(&word) {
                i = string(src, i, &word.to_ascii_lowercase(), depth, out)?;
            } else {
                out.push(Tok::Name(word.nfkc().collect()));
            }
        } else if c == '\'' || c == '"' {
            i = string(src, i, "", depth, out)?;
        } else if c.is_ascii_digit() {
            while src
                .get(i)
                .is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            {
                i += 1;
            }
            out.push(Tok::Mark('0'));
        } else {
            match c {
                '(' | '[' | '{' => nest += 1,
                ')' | ']' | '}' => nest = nest.saturating_sub(1),
                _ => {}
            }
            out.push(Tok::Mark(c));
            i += 1;
        }
    }
    Some(())
}

/// Read the string whose quote is at `src[i]` and push it. The code in
/// an f-string's fields follows it, in parentheses.
fn string(
    src: &[char],
    mut i: usize,
    prefix: &str,
    depth: usize,
    out: &mut Vec<Tok>,
) -> Option<usize> {
    if depth > DEPTH {
        return None;
    }
    let q = src[i];
    let triple = src.get(i + 1) == Some(&q) && src.get(i + 2) == Some(&q);
    i += if triple { 3 } else { 1 };
    let raw = prefix.contains('r');
    let fields = prefix.contains('f') || prefix.contains('t');
    let mut text = String::new();
    let mut code = Vec::new();
    while let Some(&c) = src.get(i) {
        if c == q && (!triple || (src.get(i + 1) == Some(&q) && src.get(i + 2) == Some(&q))) {
            i += if triple { 3 } else { 1 };
            break;
        }
        // Python refuses a quote left open at the end of its line, so
        // nothing runs. What follows is still read, as code.
        if c == '\n' && !triple {
            break;
        }
        if c == '\\' && i + 1 < src.len() {
            let next = src[i + 1];
            if raw {
                text.push('\\');
                if next == q || next == '\\' {
                    text.push(next);
                    i += 1;
                }
                i += 1;
            } else {
                i = escape(src, i + 1, &mut text)?;
            }
            continue;
        }
        if fields && c == '{' {
            if src.get(i + 1) == Some(&'{') {
                text.push('{');
                i += 2;
                continue;
            }
            let end = field_end(src, i + 1, depth)?;
            text.push(FIELD);
            code.push(Tok::Mark('('));
            lex(&src[i + 1..end], depth + 1, &mut code)?;
            code.push(Tok::Mark(')'));
            i = end + 1;
            continue;
        }
        if fields && c == '}' && src.get(i + 1) == Some(&'}') {
            text.push('}');
            i += 2;
            continue;
        }
        text.push(c);
        i += 1;
    }
    out.push(Tok::Str(text));
    out.extend(code);
    Some(i)
}

/// The `}` that closes the f-string field opened before `from`. Strings
/// inside the field may use any quote, as python 3.12 reads them.
fn field_end(src: &[char], from: usize, depth: usize) -> Option<usize> {
    let mut nest = 0usize;
    let mut i = from;
    while let Some(&c) = src.get(i) {
        match c {
            '\'' | '"' => {
                let mut s = i;
                while s > from && name_char(src[s - 1]) {
                    s -= 1;
                }
                let p: String = src[s..i].iter().collect();
                let p = if string_prefix(&p) {
                    p.to_ascii_lowercase()
                } else {
                    String::new()
                };
                i = string(src, i, &p, depth + 1, &mut Vec::new())?;
                continue;
            }
            '(' | '[' | '{' => nest += 1,
            '}' if nest == 0 => return Some(i),
            ')' | ']' | '}' => nest = nest.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Decode the escape after a backslash, as a python string does. An
/// escape python does not know keeps its backslash. A `\N{...}` name is
/// not looked up, so its string is not known.
fn escape(src: &[char], i: usize, text: &mut String) -> Option<usize> {
    let code = |from: usize, n: usize, radix: u32| -> Option<(char, usize)> {
        let s: String = src.get(from..from + n)?.iter().collect();
        let v = u32::from_str_radix(&s, radix).ok()?;
        Some((char::from_u32(v).unwrap_or('\u{fffd}'), from + n))
    };
    let c = src[i];
    let (ch, next) = match c {
        '\n' => return Some(i + 1),
        'n' => ('\n', i + 1),
        't' => ('\t', i + 1),
        'r' => ('\r', i + 1),
        'a' => ('\u{7}', i + 1),
        'b' => ('\u{8}', i + 1),
        'f' => ('\u{c}', i + 1),
        'v' => ('\u{b}', i + 1),
        '\\' | '\'' | '"' => (c, i + 1),
        'x' => code(i + 1, 2, 16).unwrap_or(('x', i + 1)),
        'u' => code(i + 1, 4, 16).unwrap_or(('u', i + 1)),
        'U' => code(i + 1, 8, 16).unwrap_or(('U', i + 1)),
        'N' => return None,
        '0'..='7' => {
            let n = src[i..]
                .iter()
                .take(3)
                .take_while(|c| ('0'..='7').contains(*c))
                .count();
            code(i, n, 8)?
        }
        _ => {
            text.push('\\');
            (c, i + 1)
        }
    };
    text.push(ch);
    Some(next)
}

/// A name the program reaches through its imports, with the arguments
/// when it is called there.
#[derive(Clone)]
struct Ref {
    name: String,
    args: Option<Vec<Vec<Tok>>>,
}

/// What the program shows: the names it reaches, and every string,
/// with each run of joined literals also whole.
#[derive(Default)]
struct Read {
    refs: Vec<Ref>,
    strs: Vec<String>,
}

/// The dotted name from `toks[i]`, and where it ends.
fn dotted(toks: &[Tok], mut i: usize) -> (String, usize) {
    let mut out = String::new();
    let mut want = true;
    while let Some(t) = toks.get(i) {
        match t {
            Tok::Name(n) if want => {
                out.push_str(n);
                want = false;
            }
            Tok::Mark('.') if !want => {
                out.push('.');
                want = true;
            }
            _ => break,
        }
        i += 1;
    }
    if want && out.ends_with('.') {
        out.pop();
        i -= 1;
    }
    (out, i)
}

/// Where the bracket opened at `toks[open]` closes.
fn close(toks: &[Tok], open: usize) -> usize {
    let mut nest = 0usize;
    for (i, t) in toks.iter().enumerate().skip(open) {
        match t {
            Tok::Mark('(' | '[' | '{') => nest += 1,
            Tok::Mark(')' | ']' | '}') => {
                nest -= 1;
                if nest == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    toks.len()
}

/// The arguments of the call whose `(` is at `toks[open]`.
fn call_args(toks: &[Tok], open: usize) -> Vec<Vec<Tok>> {
    let end = close(toks, open);
    let mut args = vec![Vec::new()];
    let mut nest = 0usize;
    for t in toks.get(open + 1..end).unwrap_or_default() {
        match t {
            Tok::Mark('(' | '[' | '{') => nest += 1,
            Tok::Mark(')' | ']' | '}') => nest = nest.saturating_sub(1),
            Tok::Mark(',') if nest == 0 => {
                args.push(Vec::new());
                continue;
            }
            _ => {}
        }
        args.last_mut().expect("one argument").push(t.clone());
    }
    if args.last().is_some_and(Vec::is_empty) {
        args.pop();
    }
    args
}

/// The text of an argument made only of string literals, joined as
/// python joins them.
fn literal(a: &[Tok]) -> Option<String> {
    let mut out = String::new();
    let mut want = true;
    for t in a {
        match t {
            Tok::Str(s) if !s.contains(FIELD) => {
                out.push_str(s);
                want = false;
            }
            Tok::Mark('+') if !want => want = true,
            _ => return None,
        }
    }
    (!want).then_some(out)
}

/// What each name the imports bind stands for, and the modules a
/// `from M import *` spills into the program.
fn bindings(toks: &[Tok]) -> (HashMap<String, Vec<String>>, Vec<String>) {
    let mut names: HashMap<String, Vec<String>> = HashMap::new();
    let mut stars = Vec::new();
    for (stmt, _) in statements(toks) {
        let Some(at) = import_at(stmt) else {
            continue;
        };
        let module = stmt[..at]
            .iter()
            .position(|t| matches!(t, Tok::Name(n) if n == "from"))
            .map(|f| dotted(stmt, f + 1).0);
        let mut i = at + 1;
        while let Some(t) = stmt.get(i) {
            match t {
                Tok::Mark('(' | ')' | ',') => {
                    i += 1;
                    continue;
                }
                Tok::Mark('*') => {
                    stars.extend(module.clone());
                    i += 1;
                    continue;
                }
                Tok::Name(_) => {}
                _ => break,
            }
            let (path, next) = dotted(stmt, i);
            i = next;
            let alias = match (stmt.get(i), stmt.get(i + 1)) {
                (Some(Tok::Name(a)), Some(Tok::Name(n))) if a == "as" => {
                    i += 2;
                    Some(n.clone())
                }
                _ => None,
            };
            let (bound, target) = match (&module, alias) {
                (Some(m), alias) => (alias.unwrap_or_else(|| path.clone()), format!("{m}.{path}")),
                (None, Some(a)) => (a, path),
                (None, None) => {
                    let top = path.split('.').next().unwrap_or_default().to_string();
                    (top.clone(), top)
                }
            };
            names.entry(bound).or_default().push(target);
        }
    }
    (names, stars)
}

/// Each statement, with where it starts.
fn statements(toks: &[Tok]) -> impl Iterator<Item = (&[Tok], usize)> {
    let mut at = 0;
    toks.split(|t| *t == Tok::Mark(';')).map(move |s| {
        let from = at;
        at += s.len() + 1;
        (s, from)
    })
}

fn import_at(stmt: &[Tok]) -> Option<usize> {
    stmt.iter()
        .position(|t| matches!(t, Tok::Name(n) if n == "import"))
}

impl Read {
    fn calls<'a>(&'a self, set: &'a [&str]) -> impl Iterator<Item = &'a Ref> + 'a {
        self.refs
            .iter()
            .filter(move |r| r.args.is_some() && matches(&r.name, set))
    }
}

fn matches(name: &str, set: &[&str]) -> bool {
    set.iter()
        .any(|s| *s == name || (s.ends_with('.') && name.starts_with(s)))
}

/// The name `head` stands for: what an import bound it to, else
/// itself and each `from M import *` spelling of it.
fn heads(head: &str, binds: &HashMap<String, Vec<String>>, stars: &[String]) -> Vec<String> {
    match binds.get(head) {
        Some(t) => t.clone(),
        None => std::iter::once(head.to_string())
            .chain(stars.iter().map(|m| format!("{m}.{head}")))
            .collect(),
    }
}

/// `f.__call__` is `f`.
fn bare(name: String) -> String {
    let name = name.replace(".__call__", "");
    match name.strip_prefix("builtins.") {
        Some(rest) => rest.to_string(),
        None => name,
    }
}

/// Read `code` into `out`. `None` when python would read it in a way
/// the reader does not follow.
fn read(code: &str, depth: usize, out: &mut Read) -> Option<()> {
    if depth > DEPTH || foreign_coding(code) {
        return None;
    }
    let chars: Vec<char> = code.chars().collect();
    let mut toks = Vec::new();
    lex(&chars, 0, &mut toks)?;
    let (binds, stars) = bindings(&toks);
    // The words of an import name modules, not calls of them.
    let mut skip = vec![false; toks.len()];
    for (stmt, at) in statements(&toks) {
        if import_at(stmt).is_some() {
            skip[at..at + stmt.len()].fill(true);
        }
    }
    for (i, t) in toks.iter().enumerate() {
        match t {
            Tok::Str(s) => {
                out.strs.push(s.clone());
                if let Some(whole) = literal_run(&toks[i..]) {
                    if whole != *s {
                        out.strs.push(whole);
                    }
                }
            }
            Tok::Name(_) if skip[i] => {}
            Tok::Name(n) => {
                let (chain, next) = dotted(&toks, i);
                let tail = chain.strip_prefix(n.as_str()).unwrap_or_default();
                let called = toks.get(next) == Some(&Tok::Mark('('));
                let args = called.then(|| call_args(&toks, next));
                for h in heads(n, &binds, &stars) {
                    let name = bare(format!("{h}{tail}"));
                    out.refs.push(Ref {
                        name,
                        args: args.clone(),
                    });
                }
            }
            _ => {}
        }
    }
    Some(())
}

/// The string literals from `toks[0]` that python joins into one.
fn literal_run(toks: &[Tok]) -> Option<String> {
    literal(&toks[..run_end(toks)])
}

fn run_end(toks: &[Tok]) -> usize {
    let mut end = 1;
    while matches!(toks.get(end), Some(Tok::Str(_)))
        || (toks.get(end) == Some(&Tok::Mark('+'))
            && matches!(toks.get(end + 1), Some(Tok::Str(_))))
    {
        end += if toks[end] == Tok::Mark('+') { 2 } else { 1 };
    }
    end
}

/// A coding line in the first two lines that names a codec other than
/// UTF-8 or Latin-1. Python decodes the file with it, so the bytes the
/// reader sees are not the program.
fn foreign_coding(code: &str) -> bool {
    code.lines().take(2).any(|line| {
        let line = line.trim_start();
        let Some(at) = line.strip_prefix('#').and_then(|l| l.find("coding")) else {
            return false;
        };
        let rest = &line[1 + at + "coding".len()..];
        let Some(rest) = rest.strip_prefix([':', '=']) else {
            return false;
        };
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect::<String>()
            .to_ascii_lowercase()
            .replace('_', "-");
        !matches!(
            name.as_str(),
            "utf-8"
                | "utf8"
                | "ascii"
                | "us-ascii"
                | "latin-1"
                | "latin1"
                | "iso-8859-1"
                | "iso8859-1"
        )
    })
}

/// Why python must not run a program, as a policy reason and a token.
pub(crate) struct Refusal {
    pub(crate) code: PolicyReason,
    pub(crate) token: String,
}

fn refused(code: PolicyReason, class: &str, what: &str) -> Option<Refusal> {
    let what: String = what
        .chars()
        .map(|c| if c == FIELD { '…' } else { c })
        .take(80)
        .collect();
    Some(Refusal {
        code,
        token: if what.is_empty() {
            format!("python-{class}")
        } else {
            format!("python-{class}: {what}")
        },
    })
}

/// Why python must not run `code`, or `None`.
pub(crate) fn refusal(code: &str) -> Option<Refusal> {
    let mut r = Read::default();
    if read(code, 0, &mut r).is_none() {
        return refused(PolicyReason::ShellDangerousRunner, "unread", "");
    }
    credential(&r).or_else(|| hook_write(&r))
}

/// Paths and parts of paths that hold a login, a key or a token.
const CREDENTIAL_PARTS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".password-store",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".vault-token",
];
const CREDENTIAL_PATHS: &[&str] = &[
    ".config/gh/",
    ".config/gcloud",
    ".config/hub",
    ".config/ljos",
    ".cargo/credentials",
    ".local/share/keyrings",
    ".codex/auth.json",
    ".claude/.credentials.json",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
];
const KEY_FILES: &[&str] = &["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];

/// Whether a string names a credential store, or a secret's variable.
fn names_credential(s: &str) -> bool {
    let low = s.to_ascii_lowercase().replace('\\', "/");
    let parts: Vec<&str> = low.split('/').collect();
    parts.iter().any(|p| CREDENTIAL_PARTS.contains(p))
        || parts
            .iter()
            .any(|p| KEY_FILES.iter().any(|k| p.starts_with(k)))
        || CREDENTIAL_PATHS.iter().any(|c| low.contains(c))
        || (low.starts_with("/proc/") && low.ends_with("/environ"))
        || secret_variable(s)
}

/// `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`: a variable a secret is kept
/// in, by the words of its name.
fn secret_variable(s: &str) -> bool {
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    let words: Vec<&str> = s.split('_').collect();
    words.iter().any(|w| {
        matches!(
            *w,
            "TOKEN" | "SECRET" | "PASSWORD" | "PASSWD" | "APIKEY" | "CREDENTIAL" | "CREDENTIALS"
        )
    }) || words
        .windows(2)
        .any(|p| matches!(p, ["API" | "ACCESS" | "PRIVATE" | "SECRET", "KEY"]))
}

/// A program that names a credential store or a secret's variable.
fn credential(r: &Read) -> Option<Refusal> {
    let s = r.strs.iter().find(|s| names_credential(s))?;
    refused(PolicyReason::PathSensitiveDeny, "reads-credential", s)
}

/// Files a tool runs or loads on its own: editor and runner hooks, git
/// hooks and config, shell startup files, python startup modules.
const HOOK_PARTS: &[&str] = &[
    ".cursor",
    ".claude",
    ".codex",
    ".husky",
    "hooks.json",
    ".envrc",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".cshrc",
    ".tcshrc",
    ".kshrc",
    ".pythonrc",
    ".pythonrc.py",
    ".gitconfig",
];
const HOOK_PATHS: &[&str] = &[
    ".git/hooks",
    ".git/config",
    "core.hookspath",
    ".config/ljos",
    ".local/state/ljos",
    ".config/git/",
    ".config/fish/",
    ".config/autostart",
    ".config/systemd",
    ".config/environment.d",
];

fn names_hook(s: &str) -> bool {
    let low = s.to_ascii_lowercase().replace('\\', "/");
    let parts: Vec<&str> = low.split('/').collect();
    parts.iter().any(|p| {
        HOOK_PARTS.contains(p)
            || p.ends_with(".pth")
            || p.starts_with("sitecustomize")
            || p.starts_with("usercustomize")
    }) || HOOK_PATHS.iter().any(|h| low.contains(h))
        || low.ends_with(".git/config")
}

/// A program that may write files and names a hook or startup file.
fn hook_write(r: &Read) -> Option<Refusal> {
    writes(r)?;
    let s = r.strs.iter().find(|s| names_hook(s))?;
    refused(PolicyReason::PathSensitiveDeny, "writes-hook", s)
}

/// Calls that may make, change or remove a file whatever their mode.
const WRITE_CALLS: &[&str] = &[
    "os.remove",
    "os.unlink",
    "os.rename",
    "os.renames",
    "os.replace",
    "os.rmdir",
    "os.removedirs",
    "os.mkdir",
    "os.makedirs",
    "os.symlink",
    "os.link",
    "os.chmod",
    "os.lchmod",
    "os.chown",
    "os.lchown",
    "os.chflags",
    "os.truncate",
    "os.utime",
    "os.mkfifo",
    "os.mknod",
    "os.setxattr",
    "os.removexattr",
    "shutil.",
    "sqlite3.connect",
    "logging.FileHandler",
    "logging.handlers.",
    "py_compile.",
    "compileall.",
    "zipapp.",
    "venv.",
    "dbm.",
    "shelve.",
    "urllib.request.urlretrieve",
];
const READ_ONLY_SHUTIL: &[&str] = &[
    "shutil.which",
    "shutil.get_terminal_size",
    "shutil.disk_usage",
    "shutil.copyfileobj",
    "shutil.get_archive_formats",
    "shutil.get_unpack_formats",
];

/// The first call or method that may write a file, by its name.
fn writes(r: &Read) -> Option<String> {
    if let Some(c) = r
        .calls(WRITE_CALLS)
        .find(|c| !READ_ONLY_SHUTIL.contains(&c.name.as_str()))
    {
        return Some(c.name.clone());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused_for(code: &str) -> Option<String> {
        refusal(code).map(|r| r.token)
    }

    #[test]
    fn names_go_through_the_imports() {
        let mut r = Read::default();
        read(
            "import os as o\nfrom subprocess import run as go\nfrom shutil import *\n\
             o.system('x'); go(['a']); rmtree('d')",
            0,
            &mut r,
        )
        .unwrap();
        let names: Vec<&str> = r.refs.iter().map(|r| r.name.as_str()).collect();
        for n in ["os.system", "subprocess.run", "shutil.rmtree"] {
            assert!(names.contains(&n), "{n} not in {names:?}");
        }
    }

    #[test]
    fn strings_are_decoded_as_python_decodes_them() {
        let mut r = Read::default();
        read(
            r#"a = "\x2essh"; b = '~/.' 'aws'; c = f"{h}/.kube/{n!r}"; d = rb'\x41'; e = "x" + "y""#,
            0,
            &mut r,
        )
        .unwrap();
        for s in [".ssh", "~/.aws", "/.kube/", "\\x41", "xy"] {
            assert!(
                r.strs.iter().any(|t| t.split(FIELD).any(|p| p == s)),
                "{s} not in {:?}",
                r.strs
            );
        }
        assert!(r.refs.iter().any(|r| r.name == "h"));
    }

    #[test]
    fn a_program_the_reader_cannot_split_is_refused() {
        for code in [
            "# -*- coding: utf-7 -*-\nprint(1)",
            "print('\\N{FULL STOP}ssh')",
            "f'{x'",
        ] {
            assert_eq!(
                refused_for(code).as_deref(),
                Some("python-unread"),
                "{code}"
            );
        }
        for code in [
            "# -*- coding: utf-8 -*-\nprint(1)",
            "print('a\\nb')",
            "print('open",
        ] {
            assert_eq!(refused_for(code), None, "{code}");
        }
    }

    #[test]
    fn a_credential_read_is_refused() {
        for code in [
            "print(open('/home/u/.ssh/id_rsa').read())",
            "import os; print(open(os.path.expanduser('~/.ssh/id_ed25519')).read())",
            "from pathlib import Path; Path.home().joinpath('.aws', 'credentials').read_text()",
            "print(open('/home/u/.netrc').read())",
            "import os; print(os.environ['GITHUB_TOKEN'])",
            "import os; print(os.getenv('AWS_SECRET_ACCESS_KEY'))",
            "print(open('/proc/self/environ').read())",
            "print(open('~/.config/gh/' + 'hosts.yml').read())",
            "print(open('\\x2fhome/u/\\x2essh/id_rsa').read())",
        ] {
            let t = refused_for(code).unwrap_or_default();
            assert!(t.starts_with("python-reads-credential"), "{code}: {t}");
        }
        for code in [
            "print(open('data.csv').read())",
            "import os; print(os.environ.get('HOME'))",
            "import os; print(os.environ['GIT_AUTHOR_NAME'])",
            "print('tokens: 3')",
        ] {
            assert_eq!(refused_for(code), None, "{code}");
        }
    }

    fn class_of(code: &str) -> String {
        let t = refused_for(code).unwrap_or_else(|| panic!("{code}: allowed"));
        t.split(':').next().unwrap_or_default().to_string()
    }

    #[test]
    fn a_hook_write_is_refused() {
        for code in [
            "import os; os.makedirs('.git/hooks', exist_ok=True)",
            "import shutil; shutil.copy('x', '.git/hooks/')",
        ] {
            assert_eq!(class_of(code), "python-writes-hook", "{code}");
        }
        for code in [
            "print(open('.git/config').read())",
            "from pathlib import Path; print(Path('.git', 'HEAD').read_text())",
            "import os; os.listdir('.git/hooks')",
        ] {
            assert_eq!(refused_for(code), None, "{code}");
        }
    }
}
