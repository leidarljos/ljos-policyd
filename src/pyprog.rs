//! What a python program may do, read from its text.
//!
//! The text is split into names, strings and marks the way python reads
//! it. Each name is taken through the program's imports, so after
//! `import os as o`, `o.system` is `os.system`. Strings are decoded as
//! python decodes them, and an f-string's fields are read as code. A
//! program the reader cannot split is refused.

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

/// What the program shows: every string, with each run of joined
/// literals also whole.
#[derive(Default)]
struct Read {
    strs: Vec<String>,
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

/// Read `code` into `out`. `None` when python would read it in a way
/// the reader does not follow.
fn read(code: &str, depth: usize, out: &mut Read) -> Option<()> {
    if depth > DEPTH || foreign_coding(code) {
        return None;
    }
    let chars: Vec<char> = code.chars().collect();
    let mut toks = Vec::new();
    lex(&chars, 0, &mut toks)?;
    for (i, t) in toks.iter().enumerate() {
        if let Tok::Str(s) = t {
            out.strs.push(s.clone());
            if let Some(whole) = literal_run(&toks[i..]) {
                if whole != *s {
                    out.strs.push(whole);
                }
            }
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
    credential(&r)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn refused_for(code: &str) -> Option<String> {
        refusal(code).map(|r| r.token)
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
}
