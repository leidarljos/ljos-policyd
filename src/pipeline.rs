//! Pipelines and commands: how a line splits, and what each stage runs.

#[cfg(doc)]
use super::{remote_exec, shell_words};
use super::{unwrap_wrappers, word_fetches};

pub(crate) fn base_of(tok: &str) -> &str {
    tok.rsplit('/').next().unwrap_or(tok)
}

/// The program a packed word may name, quotes taken off the piece.
pub(crate) fn piece_base(p: &str) -> &str {
    base_of(p.trim_matches(|c: char| c == '"' || c == '\'' || c == '\\'))
}

pub(crate) fn is_privilege(base: &str) -> bool {
    matches!(base, "sudo" | "doas" | "su" | "pkexec" | "run0")
}

/// Commands that download.
pub(crate) const FETCHERS: &[&str] = &["curl", "wget", "fetch"];
/// A word that may be a shell, or a packed `env -S` string that holds one.
/// A quoted phrase with a space is not a shell by itself.
pub(crate) fn word_may_name_shell(w: &str) -> bool {
    let hit = |p: &str| {
        let b = piece_base(p);
        b == "env" || SHELLS.contains(&b)
    };
    hit(w)
        || (w.contains(char::is_whitespace)
            && w.split(char::is_whitespace)
                .any(|p| !p.is_empty() && hit(p)))
}

/// Commands that run a script they are handed.
/// `ash` and `hush` are the shells a `busybox` or `toybox` call runs.
pub(crate) const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash", "hush",
];
/// Words that run a script in the shell that reads them: `source FILE`,
/// `. FILE` and `eval TEXT`.
pub(crate) const SOURCERS: &[&str] = &["source", ".", "eval"];
/// Interpreters that run the program they read on stdin when the call
/// names none, by base name with any version taken off (`python3.12`).
/// The second field is the short flags that hand it a program inline or a
/// module (`-c`, `-m`). The third is the short flags that take a value
/// which is not that program (`python3 -W ignore` still reads stdin).
const STDIN_INTERPRETERS: &[(&str, &str, &str)] = &[
    ("python", "cm", "WX"),
    ("pypy", "cm", "WX"),
    ("perl", "eE", "I"),
    ("ruby", "e", "IrC"),
    ("node", "ep", "rC"),
    ("nodejs", "ep", "rC"),
    ("php", "rBRE", "dcz"),
    ("lua", "e", "l"),
];
/// Long options whose next word is a value, not the program
/// (`node --require mod` still reads stdin when no script follows).
const LONG_VALUED: &[&str] = &[
    "require",
    "import",
    "loader",
    "experimental-loader",
    "env-file",
    "check-hash-based-pycs",
];
/// Words that run the command after them.
pub(crate) const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "time", "exec", "command", "nice",
];

/// Where a pipeline stage's command word sits: its first word past
/// wrappers, assignments and their flags.
pub(crate) fn command_at(stage: &[String]) -> Option<usize> {
    stage.iter().position(|w| {
        let b = base_of(w);
        !(WRAPPERS.contains(&b)
            || w.starts_with('-')
            || (w.contains('=') && !w.starts_with('='))
            || plain_redirection(w))
    })
}

/// The command a pipeline stage runs: its first word past wrappers,
/// assignments and their flags, by base name.
pub(crate) fn command_word(stage: &[String]) -> Option<&str> {
    let stage = peeled(stage);
    command_at(stage).map(|at| base_of(&stage[at]))
}

/// The interpreter a command word names, version taken off, with its
/// inline-program flags and its valued flags. `python3.12` is `python`.
pub(crate) fn stdin_interpreter(base: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let name = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    STDIN_INTERPRETERS
        .iter()
        .copied()
        .find(|(n, _, _)| *n == name)
}

/// A program path that is the process's standard input.
fn is_stdin_source(w: &str) -> bool {
    matches!(
        w,
        "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0" | "php://stdin"
    )
}

/// The command past runners (`timeout`, `busybox`, `env`, ...), so a
/// pipeline stage is judged on the program it actually runs.
pub(crate) fn peeled(stage: &[String]) -> &[String] {
    unwrap_wrappers(stage).0
}

/// A redirection word, but not a process substitution: `<(curl ...)` is
/// an operand the command reads as a file.
fn plain_redirection(a: &str) -> bool {
    is_redirection(a) && !a.starts_with("<(") && !a.starts_with(">(")
}

/// The word an interpreter or shell call runs as its program: the value
/// of an inline flag (`-c CODE`, `-e CODE`, `--eval CODE`), else the first
/// operand (a script path or `<(...)`). `None` when the call names no
/// program and so reads it from stdin, including a program word that is
/// stdin itself (`/dev/stdin`). `valued` flags take a word that is not the
/// program (`-W ignore`). The bool is true for an inline program and false
/// for an operand.
pub(crate) fn program_word<'a>(
    args: &'a [String],
    inline: &str,
    valued: &str,
) -> Option<(&'a str, bool)> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" || plain_redirection(a) {
            continue;
        }
        if a == "-" || is_stdin_source(a) {
            return None;
        }
        if let Some(long) = a.strip_prefix("--") {
            if long.contains('=') {
                continue;
            }
            if matches!(long, "eval" | "print" | "command") {
                return it.next().map(|w| (w.as_str(), true));
            }
            if LONG_VALUED.contains(&long) {
                it.next();
            }
            continue;
        }
        if let Some(flags) = a.strip_prefix('-') {
            if flags.chars().any(|c| inline.contains(c)) {
                return it.next().map(|w| (w.as_str(), true));
            }
            if let Some(at) = flags.find(|c| valued.contains(c)) {
                if flags[at + 1..].is_empty() {
                    it.next();
                }
            }
            continue;
        }
        return Some((a.as_str(), false));
    }
    None
}

/// A pipeline stage that runs what it reads on stdin as a program: a
/// shell, or an interpreter called with no program of its own (`python3`,
/// `perl -`, `node`). `python3 -m json.tool`, `python3 -c CODE`,
/// `perl -ne CODE` and `python3 parse.py` read stdin as data.
pub(crate) fn runs_stdin(stage: &[String]) -> bool {
    let stage = peeled(stage);
    let Some(at) = command_at(stage) else {
        return false;
    };
    let b = base_of(&stage[at]);
    if SHELLS.contains(&b) {
        return true;
    }
    // `curl | python3` is a warning from [`python_pipe`], not this deny.
    // `curl | jq` is not a shell. A python with a program of its own reads
    // stdin as data.
    if stdin_interpreter(b).is_some_and(|(name, _, _)| name == "python" || name == "pypy") {
        return false;
    }
    stdin_interpreter(b)
        .is_some_and(|(_, inline, valued)| program_word(&stage[at + 1..], inline, valued).is_none())
}

/// A pipeline stage that runs `python` or `pypy` on the download with no
/// program of its own (`python3`, `python3 -`, `python3 /dev/stdin`).
fn runs_python_stdin(stage: &[String]) -> bool {
    let stage = peeled(stage);
    let Some(at) = command_at(stage) else {
        return false;
    };
    let b = base_of(&stage[at]);
    stdin_interpreter(b).is_some_and(|(name, inline, valued)| {
        (name == "python" || name == "pypy")
            && program_word(&stage[at + 1..], inline, valued).is_none()
    })
}

/// A download piped into python with no program of its own. The verdict
/// is a warning. A download piped into `sh`, `bash`, or `zsh` stays a deny
/// through [`remote_exec`].
pub(crate) fn python_pipe(argv: &[String]) -> bool {
    let fetches = |s: &[String]| {
        command_word(s).is_some_and(|c| FETCHERS.contains(&c)) || s.iter().any(|w| word_fetches(w))
    };
    for line in pipelines_of(argv) {
        let stages = stages(&line);
        if stages
            .iter()
            .enumerate()
            .any(|(i, s)| fetches(s) && stages[i + 1..].iter().any(|t| runs_python_stdin(t)))
        {
            return true;
        }
    }
    false
}

/// Words of a `-c` script with quotes kept as one word. A quoted
/// `curl | sh` stays text. This does not re-enter [`shell_words`].
pub(crate) fn quote_aware_words(script: &str) -> Vec<String> {
    let chars: Vec<char> = script.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    let mut single = false;
    let mut double = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && !single {
            if let Some(next) = chars.get(i + 1) {
                cur.push(*next);
                i += 2;
                continue;
            }
        }
        if c == '\'' && !double {
            single = !single;
            i += 1;
            continue;
        }
        if c == '"' && !single {
            double = !double;
            i += 1;
            continue;
        }
        if !single && !double && c.is_whitespace() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The stages of a pipeline. A word `|` separates stages; so does a `|`
/// inside a word with no space in it (`url|sh`), for a caller that split the
/// line on whitespace. `||` is not a pipe.
pub(crate) fn stages(argv: &[String]) -> Vec<Vec<String>> {
    let mut out = vec![Vec::new()];
    for t in argv {
        if t == "|" {
            out.push(Vec::new());
            continue;
        }
        if t.contains('|') && !t.contains("||") && !t.chars().any(char::is_whitespace) {
            let mut parts = t.split('|').peekable();
            while let Some(part) = parts.next() {
                if !part.is_empty() {
                    out.last_mut().expect("one stage").push(part.to_string());
                }
                if parts.peek().is_some() {
                    out.push(Vec::new());
                }
            }
            continue;
        }
        out.last_mut().expect("one stage").push(t.clone());
    }
    out.retain(|s| !s.is_empty());
    out
}

/// The pipelines of a line: its words split at `;`, `&&`, `||` and `&`,
/// and after a word that ends in `;`. The `|` words stay, so each piece is
/// one pipeline.
pub(crate) fn pipelines_of(argv: &[String]) -> Vec<Vec<String>> {
    let mut out = vec![Vec::new()];
    for a in argv {
        if matches!(a.as_str(), ";" | "&&" | "||" | "&") {
            out.push(Vec::new());
            continue;
        }
        let closes = a.ends_with(';');
        let tok = if closes {
            a.trim_end_matches(';')
        } else {
            a.as_str()
        };
        if !tok.is_empty() {
            out.last_mut().expect("one pipeline").push(tok.to_string());
        }
        if closes {
            out.push(Vec::new());
        }
    }
    out.retain(|p| !p.is_empty());
    out
}

/// Commands that are only a `case` pattern (`./ | .// | /usr/*`). The
/// `|` there is not a pipeline, and the words are not programs. An arm
/// body after the `)` is not skipped.
pub(crate) fn commands(argv: &[String]) -> Vec<Vec<&str>> {
    ended_commands(argv).into_iter().map(|(c, _)| c).collect()
}

/// [`commands`], each with the separator that ends it: `;`, `&&`, `||`,
/// `|`, `&`, or nothing at the end of the line.
pub(crate) fn ended_commands(argv: &[String]) -> Vec<(Vec<&str>, &str)> {
    let mut out: Vec<(Vec<&str>, &str)> = vec![(Vec::new(), "")];
    for a in argv.iter().map(String::as_str) {
        if matches!(a, ";" | "&&" | "||" | "|" | "&") {
            out.last_mut().expect("one command").1 = a;
            out.push((Vec::new(), ""));
            continue;
        }
        let closes = a.ends_with(';');
        let tok = a.trim_end_matches(';');
        if !tok.is_empty() {
            out.last_mut().expect("one command").0.push(tok);
        }
        if closes {
            out.last_mut().expect("one command").1 = ";";
            out.push((Vec::new(), ""));
        }
    }
    out.retain(|(c, _)| !c.is_empty());
    out
}

pub(crate) fn is_redirection(a: &str) -> bool {
    let rest = redirection_body(a);
    rest.starts_with('>') || rest.starts_with('<')
}

/// The redirection word `a` past the descriptor in front of its
/// operator: digits, `&`, or a `{name}` bash stores the one it opens in.
pub(crate) fn redirection_body(a: &str) -> &str {
    let a = fd_variable(a).map_or(a, |n| &a[n.len() + 2..]);
    a.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
}

/// The variable a `{name}>file` or `{name}<file` redirection sets to the
/// descriptor it opens.
fn fd_variable(a: &str) -> Option<&str> {
    let (name, rest) = a.strip_prefix('{')?.split_once('}')?;
    let ident = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    (ident && rest.starts_with(['>', '<'])).then_some(name)
}

/// Shell words in front of the command `do` and `then` introduce.
/// `do rm -rf "$x"` is that `rm`.
pub(crate) fn command_after_keywords<'a>(words: &'a [&'a str]) -> &'a [&'a str] {
    let mut w = words;
    while w.first().is_some_and(|s| {
        matches!(
            *s,
            "while"
                | "until"
                | "for"
                | "do"
                | "then"
                | "else"
                | "elif"
                | "if"
                | "in"
                | "{"
                | "}"
                | "("
                | ")"
                | "!"
                | "time"
                | "done"
                | "fi"
                | "esac"
        )
    }) {
        w = &w[1..];
    }
    w
}

/// [`ended_commands`], each as the indexes of its words in `argv`.
#[cfg(has_phronesis)]
pub(crate) fn ended_indices(argv: &[String]) -> Vec<(Vec<usize>, &str)> {
    let mut out: Vec<(Vec<usize>, &str)> = vec![(Vec::new(), "")];
    for (i, a) in argv.iter().enumerate() {
        if matches!(a.as_str(), ";" | "&&" | "||" | "|" | "&") {
            out.last_mut().expect("one command").1 = a.as_str();
            out.push((Vec::new(), ""));
            continue;
        }
        let closes = a.ends_with(';');
        if !a.trim_end_matches(';').is_empty() {
            out.last_mut().expect("one command").0.push(i);
        }
        if closes {
            out.last_mut().expect("one command").1 = ";";
            out.push((Vec::new(), ""));
        }
    }
    out.retain(|(c, _)| !c.is_empty());
    out
}
