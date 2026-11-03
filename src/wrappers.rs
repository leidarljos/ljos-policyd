//! Runner words in front of a command, `case` arms, and function heads.

use std::borrow::Cow;

use super::{base_of, env_flag, is_assignment};

/// Words that run the command after them, with the flags of each that take
/// a separate value.
pub(crate) const RUNNERS: &[(&str, &[&str])] = &[
    (
        "env",
        &["-u", "--unset", "-C", "--chdir", "-S", "--split-string"],
    ),
    ("nice", &["-n", "--adjustment"]),
    ("nohup", &[]),
    ("time", &["-f", "--format", "-o", "--output"]),
    ("exec", &["-a"]),
    ("command", &[]),
    ("builtin", &[]),
    ("setsid", &[]),
    ("stdbuf", &["-i", "-o", "-e"]),
    ("ionice", &["-c", "-n", "-p", "-P", "-u"]),
    ("chrt", &[]),
    ("taskset", &[]),
    ("timeout", &["-k", "--kill-after", "-s", "--signal"]),
    (
        "strace",
        &[
            "-o", "--output", "-e", "-E", "-p", "-u", "-s", "-P", "-I", "-D",
        ],
    ),
    (
        "xargs",
        &[
            "-I",
            "-n",
            "-P",
            "-L",
            "-d",
            "-E",
            "-a",
            "-s",
            "-J",
            "-R",
            "-S",
            "--delimiter",
            "--max-args",
            "--max-procs",
            "--arg-file",
        ],
    ),
    (
        "parallel",
        &[
            "-j",
            "--jobs",
            "-S",
            "--sshlogin",
            "--sshloginfile",
            "-a",
            "--arg-file",
            "--argsep",
            "--arg-sep",
            "--env",
            "--results",
            "--tmpdir",
            "-d",
            "--delimiter",
            "--colsep",
            "-C",
            "-I",
            "--replace",
            "-n",
            "-N",
            "--max-args",
            "--timeout",
            "--delay",
            "--joblog",
            "--halt",
            "--workdir",
            "--wd",
        ],
    ),
    ("watch", &["-n", "--interval", "-d"]),
    // Shell keywords that open or continue a compound command: the
    // command after them is the one that runs.
    ("!", &[]),
    ("{", &[]),
    ("if", &[]),
    ("then", &[]),
    ("else", &[]),
    ("elif", &[]),
    ("while", &[]),
    ("until", &[]),
    ("do", &[]),
    ("coproc", &[]),
    ("flock", &["-w", "--timeout", "-E", "--conflict-exit-code"]),
    // Multi-call binaries run the applet named after them.
    ("busybox", &[]),
    ("toybox", &[]),
];

/// The command past any leading assignments and runner words, with each
/// runner's flags (and their values) taken off. `timeout`, `flock`,
/// `taskset` and `chrt` also take one positional word before the command.
///
/// Some runners take the command as one string a shell splits: `flock FILE
/// -c STRING` and `watch STRING`. That string comes back as the second
/// value, to be read as a script. An `env -S STRING` runs nothing here;
/// [`split_env_strings`] puts the words of STRING in its place first.
pub(crate) fn unwrap_wrappers(cmd: &[String]) -> (&[String], Option<&str>) {
    match wrapper_walk(cmd) {
        Walk::Run(i) => (&cmd[i..], None),
        Walk::Script(s) => (&[], s),
        Walk::Split(..) => (&[], None),
    }
}

/// Where [`wrapper_walk`] stops in a command.
pub(crate) enum Walk<'a> {
    /// The command it runs starts at this word.
    Run(usize),
    /// A runner takes the command as one string a shell splits.
    Script(Option<&'a str>),
    /// The `env` option word at this index, with the number of words it
    /// takes, holds this `-S` string.
    Split(usize, usize, &'a str),
}

/// Walk `cmd` past its leading assignments and runner words, as
/// [`unwrap_wrappers`] reads them.
pub(crate) fn wrapper_walk(cmd: &[String]) -> Walk<'_> {
    let mut i = 0;
    while i < cmd.len() {
        let w = cmd[i].as_str();
        if is_assignment(w) {
            i += 1;
            continue;
        }
        let head = case_head(&cmd[i..]);
        if head > 0 {
            i += head;
            continue;
        }
        if let Some(head) = function_head(&cmd[i..]) {
            // `f() { git push -f; }`: the body is what runs when `f` is
            // called, so it is judged as written.
            i += head;
            continue;
        }
        let Some((name, valued)) = RUNNERS.iter().find(|(n, _)| *n == base_of(w)) else {
            break;
        };
        i += 1;
        if *name == "flock" {
            if let Some(at) = cmd[i..].iter().position(|a| a == "-c" || a == "--command") {
                return Walk::Script(cmd.get(i + at + 1).map(String::as_str));
            }
        }
        while i < cmd.len() {
            let a = cmd[i].as_str();
            if a == "--" {
                i += 1;
                break;
            }
            if *name == "env" && a.starts_with('-') {
                let (taken, value) = env_flag(a, cmd.get(i + 1).map(String::as_str));
                if let Some(('S', s)) = value {
                    return Walk::Split(i, taken, s);
                }
                i += taken;
            } else if *name == "env" && is_assignment(a) {
                i += 1;
            } else if a.starts_with('-') && a.len() > 1 {
                i += if valued.contains(&a) { 2 } else { 1 };
            } else {
                break;
            }
        }
        if *name == "watch" && i + 1 == cmd.len() {
            return Walk::Script(Some(cmd[i].as_str()));
        }
        if matches!(*name, "timeout" | "flock" | "taskset" | "chrt") && i < cmd.len() {
            i += 1;
        }
    }
    Walk::Run(i.min(cmd.len()))
}

/// `cmd` with each `env -S STRING` it runs replaced the way GNU env does
/// it: the words of STRING take the option's place, after any options
/// clustered in front of the `S`, and env reads its options again.
pub(crate) fn split_env_strings(cmd: &[String]) -> Cow<'_, [String]> {
    let mut cmd = Cow::Borrowed(cmd);
    // Each round takes one `-S` off; a string may hold another.
    for _ in 0..8 {
        let Walk::Split(at, taken, s) = wrapper_walk(&cmd) else {
            break;
        };
        let word = cmd[at].as_str();
        let front = (!word.starts_with("--"))
            .then(|| &word[..word.find('S').unwrap_or(0)])
            .filter(|f| f.len() > 1);
        let mut out: Vec<String> = cmd[..at].to_vec();
        out.extend(front.map(str::to_string));
        out.extend(env_split_words(s));
        out.extend(cmd[at + taken..].iter().cloned());
        cmd = Cow::Owned(out);
    }
    cmd
}

/// The words GNU env's `-S` splits `s` into. Blanks separate words and
/// quotes group them; a backslash escapes outside single quotes, where
/// `\_` is a separator outside double quotes and a space inside, and `\c`
/// ends the string; a `#` that starts a word comments out the rest.
/// `${NAME}` is kept as written, a value the line does not show.
fn env_split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut word = false;
    let (mut single, mut double) = (false, false);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !double => {
                single = !single;
                word = true;
            }
            '"' if !single => {
                double = !double;
                word = true;
            }
            '\\' if single => match chars.peek() {
                Some(&n @ ('\\' | '\'')) => {
                    chars.next();
                    cur.push(n);
                }
                _ => cur.push('\\'),
            },
            '\\' => {
                let Some(n) = chars.next() else {
                    break;
                };
                match n {
                    'c' => break,
                    '_' if !double => {
                        if word {
                            out.push(std::mem::take(&mut cur));
                            word = false;
                        }
                        continue;
                    }
                    '_' => cur.push(' '),
                    'f' => cur.push('\u{000c}'),
                    'n' => cur.push('\n'),
                    'r' => cur.push('\r'),
                    't' => cur.push('\t'),
                    'v' => cur.push('\u{000b}'),
                    n => cur.push(n),
                }
                word = true;
            }
            '#' if !single && !double && !word => break,
            c if !single && !double && c.is_whitespace() => {
                if word {
                    out.push(std::mem::take(&mut cur));
                    word = false;
                }
            }
            c => {
                cur.push(c);
                word = true;
            }
        }
    }
    if word {
        out.push(cur);
    }
    out
}

/// How many words at the front of `words` open a `case` arm: `case WORD
/// in` with the first arm's pattern (`a)`, `(a)`, `pat )`), or the
/// pattern alone that opens each later arm after `;;`. The command after
/// them is the one the arm runs. A pattern is a word with a `)` no `(`
/// in it opens, or pattern words closed by a `)` of their own.
pub(crate) fn case_head<S: AsRef<str>>(words: &[S]) -> usize {
    let word = |i: usize| words.get(i).map(AsRef::as_ref);
    let closes =
        |p: &str| p == ")" || (p.ends_with(')') && p.matches(')').count() > p.matches('(').count());
    let n = if word(0) == Some("case") && word(2) == Some("in") {
        3
    } else {
        0
    };
    if let Some(p) = word(n) {
        if closes(p) || (n == 3 && p.starts_with('(') && p.ends_with(')')) {
            return n + 1;
        }
    }
    // `*[!_$as_cr_alnum]* )` keeps the `)` as its own word. That pattern
    // is not a command, so the `$` in it does not drop the directory.
    // `echo )` and `find \( -name x \)` are commands: their first word
    // is not a pattern.
    if let Some(k) = (n..words.len()).find(|&i| word(i).is_some_and(closes)) {
        let arm = n == 3 || (n < k && (n..k).all(|i| word(i).is_some_and(is_case_pattern)));
        if arm && k > n {
            return k + 1;
        }
    }
    n
}

/// Whether `p` can be a `case` pattern word rather than a command: a
/// glob, an option (`-V`, `--help`), an empty `''`, or `(pattern`. `[`
/// and `[[` are the test builtin.
fn is_case_pattern(p: &str) -> bool {
    if p.is_empty() || (p.starts_with('(') && !p.starts_with("((")) {
        return true;
    }
    if p == "[" || p == "[[" {
        return false;
    }
    p.contains(['*', '?', '[']) || p.starts_with('-')
}

/// How many words a function definition's head takes at the front of
/// `words`: `f(){`, `f() {`, `function f {` and `function f() {`. None
/// when the words do not open one.
fn function_head(words: &[String]) -> Option<usize> {
    let is_name = |n: &str| {
        !n.is_empty()
            && n.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    };
    let first = words.first()?.as_str();
    if let Some(name) = first.strip_suffix("(){") {
        return is_name(name).then_some(1);
    }
    if let Some(name) = first.strip_suffix("()") {
        if !is_name(name) {
            return None;
        }
        return Some(if words.get(1).is_some_and(|w| w == "{") {
            2
        } else {
            1
        });
    }
    if first == "function" {
        let name = words.get(1)?.as_str();
        let name = name
            .strip_suffix("(){")
            .or_else(|| name.strip_suffix("()"))
            .unwrap_or(name);
        if !is_name(name) {
            return None;
        }
        let mut n = 2;
        if words.get(n).is_some_and(|w| w == "()") {
            n += 1;
        }
        if words.get(n).is_some_and(|w| w == "{") {
            n += 1;
        }
        return Some(n);
    }
    None
}
