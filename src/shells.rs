//! Scripts and programs handed to a shell or an interpreter: `-c`, a file
//! operand, a process substitution, stdin, and inline code.

use super::{
    base_of, commands, interpreter_flag, is_redirection, operands, redirection_body, shell_words,
    split_env_strings, unwrap_wrappers, CONTAINER_VALUED, EXPANDS, SHELLS, SPELLED,
};

/// The script a shell runs with `-c` (or a flag cluster holding `c`, such as
/// `-lc`), if this command is one. A `--` after `-c` and the value of an
/// option such as `-o pipefail` or `--rcfile FILE` are not the script.
pub(crate) fn shell_script(run: &[String]) -> Option<&str> {
    shell_c_call(run).map(|(script, _)| script)
}

/// A shell `-c`/`-lc` script and the words after it. Those words are `$0`,
/// `$1`, and so on, bound into the script before it is checked.
pub(crate) fn shell_c_call(run: &[String]) -> Option<(&str, &[String])> {
    if !SHELLS.contains(&base_of(run.first()?)) {
        return None;
    }
    let mut i = 1;
    let mut takes = false;
    while i < run.len() {
        let a = run[i].as_str();
        if takes {
            if a == "--" {
                i += 1;
                continue;
            }
            return Some((a, &run[i + 1..]));
        }
        if !(a.starts_with('-') || a.starts_with('+')) || a.len() < 2 {
            return None;
        }
        if a.starts_with('-') && !a.starts_with("--") && a[1..].contains('c') {
            takes = true;
        } else if matches!(a, "--rcfile" | "--init-file")
            || (!a.starts_with("--") && a.ends_with(['o', 'O']))
        {
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

/// `$0`, `$1`, `${1}` in `script` become the words after `-c`. A single
/// quoted stretch is left as written. `$10` is not `$1`.
pub(crate) fn bind_positionals(script: &str, args: &[String]) -> String {
    if args.is_empty() || !script.contains('$') {
        return script.to_string();
    }
    let b = script.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut single = false;
    while i < b.len() {
        let c = b[i];
        if !single && c == b'\\' && i + 1 < b.len() {
            out.push(c as char);
            out.push(b[i + 1] as char);
            i += 2;
            continue;
        }
        if c == b'\'' {
            single = !single;
            out.push('\'');
            i += 1;
            continue;
        }
        if !single && c == b'$' {
            if let Some((n, len)) = positional_at(&script[i + 1..]) {
                if let Some(val) = args.get(n) {
                    out.push_str(val);
                    i += 1 + len;
                    continue;
                }
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

fn positional_at(rest: &str) -> Option<(usize, usize)> {
    let b = rest.as_bytes();
    if b.first() == Some(&b'{') {
        let end = rest.find('}')?;
        let name = &rest[1..end];
        if !name.is_empty() && name.bytes().all(|c| c.is_ascii_digit()) {
            return Some((name.parse().ok()?, end + 1));
        }
        return None;
    }
    let n = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    Some((rest[..n].parse().ok()?, n))
}

/// What a process substitution handed to a shell as its script produces.
#[allow(dead_code)]
pub(crate) enum ProcKind {
    /// Literal output of `echo` or `printf`, the script the shell runs.
    Text(String),
    /// Literal paths `cat` reads. The walk opens them.
    Paths(Vec<String>),
    /// The output is not shown: the script could be anything.
    Unshown,
    /// This command is not a shell fed a process substitution.
    Not,
}

/// The first script operand of a shell that has no `-c` script: the word
/// bash would open as the program. A redirection is not that operand,
/// except a `<(...)` or `>(...)` passed as the script path.
fn shell_file_operand(run: &[String]) -> Option<&str> {
    if run.first().is_none_or(|w| !SHELLS.contains(&base_of(w))) || shell_script(run).is_some() {
        return None;
    }
    let mut it = run[1..].iter().map(String::as_str);
    while let Some(a) = it.next() {
        if is_redirection(a) && !a.starts_with("<(") && !a.starts_with(">(") {
            let rest = redirection_body(a);
            if rest == "<<-" || rest.chars().all(|c| matches!(c, '>' | '<' | '&' | '|')) {
                it.next();
            }
            continue;
        }
        if a == "--" {
            return it.next();
        }
        if (a.starts_with('-') || a.starts_with('+')) && a.len() >= 2 {
            if a.starts_with('-') && !a.starts_with("--") && a[1..].contains('s') {
                return None;
            }
            if matches!(a, "--rcfile" | "--init-file")
                || (!a.starts_with("--") && a.ends_with(['o', 'O']))
            {
                it.next();
            }
            continue;
        }
        return Some(a);
    }
    None
}

/// The body of `<(...)` when that is the shell's script operand.
pub(crate) fn procsub_body(run: &[String]) -> Option<&str> {
    let op = shell_file_operand(run)?;
    let body = op.strip_prefix("<(")?.strip_suffix(')')?;
    (!body.trim().is_empty()).then_some(body)
}

/// How a shell reads a process substitution it was given as its script.
pub(crate) fn procsub_of(run: &[String]) -> ProcKind {
    let Some(op) = shell_file_operand(run) else {
        return ProcKind::Not;
    };
    if op.starts_with(">(") {
        return ProcKind::Unshown;
    }
    let Some(body) = procsub_body(run) else {
        return if op.starts_with("<(") {
            ProcKind::Unshown
        } else {
            ProcKind::Not
        };
    };
    let words = shell_words(body);
    let cmds = commands(&words);
    if cmds.len() != 1 {
        return ProcKind::Unshown;
    }
    let owned: Vec<String> = cmds[0].iter().map(|s| (*s).to_string()).collect();
    let owned = split_env_strings(&owned).into_owned();
    let (inner, handed) = unwrap_wrappers(&owned);
    if handed.is_some() {
        return ProcKind::Unshown;
    }
    let Some(head) = inner.first() else {
        return ProcKind::Unshown;
    };
    match base_of(head) {
        "echo" => echo_text(&inner[1..])
            .map(ProcKind::Text)
            .unwrap_or(ProcKind::Unshown),
        "printf" => printf_text(&inner[1..])
            .map(ProcKind::Text)
            .unwrap_or(ProcKind::Unshown),
        "cat" => cat_paths(&inner[1..])
            .map(ProcKind::Paths)
            .unwrap_or(ProcKind::Unshown),
        _ => ProcKind::Unshown,
    }
}

/// Text with no parameter, command substitution, glob or `~`, other
/// than ones a quote kept as themselves everywhere the word was split.
pub(crate) fn literal_text(s: &str) -> bool {
    !s.contains(EXPANDS) || SPELLED.with(|m| m.borrow().get(s) == Some(&true))
}

/// The text `echo` writes, when every argument is literal. `-e` escapes
/// the line does not spell out are unknown.
pub(crate) fn echo_text(args: &[String]) -> Option<String> {
    let mut i = 0;
    let mut escapes = false;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if let Some(flags) = a
            .strip_prefix('-')
            .filter(|f| !f.is_empty() && f.chars().all(|c| matches!(c, 'n' | 'e' | 'E')))
        {
            if flags.contains('e') {
                escapes = true;
            }
            if flags.contains('E') {
                escapes = false;
            }
            i += 1;
            continue;
        }
        break;
    }
    let rest = &args[i..];
    if rest.iter().any(|a| !literal_text(a)) {
        return None;
    }
    let mut parts = Vec::new();
    for a in rest {
        if escapes {
            parts.push(echo_unescape(a)?);
        } else {
            parts.push(a.clone());
        }
    }
    Some(parts.join(" "))
}

fn echo_unescape(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('a') => out.push('\u{7}'),
            Some('b') => out.push('\u{8}'),
            Some('e' | 'E') => out.push('\u{1b}'),
            Some('f') => out.push('\u{c}'),
            Some('v') => out.push('\u{b}'),
            Some('c') => return Some(out),
            _ => return None,
        }
    }
    Some(out)
}

/// The text `printf` writes for a literal format of `%s`, `%%` and
/// simple escapes. Any other conversion, or an argument left over, is
/// unknown: printf would read the leftover as another format.
fn printf_text(args: &[String]) -> Option<String> {
    let args = if args.first().is_some_and(|a| a == "--") {
        &args[1..]
    } else {
        args
    };
    if args.first().is_some_and(|a| a.starts_with('-')) {
        return None;
    }
    let (fmt, rest) = args.split_first()?;
    if !literal_text(fmt) || rest.iter().any(|a| !literal_text(a)) {
        return None;
    }
    render_printf(fmt, rest)
}

/// The text `printf FMT ARGS` writes, where bash and dash write the same
/// bytes. A conversion with no argument left writes its zero or empty
/// value. A directive neither shell knows stops printf there, after it
/// wrote the text before it. A byte past ASCII, `%c` and the escapes and
/// conversions only one shell knows are unknown.
pub(crate) fn render_printf(fmt: &str, args: &[String]) -> Option<String> {
    let mut out = String::new();
    let chars: Vec<char> = fmt.chars().collect();
    let mut i = 0;
    let mut ai = 0;
    while let Some(&c) = chars.get(i) {
        i += 1;
        if c == '\\' {
            let e = *chars.get(i)?;
            i += 1;
            match e {
                '\\' => out.push('\\'),
                'a' => out.push('\u{7}'),
                'b' => out.push('\u{8}'),
                'e' => out.push('\u{1b}'),
                'f' => out.push('\u{c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'v' => out.push('\u{b}'),
                '0'..='7' => {
                    let mut v = e.to_digit(8)?;
                    for _ in 0..2 {
                        match chars.get(i).and_then(|d| d.to_digit(8)) {
                            Some(d) => {
                                v = v * 8 + d;
                                i += 1;
                            }
                            None => break,
                        }
                    }
                    let byte = u8::try_from(v & 0xff).ok().filter(u8::is_ascii)?;
                    out.push(char::from(byte));
                }
                'E' | '\'' | '"' | '?' | 'x' | 'u' | 'U' => return None,
                // The backslash stays, and the byte after it is read
                // again: `\%` is a backslash and then a directive.
                _ => {
                    out.push('\\');
                    i -= 1;
                }
            }
            continue;
        }
        if c != '%' {
            out.push(c);
            continue;
        }
        let d = *chars.get(i)?;
        i += 1;
        let arg = args.get(ai);
        match d {
            '%' => out.push('%'),
            's' => {
                out.push_str(arg.map_or("", String::as_str));
                ai += usize::from(arg.is_some());
            }
            _ if arg.is_some() => return None,
            'b' => {}
            'd' | 'i' | 'o' | 'u' | 'x' | 'X' | 'g' | 'G' => out.push('0'),
            'f' | 'F' => out.push_str("0.000000"),
            'e' => out.push_str("0.000000e+00"),
            'E' => out.push_str("0.000000E+00"),
            // Bash writes these and goes on where dash stops, or this
            // does not render them.
            'a' | 'A' | 'c' | 'n' | 'q' | 'Q' | 'T' => return None,
            // A letter neither shell knows stops both after the text
            // before it.
            d if d.is_ascii_alphabetic() => return Some(out),
            _ => return None,
        }
    }
    (ai == args.len()).then_some(out)
}

/// The paths a literal `cat` reads. A flag or a path the line does not
/// show changes the bytes, so the script is unknown.
fn cat_paths(args: &[String]) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    let mut end = false;
    for a in args {
        if !end && a == "--" {
            end = true;
            continue;
        }
        if !end && a.starts_with('-') {
            return None;
        }
        if a.is_empty() || !literal_text(a) {
            return None;
        }
        paths.push(a.clone());
    }
    (!paths.is_empty()).then_some(paths)
}

/// What the line feeds a shell on stdin.
pub(crate) enum Fed<'a> {
    /// A here-string's text.
    Text(&'a str),
    /// A heredoc, whose lines are already commands of the line.
    Heredoc,
    /// The file a `<`, `0<` or `<>` redirection opens, which the walk
    /// reads.
    File(&'a str),
    /// Nothing the line shows: a pipe, or the stdin it inherits.
    Unshown,
}

/// The file the redirection `a`, with `next` after it, opens on stdin:
/// `<file`, `< file`, `0<file`, `<>file`. A here-string, a heredoc and a
/// duplicated descriptor (`<&3`) are not one. The flag says the file is
/// the next word.
fn stdin_redirect<'a>(a: &'a str, next: Option<&'a str>) -> Option<(&'a str, bool)> {
    let rest = a.strip_prefix('0').unwrap_or(a).strip_prefix('<')?;
    if rest.starts_with(['<', '&', '(']) {
        return None;
    }
    let rest = rest.strip_prefix('>').unwrap_or(rest);
    if rest.is_empty() {
        next.map(|n| (n, true))
    } else {
        Some((rest, false))
    }
}

/// For a shell that reads its script from stdin, having no `-c` script
/// and no file operand (or `-s`, after which operands are arguments),
/// what the line feeds it there and whether `-s` asks for it. `None` for
/// a call that is not such a shell.
pub(crate) fn shell_stdin(run: &[String]) -> Option<(Fed<'_>, bool)> {
    let (first, args) = run.split_first()?;
    if !SHELLS.contains(&base_of(first)) || shell_script(run).is_some() {
        return None;
    }
    let mut fed = Fed::Unshown;
    let mut it = args.iter().map(String::as_str).peekable();
    while let Some(a) = it.next() {
        let body = redirection_body(a);
        if let Some(text) = body.strip_prefix("<<<") {
            fed = Fed::Text(if text.is_empty() {
                it.next().unwrap_or_default()
            } else {
                text
            });
        } else if body.starts_with("<<") {
            fed = Fed::Heredoc;
        } else if let Some((file, ate)) = stdin_redirect(a, it.peek().copied()) {
            if ate {
                it.next();
            }
            fed = Fed::File(file);
        }
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut stdin = false;
    let mut it = operands(&words).into_iter();
    while let Some(a) = it.next() {
        if a == "--" || a == "-" {
            break;
        }
        if !(a.starts_with('-') || a.starts_with('+')) {
            if !stdin {
                return None;
            }
            break;
        }
        if a.starts_with('-') && !a.starts_with("--") && a[1..].contains('s') {
            stdin = true;
        }
        if matches!(a, "--rcfile" | "--init-file")
            || (!a.starts_with("--") && a.ends_with(['o', 'O']))
        {
            it.next();
        }
    }
    Some((fed, stdin))
}

/// Commands that hand their stdin to a command they run elsewhere: in a
/// container, a namespace, another root, a unit or another host.
const STDIN_RUNNERS: &[&str] = &[
    "docker",
    "podman",
    "nerdctl",
    "kubectl",
    "nsenter",
    "chroot",
    "systemd-run",
    "lxc",
    "incus",
    "ssh",
    "sftp",
];

/// For a runner in [`STDIN_RUNNERS`] that takes stdin, the command it
/// runs with it. `Some(None)` is no command: a login shell, the image's
/// own command, or the batch `sftp -b -` reads from stdin. `None` is a
/// call that does not pass stdin on.
pub(crate) fn stdin_runner(run: &[String]) -> Option<Option<&[String]>> {
    let (first, args) = run.split_first()?;
    let head = base_of(first);
    if !STDIN_RUNNERS.contains(&head) {
        return None;
    }
    let interactive = |args: &[String]| {
        args.iter().take_while(|w| *w != "--").any(|w| {
            matches!(
                w.as_str(),
                "--interactive" | "--stdin" | "--interactive=true"
            ) || (w.starts_with('-') && !w.starts_with("--") && w[1..].contains('i'))
        })
    };
    let inner: &[String] = match head {
        "docker" | "podman" | "nerdctl" => {
            let sub = args.iter().position(|w| !w.starts_with('-'))?;
            let rest = &args[sub + 1..];
            match args[sub].as_str() {
                "exec" if interactive(rest) => runner_command(rest, CONTAINER_VALUED, 1),
                "run" | "create" if interactive(rest) => runner_command(rest, CONTAINER_VALUED, 1),
                _ => return None,
            }
        }
        "kubectl" => {
            let sub = args.iter().position(|w| !w.starts_with('-'))?;
            let rest = &args[sub + 1..];
            if args[sub] != "exec" || !interactive(rest) {
                return None;
            }
            runner_command(rest, &["-c", "--container", "-n", "--namespace"], 1)
        }
        "lxc" | "incus" => {
            let sub = args.iter().position(|w| !w.starts_with('-'))?;
            let rest = &args[sub + 1..];
            if args[sub] != "exec" {
                return None;
            }
            runner_command(rest, &["--env", "--cwd", "--user", "--group"], 1)
        }
        "nsenter" => runner_command(
            args,
            &["-t", "--target", "-S", "--setuid", "-G", "--setgid"],
            0,
        ),
        "chroot" => runner_command(args, &["--userspec", "--groups", "--skip-chdir"], 1),
        "systemd-run" => {
            let piped = args.iter().any(|w| {
                matches!(w.as_str(), "--pipe" | "--pty" | "--shell")
                    || (w.starts_with('-')
                        && !w.starts_with("--")
                        && w[1..].contains(['P', 't', 'S']))
            });
            if !piped {
                return None;
            }
            let valued = [
                "-p",
                "--property",
                "-u",
                "--unit",
                "-E",
                "--setenv",
                "-M",
                "--machine",
                "-H",
                "--host",
                "--uid",
                "--gid",
                "--nice",
                "-D",
                "--description",
                "--slice",
                "--working-directory",
            ];
            runner_command(args, &valued, 0)
        }
        "ssh" => {
            let valued = [
                "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o",
                "-p", "-Q", "-R", "-S", "-W", "-w",
            ];
            runner_command(args, &valued, 1)
        }
        "sftp" => {
            let batch = args.iter().enumerate().any(|(i, w)| {
                w == "-b-" || (w == "-b" && args.get(i + 1).is_some_and(|v| v == "-"))
            });
            return batch.then_some(None);
        }
        _ => return None,
    };
    Some((!inner.is_empty()).then_some(inner))
}

/// The command a runner runs: the words past `--`, or past the first
/// `skip` operands, with each option in `valued` taking the next word.
fn runner_command<'a>(args: &'a [String], valued: &[&str], skip: usize) -> &'a [String] {
    if let Some(d) = args.iter().position(|w| w == "--") {
        return &args[d + 1..];
    }
    let mut seen = 0;
    let mut i = 0;
    while i < args.len() {
        let w = args[i].as_str();
        if w.starts_with('-') && w.len() > 1 {
            i += if valued.contains(&w) { 2 } else { 1 };
            continue;
        }
        if seen == skip {
            return &args[i..];
        }
        seen += 1;
        i += 1;
    }
    &[]
}

/// The words of `cmd` past its redirections, with the target of each one
/// whose operator is a word of its own (`< file`, `<<< text`, `2> log`).
pub(crate) fn without_redirections(cmd: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = cmd.iter();
    while let Some(w) = it.next() {
        if is_redirection(w) {
            let body = redirection_body(w);
            if body
                .trim_start_matches(['<', '>', '&', '|', '-'])
                .is_empty()
            {
                it.next();
            }
            continue;
        }
        out.push(w.clone());
    }
    out
}

/// Interpreters that take a program as an argument, with the flag for it.
pub(crate) const INTERPRETERS: &[(&str, &str)] = &[
    ("python", "-c"),
    ("python3", "-c"),
    ("python2", "-c"),
    ("pypy3", "-c"),
    ("perl", "-e"),
    ("ruby", "-e"),
    ("node", "-e"),
    ("deno", "eval"),
    ("bun", "-e"),
];

/// The program text an interpreter call runs inline (`python3 -c CODE`).
pub(crate) fn inline_program(run: &[String]) -> Option<&str> {
    run.get(inline_flag_at(run)? + 1).map(String::as_str)
}

/// Where an interpreter call's inline-program flag (`-c`, `-e`) is.
fn inline_flag_at(run: &[String]) -> Option<usize> {
    let flag = interpreter_flag(base_of(run.first()?))?;
    run.iter().position(|a| {
        a == flag
            || (a.starts_with('-')
                && !a.starts_with("--")
                && a.ends_with(&flag[1..])
                && flag.starts_with('-'))
    })
}

/// `cwd='...'` or `cwd="..."` on a `subprocess.run` call.
fn subprocess_cwd(code: &str, at: usize) -> Option<String> {
    let end = (at + 800).min(code.len());
    let window = code.get(at..end)?;
    for key in ["cwd='", "cwd=\""] {
        let Some(i) = window.find(key) else {
            continue;
        };
        let rest = &window[i + key.len()..];
        let quote = key.as_bytes()[key.len() - 1] as char;
        let stop = rest.find(quote)?;
        let dir = &rest[..stop];
        if !dir.is_empty() {
            return Some(dir.to_string());
        }
    }
    None
}

fn git_with_cwd(words: &[String], cwd: Option<String>) -> String {
    let Some(dir) = cwd.filter(|d| !d.contains([' ', '\n', '\''])) else {
        return words.join(" ");
    };
    if words
        .first()
        .is_some_and(|w| w == "git" || w.ends_with("/git"))
    {
        let rest = words[1..].join(" ");
        if rest.is_empty() {
            format!("git -C {dir}")
        } else {
            format!("git -C {dir} {rest}")
        }
    } else {
        words.join(" ")
    }
}

/// The quoted strings an inline program hands to a shell: the first string
/// argument of `os.system(`, `subprocess.*(`, `os.popen(`, `system(`,
/// `exec(`, `execSync(` or `spawnSync(`, and any backtick string in Perl or
/// Ruby. A list argument (`["git", "push", "-f"]`) is joined with spaces.
pub(crate) fn program_shell_strings(code: &str) -> Vec<String> {
    const CALLS: &[&str] = &[
        "system(",
        "popen(",
        "run(",
        "call(",
        "check_call(",
        "check_output(",
        "Popen(",
        "getoutput(",
        "getstatusoutput(",
        "execSync(",
        "exec(",
        "spawnSync(",
        "qx(",
    ];
    let mut out = Vec::new();
    for call in CALLS {
        let mut from = 0;
        while let Some(at) = code[from..].find(call) {
            let start = from + at + call.len();
            from = start;
            let rest = code[start..].trim_start();
            if let Some(list) = rest.strip_prefix('[') {
                let body = list.split(']').next().unwrap_or("");
                let words: Vec<String> = quoted_strings(body);
                if !words.is_empty() {
                    out.push(git_with_cwd(&words, subprocess_cwd(code, start)));
                }
            } else if let Some(first) = quoted_strings(rest).into_iter().next() {
                if rest.starts_with(['"', '\'', '`']) {
                    out.push(first);
                }
            }
        }
    }
    out
}

/// The contents of each quoted string in `s`, in order.
pub(crate) fn quoted_strings(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let q = chars[i];
        if matches!(q, '"' | '\'' | '`') {
            let mut j = i + 1;
            let mut cur = String::new();
            while j < chars.len() && chars[j] != q {
                if chars[j] == '\\' && j + 1 < chars.len() {
                    j += 1;
                }
                cur.push(chars[j]);
                j += 1;
            }
            out.push(cur);
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}
