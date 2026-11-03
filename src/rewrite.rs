//! Rewrite a python or pip invocation to uv when the tree asks for uv.
//!
//! The uv line runs the same program. A script stays `uv run script`.
//! `python -m` stays a module (`uv run -m`), because that is uv's spelling
//! for `python -m`. Flags uv would read as its own (`-u`, `-O`, `-W`) stay
//! on the interpreter: `uv run python -u script`. A here-document or a
//! pipe that is the program becomes `uv run -`, which is uv's stdin
//! script. A form with no such spelling is returned unchanged, with a
//! note, and only on the allow path. The law path still leaves `-c` and
//! a bare `-m` so that refusal stands.

use super::{base_of, is_assignment, shell_words, unwrap_wrappers, wrapper_walk, Walk, SHELLS};

/// The note prefix. A second look at a line that already carries it
/// stops, so a runner that judges the rewritten line does not rewrite
/// it again.
const LEFT: &str = "ljos-policyd: left as written";

const NOTE_INLINE: &str = "ljos-policyd: left as written, uv run does not take -c";
const NOTE_REPL: &str = "ljos-policyd: left as written, no script was named";
const NOTE_OPTION: &str = "ljos-policyd: left as written, that option is not a script";
const NOTE_ACTIVATE: &str = "ljos-policyd: left as written, activation is shell state";
const NOTE_PIP: &str = "ljos-policyd: left as written, uv pip has no spelling for that flag";

fn python_command(w: &str) -> bool {
    let b = base_of(w);
    let stem = b.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(stem, "python" | "pypy")
}

fn pip_command(w: &str) -> bool {
    let b = base_of(w);
    let stem = b.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    stem == "pip"
}

/// The line a hook should run instead, when this command is a python
/// invocation and the tree asks for uv.
pub(crate) fn rewrite_command(argv: &[String]) -> Option<String> {
    rewrite_with(argv, true)
}

/// The line a hook should run instead, when the law in force already
/// says python runs through uv. The tree is not asked again: the pack's
/// refusal is the reason, so a script with no project file beside it is
/// rewritten too, and the rewritten line meets the pack's PEP 723 rule
/// on its own. `-c` and a bare `-m` are not rewritten: the refusal stands.
pub(crate) fn rewrite_for_uv_law(argv: &[String]) -> Option<String> {
    rewrite_with(argv, false)
}

fn rewrite_with(argv: &[String], allow_path: bool) -> Option<String> {
    if argv.iter().any(|w| w.contains(LEFT)) {
        return None;
    }
    if shell_c(argv) {
        return rewrite_shell(argv, allow_path);
    }
    rewrite_argv(argv, allow_path)
}

fn shell_c(argv: &[String]) -> bool {
    let mut i = 0;
    while i < argv.len() && is_assignment(&argv[i]) {
        i += 1;
    }
    i < argv.len() && SHELLS.contains(&base_of(&argv[i])) && argv[i + 1..].iter().any(|w| w == "-c")
}

fn rewrite_shell(argv: &[String], allow_path: bool) -> Option<String> {
    let at = argv.iter().position(|w| w == "-c")? + 1;
    if at >= argv.len() {
        return None;
    }
    let script = splice_python(&argv[at], allow_path)?;
    if script == argv[at] {
        return None;
    }
    let mut parts = Vec::new();
    for (i, w) in argv.iter().enumerate() {
        if i == at {
            parts.push(quote_arg(&script));
        } else {
            parts.push(emit_word(w)?);
        }
    }
    Some(parts.join(" "))
}

fn rewrite_argv(argv: &[String], allow_path: bool) -> Option<String> {
    let Walk::Run(idx) = wrapper_walk(argv) else {
        return None;
    };
    if idx >= argv.len() {
        return None;
    }
    let head = argv[idx].as_str();
    if python_command(head) {
        let args = &argv[idx + 1..];
        let decision = classify(head, args, false, false, allow_path);
        return apply_argv(argv, idx, &decision, allow_path);
    }
    if pip_command(head) {
        if !allow_path {
            return None;
        }
        let decision = classify_pip(head, &argv[idx + 1..]);
        return apply_argv(argv, idx, &decision, allow_path);
    }
    if allow_path && is_activation(&argv[idx..]) {
        return noted_argv(argv, NOTE_ACTIVATE);
    }
    None
}

fn apply_argv(
    argv: &[String],
    idx: usize,
    decision: &Decision,
    allow_path: bool,
) -> Option<String> {
    if !call_fits(allow_path, decision.file.as_deref()) {
        return None;
    }
    match &decision.map {
        Map::Replace(prefix) => {
            let mut parts = Vec::new();
            for (i, w) in argv.iter().enumerate() {
                if i == idx {
                    parts.push(prefix.clone());
                } else {
                    parts.push(emit_word(w)?);
                }
            }
            Some(parts.join(" "))
        }
        Map::Leave(why) if allow_path && !why.is_empty() => noted_argv(argv, why),
        Map::Leave(_) => None,
    }
}

fn noted_argv(argv: &[String], note: &str) -> Option<String> {
    if !project_here() {
        return None;
    }
    let mut parts = Vec::new();
    for w in argv {
        parts.push(emit_word(w)?);
    }
    parts.push(format!("# {note}"));
    Some(parts.join(" "))
}

enum Map {
    Replace(String),
    Leave(&'static str),
}

struct Decision {
    map: Map,
    /// Set when the program is a file, so a PEP 723 block can ask for uv
    /// without a project file beside the shell.
    file: Option<String>,
}

fn classify(interp: &str, args: &[String], stdin: bool, active: bool, modules: bool) -> Decision {
    let mut i = 0;
    let mut other = false;
    while i < args.len() {
        if let Some(n) = skip_redirect(args, i) {
            i = n;
            continue;
        }
        let a = args[i].as_str();
        if a == "--" {
            return file_decision(args.get(i + 1).map(String::as_str), other, active, interp);
        }
        if a == "-" {
            return stdin_decision(other, true, active, interp);
        }
        if a.starts_with('-') {
            match option_step(&args[i..], other) {
                Step::Flag { words, saw_flag } => {
                    other |= saw_flag;
                    i += words;
                }
                Step::Module { other: flagged } => {
                    return module_decision(other || flagged, modules, active, interp);
                }
                Step::Inline => {
                    return Decision {
                        map: Map::Leave(NOTE_INLINE),
                        file: None,
                    };
                }
                Step::Unknown => {
                    return Decision {
                        map: Map::Leave(NOTE_OPTION),
                        file: None,
                    };
                }
            }
            continue;
        }
        return file_decision(Some(a), other, active, interp);
    }
    if stdin {
        return stdin_decision(other, false, active, interp);
    }
    if other {
        // `python -u` with no script is still that interpreter: a repl
        // when stdin is a terminal, the program when it is a pipe.
        return Decision {
            map: Map::Replace(run_prefix(active, Some(interp), false)),
            file: None,
        };
    }
    // `uv run` is not a repl. The interpreter is left as written.
    Decision {
        map: Map::Leave(NOTE_REPL),
        file: None,
    }
}

fn file_decision(script: Option<&str>, other: bool, active: bool, interp: &str) -> Decision {
    match script {
        Some("-") => stdin_decision(other, true, active, interp),
        Some(path) => Decision {
            map: Map::Replace(run_prefix(active, other.then_some(interp), false)),
            file: Some(path.to_string()),
        },
        None => Decision {
            map: Map::Leave(NOTE_REPL),
            file: None,
        },
    }
}

fn stdin_decision(other: bool, explicit_dash: bool, active: bool, interp: &str) -> Decision {
    // A flag stays on python, which already reads stdin when no file is
    // named. A bare `python <<EOF` does not: uv reads stdin only as `-`.
    let (who, dash) = if other {
        (Some(interp), false)
    } else {
        (None, !explicit_dash)
    };
    Decision {
        map: Map::Replace(run_prefix(active, who, dash)),
        file: None,
    }
}

fn module_decision(other: bool, modules: bool, active: bool, interp: &str) -> Decision {
    if other {
        return Decision {
            map: Map::Replace(run_prefix(active, Some(interp), false)),
            file: None,
        };
    }
    if modules {
        return Decision {
            map: Map::Replace(run_prefix(active, None, false)),
            file: None,
        };
    }
    // The law path leaves a bare `-m` so the pack's refusal stands.
    Decision {
        map: Map::Leave(""),
        file: None,
    }
}

fn classify_pip(_interp: &str, args: &[String]) -> Decision {
    if args.first().map(String::as_str) != Some("install") || !pip_install_same(&args[1..]) {
        return Decision {
            map: Map::Leave(NOTE_PIP),
            file: None,
        };
    }
    Decision {
        map: Map::Replace("uv pip".into()),
        file: None,
    }
}

/// Flags `uv pip install` spells the same way as `pip install`.
/// Anything else is left, so a flag uv does not share cannot change
/// what gets installed.
fn pip_install_same(args: &[String]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            while i < args.len() {
                if args[i].starts_with('-') && args[i] != "-" {
                    return false;
                }
                i += 1;
            }
            break;
        }
        if let Some(rest) = a.strip_prefix("--") {
            let (name, inline) = rest
                .split_once('=')
                .map(|(name, _)| (name, true))
                .unwrap_or((rest, false));
            let valued = matches!(
                name,
                "requirement" | "requirements" | "editable" | "constraint" | "constraints"
            );
            let bare = matches!(
                name,
                "no-deps" | "upgrade" | "quiet" | "verbose" | "dry-run"
            );
            if valued {
                if !inline && i + 1 >= args.len() {
                    return false;
                }
                i += if inline { 1 } else { 2 };
                continue;
            }
            if bare && !inline {
                i += 1;
                continue;
            }
            return false;
        }
        if let Some(cluster) = a.strip_prefix('-') {
            if cluster.is_empty() {
                i += 1;
                continue;
            }
            let c = cluster.chars().next().unwrap();
            let glued = &cluster[c.len_utf8()..];
            match c {
                'r' | 'e' | 'c' => {
                    if glued.is_empty() && i + 1 >= args.len() {
                        return false;
                    }
                    i += if glued.is_empty() { 2 } else { 1 };
                }
                'U' | 'q' | 'v' if glued.is_empty() => i += 1,
                _ => return false,
            }
            continue;
        }
        i += 1;
    }
    true
}

enum Step {
    Flag { words: usize, saw_flag: bool },
    Module { other: bool },
    Inline,
    Unknown,
}

/// One python option at the front of `args`. `-c` and `-m` end the
/// options, as they do for python. `-W` and `-X` take a value. A short
/// cluster runs until one of those.
fn option_step(args: &[String], other_before: bool) -> Step {
    let a = args.first().map(String::as_str).unwrap_or("");
    if let Some(rest) = a.strip_prefix("--") {
        if matches!(
            rest,
            "version" | "help" | "help-env" | "help-xoptions" | "help-all"
        ) {
            return Step::Flag {
                words: 1,
                saw_flag: true,
            };
        }
        if let Some(rest) = rest.strip_prefix("check-hash-based-pycs") {
            if rest.is_empty() && args.len() >= 2 {
                return Step::Flag {
                    words: 2,
                    saw_flag: true,
                };
            }
            if rest.starts_with('=') {
                return Step::Flag {
                    words: 1,
                    saw_flag: true,
                };
            }
        }
        // `--module` and `--command` are not python options. Rewriting
        // them would turn python's error into a uv command.
        return Step::Unknown;
    }
    let Some(cluster) = a.strip_prefix('-') else {
        return Step::Unknown;
    };
    if cluster.is_empty() {
        return Step::Unknown;
    }
    let bytes = cluster.as_bytes();
    let mut k = 0;
    while k < bytes.len() {
        let c = bytes[k] as char;
        if matches!(c, 'c' | 'm' | 'W' | 'X') {
            let glued = k + 1 < bytes.len();
            let words = if glued { 1 } else { 2 };
            if !glued && args.len() < 2 {
                return Step::Unknown;
            }
            let other = other_before || k > 0;
            return match c {
                'c' => Step::Inline,
                // `-mpytest` keeps the glued word on python. `uv run -m`
                // is the separate-argument form (`-m pytest`).
                'm' => Step::Module {
                    other: other || glued,
                },
                _ => Step::Flag {
                    words,
                    saw_flag: true,
                },
            };
        }
        // python's flags that do not take a value. `-OO` is two of `-O`.
        if "bBdEhiIOqRsStuvVx?".contains(c) {
            k += 1;
            continue;
        }
        return Step::Unknown;
    }
    Step::Flag {
        words: 1,
        saw_flag: true,
    }
}

fn skip_redirect(args: &[String], i: usize) -> Option<usize> {
    let w = args.get(i)?.as_str();
    if !is_redirect_op(w) {
        return None;
    }
    if redirect_has_target(w) {
        return Some(i + 1);
    }
    let next = args.get(i + 1).map(String::as_str);
    let skip_target = next.is_some_and(|n| !n.starts_with('-') && !is_redirect_op(n));
    Some(i + 1 + usize::from(skip_target))
}

fn is_redirect_op(w: &str) -> bool {
    let w = w.trim_start_matches(|c: char| c.is_ascii_digit());
    w.starts_with('>') || w.starts_with('<')
}

fn redirect_has_target(w: &str) -> bool {
    let w = w.trim_start_matches(|c: char| c.is_ascii_digit());
    let rest = w.trim_start_matches(['<', '>']);
    let rest = rest.trim_start_matches('&');
    !rest.is_empty()
}

/// `--active` prefers the virtualenv this line just sourced over the
/// project's. `--no-sync` does not install; the python line did not either.
fn run_prefix(active: bool, interp: Option<&str>, stdin_dash: bool) -> String {
    let mut s = String::from("uv run");
    if active {
        s.push_str(" --active --no-sync");
    }
    if let Some(interp) = interp {
        s.push(' ');
        s.push_str(&quote_arg(interp));
    }
    if stdin_dash {
        s.push_str(" -");
    }
    s
}

fn call_fits(allow_path: bool, file: Option<&str>) -> bool {
    if !allow_path {
        return true;
    }
    if project_here() {
        return true;
    }
    file.is_some_and(uv_rewrite_fits)
}

fn project_here() -> bool {
    project_uses_uv(&std::env::current_dir().unwrap_or_default())
}

struct Splice {
    text: String,
    /// Set when a command was left as written. Applied once, on the
    /// outermost script: a `#` inside `$(...)` would comment out the rest.
    note: Option<&'static str>,
}

/// Replace a `python` or `pip` that is the command word. A word that is
/// only an argument stays. Here-document bodies are not commands.
fn splice_python(script: &str, allow_path: bool) -> Option<String> {
    let inner = splice_inner(script, allow_path)?;
    let text = match inner.note {
        Some(why) => append_note(&inner.text, why),
        None => inner.text,
    };
    Some(text)
}

fn splice_inner(script: &str, allow_path: bool) -> Option<Splice> {
    let mut text = script.to_string();
    let mut note = None;
    for (start, end) in nested_regions(&text).into_iter().rev() {
        if let Some(inner) = splice_inner(&text[start..end], allow_path) {
            if inner.text != text[start..end] {
                text.replace_range(start..end, &inner.text);
            }
            if note.is_none() {
                note = inner.note;
            }
        }
    }
    if let Some(top) = splice_top(&text, allow_path) {
        text = top.text;
        if note.is_none() {
            note = top.note;
        }
    }
    if text == script && note.is_none() {
        return None;
    }
    Some(Splice { text, note })
}

fn splice_top(script: &str, allow_path: bool) -> Option<Splice> {
    let mut out = String::new();
    let mut last = 0;
    let mut changed = false;
    let mut note: Option<&'static str> = None;
    let mut active = false;
    let mut saw_activation = false;
    // A later `uv run` is another command. Noting the activation on a
    // second look would rewrite the line again, and the runner would
    // run neither.
    let mut other_command = false;
    for seg in command_segments(script) {
        if seg.before == Sep::Pipe {
            active = false;
        }
        let text = &script[seg.start..seg.end];
        let words = command_words(text);
        if let Some(idx) = run_index(&words) {
            let head = words[idx].as_str();
            let stdin = seg.before == Sep::Pipe || has_stdin_redirect(text);
            let decision = if python_command(head) {
                Some(classify(head, &words[idx + 1..], stdin, active, allow_path))
            } else if allow_path && pip_command(head) {
                Some(classify_pip(head, &words[idx + 1..]))
            } else {
                None
            };
            if let Some(decision) = decision {
                if call_fits(allow_path, decision.file.as_deref()) {
                    match decision.map {
                        Map::Replace(prefix) => {
                            if let Some((at, to)) = token_span(text, head) {
                                out.push_str(&script[last..seg.start + at]);
                                out.push_str(&prefix);
                                last = seg.start + to;
                                changed = true;
                            }
                        }
                        Map::Leave(why) if allow_path && !why.is_empty() && note.is_none() => {
                            note = Some(why);
                        }
                        Map::Leave(_) => {}
                    }
                }
            }
        }
        if is_activation(&words) {
            saw_activation = true;
            active = true;
        } else if run_index(&words).is_some() {
            other_command = true;
        }
    }
    out.push_str(&script[last..]);
    if !changed
        && note.is_none()
        && saw_activation
        && !other_command
        && allow_path
        && project_here()
    {
        note = Some(NOTE_ACTIVATE);
    }
    if !changed && note.is_none() {
        return None;
    }
    Some(Splice { text: out, note })
}

fn append_note(script: &str, note: &str) -> String {
    let suffix = format!(" # {note}");
    match script.find('\n') {
        Some(i) => {
            let mut out = String::with_capacity(script.len() + suffix.len());
            out.push_str(&script[..i]);
            out.push_str(&suffix);
            out.push_str(&script[i..]);
            out
        }
        None => format!("{script}{suffix}"),
    }
}

/// `shell_words` repeats a here-document's delimiter, and a `;`, when
/// the body is not in this segment. The body is not a command, so that
/// repeated name is not a script.
fn command_words(segment: &str) -> Vec<String> {
    let mut words = shell_words(segment);
    for delim in heredoc_names(&words).into_iter().rev() {
        if words.last().map(String::as_str) == Some(";") {
            words.pop();
        }
        if words.last().map(String::as_str) == Some(delim.as_str()) {
            words.pop();
        }
    }
    words
}

fn heredoc_names(words: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        if let Some(name) = attached_heredoc_name(w) {
            out.push(name);
        } else if w == "<<" || w == "<<-" {
            if let Some(next) = words.get(i + 1).map(String::as_str) {
                if next != ";" && !is_redirect_op(next) {
                    out.push(unquote_token(next));
                }
            }
        }
        i += 1;
    }
    out
}

fn attached_heredoc_name(w: &str) -> Option<String> {
    let rest = w.strip_prefix("<<")?;
    if rest.is_empty() || rest.starts_with('<') {
        return None;
    }
    let rest = rest.trim_start_matches('-');
    let rest = rest.strip_prefix('\\').unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }
    Some(unquote_token(rest))
}

fn run_index(words: &[String]) -> Option<usize> {
    let (run, handed) = unwrap_wrappers(words);
    if handed.is_some() || run.is_empty() {
        return None;
    }
    Some(words.len() - run.len())
}

fn token_span(segment: &str, head: &str) -> Option<(usize, usize)> {
    let wanted = unquote_token(head);
    shell_spans(segment).into_iter().find(|(start, end)| {
        let tok = unquote_token(&segment[*start..*end]);
        tok == wanted && (python_command(&tok) || pip_command(&tok))
    })
}

fn is_activation(words: &[String]) -> bool {
    let Some(idx) = run_index(words) else {
        return false;
    };
    let head = words[idx].as_str();
    if head != "source" && head != "." {
        return false;
    }
    words[idx + 1..].iter().any(|w| activate_path(w))
}

fn activate_path(w: &str) -> bool {
    let base = base_of(w.trim_matches(|c| c == '\'' || c == '"'));
    matches!(
        base,
        "activate"
            | "activate.fish"
            | "activate.csh"
            | "activate.nu"
            | "activate.bat"
            | "Activate.ps1"
    )
}

/// A redirection that feeds the command's stdin: a pipe is handled by
/// the separator, this is `<`, `<<` and `<<<` in the command text.
fn has_stdin_redirect(segment: &str) -> bool {
    let b = segment.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < b.len() {
        let c = b[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if q == b'"' && c == b'\\' && i + 1 < b.len() {
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == b'\'' || c == b'"' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == b'\\' && i + 1 < b.len() {
            i += 2;
            continue;
        }
        if c == b'<' && b.get(i + 1) != Some(&b'>') {
            return true;
        }
        i += 1;
    }
    false
}

/// Interiors of `$(...)`, backticks and `(...)` subshells, outermost first.
/// A here-document body is python or data, not a nested shell.
fn nested_regions(script: &str) -> Vec<(usize, usize)> {
    let skip = heredoc_skip(script);
    let b = script.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    let mut skip_at = 0;
    while i < b.len() {
        if let Some(end) = skip_over(&skip, &mut skip_at, i) {
            i = end;
            continue;
        }
        let c = b[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
                i += 1;
                continue;
            }
            if q == b'"' && c == b'\\' && i + 1 < b.len() {
                i += 2;
                continue;
            }
            if q == b'\'' {
                i += 1;
                continue;
            }
        } else if c == b'\'' {
            quote = Some(b'\'');
            i += 1;
            continue;
        } else if c == b'"' {
            quote = Some(b'"');
            i += 1;
            continue;
        }
        if c == b'\\' && i + 1 < b.len() {
            i += 2;
            continue;
        }
        if c == b'`' {
            if let Some(end) = script[i + 1..].find('`') {
                let close = i + 1 + end;
                out.push((i + 1, close));
                i = close + 1;
                continue;
            }
        }
        if c == b'$' && b.get(i + 1) == Some(&b'(') {
            if let Some(close) = match_paren(script, i + 1) {
                out.push((i + 2, close));
                i = close + 1;
                continue;
            }
        }
        if c == b'(' {
            if let Some(close) = match_paren(script, i) {
                out.push((i + 1, close));
                i = close + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn match_paren(script: &str, open: usize) -> Option<usize> {
    let b = script.as_bytes();
    let mut depth = 0;
    let mut i = open;
    let mut quote: Option<u8> = None;
    while i < b.len() {
        let c = b[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == b'\\' && q == b'"' && i + 1 < b.len() {
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == b'\'' || c == b'"' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sep {
    None,
    Pipe,
    Other,
}

struct Seg {
    start: usize,
    end: usize,
    before: Sep,
}

/// Byte ranges of commands in `script`, split on `;`, `|`, `&` and newlines
/// that are not inside quotes. Here-document bodies and their delimiter
/// lines are not commands.
fn command_segments(script: &str) -> Vec<Seg> {
    let skip = heredoc_skip(script);
    let b = script.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    let mut quote = None;
    let mut before = Sep::None;
    let mut skip_at = 0;
    let push = |out: &mut Vec<Seg>, start: usize, end: usize, before: Sep| {
        if end > start {
            out.push(Seg { start, end, before });
        }
    };
    while i < b.len() {
        if let Some(end) = skip_over(&skip, &mut skip_at, i) {
            push(&mut out, start, i.min(end), before);
            // The body is not a command. The next command is a new one.
            before = Sep::Other;
            i = end;
            start = i;
            continue;
        }
        let c = b[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == b'\\' && q == b'"' && i + 1 < b.len() {
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == b'\'' || c == b'"' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == b'|' || c == b'&' {
            let pipe = c == b'|' && b.get(i + 1) != Some(&b'|');
            let doubled = b.get(i + 1) == Some(&c);
            push(&mut out, start, i, before);
            i += if doubled { 2 } else { 1 };
            start = i;
            before = if pipe { Sep::Pipe } else { Sep::Other };
            continue;
        }
        if c == b';' || c == b'\n' {
            push(&mut out, start, i, before);
            i += 1;
            start = i;
            before = Sep::Other;
            continue;
        }
        i += 1;
    }
    push(&mut out, start, b.len(), before);
    out
}

fn skip_over(skip: &[(usize, usize)], at: &mut usize, i: usize) -> Option<usize> {
    while *at < skip.len() && skip[*at].1 <= i {
        *at += 1;
    }
    let (start, end) = *skip.get(*at)?;
    (i >= start && i < end).then_some(end)
}

/// Here-document bodies and the delimiter lines that close them.
/// The opening line stays, because that is the shell command.
fn heredoc_skip(script: &str) -> Vec<(usize, usize)> {
    let b = script.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line_start = 0;
    let mut quote: Option<u8> = None;
    let mut pending: std::collections::VecDeque<(String, bool)> = std::collections::VecDeque::new();
    while i < b.len() {
        if !pending.is_empty() {
            // An unclosed body ends with the script. Stop, or this walk
            // never leaves the last line.
            if i >= b.len() {
                break;
            }
            let line_at = i;
            while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                i += 1;
            }
            let line = &script[line_at..i];
            let Some((delim, tabs)) = pending.front().cloned() else {
                continue;
            };
            let cmp = if tabs {
                line.trim_start_matches('\t')
            } else {
                line
            };
            let closed = cmp == delim;
            if i < b.len() && b[i] == b'\r' {
                i += 1;
            }
            if i < b.len() && b[i] == b'\n' {
                i += 1;
            }
            out.push((line_at, i));
            if closed {
                pending.pop_front();
            }
            continue;
        }
        let c = b[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if q == b'"' && c == b'\\' && i + 1 < b.len() {
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == b'\'' || c == b'"' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == b'\\' && i + 1 < b.len() {
            i += 2;
            continue;
        }
        if c == b'\n' || c == b'\r' {
            let line = &script[line_start..i];
            for delim in heredoc_delims(line) {
                pending.push_back(delim);
            }
            if c == b'\r' && b.get(i + 1) == Some(&b'\n') {
                i += 2;
            } else {
                i += 1;
            }
            line_start = i;
            quote = None;
            continue;
        }
        i += 1;
    }
    out
}

/// Delimiters opened on one shell line, in order. `<<-` strips tabs.
/// `<<<` is a here-string, not a here-document.
fn heredoc_delims(line: &str) -> Vec<(String, bool)> {
    let b = line.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if q == b'"' && c == b'\\' && i + 1 < b.len() {
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == b'\'' || c == b'"' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == b'\\' && i + 1 < b.len() {
            i += 2;
            continue;
        }
        if c == b'<' && b.get(i + 1) == Some(&b'<') && b.get(i + 2) != Some(&b'<') {
            i += 2;
            let tabs = b.get(i) == Some(&b'-');
            if tabs {
                i += 1;
            }
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= b.len() {
                break;
            }
            if b.get(i) == Some(&b'\\') {
                // `<<\EOF` quotes the delimiter the way a quoted word does.
                i += 1;
            }
            if i < b.len() && (b[i] == b'\'' || b[i] == b'"') {
                let q = b[i];
                i += 1;
                let start = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                out.push((line[start..i].to_string(), tabs));
                if i < b.len() {
                    i += 1;
                }
                continue;
            }
            let start = i;
            while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b';' | b'|' | b'&')
            {
                i += 1;
            }
            if i > start {
                out.push((line[start..i].to_string(), tabs));
            }
            continue;
        }
        i += 1;
    }
    out
}

fn shell_spans(script: &str) -> Vec<(usize, usize)> {
    let b = script.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        if matches!(b[i], b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>') {
            i += 1;
            if i < b.len() && b[i] == b[i - 1] && matches!(b[i], b'>' | b'<' | b'|' | b'&') {
                i += 1;
            }
            continue;
        }
        let start = i;
        let mut quote = None;
        while i < b.len() {
            let c = b[i];
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                } else if c == b'\\' && q == b'"' && i + 1 < b.len() {
                    i += 1;
                }
                i += 1;
                continue;
            }
            if c == b'\'' || c == b'"' {
                quote = Some(c);
                i += 1;
                continue;
            }
            if c.is_ascii_whitespace()
                || matches!(c, b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')')
            {
                break;
            }
            i += 1;
        }
        if i > start {
            out.push((start, i));
        }
    }
    out
}

fn unquote_token(raw: &str) -> String {
    let b = raw.as_bytes();
    if b.len() >= 2 && (b[0] == b'\'' || b[0] == b'"') && b[0] == b[b.len() - 1] {
        return raw[1..raw.len() - 1].to_string();
    }
    raw.to_string()
}

fn bare_word(w: &str) -> bool {
    !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/-@,:+=".contains(c))
}

fn emit_word(w: &str) -> Option<String> {
    if w.contains('\0') {
        return None;
    }
    if let Some((name, value)) = assignment_of(w) {
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || name.is_empty() {
            return None;
        }
        // An unquoted `$`, `;` or space is expanded by the shell that
        // runs the rewritten line. The argv word was literal.
        if value.is_empty() || bare_word(value) {
            return Some(format!("{name}={value}"));
        }
        return Some(format!("{name}={}", quote_arg(value)));
    }
    if is_redirect_op(w) {
        return Some(w.to_string());
    }
    // A word the shell already quoted is copied with those quotes.
    if w.len() >= 2
        && ((w.starts_with('\'') && w.ends_with('\'')) || (w.starts_with('"') && w.ends_with('"')))
    {
        return Some(w.to_string());
    }
    Some(quote_arg(w))
}

fn assignment_of(w: &str) -> Option<(&str, &str)> {
    let (name, value) = w.split_once('=')?;
    let first = name.chars().next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((name, value))
}

/// One shell word. A newline is `$'\n'` so the verdict stays one line:
/// the runner's shell (bash or zsh) joins it before the command runs.
fn quote_arg(w: &str) -> String {
    if bare_word(w) {
        return w.to_string();
    }
    if !w.contains(['\n', '\r']) {
        return format!("'{}'", w.replace('\'', "'\\''"));
    }
    let mut out = String::new();
    let mut parts = w.split('\n').peekable();
    while let Some(line) = parts.next() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        out.push('\'');
        out.push_str(&line.replace('\'', "'\\''"));
        out.push('\'');
        if parts.peek().is_some() {
            out.push_str("$'\\n'");
        }
    }
    out
}

fn uv_rewrite_fits(script: &str) -> bool {
    let script = unquote_token(script);
    let cwd = std::env::current_dir().unwrap_or_default();
    if project_uses_uv(&cwd) {
        return true;
    }
    let path = std::path::Path::new(script.as_str());
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    pep723_header(&path)
}

fn project_uses_uv(start: &std::path::Path) -> bool {
    let mut dir = Some(start);
    while let Some(d) = dir {
        if d.join("pyproject.toml").is_file() || d.join("uv.lock").is_file() {
            return true;
        }
        dir = d.parent();
    }
    false
}

/// A PEP 723 script block: `# /// script`, then only `#` comment lines,
/// then `# ///`. The block may be longer than a screen.
fn pep723_header(path: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() != "# /// script" {
            i += 1;
            continue;
        }
        i += 1;
        let mut closed = false;
        while i < lines.len() {
            let line = lines[i];
            i += 1;
            if line.trim() == "# ///" {
                closed = true;
                break;
            }
            if !(line == "#" || line.starts_with("# ")) {
                closed = false;
                break;
            }
        }
        if closed {
            return true;
        }
    }
    false
}
