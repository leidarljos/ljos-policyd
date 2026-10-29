//! Rewrite a python script invocation to `uv run` when the tree asks for uv.
//!
//! The characters after the interpreter stay as they were. A prefix stays
//! in front. When a word would have to be quoted in a way that changes how
//! a shell reads it, there is no rewrite.

use super::{base_of, is_assignment, shell_words, unwrap_wrappers, wrapper_walk, Walk, SHELLS};

fn python_command(w: &str) -> bool {
    let b = base_of(w);
    let stem = b.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(stem, "python" | "pypy")
}

/// The line a hook should run instead, when this command is a python
/// invocation and the tree asks for uv.
pub(crate) fn rewrite_command(argv: &[String]) -> Option<String> {
    if shell_c(argv) {
        return rewrite_shell(argv);
    }
    rewrite_argv(argv)
}

fn shell_c(argv: &[String]) -> bool {
    let mut i = 0;
    while i < argv.len() && is_assignment(&argv[i]) {
        i += 1;
    }
    i < argv.len() && SHELLS.contains(&base_of(&argv[i])) && argv[i + 1..].iter().any(|w| w == "-c")
}

fn rewrite_shell(argv: &[String]) -> Option<String> {
    let at = argv.iter().position(|w| w == "-c")? + 1;
    if at >= argv.len() {
        return None;
    }
    let script = splice_python(&argv[at])?;
    let file = script_token(&script)?;
    if !uv_rewrite_fits(file) {
        return None;
    }
    let mut parts = Vec::new();
    for (i, w) in argv.iter().enumerate() {
        if i == at {
            parts.push(quote_arg(&script)?);
        } else {
            parts.push(emit_word(w)?);
        }
    }
    Some(parts.join(" "))
}

fn rewrite_argv(argv: &[String]) -> Option<String> {
    let Walk::Run(idx) = wrapper_walk(argv) else {
        return None;
    };
    if idx >= argv.len() || !python_command(&argv[idx]) {
        return None;
    }
    let file = script_arg(&argv[idx + 1..])?;
    if !uv_rewrite_fits(file) {
        return None;
    }
    let mut parts = Vec::new();
    for (i, w) in argv.iter().enumerate() {
        if i == idx {
            parts.push("uv run".into());
        } else {
            parts.push(emit_word(w)?);
        }
    }
    Some(parts.join(" "))
}

/// Replace a `python` that is the command word with `uv run`. A `python`
/// that is only an argument stays. Everything else in `script`, including
/// redirections and quotes, stays byte for byte. `-c` and `-m` are not a
/// script, so they are not rewritten.
fn splice_python(script: &str) -> Option<String> {
    let mut spans = Vec::new();
    for (start, end) in command_segments(script) {
        if let Some((at, to)) = command_python(&script[start..end]) {
            let words = shell_words(&script[start..end]);
            let after = words
                .iter()
                .position(|w| python_command(w))
                .and_then(|i| words.get(i + 1));
            if after.is_some_and(|t| t == "-c" || t == "--command" || t == "-m" || t == "--module")
            {
                continue;
            }
            spans.push((start + at, start + to));
        }
    }
    if spans.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut last = 0;
    for (start, end) in spans {
        out.push_str(&script[last..start]);
        out.push_str("uv run");
        last = end;
    }
    out.push_str(&script[last..]);
    Some(out)
}

/// Byte ranges of commands in `script`, split on `;`, `|`, `&` and newlines
/// that are not inside quotes.
fn command_segments(script: &str) -> Vec<(usize, usize)> {
    let b = script.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
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
        if matches!(c, b';' | b'|' | b'&' | b'\n') {
            if i > start {
                out.push((start, i));
            }
            i += 1;
            start = i;
            continue;
        }
        i += 1;
    }
    if start < b.len() {
        out.push((start, b.len()));
    }
    out
}

/// The span of `python` when it is the command word of this one command.
fn command_python(command: &str) -> Option<(usize, usize)> {
    let words = shell_words(command);
    let (run, handed) = unwrap_wrappers(&words);
    if handed.is_some() {
        return None;
    }
    let head = run.first()?;
    if !python_command(head) {
        return None;
    }
    let spans = shell_spans(command);
    let wanted = unquote_token(head);
    spans.into_iter().find(|(start, end)| {
        unquote_token(&command[*start..*end]) == wanted
            && python_command(&unquote_token(&command[*start..*end]))
    })
}

fn script_token(script: &str) -> Option<&str> {
    let tokens = shell_spans(script);
    let mut saw = false;
    for (start, end) in tokens {
        let text = unquote_token(&script[start..end]);
        if !saw {
            if text == "uv" {
                saw = true;
            }
            continue;
        }
        if text == "run" {
            continue;
        }
        if text == "--" {
            continue;
        }
        if text.starts_with('-') {
            return None;
        }
        return Some(&script[start..end]);
    }
    None
}

fn script_arg(args: &[String]) -> Option<&str> {
    let dashed = args.first().map(String::as_str) == Some("--");
    let i = usize::from(dashed);
    if !dashed && args.first().is_some_and(|a| a.starts_with('-') && a != "-") {
        return None;
    }
    let name = args.get(i)?;
    if name == "/dev/stdin" || name.starts_with("/dev/") {
        return None;
    }
    Some(name)
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
        if end_word(start, i) {
            out.push((start, i));
        }
    }
    out
}

fn end_word(start: usize, end: usize) -> bool {
    end > start
}

fn unquote_token(raw: &str) -> String {
    let b = raw.as_bytes();
    if b.len() >= 2 && (b[0] == b'\'' || b[0] == b'"') && b[0] == b[b.len() - 1] {
        return raw[1..raw.len() - 1].to_string();
    }
    raw.to_string()
}

fn emit_word(w: &str) -> Option<String> {
    if let Some((name, value)) = assignment_of(w) {
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || name.is_empty() {
            return None;
        }
        if value.chars().any(|c| c.is_whitespace() || c == '\'') {
            return Some(format!("{name}='{}'", value.replace('\'', "'\\''")));
        }
        return Some(format!("{name}={value}"));
    }
    // A word the shell already quoted is copied with those quotes.
    if w.len() >= 2
        && ((w.starts_with('\'') && w.ends_with('\'')) || (w.starts_with('"') && w.ends_with('"')))
    {
        return Some(w.to_string());
    }
    if w.chars().any(|c| c.is_whitespace())
        && !w
            .chars()
            .any(|c| "\"'$|&;<>()`".contains(c) || c.is_control())
    {
        return Some(format!("'{w}'"));
    }
    if w.chars()
        .any(|c| c.is_whitespace() || "\"'`$|&;<>()".contains(c) || c.is_control())
    {
        return None;
    }
    Some(w.to_string())
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

fn quote_arg(w: &str) -> Option<String> {
    if w.is_empty() {
        return Some("''".into());
    }
    if w.chars()
        .all(|c| c.is_ascii_alphanumeric() || "._/-@=,:+".contains(c))
    {
        return Some(w.to_string());
    }
    Some(format!("'{}'", w.replace('\'', "'\\''")))
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
