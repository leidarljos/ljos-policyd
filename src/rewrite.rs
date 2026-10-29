//! Rewrite a python script invocation to `uv run` when the tree asks for uv.

use super::{base_of, commands, is_assignment, shell_script, shell_words, unwrap_wrappers, SHELLS};

fn shell_quote(w: &str) -> String {
    if w.is_empty() {
        return "''".into();
    }
    if w.chars()
        .all(|c| c.is_ascii_alphanumeric() || "._/-@=,:+".contains(c))
    {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', "'\\''"))
    }
}

fn join_line(words: &[String]) -> String {
    words
        .iter()
        .map(|w| shell_quote(w))
        .collect::<Vec<_>>()
        .join(" ")
}

fn python_command(w: &str) -> bool {
    let b = base_of(w);
    let stem = b.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(stem, "python" | "pypy")
}

/// `python x.py` and `python3 x.py` become `uv run x.py`. `python -c`
/// and `python -m` stay as written: `uv run -c` is not a program.
fn rewrite_python_args(args: &[String]) -> Option<Vec<String>> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if a == "-c" || a == "--command" || a == "-m" || a == "--module" {
            return None;
        }
        if a.starts_with('-') && a != "-" {
            return None;
        }
        break;
    }
    if i >= args.len() {
        return None;
    }
    if args[i] == "/dev/stdin" || args[i].starts_with("/dev/") {
        return None;
    }
    let mut out = vec!["uv".into(), "run".into()];
    out.extend(args[i..].iter().cloned());
    Some(out)
}

fn rewrite_words(argv: &[String]) -> Option<Vec<String>> {
    let mut i = 0;
    while i < argv.len() && is_assignment(&argv[i]) {
        i += 1;
    }
    if i < argv.len() && python_command(&argv[i]) {
        let mut out = argv[..i].to_vec();
        out.extend(rewrite_python_args(&argv[i + 1..])?);
        return Some(out);
    }
    let (run, _) = unwrap_wrappers(argv);
    let head = run.first()?;
    if !SHELLS.contains(&base_of(head)) {
        return None;
    }
    let script = shell_script(run)?;
    let words = shell_words(script);
    if commands(&words).len() != 1 {
        return None;
    }
    let inner = rewrite_words(&words)?;
    inner.iter().any(|w| w == "uv").then_some(inner)
}

/// The line a hook should run instead, when this command is a python
/// invocation and the tree asks for uv.
pub(crate) fn rewrite_command(argv: &[String]) -> Option<String> {
    let words = rewrite_words(argv)?;
    if words.as_slice() == argv {
        return None;
    }
    let script = rewritten_script(&words)?;
    if !uv_rewrite_fits(script) {
        return None;
    }
    Some(join_line(&words))
}

fn rewritten_script(words: &[String]) -> Option<&str> {
    let i = words.iter().position(|w| w == "uv")?;
    if words.get(i + 1).map(String::as_str) != Some("run") {
        return None;
    }
    words.get(i + 2).map(String::as_str)
}

/// Rewrite only when this directory or a parent has `pyproject.toml` or
/// `uv.lock`, or the script itself carries a PEP 723 header.
fn uv_rewrite_fits(script: &str) -> bool {
    let cwd = std::env::current_dir().unwrap_or_default();
    if project_uses_uv(&cwd) {
        return true;
    }
    let path = std::path::Path::new(script);
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

fn pep723_header(path: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "# /// script" {
            continue;
        }
        for line in lines.by_ref().take(64) {
            if line.trim() == "# ///" {
                return true;
            }
        }
        return false;
    }
    false
}
