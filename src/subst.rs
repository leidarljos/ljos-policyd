//! The scripts a script runs one level down: substitutions, nested
//! constructs, and comments.

use super::{
    heredoc_fed_to_sftp, heredoc_read_as_text, heredoc_runs_script, phase, sftp_batch_lines,
    shell_words, MAX_DEPTH,
};

/// A script and every line it runs inside itself, outermost first: the
/// body of each `$(...)`, backtick pair, `<(...)`, `>(...)` and `( ... )`
/// subshell, read the same way down to [`MAX_DEPTH`] levels. Nothing in
/// single quotes runs, and an escaped `$` is a dollar sign.
pub(crate) fn script_lines(script: &str, depth: usize) -> Vec<String> {
    let _span = phase::enter(phase::SUBST);
    let mut out = vec![script.to_string()];
    if depth < MAX_DEPTH {
        for body in substitutions(script) {
            out.extend(script_lines(&body, depth + 1));
        }
    }
    out
}

/// The end of the construct that opens at `chars[i]`: just past the
/// backtick that closes one, or past the `)` that closes the first `(` at
/// or after `i`. Quotes, escapes and constructs nested inside count; an
/// unclosed one runs to the end.
pub(crate) fn nested_end(chars: &[char], i: usize) -> usize {
    let _span = phase::enter(phase::NESTED);
    let n = chars.len();
    if chars.get(i) == Some(&'`') {
        let mut j = i + 1;
        while j < n {
            match chars[j] {
                '\\' => j += 2,
                '`' => return j + 1,
                _ => j += 1,
            }
        }
        return n;
    }
    let Some(open) = (i..n).find(|k| chars[*k] == '(') else {
        return n;
    };
    let mut depth = 0usize;
    let mut j = open;
    while j < n {
        match chars[j] {
            '\\' => j += 2,
            '#' if starts_comment(chars, j) => {
                while j < n && !matches!(chars[j], '\n' | '\r') {
                    j += 1;
                }
            }
            '\'' => j = (j + 1..n).find(|k| chars[*k] == '\'').map_or(n, |k| k + 1),
            '"' => j = double_end(chars, j),
            '`' => j = nested_end(chars, j),
            '(' => {
                depth += 1;
                j += 1;
            }
            ')' => {
                depth -= 1;
                j += 1;
                if depth == 0 {
                    return j;
                }
            }
            _ => j += 1,
        }
    }
    n
}

/// `#` starts a comment when it is the first character of a word. An
/// apostrophe later on that line is text, not a quote. A `)` that closes
/// `$(...)`, `<(...)` or `>(...)` does not end the word, so `#` after it
/// is still that word.
fn starts_comment(chars: &[char], i: usize) -> bool {
    if chars.get(i) != Some(&'#') {
        return false;
    }
    if i == 0 || chars[i - 1].is_whitespace() || matches!(chars[i - 1], ';' | '&' | '|' | '(') {
        return true;
    }
    chars[i - 1] == ')' && !hash_stays_in_word(chars, i - 1)
}

/// What a `(` opened, so the `)` that closes it can say whether `#` is
/// still inside the word.
#[derive(Clone, Copy, PartialEq)]
enum Paren {
    /// `$(`, `<(`, `>(`. The `)` does not end the word.
    Sub,
    /// A subshell. The `)` ends that token, and `#` is a new word.
    Group,
    /// An array or a function's `()`. The `)` does not end the word.
    Word,
}

/// Whether `chars[close]` (a `)`) leaves the next character in the same
/// word. A substitution, array or function does. A subshell or a case
/// pattern does not.
fn hash_stays_in_word(chars: &[char], close: usize) -> bool {
    let _span = phase::enter(phase::HASH);
    phase::hash_chars(close);
    let n = chars.len();
    if close >= n || chars[close] != ')' {
        return true;
    }
    let mut stack: Vec<Paren> = Vec::new();
    let mut j = 0;
    while j <= close && j < n {
        let c = chars[j];
        if c == '\\' {
            j += 2;
            continue;
        }
        if c == '#' && j != close && hash_scan_comment(chars, j) {
            while j <= close && j < n && !matches!(chars[j], '\n' | '\r') {
                j += 1;
            }
            continue;
        }
        if c == '\'' {
            j += 1;
            while j <= close && j < n && chars[j] != '\'' {
                j += 1;
            }
            j = (j + 1).min(close + 1);
            continue;
        }
        if c == '"' {
            j += 1;
            let mut inner = 0i32;
            while j <= close && j < n && chars[j] != '"' {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '`' {
                    j = skip_backtick(chars, j, close);
                    continue;
                }
                if chars[j] == '$' && chars.get(j + 1) == Some(&'(') {
                    stack.push(Paren::Sub);
                    inner += 1;
                    j += 2;
                    continue;
                }
                if chars[j] == ')' && inner > 0 && stack.last() == Some(&Paren::Sub) {
                    stack.pop();
                    inner -= 1;
                    if j == close {
                        return true;
                    }
                }
                j += 1;
            }
            j = (j + 1).min(n);
            continue;
        }
        if c == '`' {
            j = skip_backtick(chars, j, close);
            continue;
        }
        if c == '(' {
            let nest = if j > 0 && matches!(chars[j - 1], '$' | '<' | '>') {
                Paren::Sub
            } else if opens_subshell(chars, j) {
                Paren::Group
            } else {
                Paren::Word
            };
            stack.push(nest);
            j += 1;
            continue;
        }
        if c == ')' {
            let kind = stack.pop();
            if j == close {
                return matches!(kind, Some(Paren::Sub | Paren::Word));
            }
            j += 1;
            continue;
        }
        j += 1;
    }
    true
}

/// `#` during the paren scan. A `)` is not a comment start here: that is
/// what [`starts_comment`] is deciding, and calling it would loop.
fn hash_scan_comment(chars: &[char], i: usize) -> bool {
    i == 0 || chars[i - 1].is_whitespace() || matches!(chars[i - 1], ';' | '&' | '|' | '(')
}

/// Just past the backtick that closes the one at `chars[open]`, or past
/// `limit` when it does not close.
fn skip_backtick(chars: &[char], open: usize, limit: usize) -> usize {
    let mut k = open + 1;
    let n = chars.len();
    while k < n && k <= limit {
        if chars[k] == '\\' {
            k += 2;
            continue;
        }
        if chars[k] == '`' {
            return k + 1;
        }
        k += 1;
    }
    k
}

/// Just past the `"` that closes the string opening at `chars[i]`.
fn double_end(chars: &[char], i: usize) -> usize {
    let n = chars.len();
    let mut j = i + 1;
    while j < n {
        match chars[j] {
            '\\' => j += 2,
            '"' => return j + 1,
            '$' if chars.get(j + 1) == Some(&'(') => j = nested_end(chars, j),
            '`' => j = nested_end(chars, j),
            _ => j += 1,
        }
    }
    n
}

/// Whether a `(` at `chars[i]` opens a subshell rather than an array
/// (`x=(a b)`) or a function's `()`.
fn opens_subshell(chars: &[char], i: usize) -> bool {
    i == 0 || chars[i - 1].is_whitespace() || matches!(chars[i - 1], ';' | '&' | '|' | '(' | '!')
}

/// Whether a construct whose body runs as commands opens at `chars[i]`.
pub(crate) fn opens_nested(chars: &[char], i: usize, double: bool) -> bool {
    let next = chars.get(i + 1) == Some(&'(');
    match chars[i] {
        '$' => next,
        '`' => true,
        '<' | '>' => !double && next,
        '(' => !double && opens_subshell(chars, i),
        _ => false,
    }
}

/// The bodies a script runs one level down: each `$(...)` (and arithmetic
/// `$((...))`, which can hold one), each backtick pair with `\``, `\\`
/// and `\$` unescaped, and outside double quotes each `<(...)`, `>(...)`
/// and subshell.
fn substitutions(script: &str) -> Vec<String> {
    let _span = phase::enter(phase::SUBST);
    let chars: Vec<char> = script.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut double = false;
    let mut i = 0;
    // Here-documents the current line opens, and where that line starts.
    let mut pending: Vec<(String, bool, bool)> = Vec::new();
    let mut line_at = 0;
    while i < n {
        match chars[i] {
            '<' if !double
                && chars.get(i + 1) == Some(&'<')
                && chars.get(i + 2) != Some(&'<')
                && (i == 0 || chars[i - 1] != '<') =>
            {
                let (doc, end) = heredoc_at(&chars, i + 2);
                pending.extend(doc);
                i = end;
            }
            '\n' if !double && !pending.is_empty() => {
                let line: String = chars[line_at..i].iter().collect();
                let words = shell_words(&line);
                // A shell, python3 -, ssh, docker exec, source, at, and
                // any other reader that does not take the body as plain
                // text runs it as a script, quoted delimiter or not.
                let runs_script = heredoc_runs_script(&words) || !heredoc_read_as_text(&words);
                i += 1;
                // A quoted delimiter expands nothing in the outer shell.
                // An unquoted body expands `$(...)`, backticks and
                // `<(...)` for every reader. Quotes and `#` in that body
                // are literal.
                for (delim, tabs, quoted) in std::mem::take(&mut pending) {
                    let mut body = String::new();
                    while i < n {
                        let eol = (i..n).find(|k| chars[*k] == '\n').unwrap_or(n);
                        let raw: String = chars[i..eol].iter().collect();
                        i = (eol + 1).min(n);
                        let cmp = if tabs {
                            raw.trim_start_matches('\t')
                        } else {
                            raw.as_str()
                        };
                        // `\r` is part of the line, the way bash keeps it
                        // in the delimiter word. `EOF` does not close `EOF\r`.
                        if cmp == delim {
                            break;
                        }
                        body.push_str(&raw);
                        body.push('\n');
                    }
                    if !quoted {
                        for script in heredoc_substitutions(&body) {
                            if !script.trim().is_empty() {
                                out.push(script);
                            }
                        }
                    }
                    if runs_script && !body.trim().is_empty() {
                        // `!` on an sftp batch line marks a local shell command.
                        if heredoc_fed_to_sftp(&words) {
                            out.push(sftp_batch_lines(&body));
                        } else {
                            out.push(body);
                        }
                    }
                }
                line_at = i;
            }
            '\n' if !double => {
                i += 1;
                line_at = i;
            }
            '\\' => i += 2,
            '#' if !double && starts_comment(&chars, i) => {
                while i < n && !matches!(chars[i], '\n' | '\r') {
                    i += 1;
                }
            }
            '\'' if !double => {
                i = (i + 1..n).find(|k| chars[*k] == '\'').map_or(n, |k| k + 1);
            }
            '"' => {
                double = !double;
                i += 1;
            }
            _ if opens_nested(&chars, i, double) => {
                let end = nested_end(&chars, i);
                let tick = chars[i] == '`';
                // `<(cmd)` and `>(cmd)` run. The body is a command.
                let from = if tick || chars[i] == '(' {
                    i + 1
                } else {
                    i + 2
                };
                let closed = end > from && matches!(chars[end - 1], ')' | '`');
                let to = if closed { end - 1 } else { end };
                let body: String = chars[from.min(to)..to].iter().collect();
                let body = if tick {
                    body.replace("\\\\", "\u{0}")
                        .replace("\\`", "`")
                        .replace("\\$", "$")
                        .replace('\u{0}', "\\")
                } else {
                    body
                };
                if !body.trim().is_empty() {
                    out.push(body);
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    out
}

/// Substitutions an unquoted here-document body runs. Bash ignores quotes
/// and `#` in that body, so every `$(...)`, backtick, `<(...)` and
/// `>(...)` counts, including one that follows `#`, `'` or an apostrophe.
/// A backslash escapes the next character. The inside of each
/// substitution is a shell command, so its own quotes and comments still
/// close it.
pub(crate) fn heredoc_substitutions(body: &str) -> Vec<String> {
    let _span = phase::enter(phase::SUBST);
    let chars: Vec<char> = body.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        let tick = chars[i] == '`';
        let proc = matches!(chars[i], '$' | '<' | '>') && chars.get(i + 1) == Some(&'(');
        if tick || proc {
            let end = nested_end(&chars, i);
            let from = if tick { i + 1 } else { i + 2 };
            let closed = end > from && matches!(chars[end - 1], ')' | '`');
            let to = if closed { end - 1 } else { end };
            let inner: String = chars[from.min(to)..to].iter().collect();
            let inner = if tick {
                inner
                    .replace("\\\\", "\u{0}")
                    .replace("\\`", "`")
                    .replace("\\$", "$")
                    .replace('\u{0}', "\\")
            } else {
                inner
            };
            if !inner.trim().is_empty() {
                out.push(inner);
            }
            i = end;
            continue;
        }
        i += 1;
    }
    out
}

/// The here-document a `<<` opens, read from just past it: its
/// delimiter, whether `<<-` strips tabs, and whether the delimiter is
/// quoted. With where the delimiter word ends.
pub(crate) fn heredoc_at(chars: &[char], mut i: usize) -> (Option<(String, bool, bool)>, usize) {
    let tabs = chars.get(i) == Some(&'-');
    if tabs {
        i += 1;
    }
    while chars.get(i).is_some_and(|c| *c == ' ' || *c == '\t') {
        i += 1;
    }
    let mut name = String::new();
    let mut quoted = false;
    let mut quote: Option<char> = None;
    while let Some(&c) = chars.get(i) {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => name.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                quoted = true;
            }
            (None, '\\') => {
                quoted = true;
                if let Some(&n) = chars.get(i + 1) {
                    name.push(n);
                    i += 1;
                }
            }
            // `\r` is not IFS, so it stays in the delimiter word.
            (None, c) if c != '\r' && (c.is_whitespace() || ";&|<>()".contains(c)) => break,
            (None, c) => name.push(c),
        }
        i += 1;
    }
    let doc = (!name.is_empty()).then_some((name, tabs, quoted));
    (doc, i)
}

/// A `NAME=value` or `NAME+=value` word, where NAME may be an array
/// element, `NAME[i]`. The subscript ends at its matching `]` and may
/// hold `=` (`a[b=c]=1`).
pub(crate) fn is_assignment(w: &str) -> bool {
    let end = w
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(w.len());
    if end == 0 || w.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    let mut rest = &w[end..];
    if rest.starts_with('[') {
        let mut depth = 0;
        let close = rest.char_indices().find(|&(_, c)| {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            }
            depth == 0
        });
        let Some((i, _)) = close else {
            return false;
        };
        rest = &rest[i + 1..];
    }
    rest.starts_with('=') || rest.starts_with("+=")
}
