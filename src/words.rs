//! Shell words: the lexer, its quotes and escapes, and brace expansion.

use super::{
    braced, closed_word, heredoc_name, heredoc_operator, is_name, nested_end, opens_nested, phase,
    spelled, take_heredoc_bodies, EXPANDS,
};

/// How many words one brace expansion may produce. Past this the
/// command is not the one the line shows.
const BRACE_CAP: usize = 32;

/// Whether `word` is a bash brace expansion (`{a,b}`, `{1..3}`), not a
/// parameter expansion (`${name}`) and not a lone `{`.
pub(crate) fn brace_expands(word: &str) -> bool {
    !matches!(first_brace(word), Ok(None))
}

#[allow(dead_code)]
struct BraceHit {
    start: usize,
    end: usize,
    alts: Vec<String>,
}

fn first_brace(word: &str) -> Result<Option<BraceHit>, ()> {
    let chars: Vec<(usize, char)> = word.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].1 == '$' && chars.get(i + 1).is_some_and(|(_, c)| *c == '{') {
            i = skip_braced_param(&chars, i);
            continue;
        }
        if chars[i].1 == '{' {
            if let Some(hit) = brace_at(word, &chars, i)? {
                return Ok(Some(hit));
            }
        }
        i += 1;
    }
    Ok(None)
}

fn skip_braced_param(chars: &[(usize, char)], i: usize) -> usize {
    let mut depth = 0i32;
    let mut j = i + 1;
    while j < chars.len() {
        match chars[j].1 {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    chars.len()
}

fn brace_at(word: &str, chars: &[(usize, char)], open: usize) -> Result<Option<BraceHit>, ()> {
    let mut depth = 0i32;
    let mut j = open;
    while j < chars.len() {
        match chars[j].1 {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    let start = chars[open].0;
                    let end = chars.get(j + 1).map_or(word.len(), |(p, _)| *p);
                    let body = &word[chars[open].0 + '{'.len_utf8()..chars[j].0];
                    let Some(alts) = brace_alts(body)? else {
                        return Ok(None);
                    };
                    return Ok(Some(BraceHit { start, end, alts }));
                }
            }
            _ => {}
        }
        j += 1;
    }
    Ok(None)
}

fn brace_alts(body: &str) -> Result<Option<Vec<String>>, ()> {
    if body.contains(',') {
        let mut alts = Vec::new();
        let mut cur = String::new();
        let mut depth = 0i32;
        for c in body.chars() {
            match c {
                '{' => {
                    depth += 1;
                    cur.push(c);
                }
                '}' => {
                    depth -= 1;
                    cur.push(c);
                }
                ',' if depth == 0 => alts.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
        alts.push(cur);
        if alts.len() > BRACE_CAP {
            return Err(());
        }
        return Ok(Some(alts));
    }
    sequence_alts(body)
}

fn sequence_alts(body: &str) -> Result<Option<Vec<String>>, ()> {
    let parts: Vec<&str> = body.split("..").collect();
    if parts.len() != 2 && parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Ok(None);
    }
    let step: i64 = if parts.len() == 3 {
        match parts[2].parse() {
            Ok(n) => n,
            Err(_) => return Ok(None),
        }
    } else {
        1
    };
    let step = if step == 0 { 1 } else { step.abs() };
    if let (Ok(start), Ok(end)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) {
        return num_range(parts[0], parts[1], start, end, step).map(Some);
    }
    let mut ac = parts[0].chars();
    let mut bc = parts[1].chars();
    let (Some(a), Some(b)) = (ac.next(), bc.next()) else {
        return Ok(None);
    };
    if ac.next().is_some() || bc.next().is_some() {
        return Ok(None);
    }
    if !a.is_ascii_alphabetic() || !b.is_ascii_alphabetic() {
        return Ok(None);
    }
    if a.is_ascii_uppercase() != b.is_ascii_uppercase() {
        return Ok(None);
    }
    char_range(a, b, step).map(Some)
}

fn num_range(raw_a: &str, raw_b: &str, start: i64, end: i64, step: i64) -> Result<Vec<String>, ()> {
    let padded = raw_a.starts_with('0') || raw_b.starts_with('0') || raw_a.starts_with("-0");
    let width = if padded {
        raw_a.len().max(raw_b.len())
    } else {
        0
    };
    let dir = if end >= start { step } else { -step };
    let mut n = start;
    let mut out = Vec::new();
    loop {
        if out.len() >= BRACE_CAP {
            return Err(());
        }
        if width == 0 {
            out.push(n.to_string());
        } else if n < 0 {
            out.push(format!("-{:0width$}", -n, width = width.saturating_sub(1)));
        } else {
            out.push(format!("{n:0width$}"));
        }
        if n == end {
            break;
        }
        n = n.checked_add(dir).ok_or(())?;
        if dir > 0 && n > end || dir < 0 && n < end {
            break;
        }
    }
    Ok(out)
}

fn char_range(a: char, b: char, step: i64) -> Result<Vec<String>, ()> {
    let (start, end) = (a as u8, b as u8);
    let dir: i32 = if end >= start {
        step as i32
    } else {
        -(step as i32)
    };
    let mut n = start as i32;
    let end = end as i32;
    let mut out = Vec::new();
    loop {
        if out.len() >= BRACE_CAP {
            return Err(());
        }
        out.push(char::from_u32(n as u32).ok_or(())?.to_string());
        if n == end {
            break;
        }
        n += dir;
        if dir > 0 && n > end || dir < 0 && n < end {
            break;
        }
    }
    Ok(out)
}

fn decode_ansi_c_quoted(chars: &[char], i: &mut usize, out: &mut String) {
    while *i < chars.len() {
        let c = chars[*i];
        *i += 1;
        if c == '\'' {
            return;
        }
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(esc) = chars.get(*i).copied() else {
            out.push('\\');
            return;
        };
        *i += 1;
        match esc {
            'a' => out.push('\u{0007}'),
            'b' => out.push('\u{0008}'),
            'e' | 'E' => out.push('\u{001b}'),
            'f' => out.push('\u{000c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'v' => out.push('\u{000b}'),
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            '?' => out.push('?'),
            'x' => {
                let mut value = 0u32;
                let mut n = 0;
                while *i < chars.len() && n < 2 {
                    if let Some(d) = chars[*i].to_digit(16) {
                        value = value * 16 + d;
                        *i += 1;
                        n += 1;
                        continue;
                    }
                    break;
                }
                if n == 0 {
                    out.push('x');
                } else if let Some(c) = char::from_u32(value) {
                    out.push(c);
                }
            }
            'u' | 'U' => {
                let max = if esc == 'u' { 4 } else { 8 };
                let mut value = 0u32;
                let mut n = 0;
                while *i < chars.len() && n < max {
                    if let Some(d) = chars[*i].to_digit(16) {
                        value = value * 16 + d;
                        *i += 1;
                        n += 1;
                        continue;
                    }
                    break;
                }
                if n == 0 {
                    out.push(esc);
                } else if let Some(c) = char::from_u32(value) {
                    out.push(c);
                }
            }
            c if matches!(c, '0'..='7') => {
                let mut value = c.to_digit(8).expect("octal digit");
                let mut n = 1;
                while *i < chars.len() && n < 3 {
                    if let Some(d) = chars[*i].to_digit(8) {
                        value = value * 8 + d;
                        *i += 1;
                        n += 1;
                        continue;
                    }
                    break;
                }
                if let Some(c) = char::from_u32(value) {
                    out.push(c);
                }
            }
            c => out.push(c),
        }
    }
}

/// `$name` or `${name}` with nothing else in the word.
fn pure_param(w: &str) -> bool {
    let Some(rest) = w.strip_prefix('$') else {
        return false;
    };
    if let Some(name) = rest.strip_prefix('{') {
        return name.strip_suffix('}').is_some_and(is_name);
    }
    is_name(rest)
}

/// A script split into words the way a shell would: quotes group, a
/// backslash escapes the next character outside single quotes, a
/// backslash and the newline after it drop out, a `#` that starts a word
/// comments out the rest of its line, and `;`, `&&`, `||`, `|` and `&`
/// stand as words of their own. The `&` of a redirection (`2>&1`, `<&3`,
/// `&>log`) stays in its word. A double-quoted `$name` or `${name}` keeps
/// its quotes so a later split can tell `"$x"` from `$x`.
pub(crate) fn shell_words(script: &str) -> Vec<String> {
    let _span = phase::enter(phase::SHELL_WORDS);
    let chars: Vec<char> = script.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut word = false;
    let (mut single, mut double) = (false, false);
    // A double-quoted `$` keeps its quotes, so a later split can tell
    // `"$x"` from `$x`. A quoted word with no `$` stays bare.
    let mut dq_at: Option<usize> = None;
    let mut dq_dollar = false;
    // The word has a character the shell may expand where it stands.
    let mut bare = false;
    // The word has a `{` outside quotes and outside a substitution,
    // which bash may brace-expand.
    let mut bare_brace = false;
    let mut i = 0;
    // Here-documents opened on the command just finished, read from the
    // next line. A body is not the script that follows it: a quote in
    // help text would otherwise swallow the rest of the file.
    let mut pending: std::collections::VecDeque<(String, bool, bool)> =
        std::collections::VecDeque::new();
    let mut want_delim: Option<bool> = None;
    // The word has a quote or a backslash in it, as a here-document
    // delimiter that turns expansion off in its body does.
    let mut quoted = false;
    // Where the words of the line now being read start.
    let mut line_start = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        match c {
            _ if !single && opens_nested(&chars, i - 1, double) => {
                // A substitution or subshell is one piece of its word; its
                // body is read on its own by `script_lines`.
                let end = nested_end(&chars, i - 1);
                cur.extend(&chars[i - 1..end]);
                word = true;
                bare = true;
                i = end;
            }
            '$' if !single && !double && chars.get(i) == Some(&'\'') => {
                i += 1;
                decode_ansi_c_quoted(&chars, &mut i, &mut cur);
                word = true;
                quoted = true;
            }
            '\\' if !single && chars.get(i) == Some(&'\n') => i += 1,
            '\\' if !single => {
                if let Some(n) = chars.get(i) {
                    cur.push(*n);
                    word = true;
                    quoted = true;
                    i += 1;
                }
            }
            '\'' if !double => {
                single = !single;
                word = true;
                quoted = true;
            }
            '"' if !single => {
                quoted = true;
                if double {
                    double = false;
                    // Only a quoted `$name` or `${name}` keeps its quotes.
                    // A longer quoted value is the text inside, as before.
                    if dq_dollar {
                        if let Some(at) = dq_at {
                            if pure_param(&cur[at..]) {
                                cur.insert(at, '"');
                                cur.push('"');
                            }
                        }
                    }
                    dq_at = None;
                    dq_dollar = false;
                } else {
                    double = true;
                    dq_at = Some(cur.len());
                    dq_dollar = false;
                }
                word = true;
            }
            '&' if !single
                && !double
                && ((word && cur.ends_with(['>', '<']))
                    || (!word && chars.get(i) == Some(&'>'))) =>
            {
                cur.push('&');
                word = true;
            }
            // `>|` overwrites a file under noclobber; the `>` before it is
            // bare unless a backslash escapes it.
            '|' if !single
                && !double
                && i >= 2
                && chars[i - 2] == '>'
                && (i < 3 || chars[i - 3] != '\\') =>
            {
                cur.push('|');
                word = true;
            }
            '#' if !single && !double && !word => {
                while i < chars.len() && !matches!(chars[i], '\n' | '\r') {
                    i += 1;
                }
            }
            // `\r` is not IFS. It stays on a here-document delimiter
            // (`<<EOF\r`, `<< 'EOF'\r`, and a bare `<< \r`, whose delimiter
            // is the carriage return). A stray `\r` elsewhere is judged as
            // a command separator and does not start the body: the body
            // starts at `\n`. Bash keeps a stray `\r` in the word; splitting
            // here can only add a command to judge.
            '\r' if !single && !double => {
                // `<<WORD\r` keeps the carriage return on WORD. So does the
                // delimiter word after a bare `<<` or `<<-` (`<< 'EOF'\r`).
                // `<< \r` with no word yet makes `\r` itself the delimiter.
                let delim_word = word
                    && (want_delim.is_some() || (cur.starts_with("<<") && !cur.starts_with("<<<")));
                if delim_word || (!word && want_delim.is_some()) {
                    cur.push('\r');
                    word = true;
                } else {
                    if word {
                        spelled(&cur, !std::mem::take(&mut bare));
                        braced(&cur, std::mem::take(&mut bare_brace));
                        finish_word(
                            std::mem::take(&mut cur),
                            std::mem::take(&mut quoted),
                            &mut out,
                            &mut pending,
                            &mut want_delim,
                        );
                        word = false;
                    }
                    out.push(";".to_string());
                }
            }
            c if !single && !double && (c.is_whitespace() || matches!(c, ';' | '|' | '&')) => {
                if word {
                    spelled(&cur, !std::mem::take(&mut bare));
                    braced(&cur, std::mem::take(&mut bare_brace));
                    finish_word(
                        std::mem::take(&mut cur),
                        std::mem::take(&mut quoted),
                        &mut out,
                        &mut pending,
                        &mut want_delim,
                    );
                    word = false;
                }
                if matches!(c, '\n' | '\r') {
                    out.push(";".to_string());
                    take_heredoc_bodies(&chars, &mut i, &mut out, &mut pending, line_start);
                    line_start = out.len();
                    continue;
                }
                if matches!(c, ';' | '|' | '&') {
                    let mut sep = c.to_string();
                    if chars.get(i) == Some(&c) && c != ';' {
                        sep.push(c);
                        i += 1;
                    }
                    out.push(sep);
                }
            }
            c => {
                if double && c == '$' {
                    dq_dollar = true;
                }
                if !single
                    && (matches!(c, '$' | '`') || (!double && (EXPANDS.contains(&c) || c == '(')))
                {
                    bare = true;
                }
                bare_brace |= c == '{' && !single && !double;
                cur.push(c);
                word = true;
            }
        }
    }
    if word {
        spelled(&cur, !bare);
        braced(&cur, bare_brace);
        finish_word(cur, quoted, &mut out, &mut pending, &mut want_delim);
    }
    take_heredoc_bodies(&chars, &mut i, &mut out, &mut pending, line_start);
    out
}

/// Record a finished word, and a here-document it opens. `<<WORD` names
/// the delimiter. `<<` and `<<-` alone take the next word as the name.
/// `quoted` is whether the word had a quote or a backslash in it.
fn finish_word(
    w: String,
    quoted: bool,
    out: &mut Vec<String>,
    pending: &mut std::collections::VecDeque<(String, bool, bool)>,
    want_delim: &mut Option<bool>,
) {
    let w = closed_word(w);
    if let Some(tabs) = want_delim.take() {
        let name = heredoc_name(&w);
        pending.push_back((name, tabs, quoted));
        out.push(w);
        return;
    }
    if let Some((delim, tabs)) = heredoc_operator(&w) {
        if delim.is_empty() {
            *want_delim = Some(tabs);
        } else {
            pending.push_back((delim, tabs, quoted));
        }
    }
    out.push(w);
}
