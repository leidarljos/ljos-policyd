//! The person's allow rules, as ljos keeps them in `user-rules.json`
//! under the XDG config home. A rule written at the person's own terminal
//! with the verdict `allow` clears this check for the lines it matches:
//! their word is the verdict, and the table and the pack are not asked.
//! ljos refuses to write such a rule under a runner, so an agent cannot
//! grant itself one.
//!
//! The file is read with the small parser below: this crate is the
//! trusted computing base and takes no JSON dependency.

use std::path::{Path, PathBuf};

/// The rule that cleared a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonAllow {
    pub id: String,
    pub pattern: String,
}

/// `$XDG_CONFIG_HOME/ljos/user-rules.json`, else `~/.config/ljos/user-rules.json`.
#[must_use]
pub fn rules_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })?;
    Some(base.join("ljos").join("user-rules.json"))
}

/// The person's allow rule that matches `argv`, from the seat's file.
#[must_use]
pub fn allows(argv: &[String]) -> Option<PersonAllow> {
    allows_from(&rules_path()?, argv)
}

/// [`allows`] against the rules in `path`. A file that is missing or does
/// not read allows nothing.
#[must_use]
pub fn allows_from(path: &Path, argv: &[String]) -> Option<PersonAllow> {
    let text = std::fs::read_to_string(path).ok()?;
    let rules = person_rules(&text);
    if rules.is_empty() {
        return None;
    }
    let texts = candidates(argv);
    rules
        .into_iter()
        .find(|rule| texts.iter().any(|t| rule_matches(&rule.pattern, t)))
}

/// The live allow rules with the basis `person`, in file order.
fn person_rules(text: &str) -> Vec<PersonAllow> {
    let Some(Json::Arr(rows)) = json::parse(text) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let field = |name: &str| row.get(name).and_then(Json::as_str);
            if row.get("deleted").and_then(Json::as_bool) == Some(true) {
                return None;
            }
            if field("verdict") != Some("allow") || field("basis") != Some("person") {
                return None;
            }
            let pattern = field("pattern")?.trim().to_string();
            if pattern.is_empty() {
                return None;
            }
            Some(PersonAllow {
                id: field("id").unwrap_or("").to_string(),
                pattern,
            })
        })
        .collect()
}

/// The texts a rule is matched against: the argv as one line, each of its
/// pipelines, and for a shell `-c` the script and each of its pipelines.
fn candidates(argv: &[String]) -> Vec<String> {
    let mut out = vec![argv.join(" ")];
    for piece in super::pipelines_of(argv) {
        out.push(piece.join(" "));
    }
    if let Some(script) = shell_script(argv) {
        out.push(script.to_string());
        let words = super::shell_words(script);
        for piece in super::pipelines_of(&words) {
            out.push(piece.join(" "));
        }
    }
    out.retain(|t| !t.trim().is_empty());
    out.dedup();
    out
}

/// The script a `sh -c`, `bash -c`, `zsh -c` or `dash -c` runs.
fn shell_script(argv: &[String]) -> Option<&str> {
    let shell = argv.first()?.rsplit('/').next()?;
    if !matches!(shell, "sh" | "bash" | "zsh" | "dash") {
        return None;
    }
    let at = argv.iter().position(|a| a == "-c")?;
    argv.get(at + 1).map(String::as_str)
}

/// ljos's rule match: a glob over the whole text, where `*` is any run and
/// `?` one character, and a `*` straight after a word goes on past the
/// word's end and not into it, so `git push*` is `git push` and what
/// follows, never `git pushx`. A `re:` pattern needs a regex engine this
/// crate does not carry, so it clears nothing here.
#[must_use]
pub fn rule_matches(pattern: &str, text: &str) -> bool {
    if pattern.starts_with("re:") {
        return false;
    }
    if let Some(stem) = pattern.strip_suffix('*') {
        let word_end = stem
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        if word_end && !stem.contains(['*', '?']) {
            return text.trim().strip_prefix(stem).is_some_and(|rest| {
                rest.chars()
                    .next()
                    .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            });
        }
    }
    glob_matches(pattern, text)
}

fn glob_matches(pattern: &str, line: &str) -> bool {
    fn go(p: &[char], l: &[char]) -> bool {
        match (p.first(), l.first()) {
            (None, None) => true,
            (Some('*'), _) => go(&p[1..], l) || (!l.is_empty() && go(p, &l[1..])),
            (Some('?'), Some(_)) => go(&p[1..], &l[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &l[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let l: Vec<char> = line.trim().chars().collect();
    go(&p, &l)
}

/// A JSON value, as far as the rules file needs.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

mod json {
    use super::Json;

    /// Parse one JSON document. Anything malformed is `None`.
    pub(super) fn parse(text: &str) -> Option<Json> {
        let bytes = text.as_bytes();
        let mut at = 0;
        let value = value(bytes, &mut at, 0)?;
        skip_ws(bytes, &mut at);
        (at == bytes.len()).then_some(value)
    }

    const MAX_DEPTH: usize = 64;

    fn skip_ws(b: &[u8], at: &mut usize) {
        while *at < b.len() && matches!(b[*at], b' ' | b'\t' | b'\n' | b'\r') {
            *at += 1;
        }
    }

    fn value(b: &[u8], at: &mut usize, depth: usize) -> Option<Json> {
        if depth > MAX_DEPTH {
            return None;
        }
        skip_ws(b, at);
        match *b.get(*at)? {
            b'{' => {
                *at += 1;
                let mut pairs = Vec::new();
                skip_ws(b, at);
                if b.get(*at) == Some(&b'}') {
                    *at += 1;
                    return Some(Json::Obj(pairs));
                }
                loop {
                    skip_ws(b, at);
                    let key = string(b, at)?;
                    skip_ws(b, at);
                    if b.get(*at) != Some(&b':') {
                        return None;
                    }
                    *at += 1;
                    let v = value(b, at, depth + 1)?;
                    pairs.push((key, v));
                    skip_ws(b, at);
                    match b.get(*at)? {
                        b',' => *at += 1,
                        b'}' => {
                            *at += 1;
                            return Some(Json::Obj(pairs));
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                *at += 1;
                let mut items = Vec::new();
                skip_ws(b, at);
                if b.get(*at) == Some(&b']') {
                    *at += 1;
                    return Some(Json::Arr(items));
                }
                loop {
                    items.push(value(b, at, depth + 1)?);
                    skip_ws(b, at);
                    match b.get(*at)? {
                        b',' => *at += 1,
                        b']' => {
                            *at += 1;
                            return Some(Json::Arr(items));
                        }
                        _ => return None,
                    }
                }
            }
            b'"' => string(b, at).map(Json::Str),
            b't' if b[*at..].starts_with(b"true") => {
                *at += 4;
                Some(Json::Bool(true))
            }
            b'f' if b[*at..].starts_with(b"false") => {
                *at += 5;
                Some(Json::Bool(false))
            }
            b'n' if b[*at..].starts_with(b"null") => {
                *at += 4;
                Some(Json::Null)
            }
            b'-' | b'0'..=b'9' => {
                let start = *at;
                while *at < b.len()
                    && matches!(b[*at], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    *at += 1;
                }
                std::str::from_utf8(&b[start..*at])
                    .ok()?
                    .parse::<f64>()
                    .ok()
                    .map(Json::Num)
            }
            _ => None,
        }
    }

    fn string(b: &[u8], at: &mut usize) -> Option<String> {
        if b.get(*at) != Some(&b'"') {
            return None;
        }
        *at += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *b.get(*at)?;
            *at += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = *b.get(*at)?;
                    *at += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut code = hex4(b, at)?;
                            if (0xD800..0xDC00).contains(&code) {
                                if b.get(*at) != Some(&b'\\') || b.get(*at + 1) != Some(&b'u') {
                                    return None;
                                }
                                *at += 2;
                                let low = hex4(b, at)?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return None;
                                }
                                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            }
                            let ch = char::from_u32(code)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None,
                    }
                }
                _ => out.push(c),
            }
        }
        String::from_utf8(out).ok()
    }

    fn hex4(b: &[u8], at: &mut usize) -> Option<u32> {
        let s = std::str::from_utf8(b.get(*at..*at + 4)?).ok()?;
        *at += 4;
        u32::from_str_radix(s, 16).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn the_rule_match_is_the_glob_ljos_uses() {
        assert!(rule_matches("git push*", "git push origin main"));
        assert!(rule_matches("git push*", "git push"));
        assert!(!rule_matches("git push*", "git pushx"));
        assert!(rule_matches("*sudo*", "echo a && sudo id"));
        assert!(rule_matches("rm -rf ?", "rm -rf x"));
        assert!(!rule_matches("rm -rf ?", "rm -rf xy"));
        assert!(!rule_matches("re:git push", "git push"));
    }

    #[test]
    fn only_a_live_person_allow_row_clears_a_line() {
        let dir = std::env::temp_dir().join(format!("policyd-person-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("user-rules.json");
        std::fs::write(
            &file,
            r#"[
  {"id": "r1", "text": "push develop", "author": "rohit", "reason": "mine", "pattern": "git push origin HEAD:refs/heads/develop", "verdict": "allow", "basis": "person", "written_at": "2026-10-31T12:00:00Z"},
  {"id": "r2", "text": "gone", "author": "rohit", "reason": "", "pattern": "sudo *", "verdict": "allow", "basis": "person", "written_at": "", "deleted": true},
  {"id": "r3", "text": "agent", "author": "bot", "reason": "", "pattern": "rm -rf *", "verdict": "allow", "basis": "runner", "written_at": ""},
  {"id": "r4", "text": "deny", "author": "rohit", "reason": "", "pattern": "curl *", "verdict": "deny", "basis": "person", "written_at": ""},
  {"id": "r5", "text": "force", "author": "rohit", "reason": "", "pattern": "git push --force origin main", "verdict": "allow", "basis": "person", "written_at": "", "unicode": "\u00e9\ud83d\ude00"}
]"#,
        )
        .unwrap();
        let hit = allows_from(&file, &words("git push origin HEAD:refs/heads/develop")).unwrap();
        assert_eq!(hit.id, "r1");
        let script = vec![
            "bash".to_string(),
            "-c".to_string(),
            "cd repo && git push --force origin main".to_string(),
        ];
        assert_eq!(allows_from(&file, &script).unwrap().id, "r5");
        assert!(allows_from(&file, &words("sudo id")).is_none(), "deleted");
        assert!(
            allows_from(&file, &words("rm -rf /")).is_none(),
            "runner basis"
        );
        assert!(
            allows_from(&file, &words("curl x")).is_none(),
            "a deny is not an allow"
        );
        assert!(allows_from(&dir.join("missing.json"), &words("git push")).is_none());
        std::fs::write(&file, "[{\"id\": ").unwrap();
        assert!(allows_from(&file, &words("git push origin HEAD:refs/heads/develop")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_json_reader_takes_the_file_shape_and_refuses_the_rest() {
        assert_eq!(json::parse(" [ ] "), Some(Json::Arr(Vec::new())));
        assert_eq!(
            json::parse(r#"{"a": [1, true, null, "x\n\u0041"]}"#),
            Some(Json::Obj(vec![(
                "a".into(),
                Json::Arr(vec![
                    Json::Num(1.0),
                    Json::Bool(true),
                    Json::Null,
                    Json::Str("x\nA".into())
                ])
            )]))
        );
        for bad in ["[1,]", "{\"a\" 1}", "[1] x", "\"open", "[\"\\q\"]", "tru"] {
            assert_eq!(json::parse(bad), None, "{bad}");
        }
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert_eq!(json::parse(&deep), None);
    }
}
