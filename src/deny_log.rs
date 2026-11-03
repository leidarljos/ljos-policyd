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

/// The argv a deny-log line stands for. The log keeps the words joined by
/// one space, so a shell `-c` script is read back as that one script word
/// and any other line is split on spaces; quoting inside a word is lost,
/// and a replay is as close as the log allows.
#[must_use]
pub fn replay_argv(line: &str) -> Vec<String> {
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
    let flat = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{secs}\t{}\t{}\n", flat(token), flat(&argv.join(" ")));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    use std::io::Write;
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}
