//! Credential reads: file readers, `head` and `wc` counts, and uploads of a
//! secrets file.

use super::{base_of, commands, disk, is_assignment, is_redirection, redirection_body};

/// Programs whose words name files they read out to the line.
const FILE_READERS: &[&str] = &[
    "cat",
    "tac",
    "head",
    "tail",
    "less",
    "more",
    "most",
    "bat",
    "batcat",
    "nl",
    "od",
    "xxd",
    "hexdump",
    "strings",
    "base64",
    "base32",
    "cp",
    "scp",
    "rsync",
    "tar",
    "zip",
    "gzip",
    "zcat",
    "bzcat",
    "xzcat",
    "dd",
    "install",
    "diff",
    "cmp",
    "sort",
    "uniq",
    "cut",
    "paste",
    "wc",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "b2sum",
    "cksum",
    "grep",
    "egrep",
    "fgrep",
    "sed",
    "awk",
    "gawk",
    "jq",
    "yq",
];

/// A credential read on the line. A `wc` that only counts (`-c`, `-l`,
/// `-m`, `-w`) warns. So does that count together with `head -c` of at
/// most 4 bytes of the same path. Any other reader denies, including
/// `head -c` of 5 or more, `head -n`, plain `head`, and `head -c` of 4
/// bytes with no count of that path on the line.
pub(crate) enum CredRead {
    None,
    Count(String, String),
    Deny(String, String),
}

/// A pure `head -c N` (or `--bytes N`). Anything else `head` does is not
/// this, so a line count or a plain `head` stays a content read.
#[derive(Clone, Copy)]
enum HeadBytes {
    NotHead,
    Bytes(u64),
    Other,
}

/// A credential path the line reads, with what reads it: a file reader's
/// word, an input redirect, or a string an inline perl, ruby or node
/// program spells. Python, perl, ruby and node inline text that names a credential path asks.
pub(crate) fn credential_read(argv: &[String]) -> CredRead {
    let named = |w: &str| credential_named(w).then(|| w.to_string());
    let mut counts: Vec<(String, String)> = Vec::new();
    let mut prefixes: Vec<(String, String, u64)> = Vec::new();
    let mut deny: Option<(String, String)> = None;
    let mut note_deny = |by: String, path: String| {
        if deny.is_none() {
            deny = Some((by, path));
        }
    };
    for cmd in commands(argv) {
        let counting = wc_count_command(&cmd);
        let prefix = head_bytes(&cmd);
        let mut words = cmd.iter().copied().peekable();
        while let Some(w) = words.next() {
            let body = redirection_body(w);
            if body.starts_with("<(") || body.starts_with(">(") {
                continue;
            }
            if body.starts_with('<') && !body.starts_with("<<") {
                let target = body.trim_start_matches(['<', '>']);
                let target = if target.is_empty() {
                    words.peek().copied().unwrap_or("")
                } else {
                    target
                };
                if let Some(p) = named(target) {
                    if counting {
                        counts.push(("<".into(), p));
                    } else if let HeadBytes::Bytes(n) = prefix {
                        prefixes.push(("<".into(), p, n));
                    } else {
                        note_deny("<".into(), p);
                    }
                }
            }
        }
        let Some(at) = cmd
            .iter()
            .position(|w| !is_assignment(w) && !is_redirection(w))
        else {
            continue;
        };
        let head = base_of(cmd[at]);
        if FILE_READERS.contains(&head) {
            if let Some(p) = read_sources(head, &cmd[at + 1..])
                .into_iter()
                .find_map(named)
            {
                if counting && head == "wc" {
                    counts.push((head.to_string(), p));
                } else if head == "head" {
                    if let HeadBytes::Bytes(n) = prefix {
                        prefixes.push((head.to_string(), p, n));
                    } else {
                        note_deny(head.to_string(), p);
                    }
                } else {
                    note_deny(head.to_string(), p);
                }
            }
        }
        if matches!(head, "curl" | "wget") {
            if let Some(p) = upload_files(head, &cmd[at + 1..])
                .into_iter()
                .find_map(named)
            {
                note_deny(head.to_string(), p);
            }
        }
    }
    if let Some((by, path)) = deny {
        return CredRead::Deny(by, path);
    }
    for (by, path, n) in prefixes {
        let counted = counts
            .iter()
            .any(|(_, counted)| same_cred_path(counted, &path));
        if n > 4 || !counted {
            return CredRead::Deny(by, path);
        }
    }
    match counts.into_iter().next() {
        Some((by, path)) => CredRead::Count(by, path),
        None => CredRead::None,
    }
}

/// The spelled path, so `file` and `"file"` name one secrets file.
fn same_cred_path(a: &str, b: &str) -> bool {
    a.trim_matches(['"', '\'']) == b.trim_matches(['"', '\''])
}

/// `head -c N` or `head --bytes N`, and only that. `N` is the byte count.
/// A line count, a second mode, or a bare `head` is [`HeadBytes::Other`].
fn head_bytes(cmd: &[&str]) -> HeadBytes {
    let Some(at) = cmd
        .iter()
        .position(|w| !is_assignment(w) && !is_redirection(w))
    else {
        return HeadBytes::NotHead;
    };
    if base_of(cmd[at]) != "head" {
        return HeadBytes::NotHead;
    }
    let args = &cmd[at + 1..];
    let mut n: Option<u64> = None;
    let mut i = 0;
    let mut opts = true;
    while i < args.len() {
        let w = args[i];
        if is_redirection(w) || is_assignment(w) {
            i += 1;
            continue;
        }
        if opts && w == "--" {
            opts = false;
            i += 1;
            continue;
        }
        if opts && w.starts_with('-') {
            let take = |raw: &str, n: &mut Option<u64>| -> bool {
                match byte_count(raw) {
                    Some(k) if n.is_none() => {
                        *n = Some(k);
                        true
                    }
                    _ => false,
                }
            };
            if let Some(rest) = w.strip_prefix("--bytes=") {
                if !take(rest, &mut n) {
                    return HeadBytes::Other;
                }
            } else if w == "--bytes" || w == "-c" {
                let Some(raw) = args.get(i + 1).copied() else {
                    return HeadBytes::Other;
                };
                if !take(raw, &mut n) {
                    return HeadBytes::Other;
                }
                i += 2;
                continue;
            } else if let Some(rest) = w.strip_prefix("-c").filter(|r| !r.is_empty()) {
                if !take(rest, &mut n) {
                    return HeadBytes::Other;
                }
            } else {
                return HeadBytes::Other;
            }
            i += 1;
            continue;
        }
        i += 1;
    }
    match n {
        Some(k) => HeadBytes::Bytes(k),
        None => HeadBytes::Other,
    }
}

/// A decimal byte count, with no suffix.
fn byte_count(raw: &str) -> Option<u64> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

/// `wc` with only a count flag: `-c`, `-l`, `-m`, `-w`, or the long form
/// of one of those. `wc FILE` with no such flag prints three counts and
/// stays a deny. `--` ends the flags and is not itself a count.
fn wc_count_command(cmd: &[&str]) -> bool {
    let Some(at) = cmd
        .iter()
        .position(|w| !is_assignment(w) && !is_redirection(w))
    else {
        return false;
    };
    if base_of(cmd[at]) != "wc" {
        return false;
    }
    let mut saw = false;
    let mut opts = true;
    for w in &cmd[at + 1..] {
        if is_redirection(w) || is_assignment(w) {
            continue;
        }
        if opts && *w == "--" {
            opts = false;
            continue;
        }
        if opts && w.starts_with('-') {
            if !wc_count_flag(w) {
                return false;
            }
            saw = true;
        }
    }
    saw
}

/// One `wc` option that only asks for bytes, lines, characters or words.
fn wc_count_flag(w: &str) -> bool {
    match w {
        "--bytes" | "--lines" | "--chars" | "--words" => true,
        s if s.starts_with("--") => false,
        s if s.starts_with('-') && s.len() > 1 => {
            s[1..].chars().all(|c| matches!(c, 'c' | 'l' | 'm' | 'w'))
        }
        _ => false,
    }
}

/// Files a curl or wget invocation uploads. `@file` and `<file` are file
/// reads. A literal data string is not.
fn upload_files<'a>(head: &str, args: &[&'a str]) -> Vec<&'a str> {
    let flags: &[&str] = if head == "wget" {
        &["--post-file", "--body-file"]
    } else {
        &[
            "--upload-file",
            "-T",
            "-d",
            "--data",
            "--data-binary",
            "--data-urlencode",
            "-F",
            "--form",
        ]
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if flags.contains(&a) {
            if let Some(v) = args.get(i + 1).copied() {
                if head == "wget" || matches!(a, "-T" | "--upload-file") {
                    out.push(v.trim_start_matches('@'));
                } else if let Some(p) = file_upload(v) {
                    out.push(p);
                }
            }
            i += 2;
            continue;
        }
        if head == "curl" {
            if let Some(v) = a.strip_prefix("-T").filter(|v| !v.is_empty()) {
                out.push(
                    v.trim_start_matches('@')
                        .trim_matches(|c| c == '"' || c == '\''),
                );
                i += 1;
                continue;
            }
            if let Some(v) = a.strip_prefix("--upload-file=") {
                out.push(v.trim_start_matches('@'));
                i += 1;
                continue;
            }
            if let Some(v) = a
                .strip_prefix("--data=")
                .or_else(|| a.strip_prefix("--data-binary="))
                .or_else(|| a.strip_prefix("--data-urlencode="))
                .or_else(|| a.strip_prefix("--form="))
                .or_else(|| a.strip_prefix("-d"))
                .or_else(|| a.strip_prefix("-F"))
                .filter(|v| !v.is_empty())
            {
                if let Some(p) = file_upload(v) {
                    out.push(p);
                }
            }
        } else if let Some(v) = a
            .strip_prefix("--post-file=")
            .or_else(|| a.strip_prefix("--body-file="))
        {
            out.push(v);
        }
        i += 1;
    }
    out
}

/// `@path`, `<path`, or `field=@path` from a curl upload or form.
fn file_upload(v: &str) -> Option<&str> {
    let body = v.split(';').next().unwrap_or(v);
    let spec = body.rsplit('=').next().unwrap_or(body);
    let spec = spec.trim_matches(|c| c == '\'' || c == '"');
    spec.strip_prefix('@')
        .or_else(|| spec.strip_prefix('<'))
        .filter(|p| !p.is_empty())
}

/// The word names a credential path, or a symlink whose target does.
fn credential_named(w: &str) -> bool {
    let w = w.trim_matches(|c| c == '"' || c == '\'');
    if disk::names_credential_path(w) {
        return true;
    }
    let path = std::path::Path::new(w);
    if let Ok(target) = std::fs::read_link(path) {
        let abs = if target.is_absolute() {
            target
        } else {
            path.parent()
                .unwrap_or(std::path::Path::new("/"))
                .join(target)
        };
        if disk::names_credential_path(&abs.to_string_lossy()) {
            return true;
        }
    }
    std::fs::canonicalize(path)
        .ok()
        .is_some_and(|p| disk::names_credential_path(&p.to_string_lossy()))
}

/// The words of a [`FILE_READERS`] call that name what it reads. The
/// place a copy, an archive or `dd` writes to is left to the write checks.
fn read_sources<'a>(head: &str, args: &[&'a str]) -> Vec<&'a str> {
    let mut out: Vec<&'a str> = Vec::new();
    let mut skip_next = false;
    for (i, w) in args.iter().copied().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if is_redirection(w) {
            continue;
        }
        let takes_value = match head {
            "cp" | "install" | "rsync" | "scp" => matches!(w, "-t" | "--target-directory"),
            "tar" => matches!(w, "-C" | "--directory"),
            "sort" => matches!(w, "-o" | "--output"),
            _ => false,
        };
        if takes_value {
            skip_next = true;
            continue;
        }
        let write_opt = w.starts_with("--target-directory=")
            || w.starts_with("--directory=")
            || w.starts_with("--output=")
            || (head == "dd" && !w.starts_with("if="));
        if !(write_opt || (i > 0 && is_redirection(args[i - 1]))) {
            out.push(w);
        }
    }
    if matches!(head, "cp" | "install" | "rsync" | "scp")
        && !args
            .iter()
            .any(|w| *w == "-t" || w.starts_with("--target-directory"))
    {
        if let Some(last) = out.iter().rposition(|w| !w.starts_with('-')) {
            out.remove(last);
        }
    }
    if head == "zip" {
        if let Some(first) = out.iter().position(|w| !w.starts_with('-')) {
            out.remove(first);
        }
    }
    out
}
