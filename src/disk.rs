//! Paths as the kernel opens them, and the credential directories a
//! mention of a secret store is named by. The shell rules and the
//! inline-program ask share this list.

use std::path::{Component, Path, PathBuf};

/// Path parts that hold a login, a key or a token.
pub(crate) const CREDENTIAL_PARTS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".password-store",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".vault-token",
    ".secrets",
];

/// Longer credential paths, matched as a substring of a spelled path.
pub(crate) const CREDENTIAL_PATHS: &[&str] = &[
    ".config/gh/",
    ".config/gcloud",
    ".config/hub",
    ".config/ljos/",
    ".cargo/credentials",
    ".local/share/keyrings",
    ".codex/auth.json",
    ".claude/.credentials.json",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
];

/// `a/../b` as `b`, without asking the disk.
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// `p` as the kernel opens it: the longest part that exists is read
/// from the disk, with each link followed before a `..` after it, and
/// the rest as spelled.
pub(crate) fn on_disk(p: &Path) -> PathBuf {
    on_disk_at(p, 0)
}

fn on_disk_at(p: &Path, depth: usize) -> PathBuf {
    let parts: Vec<Component> = p.components().collect();
    for k in (1..=parts.len()).rev() {
        let head: PathBuf = parts[..k].iter().collect();
        let rest = parts[k..].iter();
        if let Ok(real) = head.canonicalize() {
            return lexical(&rest.fold(real, |a, c| a.join(c)));
        }
        if let Ok(to) = std::fs::read_link(&head) {
            if depth < 40 {
                let to = head.parent().map_or(to.clone(), |d| d.join(&to));
                return on_disk_at(&rest.fold(to, |a, c| a.join(c)), depth + 1);
            }
        }
    }
    lexical(p)
}

fn inside(p: &Path, work: Option<&Path>) -> bool {
    let tmp = ["/tmp", "/var/tmp", "/dev/shm", "/dev/fd", "/proc/self/fd"];
    let dev = ["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"];
    tmp.iter().any(|t| p.starts_with(t))
        || dev.iter().any(|d| p == Path::new(d))
        || work.is_some_and(|w| p.starts_with(w))
}

fn inside_lexical_and_disk(p: &Path, work: Option<&Path>) -> bool {
    let lexical = lexical(p);
    if !inside(&lexical, work) {
        return false;
    }
    let has_parent = p
        .components()
        .any(|part| matches!(part, Component::ParentDir));
    if !has_parent && skip_on_disk_check(&lexical) {
        return true;
    }
    let tree = work.map(on_disk);
    inside(&on_disk(p), tree.as_deref())
}

fn skip_on_disk_check(p: &Path) -> bool {
    let dev = ["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"];
    dev.iter().any(|d| p == Path::new(d))
        || p.starts_with("/dev/fd")
        || p.starts_with("/proc/self/fd")
}

/// Whether a write to the absolute path `p` goes out of the tree `work`.
pub(crate) fn writes_outside(p: &Path, work: Option<&Path>) -> bool {
    if inside_lexical_and_disk(p, None) {
        return false;
    }
    let tree = work.map(on_disk);
    !inside(&on_disk(p), tree.as_deref())
}

/// Whether `s` names a credential store by a path part such as `.ssh`.
pub(crate) fn names_credential_path(s: &str) -> bool {
    let low = s.to_ascii_lowercase().replace('\\', "/");
    let parts: Vec<&str> = low.split('/').collect();
    parts.iter().any(|p| CREDENTIAL_PARTS.contains(p))
        || CREDENTIAL_PATHS.iter().any(|c| low.contains(c))
        || low.ends_with(".config/ljos")
        || (low.starts_with("/proc/") && low.ends_with("/environ"))
}

/// Whether inline program text mentions a credential path. A part has to
/// stand on its own, so `.secrets.example` and `os.environ` do not.
pub(crate) fn mentions_credential(code: &str) -> bool {
    let low = code.to_ascii_lowercase().replace('\\', "/");
    if CREDENTIAL_PATHS.iter().any(|c| low.contains(c)) || path_mention(&low, ".env") {
        return true;
    }
    if low.contains("/proc/") && low.contains("/environ") {
        return true;
    }
    CREDENTIAL_PARTS.iter().any(|part| path_mention(&low, part))
}

fn path_mention(text: &str, part: &str) -> bool {
    let mut rest = text;
    while let Some(i) = rest.find(part) {
        let before = rest[..i].chars().next_back();
        let after = rest[i + part.len()..].chars().next();
        let before_ok = before.is_none_or(|c| {
            matches!(c, '/' | '~' | '\'' | '"' | ' ' | '(' | ',' | '=' | ':' | '\n')
        });
        let after_ok = after.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'));
        if before_ok && after_ok {
            return true;
        }
        rest = &rest[i + 1..];
    }
    false
}
