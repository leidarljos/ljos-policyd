//! The one inline python that may read a secret, named in a config file
//! the user owns and nowhere in this crate.
//!
//! ```toml
//! [relay]
//! seat = "relay"
//! dir = "/srv/relay"
//! secret = "EXAMPLE_TOKEN"
//! ```
//!
//! The file is `$LJOS_POLICYD_CONFIG`, else
//! `$XDG_CONFIG_HOME/ljos-policyd/config.toml`, else
//! `~/.config/ljos-policyd/config.toml`. A file that is missing, not a
//! regular file, owned by someone else, writable by group or world, or
//! not exactly the three keys above names no relay.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The seat the relay runs for, the directory it runs in, and the
/// variable `nimvault run --env` hands it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Relay {
    pub(crate) seat: String,
    pub(crate) dir: PathBuf,
    pub(crate) secret: String,
}

static CONFIG: OnceLock<Option<Relay>> = OnceLock::new();

/// Reads the config file once, so every check in the process sees the
/// relay the process started with.
pub fn load_config() {
    let _ = relay();
}

pub(crate) fn relay() -> Option<&'static Relay> {
    CONFIG
        .get_or_init(|| config_path().and_then(|p| read(&p)))
        .as_ref()
}

fn config_path() -> Option<PathBuf> {
    let var = |n: &str| std::env::var_os(n).filter(|v| !v.is_empty());
    if let Some(p) = var("LJOS_POLICYD_CONFIG") {
        return Some(PathBuf::from(p));
    }
    let base = var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .filter(|p| p.is_absolute())
        })?;
    Some(base.join("ljos-policyd").join("config.toml"))
}

pub(crate) fn read(path: &Path) -> Option<Relay> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return None;
    }
    parse(&std::fs::read_to_string(path).ok()?)
}

/// The relay a config text names. Other tables are left alone; inside
/// `[relay]` each of `seat`, `dir` and `secret` must appear once, as a
/// plain double quoted string, and nothing else may.
pub(crate) fn parse(text: &str) -> Option<Relay> {
    let mut in_relay = false;
    let mut seen = false;
    let (mut seat, mut dir, mut secret) = (None, None, None);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_relay = line == "[relay]";
            if in_relay && std::mem::replace(&mut seen, true) {
                return None;
            }
            continue;
        }
        if !in_relay {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        let value = value.trim().strip_prefix('"')?.strip_suffix('"')?;
        if value.contains(['"', '\\']) {
            return None;
        }
        let slot = match key.trim() {
            "seat" => &mut seat,
            "dir" => &mut dir,
            "secret" => &mut secret,
            _ => return None,
        };
        if slot.replace(value.to_string()).is_some() {
            return None;
        }
    }
    let (seat, dir, secret) = (seat?, dir?, secret?);
    let word = |s: &str, ok: fn(char) -> bool| !s.is_empty() && s.chars().all(ok);
    let dir = dir
        .strip_suffix('/')
        .filter(|d| !d.is_empty())
        .unwrap_or(&dir);
    let dir_ok = dir.len() > 1
        && dir.starts_with('/')
        && dir[1..]
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..");
    let ok = word(&seat, |c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && word(&secret, |c| {
            c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'
        })
        && !secret.starts_with(|c: char| c.is_ascii_digit())
        && dir_ok;
    ok.then(|| Relay {
        seat,
        dir: PathBuf::from(dir),
        secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const TEXT: &str = "# relay\n[other]\nseat = \"x\"\n\n[relay]\nseat = \"relay\"\ndir = \"/srv/relay/\"\nsecret = \"EXAMPLE_TOKEN\"\n";

    fn example() -> Relay {
        Relay {
            seat: "relay".into(),
            dir: PathBuf::from("/srv/relay"),
            secret: "EXAMPLE_TOKEN".into(),
        }
    }

    #[test]
    fn the_config_names_one_relay() {
        assert_eq!(parse(TEXT), Some(example()));
        for text in [
            "",
            "[relay]\nseat = \"relay\"\ndir = \"/srv/relay\"\n",
            &TEXT.replace(
                "secret = \"EXAMPLE_TOKEN\"\n",
                "secret = \"EXAMPLE_TOKEN\"\nmode = \"x\"\n",
            ),
            &TEXT.replace("\"relay\"", "\"relay\"\nseat = \"two\""),
            &format!("{TEXT}[relay]\n"),
            &TEXT.replace("/srv/relay/", "srv/relay"),
            &TEXT.replace("/srv/relay/", "/srv/../relay"),
            &TEXT.replace("/srv/relay/", "/"),
            &TEXT.replace("EXAMPLE_TOKEN", "example token"),
            &TEXT.replace("\"relay\"", "relay"),
            &TEXT.replace("\"relay\"", "\"re\\\"lay\""),
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    #[test]
    fn a_config_others_may_write_is_ignored() {
        let dir = std::env::temp_dir().join(format!("relay-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.toml");
        std::fs::write(&file, TEXT).unwrap();
        let mode = |m: u32| std::fs::set_permissions(&file, std::fs::Permissions::from_mode(m));
        mode(0o600).unwrap();
        assert_eq!(read(&file), Some(example()));
        mode(0o644).unwrap();
        assert_eq!(read(&file), Some(example()));
        for m in [0o620, 0o602, 0o666] {
            mode(m).unwrap();
            assert_eq!(read(&file), None, "{m:o}");
        }
        mode(0o600).unwrap();
        let link = dir.join("link.toml");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(read(&link), None);
        assert_eq!(read(&dir.join("missing.toml")), None);
        assert_eq!(read(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
