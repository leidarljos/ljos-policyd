//! git push's long options, for reading an abbreviated one the way git
//! does. The host reads a push to know whether it rewrites a default
//! branch, the checkout fact the pack has no access to.

use std::borrow::Cow;

pub(crate) const GIT_PUSH_LONG: &[&str] = &[
    "--all",
    "--atomic",
    "--delete",
    "--dry-run",
    "--exec",
    "--follow-tags",
    "--force",
    "--force-if-includes",
    "--force-with-lease",
    "--mirror",
    "--no-force-with-lease",
    "--no-thin",
    "--no-verify",
    "--porcelain",
    "--progress",
    "--prune",
    "--push-option",
    "--quiet",
    "--receive-pack",
    "--recurse-submodules",
    "--repo",
    "--set-upstream",
    "--signed",
    "--tags",
    "--thin",
    "--verbose",
];

/// A unique prefix of one long option becomes that option. An exact name
/// wins, so `--force` is not `--force-with-lease`.
pub(crate) fn expand_long<'a>(word: &'a str, options: &[&str]) -> Cow<'a, str> {
    let (name, eq) = match word.split_once('=') {
        Some((n, v)) if n.starts_with("--") => (n, Some(v)),
        _ => (word, None),
    };
    if !name.starts_with("--") || name == "--" {
        return Cow::Borrowed(word);
    }
    let chosen = if options.contains(&name) {
        name
    } else {
        let mut hits = options.iter().copied().filter(|o| o.starts_with(name));
        match (hits.next(), hits.next()) {
            (Some(one), None) => one,
            _ => return Cow::Borrowed(word),
        }
    };
    match eq {
        Some(v) => Cow::Owned(format!("{chosen}={v}")),
        None if chosen == word => Cow::Borrowed(word),
        None => Cow::Owned(chosen.to_string()),
    }
}
