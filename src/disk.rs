//! Paths as the kernel opens them: a link on the way followed, the rest
//! as spelled.

use std::path::{Component, Path, PathBuf};

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
