use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const SHELL_WORDS: usize = 0;
pub const SUBST: usize = 1;
pub const NESTED: usize = 2;
pub const HASH: usize = 3;
pub const TABLE: usize = 4;
pub const WALK: usize = 5;
pub const OBSERVE: usize = 7;
pub const RULES: usize = 8;
pub const INNER: usize = 9;
const N: usize = 10;

#[cfg(test)]
const NAMES: [&str; N] = [
    "parsing shell words",
    "substitution scan",
    "nested construct scan",
    "comment paren scan",
    "per-line rule walk",
    "script walk",
    "python",
    "scratch observe",
    "argv rules",
    "inner command split",
];

static ON: AtomicBool = AtomicBool::new(false);

struct Frame {
    slot: usize,
    start: Instant,
    child: Duration,
}

struct Rec {
    exclusive: [Duration; N],
    calls: [u64; N],
    hash_chars: u64,
    stack: Vec<Frame>,
    walk_buckets: [u64; 6],
}

thread_local! {
    static REC: RefCell<Rec> = const {
        RefCell::new(Rec {
            exclusive: [Duration::ZERO; N],
            calls: [0; N],
            hash_chars: 0,
            stack: Vec::new(),
            walk_buckets: [0; 6],
        })
    };
}

pub struct Guard(bool);

#[cfg(test)]
pub fn enable() {
    ON.store(true, Ordering::Relaxed);
    REC.with(|r| {
        let mut r = r.borrow_mut();
        r.exclusive = [Duration::ZERO; N];
        r.calls = [0; N];
        r.hash_chars = 0;
        r.stack.clear();
        r.walk_buckets = [0; 6];
    });
}

#[cfg(test)]
pub fn disable() {
    ON.store(false, Ordering::Relaxed);
}

pub fn enter(slot: usize) -> Guard {
    if !ON.load(Ordering::Relaxed) {
        return Guard(false);
    }
    REC.with(|r| {
        let mut r = r.borrow_mut();
        r.calls[slot] += 1;
        r.stack.push(Frame {
            slot,
            start: Instant::now(),
            child: Duration::ZERO,
        });
    });
    Guard(true)
}

pub fn walk_words(n: usize) {
    if !ON.load(Ordering::Relaxed) {
        return;
    }
    let bucket = match n {
        0..=8 => 0,
        9..=32 => 1,
        33..=128 => 2,
        129..=512 => 3,
        513..=2048 => 4,
        _ => 5,
    };
    REC.with(|r| r.borrow_mut().walk_buckets[bucket] += 1);
}

pub fn hash_chars(n: usize) {
    if !ON.load(Ordering::Relaxed) {
        return;
    }
    REC.with(|r| r.borrow_mut().hash_chars += n as u64);
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.0 {
            return;
        }
        REC.with(|r| {
            let mut r = r.borrow_mut();
            let Some(frame) = r.stack.pop() else {
                return;
            };
            let total = frame.start.elapsed();
            r.exclusive[frame.slot] += total.saturating_sub(frame.child);
            if let Some(parent) = r.stack.last_mut() {
                parent.child += total;
            }
        });
    }
}

#[cfg(test)]
pub fn report() -> String {
    REC.with(|r| {
        let r = r.borrow();
        let mut total = Duration::ZERO;
        let mut lines = Vec::new();
        for (i, name) in NAMES.iter().enumerate() {
            total += r.exclusive[i];
            if r.calls[i] == 0 {
                continue;
            }
            lines.push(format!(
                "  {name}: {:?} ({} calls)",
                r.exclusive[i], r.calls[i]
            ));
        }
        if r.hash_chars > 0 {
            lines.push(format!("  comment paren chars scanned {}", r.hash_chars));
        }
        let labels = ["1-8", "9-32", "33-128", "129-512", "513-2048", "2049+"];
        let buckets: Vec<String> = r
            .walk_buckets
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .map(|(i, n)| format!("{}:{n}", labels[i]))
            .collect();
        if !buckets.is_empty() {
            lines.push(format!("  walk argv sizes {}", buckets.join(" ")));
        }
        format!("exclusive phases {total:?}\n{}", lines.join("\n"))
    })
}
