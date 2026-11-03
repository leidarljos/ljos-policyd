//! Wall time of `ljos-policyd check` on the command lines the fixtures
//! hold: every argv `ljos hook` sent policyd in the pyopts17 review, and
//! every policydpy2 program in the shapes the hook sends one. Each check is
//! its own process, as a hook spawns it, run one after another.
//!
//! `cargo bench --bench check_latency` prints the table kept in
//! `measurements/check-latency.md`. Set `PHRONESIS_DIR` to bench the build
//! that links phronesis.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ljos-policyd");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Nearest-rank p99 of fewer than 100 samples is the largest one, so 100
/// fresh state directories is the least that gives the cold row a p99.
const COLD_SAMPLES: usize = 100;

/// One argv, and where it came from: the fixture, its line, and for a
/// policydpy2 program the shape the hook sent it in.
struct Line {
    argv: Vec<String>,
    from: String,
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The `A` rows of a pyopts17 set: each is an argv the hook sent for the
/// `L` line above it.
fn pyopts17(name: &str, text: &str) -> Vec<Line> {
    text.lines()
        .enumerate()
        .filter_map(|(i, row)| {
            let row = row.strip_prefix("A\t")?;
            Some(Line {
                argv: row.split('\t').skip(1).map(unescape).collect(),
                from: format!("{name}:{}", i + 1),
            })
        })
        .collect()
}

/// A policydpy2 set: a shell line `S` under `bash -c`, and a program `P`
/// as `python3 -c`, that line under `bash -c`, and the file `printf`
/// writes for python to run.
fn policydpy2(name: &str, text: &str) -> Vec<Line> {
    let bash = |line: String| vec!["bash".to_string(), "-c".to_string(), line];
    let mut out = Vec::new();
    for (i, row) in text.lines().enumerate() {
        let mut fields = row.splitn(3, '\t');
        let (Some(kind), Some(_), Some(body)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let body = unescape(body);
        let shapes = if kind == "S" {
            vec![bash(body)]
        } else {
            let q = format!("'{}'", body.replace('\'', "'\\''"));
            vec![
                vec!["python3".into(), "-c".into(), body],
                bash(format!("python3 -c {q}")),
                bash(format!(
                    "printf {q} > ljos-stdin.py && python3 ljos-stdin.py"
                )),
            ]
        };
        let one = shapes.len() == 1;
        for (shape, argv) in shapes.into_iter().enumerate() {
            let from = if one {
                format!("{name}:{}", i + 1)
            } else {
                format!("{name}:{} shape {shape}", i + 1)
            };
            out.push(Line { argv, from });
        }
    }
    out
}

fn sets() -> Vec<(&'static str, Vec<Line>)> {
    let read = |name: &str| {
        let path = Path::new(FIXTURES).join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    };
    let mut sets = Vec::new();
    for name in [
        "pyopts17/corpus.tsv",
        "pyopts17/ordinary.tsv",
        "pyopts17/risky.tsv",
    ] {
        sets.push((name, pyopts17(name, &read(name))));
    }
    for name in [
        "policydpy2/ordinary.tsv",
        "policydpy2/items.tsv",
        "policydpy2/classes.tsv",
    ] {
        sets.push((name, policydpy2(name, &read(name))));
    }
    sets
}

/// The python project the reviews ran their lines in. It sits under the
/// target directory, not `/tmp`, because a write to `/tmp` is judged
/// apart from a write in the tree.
fn review_tree(root: &Path) -> PathBuf {
    let tree = root.join("w");
    let _ = std::fs::remove_dir_all(root);
    for d in ["src/pkg", "tests", ".git"] {
        std::fs::create_dir_all(tree.join(d)).unwrap();
    }
    for (path, text) in [
        ("src/pkg/__init__.py", "def add(a, b):\n    return a + b\n"),
        (
            "tests/test_a.py",
            "from pkg import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
        ),
        ("data.csv", "a,b\n1,2\n3,4\n"),
        ("data.json", "{\"a\": 1, \"b\": [1, 2]}\n"),
        (
            "pyproject.toml",
            "[project]\nname = \"pkg\"\nversion = \"0.1\"\n",
        ),
        ("hello.py", "print(\"hi\")\n"),
    ] {
        std::fs::write(tree.join(path), text).unwrap();
    }
    tree
}

/// What one check printed and how long the process took, spawn to exit.
struct Sample {
    took: Duration,
    allowed: bool,
}

fn check(argv: &[String], tree: &Path, state: &Path) -> Sample {
    let mut cmd = Command::new(BIN);
    cmd.arg("check")
        .arg("--")
        .args(argv)
        .current_dir(tree)
        .env("PHRONESIS_STATE_DIR", state)
        .env("LJOS_POLICYD_DENY_LOG", state.join("deny.log"));
    for name in [
        "PHRONESIS_WORKSPACE",
        "PHRONESIS_JANET_PACK",
        "LJOS_POLICYD_PACK",
        "LJOS_POLICYD_DAEMON",
        "LJOS_POLICYD_CONFIG",
        "LJOS_USER_ALLOW",
        "LJOS_CONSENT_FILE",
    ] {
        cmd.env_remove(name);
    }
    let started = Instant::now();
    let out = cmd.output().expect("spawn ljos-policyd check");
    let took = started.elapsed();
    Sample {
        took,
        allowed: out.status.success() && out.stdout.starts_with(b"allow"),
    }
}

/// Nearest rank: the smallest sample with at least `p` percent of the
/// samples at or below it.
fn rank(sorted: &[Duration], p: usize) -> Duration {
    sorted[(p * sorted.len()).div_ceil(100) - 1]
}

fn row(label: &str, took: &[Duration]) -> String {
    let mut sorted = took.to_vec();
    sorted.sort();
    let ms = |d: Duration| format!("{:.2}", d.as_secs_f64() * 1e3);
    format!(
        "| {label} | {} | {} | {} | {} | {} |",
        sorted.len(),
        ms(rank(&sorted, 50)),
        ms(rank(&sorted, 95)),
        ms(rank(&sorted, 99)),
        ms(*sorted.last().unwrap()),
    )
}

/// The model name, and the family and model numbers, since a model name
/// can be as bare as "Intel(R) Xeon(R) Processor".
fn cpu_model() -> String {
    let text = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let field = |name: &str| {
        text.lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim() == name)
            .map_or("unknown", |(_, v)| v.trim())
    };
    format!(
        "{} (family {} model {})",
        field("model name"),
        field("cpu family"),
        field("model")
    )
}

fn said(cmd: &mut Command) -> String {
    cmd.output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn main() {
    let sets = sets();
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("check-latency");
    let tree = review_tree(&root);
    let first = &sets[0].1;

    let cold: Vec<Duration> = (0..COLD_SAMPLES)
        .map(|i| {
            let state = root.join(format!("cold-{i}"));
            check(&first[i % first.len()].argv, &tree, &state).took
        })
        .collect();

    let state = root.join("warm");
    // The pack is unpacked here, so no warm row is a first check.
    check(&first[0].argv, &tree, &state);
    let mut all = Vec::new();
    let mut rows = Vec::new();
    let mut not_allowed = Vec::new();
    let mut slowest: Option<(Duration, &str)> = None;
    for (name, lines) in &sets {
        let mut took = Vec::new();
        for line in lines {
            let s = check(&line.argv, &tree, &state);
            if !s.allowed {
                not_allowed.push(line.from.as_str());
            }
            if slowest.is_none_or(|(d, _)| s.took > d) {
                slowest = Some((s.took, line.from.as_str()));
            }
            took.push(s.took);
        }
        rows.push(row(name, &took));
        all.extend(took);
    }

    println!("{}", said(Command::new(BIN).arg("version")));
    println!(
        "cpu: {}, {} cores",
        cpu_model(),
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    let git = |args: &[&str]| {
        let mut cmd = Command::new("git");
        cmd.args(args).current_dir(env!("CARGO_MANIFEST_DIR"));
        cmd
    };
    let changed = git(&[
        "diff",
        "--quiet",
        "HEAD",
        "--",
        "src",
        "build.rs",
        "Cargo.lock",
    ])
    .status()
    .is_ok_and(|s| !s.success());
    println!(
        "commit: {}{}",
        said(&mut git(&["rev-parse", "HEAD"])),
        if changed { ", src changed" } else { "" }
    );
    println!();
    println!("| lines | n | p50 ms | p95 ms | p99 ms | max ms |");
    println!("|---|---:|---:|---:|---:|---:|");
    println!("{}", row("first check, fresh state dir", &cold));
    for r in &rows {
        println!("{r}");
    }
    println!("{}", row("every fixture line, warm", &all));
    println!();
    if let Some((d, from)) = slowest {
        println!("slowest: {from}, {:.2} ms", d.as_secs_f64() * 1e3);
    }
    println!(
        "not allow or not exit 0: {}{}",
        not_allowed.len(),
        if not_allowed.is_empty() {
            String::new()
        } else {
            format!(" ({})", not_allowed.join(", "))
        }
    );
    let _ = std::fs::remove_dir_all(&root);
}
