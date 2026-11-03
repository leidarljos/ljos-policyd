//! The parent walk has no step cap. It ends at a terminal, sshd or tmux,
//! at init, at a parent it cannot read, or at a pid it has read before.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// One more parent than the 133 the walk stopped after before it lost its
/// cap, so these chains are deeper than any cap the walk has had.
const DEEP: usize = 134;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

/// The argv of a check under one shell per name, the first name outermost,
/// so the first name is parent `names.len()`. Each shell is a copy of bash
/// with that name, so the walk reads the name as its comm and exe.
fn chain(names: &[&str], dir: &Path) -> Vec<PathBuf> {
    let bash = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|d| d.join("bash"))
        .find(|p| p.is_file())
        .expect("`bash` on PATH");
    let mut argv = Vec::new();
    for name in names {
        let copy = dir.join(name);
        if !copy.exists() {
            std::fs::copy(&bash, &copy).unwrap();
        }
        // `exit $?` keeps bash from exec'ing the next level in its own place.
        argv.extend([copy, "-c".into(), "\"$@\"; exit $?".into(), name.into()]);
    }
    argv.extend(
        [bin(), "check", "--", "rm", "-rf", "/srv/x"]
            .iter()
            .map(PathBuf::from),
    );
    argv
}

fn check_under(names: &[&str], dir: &Path) -> Output {
    let argv = chain(names, dir);
    Command::new(&argv[0])
        .args(&argv[1..])
        .env_remove("LJOS_POLICYD_DAEMON")
        .env("LJOS_POLICYD_DENY_LOG", dir.join("deny.log"))
        .output()
        .expect("run policyd under nested shells")
}

/// Runs the chain in the background of a sh that exits at once, so the
/// chain's root is reparented to init or to the nearest subreaper. A
/// terminal or tmux that runs this test is then not among its parents.
/// Returns the check's stdout and exit code.
fn check_under_orphan(names: &[&str], dir: &Path) -> (String, String) {
    // A check takes milliseconds. This wait only turns a hang into a failure.
    const WAIT: Duration = Duration::from_secs(60);
    let argv = chain(names, dir);
    let (out, code) = (dir.join("out"), dir.join("code"));
    let status = Command::new("sh")
        .arg("-c")
        .arg("(\"$@\" > \"$OUT\"; echo $? > \"$CODE.tmp\"; mv \"$CODE.tmp\" \"$CODE\") &")
        .arg("sh")
        .args(&argv)
        .env("OUT", &out)
        .env("CODE", &code)
        .env_remove("LJOS_POLICYD_DAEMON")
        .env("LJOS_POLICYD_DENY_LOG", dir.join("deny.log"))
        .status()
        .expect("start the orphaned chain");
    assert!(status.success());
    let start = Instant::now();
    while !code.exists() {
        assert!(start.elapsed() < WAIT, "the orphaned check did not finish");
        std::thread::sleep(Duration::from_millis(10));
    }
    (
        std::fs::read_to_string(out).unwrap(),
        std::fs::read_to_string(code).unwrap(),
    )
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("policyd-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_check_from_seats_nested_past_every_old_cap_names_a_person() {
    // A seat is a coding CLI and the bash its command tool runs, and the
    // next seat starts from that bash. The innermost seat's hook runner
    // runs `ljos hook` through sh, and ljos runs the check.
    const SEAT: [&str; 2] = ["node", "bash"];
    const HOOK: [&str; 3] = ["node", "sh", "ljos"];
    let mut names = vec!["tmux", "bash"];
    while names.len() + HOOK.len() < DEEP {
        names.extend(SEAT);
    }
    names.extend(HOOK);
    let dir = temp_dir("walk-nested-seats");
    let out = check_under(&names, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let line = String::from_utf8(out.stdout).unwrap();
    assert!(
        line.starts_with("allow\twarn\trm-rf-outside-tmp ancestry=person\t"),
        "tmux at parent {}: {line}",
        names.len()
    );
}

#[test]
fn a_deep_chain_with_no_terminal_ends_at_init_and_the_check_still_answers() {
    let names = vec!["sh"; DEEP];
    let dir = temp_dir("walk-to-init");
    let (line, code) = check_under_orphan(&names, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code.trim(), "0", "{line}");
    assert!(
        line.starts_with("allow\twarn\trm-rf-outside-tmp\t"),
        "{line}"
    );
}
