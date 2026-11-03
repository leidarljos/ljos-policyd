//! The parent walk reads up to `PARENT_WALK_STEPS` parents and then stops.
//! Past the cap the verdict is unchanged; only `ancestry=person` is missing.

use ljos_policyd::PARENT_WALK_STEPS;
use std::path::Path;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

/// Runs a check under one shell per name, the first name outermost, so the
/// first name is parent `names.len()`. Each shell is a copy of bash with
/// that name, so the walk reads the name as its comm and exe.
fn check_under(names: &[&str], dir: &Path) -> Output {
    let bash = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|d| d.join("bash"))
        .find(|p| p.is_file())
        .expect("`bash` on PATH");
    for name in names {
        let copy = dir.join(name);
        if !copy.exists() {
            std::fs::copy(&bash, &copy).unwrap();
        }
    }
    let mut cmd = Command::new(dir.join(names[0]));
    // `exit $?` keeps bash from exec'ing the next level in its own place.
    cmd.args(["-c", "\"$@\"; exit $?", names[0]]);
    for name in &names[1..] {
        cmd.arg(dir.join(name))
            .args(["-c", "\"$@\"; exit $?", name]);
    }
    cmd.args([bin(), "check", "--", "rm", "-rf", "/srv/x"])
        .env_remove("LJOS_POLICYD_DAEMON")
        .env("LJOS_POLICYD_DENY_LOG", dir.join("deny.log"))
        .output()
        .expect("run policyd under nested shells")
}

/// A chain whose `depth`-th parent is tmux and every parent below it is sh.
fn tmux_at(depth: usize) -> Vec<&'static str> {
    let mut names = vec!["tmux"];
    names.resize(depth, "sh");
    names
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("policyd-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn first_line(names: &[&str], name: &str) -> String {
    let dir = temp_dir(name);
    let out = check_under(names, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn a_terminal_at_the_cap_names_a_person() {
    let line = first_line(&tmux_at(PARENT_WALK_STEPS), "walk-at-cap");
    assert!(
        line.starts_with("allow\twarn\trm-rf-outside-tmp ancestry=person\t"),
        "{line}"
    );
}

#[test]
fn a_terminal_past_the_cap_leaves_the_verdict_and_drops_only_the_ancestry_note() {
    let line = first_line(&tmux_at(PARENT_WALK_STEPS + 1), "walk-past-cap");
    assert!(
        line.starts_with("allow\twarn\trm-rf-outside-tmp\t"),
        "{line}"
    );
}

#[test]
fn a_check_from_seats_nested_up_to_the_cap_names_a_person() {
    // A seat is a harness CLI and the bash its command tool runs, and the
    // next seat starts from that bash. The innermost seat's hook runner
    // runs `ljos hook` through sh, and ljos runs the check.
    const SEAT: [&str; 2] = ["node", "bash"];
    const HOOK: [&str; 3] = ["node", "sh", "ljos"];
    let mut names = vec!["tmux", "bash"];
    while names.len() + SEAT.len() + HOOK.len() <= PARENT_WALK_STEPS {
        names.extend(SEAT);
    }
    names.extend(HOOK);
    let seats = (names.len() - 2 - HOOK.len()) / SEAT.len() + 1;
    // Nothing in ljos stops a seat inside a seat inside a seat.
    assert!(seats >= 3, "only {seats} seats fit under the cap");
    let line = first_line(&names, "walk-nested-seats");
    assert!(
        line.starts_with("allow\twarn\trm-rf-outside-tmp ancestry=person\t"),
        "{seats} nested seats: {line}"
    );
}
