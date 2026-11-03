//! The parent walk reads `PARENT_WALK_STEPS` parents and then stops.
//! A terminal past the cap leaves the check as it was: allow, warn, exit 0.

use ljos_policyd::PARENT_WALK_STEPS;
use std::path::Path;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

/// Runs a check whose `depth`-th parent is a shell named tmux.
fn check_under_tmux_at(depth: usize, dir: &Path) -> Output {
    let bash = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|d| d.join("bash"))
        .find(|p| p.is_file())
        .expect("`bash` on PATH");
    let tmux = dir.join("tmux");
    std::fs::copy(bash, &tmux).unwrap();
    // Each level is one sh. `exit $?` keeps sh from exec'ing the next one in
    // its own place.
    let nest = dir.join("nest.sh");
    std::fs::write(
        &nest,
        "#!/bin/sh\nn=$1; shift\nif [ \"$n\" -gt 0 ]; then \"$0\" $((n-1)) \"$@\"; exit $?; fi\n\"$@\"; exit $?\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&nest, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // nest.sh runs `levels + 1` shells between tmux and policyd, so tmux is
    // parent `levels + 2`.
    let levels = (depth - 2).to_string();
    Command::new(&tmux)
        .args(["-c", "\"$@\"; exit $?", "tmux"])
        .arg(&nest)
        .arg(levels)
        .args([bin(), "check", "--", "rm", "-rf", "/srv/x"])
        .env_remove("LJOS_POLICYD_DAEMON")
        .env("LJOS_POLICYD_DENY_LOG", dir.join("deny.log"))
        .output()
        .expect("run policyd under nested shells")
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("policyd-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_terminal_at_the_cap_names_a_person() {
    let dir = temp_dir("walk-at-cap");
    let out = check_under_tmux_at(PARENT_WALK_STEPS, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{out:?}");
    let line = String::from_utf8(out.stdout).unwrap();
    assert!(
        line.starts_with("allow\twarn\trm-rf-outside-tmp ancestry=person\t"),
        "{line}"
    );
}

#[test]
fn a_terminal_past_the_cap_stops_the_walk_and_the_check_still_answers() {
    let dir = temp_dir("walk-past-cap");
    let out = check_under_tmux_at(PARENT_WALK_STEPS + 1, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let line = String::from_utf8(out.stdout).unwrap();
    assert!(
        line.starts_with("allow\twarn\trm-rf-outside-tmp\t"),
        "{line}"
    );
}
