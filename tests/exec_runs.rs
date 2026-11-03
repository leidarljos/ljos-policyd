//! `exec` prints a warning on stderr and then runs the command.
//! The process status is the command's status.
//! `block-on-warning true` in `--config` prints the warning and does not run it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("policyd-exec-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A git repo with one stash entry named `kept`.
fn repo_with_stash(name: &str) -> PathBuf {
    let dir = scratch(name);
    let init = git(&dir, &["init", "-q", "-b", "develop"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    std::fs::write(dir.join("notes.txt"), "one\n").unwrap();
    let add = git(&dir, &["add", "notes.txt"]);
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    let commit = git(&dir, &["commit", "-q", "-m", "notes"]);
    assert!(
        commit.status.success(),
        "{}",
        String::from_utf8_lossy(&commit.stderr)
    );
    std::fs::write(dir.join("notes.txt"), "two\n").unwrap();
    let stashed = git(&dir, &["stash", "push", "-q", "-m", "kept"]);
    assert!(
        stashed.status.success(),
        "{}",
        String::from_utf8_lossy(&stashed.stderr)
    );
    let before = git(&dir, &["stash", "list"]);
    let listed = String::from_utf8_lossy(&before.stdout);
    assert!(before.status.success(), "{listed}");
    assert!(listed.contains("kept"), "{listed}");
    dir
}

fn config(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("ljos-policyd.conf");
    std::fs::write(&path, body).unwrap();
    path
}

fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Test User")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test User")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .expect("git")
}

#[test]
fn exec_returns_the_command_status() {
    let out = Command::new(bin())
        .args(["exec", "--", "sh", "-c", "exit 3"])
        .output()
        .expect("run policyd");
    assert_eq!(
        out.status.code(),
        Some(3),
        "stdout {}\nstderr {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn exec_prints_the_stash_warning_and_clears_the_stash() {
    let dir = repo_with_stash("stash");
    let exec = Command::new(bin())
        .args(["exec", "--", "git", "stash", "clear"])
        .current_dir(&dir)
        .output()
        .expect("run policyd");
    let stderr = String::from_utf8_lossy(&exec.stderr);
    assert_eq!(exec.status.code(), Some(0), "{stderr}");
    assert_eq!(
        stderr.trim_end(),
        ljos_policyd::allow_annotation("git-stash-clear"),
        "{stderr}"
    );
    assert_stash_empty(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exec_runs_when_block_on_warning_is_off() {
    let dir = repo_with_stash("off");
    let path = config(&dir, "block-on-warning false\n");
    let exec = Command::new(bin())
        .args([
            "exec",
            "--config",
            path.to_str().unwrap(),
            "--",
            "git",
            "stash",
            "clear",
        ])
        .current_dir(&dir)
        .output()
        .expect("run policyd");
    let stderr = String::from_utf8_lossy(&exec.stderr);
    assert_eq!(exec.status.code(), Some(0), "{stderr}");
    assert_eq!(
        stderr.trim_end(),
        ljos_policyd::allow_annotation("git-stash-clear"),
        "{stderr}"
    );
    assert_stash_empty(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exec_does_not_run_when_block_on_warning_is_on() {
    let dir = repo_with_stash("on");
    let path = config(&dir, "block-on-warning true\n");
    let exec = Command::new(bin())
        .args([
            "exec",
            "--config",
            path.to_str().unwrap(),
            "--",
            "git",
            "stash",
            "clear",
        ])
        .current_dir(&dir)
        .output()
        .expect("run policyd");
    let stderr = String::from_utf8_lossy(&exec.stderr);
    let warning = ljos_policyd::allow_annotation("git-stash-clear");
    assert_eq!(exec.status.code(), Some(2), "{stderr}");
    assert_eq!(
        stderr,
        format!("{warning}\nexec: not run because block-on-warning is on\n"),
        "{stderr}"
    );
    let after = git(&dir, &["stash", "list"]);
    let listed = String::from_utf8_lossy(&after.stdout);
    assert!(after.status.success(), "{listed}");
    assert!(listed.contains("kept"), "{listed}");

    let allowed = Command::new(bin())
        .args([
            "exec",
            "--config",
            path.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "exit 3",
        ])
        .output()
        .expect("run policyd");
    assert_eq!(allowed.status.code(), Some(3));
    let _ = std::fs::remove_dir_all(&dir);
}

fn assert_stash_empty(dir: &Path) {
    let after = git(dir, &["stash", "list"]);
    let cleared = String::from_utf8_lossy(&after.stdout);
    assert!(after.status.success(), "{cleared}");
    assert!(cleared.trim().is_empty(), "{cleared}");
}
