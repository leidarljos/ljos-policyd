//! `block-on-warning true` in the `--config` file turns a warning into a
//! deny with the same rule and warning. Every fail-open line stays allow.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

const SUDO: &[&str] = &["sudo", "id"];

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

/// A config file holding `body`, in a directory of its own.
fn config(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("policyd-block-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ljos-policyd.conf");
    std::fs::write(&path, body).unwrap();
    path
}

fn check(config: Option<&Path>, argv: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.arg("check");
    if let Some(path) = config {
        cmd.arg("--config").arg(path);
    }
    cmd.arg("--").args(argv).env_remove("LJOS_POLICYD_DAEMON");
    cmd
}

fn run(mut cmd: Command) -> (Option<i32>, String) {
    let out = cmd.output().expect("run policyd");
    (out.status.code(), String::from_utf8(out.stdout).unwrap())
}

fn allowed(line: &str) -> (Option<i32>, String) {
    (Some(0), format!("{line}\n"))
}

#[test]
fn the_default_allows_with_the_warning() {
    let bare = run(check(None, SUDO));
    assert_eq!(bare.0, Some(0), "{}", bare.1);
    assert!(bare.1.starts_with("allow\twarn\tsudo"), "{}", bare.1);
    for (name, body) in [
        ("empty", ""),
        ("other", "identity mailseat@example.test\n"),
        ("off", "block-on-warning false\n"),
        ("comment", "# block-on-warning true\n"),
    ] {
        let path = config(name, body);
        assert_eq!(run(check(Some(&path), SUDO)), bare, "{body:?}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

#[test]
fn the_setting_denies_the_same_line_with_the_same_rule() {
    let path = config("on", "block-on-warning true\n");
    let (_, warned) = run(check(None, SUDO));
    let (code, denied) = run(check(Some(&path), SUDO));
    assert_eq!(code, Some(2), "{denied}");
    let hit = warned.strip_prefix("allow\twarn\t").unwrap();
    assert_eq!(denied, format!("deny\t{hit}"));
    let rule = denied.split('\t').nth(1).unwrap();
    assert_eq!(rule.split(" ancestry=").next(), Some("sudo"), "{denied}");
    assert_eq!(run(check(Some(&path), &["true"])), allowed("allow"));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn an_unwritable_deny_log_does_not_hide_the_warning_from_the_setting() {
    let path = config("log", "block-on-warning true\n");
    let mut cmd = check(None, &["rm", "-rf", "/srv/x"]);
    cmd.env("LJOS_POLICYD_DENY_LOG", "/dev/null/deny.log");
    let (code, warned) = run(cmd);
    assert_eq!(code, Some(0), "{warned}");
    let hit = warned.strip_prefix("allow\twarn\t").expect(&warned);
    let mut cmd = check(Some(&path), &["rm", "-rf", "/srv/x"]);
    cmd.env("LJOS_POLICYD_DENY_LOG", "/dev/null/deny.log");
    assert_eq!(run(cmd), (Some(2), format!("deny\t{hit}")));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn the_setting_still_allows_on_a_missing_config_and_a_timeout() {
    let path = config("gone", "block-on-warning true\n");
    assert_eq!(run(check(Some(&path), SUDO)).0, Some(2));
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        run(check(Some(&path), SUDO)),
        allowed("allow\tfail-open\tmissing config")
    );

    let path = config("daemon", "block-on-warning true\n");
    // 192.0.2.1 is TEST-NET-1 (RFC 5737). Nothing there accepts, so the
    // connect runs to its timeout.
    let mut cmd = check(Some(&path), &["true"]);
    cmd.env("LJOS_POLICYD_DAEMON", "192.0.2.1:81");
    assert_eq!(run(cmd), allowed("allow"));
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut cmd = check(Some(&path), &["true"]);
    cmd.env("LJOS_POLICYD_DAEMON", closed.to_string());
    assert_eq!(run(cmd), allowed("allow"));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn the_setting_still_allows_when_the_check_fails_open() {
    let path = config("error", "block-on-warning true\n");
    assert_eq!(
        run(check(Some(&path), &["bash", "-c", "rm -rf '/srv"])),
        allowed("allow\tfail-open\tparse failure")
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
