//! A hit that used to stop the command is allow, with the rule and one warning.
//! A daemon that never accepts does not hold the answer past the connect timeout.

use std::process::Command;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

#[test]
fn a_former_deny_is_allow_with_the_rule_and_a_warning() {
    let out = Command::new(bin())
        .args(["check", "--", "rm", "-rf", "/srv/x"])
        .env_remove("LJOS_POLICYD_DAEMON")
        .output()
        .expect("run policyd");
    assert!(out.status.success(), "{out:?}");
    let line = String::from_utf8(out.stdout).unwrap();
    let line = line.trim();
    let mut fields = line.split('\t');
    assert_eq!(fields.next(), Some("allow"), "{line}");
    assert_eq!(fields.next(), Some("warn"), "{line}");
    let rule = fields.next().unwrap_or("");
    let warning = fields.next().unwrap_or("");
    assert!(fields.next().is_none(), "{line}");
    let bare = rule.split(" ancestry=").next().unwrap_or(rule);
    assert_eq!(bare, "rm-rf-outside-tmp", "{line}");
    assert!(!warning.is_empty(), "{line}");
}

#[test]
fn a_missing_daemon_is_not_waited_out() {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737). A 400 ms socket timeout returned
    // at 400 ms on this host, so this connect is the timeout, not a miss.
    let started = Instant::now();
    let out = Command::new(bin())
        .args(["check", "--", "true"])
        .env("LJOS_POLICYD_DAEMON", "192.0.2.1:81")
        .output()
        .expect("run policyd");
    let elapsed = started.elapsed();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.trim(), "allow");
    assert!(
        elapsed >= Duration::from_millis(200),
        "the connect did not run: {elapsed:?}"
    );
    let cap = ljos_policyd::CONNECT_TIMEOUT + Duration::from_millis(400);
    assert!(
        elapsed < cap,
        "waited {elapsed:?}, longer than the connect timeout plus startup ({cap:?})"
    );
}
