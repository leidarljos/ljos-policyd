//! A hit that used to stop the command is allow, with the rule and one warning.
//! `LJOS_POLICYD_DAEMON` is not read, so a set address does not hold the answer.

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
fn a_check_under_tmux_names_a_person() {
    let dir = std::env::temp_dir().join(format!("policyd-tmux-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bash = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|d| d.join("bash"))
        .find(|p| p.is_file())
        .expect("`bash` on PATH");
    // A shell under the name tmux is a parent the walk names. The `exit`
    // after the check keeps bash from exec'ing policyd in its own place.
    let tmux = dir.join("tmux");
    std::fs::copy(bash, &tmux).unwrap();
    let out = Command::new(&tmux)
        .args([
            "-c",
            "\"$1\" check -- rm -rf /srv/x; exit $?",
            "tmux",
            bin(),
        ])
        .env_remove("LJOS_POLICYD_DAEMON")
        .env("LJOS_POLICYD_DENY_LOG", dir.join("deny.log"))
        .output()
        .expect("run policyd under tmux");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{out:?}");
    let line = String::from_utf8(out.stdout).unwrap();
    assert!(
        line.starts_with("allow\twarn\trm-rf-outside-tmp ancestry=person\t"),
        "{line}"
    );
}

#[test]
fn a_missing_daemon_is_not_waited_out() {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737) and does not answer. The old
    // connect waited 300 ms there: a 400 ms socket timeout returned at
    // 400 ms on the host that set that limit, and a return under 200 ms
    // was too fast to be that wait. Policyd does not read the variable,
    // so this check is the table. The bound stays 100 ms under the old
    // 300 ms, and a connect that still waited that timeout cannot pass.
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
    let cap = Duration::from_millis(200);
    assert!(
        elapsed < cap,
        "waited {elapsed:?}; a table check finishes under {cap:?}"
    );
}
