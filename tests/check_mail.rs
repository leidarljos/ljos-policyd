//! check-mail reads a message on stdin and a config path, and prints JSON.
//! An allow means this check found nothing to refuse.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], message: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn check-mail");
    let mut stdin = child.stdin.take().expect("stdin");
    match stdin.write_all(message) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(err) => panic!("write stdin: {err}"),
    }
    drop(stdin);
    child.wait_with_output().expect("wait")
}

fn config(deny: &str, law: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "policyd-cli-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("deny.txt"), deny).unwrap();
    std::fs::write(dir.join("law.txt"), law).unwrap();
    std::fs::write(
        dir.join("mail.conf"),
        "identity mailseat@example.test\ndeny-file deny.txt\npack-law law.txt\n",
    )
    .unwrap();
    dir.join("mail.conf")
}

#[test]
fn an_encoded_word_from_is_not_refused() {
    let conf = config("", "");
    let out = run(
        &["check-mail", "--config", conf.to_str().unwrap()],
        b"From: =?utf-8?q?Mail_Seat?= <mailseat@example.test>\r\n",
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        r#"{"verdict":"allow","reasons":[]}"#
    );
    assert!(out.stderr.is_empty());
    let _ = std::fs::remove_dir_all(conf.parent().unwrap());
}

#[test]
fn a_duplicate_from_and_a_lookalike_domain_are_refused() {
    let conf = config("domain blocked.test\n", "");
    let full = "\u{FF42}\u{FF4C}\u{FF4F}\u{FF43}\u{FF4B}\u{FF45}\u{FF44}.test";
    let message = format!(
        "From: mailseat@example.test\r\nFrom: mailseat@example.test\r\nTo: person@{full}\r\n"
    );
    let out = run(
        &["check-mail", &format!("--config={}", conf.display())],
        message.as_bytes(),
    );
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(r#""verdict":"deny""#), "{stdout}");
    assert!(stdout.contains("duplicate-from"), "{stdout}");
    assert!(stdout.contains("recipient-domain-denied"), "{stdout}");
    assert!(stdout.contains("to blocked.test"), "{stdout}");
    assert!(!stdout.to_ascii_lowercase().contains("approv"));
    assert!(
        out.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(conf.parent().unwrap());
}

#[test]
fn a_missing_config_flag_is_usage() {
    let out = run(&["check-mail"], b"From: mailseat@example.test\r\n");
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("check-mail --config PATH"), "{err}");
}

#[test]
fn a_dead_domain_rule_exits_2_and_names_the_line() {
    let conf = config(
        "#\ndomain *.example.test\n",
        "deny-domain example.test:25\n",
    );
    let out = run(
        &["check-mail", "--config", conf.to_str().unwrap()],
        b"From: mailseat@example.test\r\nTo: john@example.test\r\n",
    );
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains(r#""verdict":"deny""#), "{stdout}");
    assert!(stdout.contains("deny-file-invalid"), "{stdout}");
    assert!(stdout.contains("line 2"), "{stdout}");
    assert!(!stdout.contains("*.example.test"), "{stdout}");
    assert!(!stdout.contains('*'), "{stdout}");
    assert!(
        out.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(conf.parent().unwrap());
}

#[test]
fn bytes_that_are_not_utf8_are_refused() {
    let conf = config("", "");
    let out = run(
        &["check-mail", "--config", conf.to_str().unwrap()],
        &[0xff, 0xfe],
    );
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("message-invalid"), "{stdout}");
    let _ = std::fs::remove_dir_all(conf.parent().unwrap());
}
