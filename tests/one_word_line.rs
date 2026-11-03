//! A command string passed as one argv word is read as a shell line.
//! A longer argv is the program and its arguments.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

fn check(argv: &[&str]) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("policyd-one-word-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let out = Command::new(bin())
        .arg("check")
        .arg("--")
        .args(argv)
        .env_remove("LJOS_POLICYD_DAEMON")
        .env_remove("LJOS_USER_ALLOW")
        .env_remove("LJOS_CONSENT_FILE")
        .env("LJOS_POLICYD_DENY_LOG", dir.join("deny.log"))
        .env("XDG_CONFIG_HOME", &dir)
        .output()
        .expect("run policyd");
    let code = out.status.code().unwrap_or(1);
    let line = String::from_utf8(out.stdout).expect("stdout");
    (code, line.trim().to_string())
}

#[test]
fn a_one_word_force_push_warns_like_the_split_form() {
    let split = check(&["git", "push", "--force", "origin", "main"]);
    let whole = check(&["git push --force origin main"]);
    assert_eq!(split.0, 0, "{}", split.1);
    assert_eq!(whole.0, 0, "{}", whole.1);
    assert_eq!(whole.1, split.1);
    assert!(
        split.1.starts_with("allow\twarn\tgit-force-push\t"),
        "{}",
        split.1
    );
    assert!(
        split.1.contains("a force push rewrites a published branch"),
        "{}",
        split.1
    );
}

#[test]
fn a_one_word_sudo_warns() {
    let split = check(&["sudo", "id"]);
    let whole = check(&["sudo id"]);
    assert_eq!(whole.0, 0, "{}", whole.1);
    assert_eq!(split.0, 0, "{}", split.1);
    assert_eq!(whole.1, split.1);
    assert!(whole.1.starts_with("allow\twarn\tsudo\t"), "{}", whole.1);
}

#[test]
fn a_quoted_sentence_is_not_sudo() {
    let (code, line) = check(&["echo", "sudo is bad"]);
    assert_eq!(code, 0);
    assert_eq!(line, "allow");
    let (code, line) = check(&["echo \"sudo is bad\""]);
    assert_eq!(code, 0);
    assert_eq!(line, "allow");
}

#[test]
fn a_one_word_program_name_stays_allow() {
    let (code, line) = check(&["true"]);
    assert_eq!(code, 0);
    assert_eq!(line, "allow");
}

#[test]
fn a_shell_operator_without_whitespace_is_a_shell_line() {
    let whole = check(&["true;sudo id"]);
    let shell = check(&["sh", "-c", "true;sudo id"]);
    assert_eq!(whole.0, 0, "{}", whole.1);
    assert_eq!(shell.0, 0, "{}", shell.1);
    assert_eq!(whole.1, shell.1);
    assert!(whole.1.starts_with("allow\twarn\tsudo\t"), "{}", whole.1);
}
