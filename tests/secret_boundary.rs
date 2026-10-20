//! A vendor prefix matches only at a token boundary. Ordinary words that
//! contain the same letters are allowed, and a key in a header is denied.

#[cfg(has_phronesis)]
fn check(dir: &std::path::Path, argv: &[&str]) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
        .arg("check")
        .arg("--")
        .args(argv)
        .current_dir(dir)
        .env("PHRONESIS_STATE_DIR", dir.join("state"))
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_JANET_PACK")
        .env_remove("PHRONESIS_PREFIX")
        .env_remove("PHRONESIS_PACK_ROOT")
        .output()
        .expect("spawn check");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `git commit -m 'fix task-creation'`, `cat disk-usage.rs` and
/// `git checkout risk-notes` are ordinary words. A bearer key in a header
/// is still a secret.
#[cfg(has_phronesis)]
#[test]
fn a_prefix_inside_a_word_is_allowed_and_a_bearer_key_is_denied() {
    let base = std::env::temp_dir().join(format!("ljos-policyd-secret-{}", std::process::id()));
    let dir = base.join("ws");
    std::fs::create_dir_all(&dir).unwrap();
    for argv in [
        &["git", "commit", "-m", "fix task-creation"][..],
        &["cat", "disk-usage.rs"],
        &["git", "checkout", "risk-notes"],
    ] {
        assert_eq!(check(&dir, argv), "allow", "{argv:?}");
    }
    // Pieces stay split so the source has no contiguous credential shape.
    let header = format!(
        "Authorization: Bearer {}{}{}",
        "sk-",
        "proj-",
        concat!(
            "abc123DEF456ghi789JKL012mno345PQR678stu901vwx234YZ",
            "abc567def890GHI123jkl456MNO789pqr012STU345vwx678",
        ),
    );
    let line = check(&dir, &["curl", "-H", header.as_str()]);
    assert!(line.starts_with("deny\tshell-secret-in-argv: "), "{line}");
    let _ = std::fs::remove_dir_all(&base);
}
