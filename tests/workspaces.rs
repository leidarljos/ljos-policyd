//! A phronesis build judges lines in more than one workspace with one
//! state directory: the first workspace does not claim the seat.

#[cfg(has_phronesis)]
#[test]
fn a_second_workspace_is_judged_like_the_first() {
    let base = std::env::temp_dir().join(format!("ljos-policyd-ws-{}", std::process::id()));
    let state = base.join("state");
    let check = |dir: &std::path::Path, argv: &[&str]| {
        std::fs::create_dir_all(dir).unwrap();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
            .arg("check")
            .arg("--")
            .args(argv)
            .current_dir(dir)
            .env("PHRONESIS_STATE_DIR", &state)
            .env_remove("PHRONESIS_WORKSPACE")
            .env_remove("PHRONESIS_JANET_PACK")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    for ws in ["one", "two", "one"] {
        let dir = base.join(ws);
        assert_eq!(check(&dir, &["git", "status"]), "allow", "{ws}");
        assert_eq!(
            check(&dir, &["git", "push", "--force", "origin", "main"]),
            "deny\tgit-force-push",
            "{ws}"
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}
