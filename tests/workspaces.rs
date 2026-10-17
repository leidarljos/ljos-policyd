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

/// The pack's refusal names its code and carries its own words. The
/// workspace rule is the host's and has no pack text: it judges the working
/// directory against the bound workspace, so a line run in another directory
/// is refused as `path-outside-workspace`, and a line run inside the
/// workspace may name any path.
#[cfg(has_phronesis)]
#[test]
fn a_refusal_names_its_code_and_the_pack_reason() {
    let base = std::env::temp_dir().join(format!("ljos-policyd-code-{}", std::process::id()));
    let ws = base.join("bound");
    let elsewhere = base.join("elsewhere");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let check = |dir: &std::path::Path, argv: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
            .arg("check")
            .arg("--")
            .args(argv)
            .current_dir(dir)
            .env("PHRONESIS_STATE_DIR", base.join("state"))
            .env("PHRONESIS_WORKSPACE", &ws)
            .env_remove("PHRONESIS_JANET_PACK")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(check(&elsewhere, &["ls"]), "deny\tpath-outside-workspace");
    assert_eq!(check(&ws, &["ls", "/etc"]), "allow");
    let url = format!(
        "https://oauth2:{}{}@gitlab.example/x.git",
        "glpat-", "SecretTokenValue99"
    );
    let line = check(&ws, &["git", "push", url.as_str()]);
    assert!(line.starts_with("deny\tshell-secret-in-argv: "), "{line}");
    assert!(line.len() > "deny\tshell-secret-in-argv: ".len(), "{line}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_pack_token_is_the_code_name_then_the_reason() {
    use ljos_policyd::policy_capnp::PolicyReason;
    use ljos_policyd::token_for;
    assert_eq!(
        token_for(PolicyReason::PathOutsideWorkspace, "path outside workspace"),
        "path-outside-workspace: path outside workspace"
    );
    assert_eq!(
        token_for(PolicyReason::PythonMissingPep723, " python missing PEP 723 metadata "),
        "python-missing-pep723: python missing PEP 723 metadata"
    );
    assert_eq!(token_for(PolicyReason::PackMissing, ""), "pack-missing");
}
