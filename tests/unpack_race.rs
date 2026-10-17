//! Concurrent checks are separate processes sharing one state directory.
//! Unpacking the embedded pack must not delete the copy another check is
//! reading, and a refusal must carry a reason.

#[cfg(has_phronesis)]
fn check(dir: &std::path::Path, state: &std::path::Path, argv: &[&str]) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
        .arg("check")
        .arg("--")
        .args(argv)
        .current_dir(dir)
        .env("PHRONESIS_STATE_DIR", state)
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_JANET_PACK")
        .env_remove("PHRONESIS_PREFIX")
        .env_remove("PHRONESIS_PACK_ROOT")
        .output()
        .expect("spawn check");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `deny` with nothing after the tab, or the old stand-in for an empty
/// phronesis reason.
#[cfg(has_phronesis)]
fn empty_reason_denial(line: &str) -> bool {
    if line == "deny" || line == "deny\tphronesis" {
        return true;
    }
    match line.split_once('\t') {
        Some(("deny", reason)) => reason.is_empty(),
        _ => false,
    }
}

#[cfg(has_phronesis)]
#[test]
fn concurrent_checks_do_not_deny_with_an_empty_reason() {
    const CHECKS: usize = 16;
    const ROUNDS: usize = 24;
    for round in 0..ROUNDS {
        let base = std::env::temp_dir().join(format!(
            "ljos-policyd-unpack-{}-{round}",
            std::process::id()
        ));
        let state = base.join("state");
        let dir = base.join("ws");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let _clean = Clean(base.clone());
        let lines = std::thread::scope(|scope| {
            let mut joins = Vec::with_capacity(CHECKS);
            for _ in 0..CHECKS {
                let dir = dir.clone();
                let state = state.clone();
                joins.push(scope.spawn(move || {
                    check(&dir, &state, &["git", "add", "slug.py", "test_slug.py"])
                }));
            }
            joins
                .into_iter()
                .map(|join| join.join().expect("check thread"))
                .collect::<Vec<_>>()
        });
        for (i, line) in lines.iter().enumerate() {
            assert!(
                !empty_reason_denial(line),
                "round {round} check {i} empty-reason denial: {line}"
            );
            assert_eq!(line, "allow", "round {round} check {i}");
        }
    }
}

/// A pack that cannot be loaded is a denial with its own token, not an
/// empty reason and not the generic `phronesis` stand-in.
#[cfg(has_phronesis)]
#[test]
fn an_unloadable_pack_names_itself() {
    let base = std::env::temp_dir().join(format!("ljos-policyd-nopack-{}", std::process::id()));
    let _clean = Clean(base.clone());
    let root = base.join("policy");
    std::fs::create_dir_all(&root).unwrap();
    let entry = root.join("shell.janet");
    std::fs::write(&entry, b"# not a pack\n").unwrap();
    let dir = base.join("ws");
    std::fs::create_dir_all(&dir).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
        .arg("check")
        .arg("--")
        .args(["git", "add", "slug.py", "test_slug.py"])
        .current_dir(&dir)
        .env("PHRONESIS_STATE_DIR", base.join("state"))
        .env("PHRONESIS_JANET_PACK", &entry)
        .env("PHRONESIS_PACK_ROOT", &root)
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_PREFIX")
        .output()
        .expect("spawn check");
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(!empty_reason_denial(&line), "{line}");
    assert_eq!(line, "deny\tpack-unavailable");
}

#[cfg(has_phronesis)]
struct Clean(std::path::PathBuf);

#[cfg(has_phronesis)]
impl Drop for Clean {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
