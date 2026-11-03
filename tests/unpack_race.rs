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

/// A warn line with an empty rule or an empty warning, or a fail-open
/// that names nothing or only `phronesis`. A plain `allow` is fine.
#[cfg(has_phronesis)]
fn empty_reason_denial(line: &str) -> bool {
    let mut fields = line.split('\t');
    let Some(head) = fields.next() else {
        return true;
    };
    if head != "allow" {
        return true;
    }
    match fields.next() {
        None => false,
        Some("warn") => {
            let rule = fields.next().unwrap_or("");
            let warning = fields.next().unwrap_or("");
            rule.is_empty() || warning.is_empty()
        }
        Some("fail-open") => {
            let reason = fields.next().unwrap_or("");
            reason.is_empty() || reason == "phronesis"
        }
        Some(_) => false,
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

/// A pack that cannot be loaded allows and names `pack-unavailable`, not
/// an empty reason and not the generic `phronesis` stand-in.
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
    assert_eq!(line, "allow\tfail-open\tpack-unavailable");
}

#[cfg(has_phronesis)]
struct Clean(std::path::PathBuf);

#[cfg(has_phronesis)]
impl Drop for Clean {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
