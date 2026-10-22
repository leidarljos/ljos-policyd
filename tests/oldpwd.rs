//! `cd -` and `pushd -` enter `OLDPWD`, which each move on the line sets,
//! so a task runner after one is read where the shell goes back to.

fn check(dir: &std::path::Path, oldpwd: Option<&std::path::Path>, line: &str) -> String {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"));
    cmd.args(["check", "--", "sh", "-c", line])
        .current_dir(dir)
        .env("PHRONESIS_STATE_DIR", dir.join("state"))
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_JANET_PACK")
        .env_remove("PHRONESIS_PREFIX")
        .env_remove("PHRONESIS_PACK_ROOT")
        .env_remove("CDPATH");
    match oldpwd {
        Some(p) => cmd.env("OLDPWD", p),
        None => cmd.env_remove("OLDPWD"),
    };
    let out = cmd.output().expect("spawn check");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `safe` and `other` are harmless, and `old` and `proj` run `rm -rf ~/`.
#[test]
fn reads_a_runner_where_cd_dash_goes_back() {
    let base = std::env::temp_dir().join(format!("ljos-policyd-oldpwd-{}", std::process::id()));
    let [safe, other, old, proj] = ["safe", "other", "old", "proj"].map(|d| base.join(d));
    let harmless = "test:\n\tcargo test\nclean-all:\n\techo clean\n";
    let wipe = "test:\n\tcargo test\nclean-all:\n\trm -rf ~/\n";
    for (d, body) in [
        (&safe, harmless),
        (&other, harmless),
        (&old, wipe),
        (&proj, wipe),
    ] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("Makefile"), body).unwrap();
    }
    let line = |l: &str| {
        l.replace("{proj}", &proj.to_string_lossy())
            .replace("{other}", &other.to_string_lossy())
    };
    for (oldpwd, l) in [
        (Some(&old), "cd - && make clean-all"),
        (Some(&old), "pushd - && make clean-all"),
        (Some(&old), "cd -- - ; make clean-all"),
        (Some(&old), "sh -c 'cd - && make clean-all'"),
        (Some(&old), "(cd {other}) && cd - && make clean-all"),
        (
            Some(&other),
            "cd {proj} && cd {other} && cd - && make clean-all",
        ),
        (
            Some(&other),
            "cd {proj} && cd {other} && sh -c 'cd - && make clean-all'",
        ),
        (
            Some(&other),
            "pushd {proj} && popd && cd - && make clean-all",
        ),
        (None, "cd - && make clean-all"),
        (None, "cd - ; make clean-all"),
    ] {
        let v = check(&safe, oldpwd.map(|p| p.as_path()), &line(l));
        assert!(v.starts_with("deny\t"), "OLDPWD={oldpwd:?} {l}: {v}");
    }
    let v = check(&safe, None, "cd - && make clean-all");
    assert!(
        v.ends_with("make clean-all may run in an untracked directory"),
        "{v}"
    );
    let v = check(&proj, Some(&other), "cd \"$X\" && cd - && make clean-all");
    assert!(v.starts_with("deny\t"), "{v}");
    for (oldpwd, l) in [
        (Some(&other), "cd - && make clean-all"),
        (Some(&old), "cd - && make test"),
        (Some(&old), "cd {other} && cd - && make clean-all"),
        (
            Some(&old),
            "cd /nonexistent ; cd {other} && cd - && make clean-all",
        ),
        (None, "cd {proj} && cd - && make clean-all"),
        (None, "cargo test"),
    ] {
        let v = check(&safe, oldpwd.map(|p| p.as_path()), &line(l));
        assert_eq!(v, "allow", "OLDPWD={oldpwd:?} {l}");
    }
    let _ = std::fs::remove_dir_all(&base);
}
