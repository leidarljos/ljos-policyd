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
    for (d, body) in [
        (&safe, "echo clean\n"),
        (&other, "echo clean\n"),
        (&old, "rm -rf ~/\n"),
        (&proj, "rm -rf ~/\n"),
    ] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("clean-all"), body).unwrap();
    }
    let line = |l: &str| {
        l.replace("{proj}", &proj.to_string_lossy())
            .replace("{other}", &other.to_string_lossy())
    };
    for (oldpwd, l) in [
        (Some(&old), "cd - && sh clean-all"),
        (Some(&old), "pushd - && sh clean-all"),
        (Some(&old), "cd -- - ; sh clean-all"),
        (Some(&old), "sh -c 'cd - && sh clean-all'"),
        (Some(&old), "(cd {other}) && cd - && sh clean-all"),
        (
            Some(&other),
            "cd {proj} && cd {other} && cd - && sh clean-all",
        ),
        (
            Some(&other),
            "cd {proj} && cd {other} && sh -c 'cd - && sh clean-all'",
        ),
        (
            Some(&other),
            "pushd {proj} && popd && cd - && sh clean-all",
        ),
        (None, "cd - && sh clean-all"),
        (None, "cd - ; sh clean-all"),
    ] {
        let v = check(&safe, oldpwd.map(|p| p.as_path()), &line(l));
        assert!(v.starts_with("deny\t"), "OLDPWD={oldpwd:?} {l}: {v}");
    }
    let v = check(&safe, None, "cd - && sh clean-all");
    assert!(v.starts_with("deny\t"), "{v}");
    let v = check(&proj, Some(&other), "cd \"$X\" && cd - && sh clean-all");
    assert!(v.starts_with("deny\t"), "{v}");
    for (oldpwd, l) in [
        (Some(&other), "cd - && sh clean-all"),
        (Some(&old), "cd - && make test"),
        (Some(&old), "cd {other} && cd - && sh clean-all"),
        (
            Some(&old),
            "cd /nonexistent ; cd {other} && cd - && sh clean-all",
        ),
        (None, "cd {proj} && cd - && sh clean-all"),
        (None, "cargo test"),
    ] {
        let v = check(&safe, oldpwd.map(|p| p.as_path()), &line(l));
        assert_eq!(v, "allow", "OLDPWD={oldpwd:?} {l}");
    }
    let _ = std::fs::remove_dir_all(&base);
}
