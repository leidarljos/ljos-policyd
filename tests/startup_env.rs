//! A `BASH_ENV` or `ENV` in the guard's own environment is exported to
//! every shell the line starts, so the file it names is judged as one
//! the line exported itself.

fn check(dir: &std::path::Path, env: &[(&str, &str)], argv: &[&str]) -> String {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"));
    cmd.arg("check")
        .arg("--")
        .args(argv)
        .current_dir(dir)
        .env("PHRONESIS_STATE_DIR", dir.join("state"))
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_JANET_PACK")
        .env_remove("PHRONESIS_PREFIX")
        .env_remove("PHRONESIS_PACK_ROOT")
        .env_remove("BASH_ENV")
        .env_remove("ENV");
    cmd.envs(env.iter().copied());
    let out = cmd.output().expect("spawn check");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn an_inherited_startup_file_is_judged() {
    let dir = std::env::temp_dir().join(format!("ljos-policyd-stenv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("evil.sh"), "git push -f origin\n").unwrap();
    std::fs::write(dir.join("hi.sh"), "echo hi\n").unwrap();
    for (env, argv) in [
        (("BASH_ENV", "evil.sh"), &["bash", "-c", "echo ok"][..]),
        (("BASH_ENV", "evil.sh"), &["bash", "hi.sh"]),
        (("BASH_ENV", "evil.sh"), &["sh", "-c", "bash -c true"]),
        (("ENV", "evil.sh"), &["sh", "-c", "echo ok"]),
    ] {
        let got = check(&dir, &[env], argv);
        assert_eq!(got, "deny\tgit-force-push", "{env:?} {argv:?}");
    }
    let got = check(
        &dir,
        &[("BASH_ENV", "$HOME/x.sh")],
        &["bash", "-c", "echo ok"],
    );
    assert_eq!(got, "deny\tstartup-script-unshown");
    for (env, argv) in [
        (("BASH_ENV", "evil.sh"), &["echo", "ok"][..]),
        (
            ("BASH_ENV", "evil.sh"),
            &["env", "-u", "BASH_ENV", "bash", "-c", "echo ok"],
        ),
        (
            ("BASH_ENV", "evil.sh"),
            &["env", "-i", "bash", "-c", "echo ok"],
        ),
        (
            ("BASH_ENV", "evil.sh"),
            &["sh", "-c", "unset BASH_ENV; bash -c true"],
        ),
        (("BASH_ENV", "hi.sh"), &["bash", "-c", "echo ok"]),
        (("BASH_ENV", ""), &["bash", "-c", "echo ok"]),
        (("ENV", "evil.sh"), &["bash", "-c", "echo ok"]),
    ] {
        let got = check(&dir, &[env], argv);
        assert_eq!(got, "allow", "{env:?} {argv:?}");
    }
}
