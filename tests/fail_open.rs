//! Faults, an empty argv, and an unknown verb allow and exit 0.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

fn run(args: &[&str], fault: Option<&str>) -> (i32, String, String) {
    let mut cmd = Command::new(bin());
    cmd.env_remove("LJOS_POLICYD_FAULT");
    if let Some(site) = fault {
        cmd.env("LJOS_POLICYD_FAULT", site);
    }
    cmd.args(args);
    let out = cmd.output().expect("run policyd");
    let code = out.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    (code, stdout, stderr)
}

#[test]
fn no_args_and_an_unknown_verb_allow() {
    let (code, stdout, _) = run(&[], None);
    assert_eq!(code, 0);
    assert_eq!(stdout, "allow\tfail-open\tno args");
    let (code, stdout, _) = run(&["no-such-verb"], None);
    assert_eq!(code, 0);
    assert_eq!(stdout, "allow\tfail-open\tunknown verb");
}

#[test]
fn a_fault_env_on_an_allowed_command_stays_an_allow() {
    for site in ["main", "user_allows", "config_gap", "script_unparsed"] {
        let (code, stdout, stderr) = run(&["check", "--", "true"], Some(site));
        assert_eq!(code, 0, "{site} stderr={stderr} stdout={stdout}");
        assert_eq!(stdout, "allow", "{site}");
    }
}

#[test]
fn a_lost_work_prompt_is_a_warning_for_the_hook() {
    let (code, stdout, _) = run(&["check", "--", "git", "reset", "--hard"], None);
    assert_eq!(code, 0);
    assert_eq!(stdout, "allow\twarn\tgit-reset-hard");
    let (code, stdout, _) = run(&["check", "--", "git", "checkout", "--", "."], None);
    assert_eq!(code, 0);
    assert_eq!(stdout, "allow\twarn\tgit-discard-worktree");
    let (code, stdout, _) = run(&["check", "--", "git", "clean", "-fd"], None);
    assert_eq!(code, 0);
    assert_eq!(stdout, "allow\twarn\tgit-clean-force");
    let (code, stdout, _) = run(&["check", "--", "git", "stash", "drop"], None);
    assert_eq!(code, 0);
    assert_eq!(stdout, "allow\twarn\tgit-stash-drop");

    let capnp = Command::new(bin())
        .args(["capnp", "--", "git", "reset", "--hard"])
        .output()
        .unwrap();
    assert_eq!(capnp.status.code(), Some(0));

    let scratch = std::env::temp_dir().join(format!("policyd-exec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    assert!(Command::new("git")
        .args(["init", "-q", "-b", "develop"])
        .current_dir(&scratch)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args(["commit", "-q", "--allow-empty", "-m", "empty"])
        .current_dir(&scratch)
        .env("GIT_AUTHOR_NAME", "Test User")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test User")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .status()
        .unwrap()
        .success());
    let exec = Command::new(bin())
        .args(["exec", "--", "git", "reset", "--hard"])
        .current_dir(&scratch)
        .output()
        .unwrap();
    assert_eq!(
        exec.status.code(),
        Some(0),
        "stderr {}",
        String::from_utf8_lossy(&exec.stderr)
    );
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn the_fault_env_does_not_open_the_binary() {
    let (code, stdout, _) = run(&["check", "--", "rm", "-rf", "/srv/x"], Some("log_deny"));
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.starts_with("deny\trm-rf-outside-tmp"), "{stdout}");
}

#[test]
fn a_comment_quote_does_not_fail_open() {
    let (code, stdout, _) = run(
        &["check", "--", "bash", "-c", "rm -rf /srv/x # don't"],
        None,
    );
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.starts_with("deny\trm-rf-outside-tmp"), "{stdout}");
}

#[test]
fn config_inside_the_command_is_not_a_policyd_flag() {
    let (code, stdout, _) = run(
        &[
            "check", "--", "rm", "-rf", "--", "/srv/x", "--config", "/nope",
        ],
        None,
    );
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.starts_with("deny\trm-rf-outside-tmp"), "{stdout}");
    let (code, stdout, _) = run(
        &[
            "check",
            "--config",
            "/no/such/ljos-policyd.conf",
            "--",
            "rm",
            "-rf",
            "/srv/x",
        ],
        None,
    );
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(stdout, "allow\tfail-open\tmissing config");
}

#[test]
fn the_binary_allows_on_parse_a_missing_rules_file_and_io() {
    let (code, stdout, _) = run(&["check", "--", "bash", "-c", "rm -rf '/srv"], None);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(stdout, "allow\tfail-open\tparse failure");

    let (code, stdout, _) = run(
        &[
            "check",
            "--config",
            "/no/such/ljos-policyd.rules",
            "--",
            "true",
        ],
        None,
    );
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(stdout, "allow\tfail-open\tmissing config");

    let mut cmd = Command::new(bin());
    cmd.env("LJOS_POLICYD_DENY_LOG", "/dev/null/deny.log");
    cmd.args(["check", "--", "rm", "-rf", "/srv/x"]);
    let out = cmd.output().expect("run policyd");
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert_eq!(stdout, "allow\tfail-open\tio");
}

#[test]
fn consent_is_not_a_verb() {
    let (code, stdout, _) = run(
        &["consent", "--repo", "https://example.test/widget.git"],
        None,
    );
    assert_eq!(code, 0);
    assert_eq!(stdout, "allow\tfail-open\tunknown verb");
}
