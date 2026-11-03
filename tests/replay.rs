//! The lines that blocked an approved edit, and the lines that still warn.

use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

fn run(cwd: &Path, env: &[(&str, &str)], args: &[&str]) -> String {
    let mut cmd = Command::new(bin());
    cmd.current_dir(cwd).args(args);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("run policyd");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn repo() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn allows(line: &str) -> bool {
    line == "allow" || line.starts_with("allow\t")
}

struct Row {
    name: &'static str,
    line: String,
    want_deny: bool,
}

#[test]
fn replay_the_blocked_lines() {
    let root = repo();
    let body = "rm -rf \"$out/raw\" \"$out/prs\"";
    let cat = format!("cat > /srv/work/x/PROMPT.md <<'EOF'\n{body}\nEOF");
    let bash_doc = format!("bash <<'EOF'\n{body}\nEOF");
    let deed =
        "cat > /srv/work/x/DEED.md <<'EOF'\nThe note mentions a force-push only as prose.\nEOF";
    let scratch = std::env::temp_dir().join(format!("policyd-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    assert!(Command::new("git")
        .args(["init", "-q", "-b", "develop"])
        .current_dir(&scratch)
        .status()
        .unwrap()
        .success());
    let origin = String::from_utf8(
        Command::new("git")
            .args(["remote", "get-url", "origin"])
            .current_dir(&root)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let origin = origin.trim();
    let origin = match origin.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_, host)) => format!("{scheme}://{host}"),
            None => origin.to_string(),
        },
        None => origin.to_string(),
    };
    let consent = scratch.join("consent.json");
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    std::fs::write(
        &consent,
        format!(
            "{{\"repo\":\"{origin}\",\"ref\":\"refs/heads/main\",\"action\":\"git-force-push\",\"exp\":{exp}}}\n"
        ),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&consent).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
    std::fs::set_permissions(&consent, perms).unwrap();

    let mut rows = vec![
        Row {
            name: "cat heredoc body is data",
            line: run(&root, &[], &["check", "--", "bash", "-c", &cat]),
            want_deny: false,
        },
        Row {
            name: "fast-forward push to main",
            line: run(
                &root,
                &[],
                &["check", "--", "git", "push", "origin", "main"],
            ),
            want_deny: false,
        },
        Row {
            name: "fast-forward push to develop",
            line: run(
                &root,
                &[],
                &["check", "--", "git", "push", "origin", "develop"],
            ),
            want_deny: false,
        },
        Row {
            name: "rm -rf target missing inside a work tree",
            line: run(&scratch, &[], &["check", "--", "rm", "-rf", "target"]),
            want_deny: false,
        },
        Row {
            name: "move scratch from /tmp into the work tree",
            line: run(
                &root,
                &[],
                &[
                    "check",
                    "--",
                    "mv",
                    "/tmp/policyd-scratch",
                    "/srv/work/policyd-scratch",
                ],
            ),
            want_deny: false,
        },
        Row {
            name: "git worktree remove of a clean worktree",
            line: run(
                &root,
                &[],
                &["check", "--", "git", "worktree", "remove", "/tmp/clean-wt"],
            ),
            want_deny: false,
        },
        Row {
            name: "deed text mentions force-push in prose",
            line: run(&root, &[], &["check", "--", "bash", "-c", deed]),
            want_deny: false,
        },
        Row {
            name: "policyd binary missing",
            line: ljos_policyd::missing_tool(false, true).unwrap().to_string(),
            want_deny: false,
        },
        Row {
            name: "policyd config missing",
            line: run(
                &root,
                &[],
                &[
                    "check",
                    "--config",
                    "/no/such/ljos-policyd.conf",
                    "--",
                    "rm",
                    "-rf",
                    "/srv/x",
                ],
            ),
            want_deny: false,
        },
        Row {
            name: "user allow turns a deny into an allow",
            line: run(
                &root,
                &[],
                &[
                    "check",
                    "--user-allow",
                    "rm -rf /srv/x",
                    "--",
                    "rm",
                    "-rf",
                    "/srv/x",
                ],
            ),
            want_deny: false,
        },
        Row {
            name: "consent turns a force-push into an allow",
            line: run(
                &root,
                &[("LJOS_CONSENT_FILE", consent.to_str().unwrap())],
                &["check", "--", "git", "push", "--force", "origin", "main"],
            ),
            want_deny: false,
        },
        Row {
            name: "bash heredoc body is still a command",
            line: run(&root, &[], &["check", "--", "bash", "-c", &bash_doc]),
            want_deny: true,
        },
        Row {
            name: "rm -rf outside the work tree",
            line: run(&root, &[], &["check", "--", "rm", "-rf", "/srv/x"]),
            want_deny: true,
        },
        Row {
            name: "force-push to main without consent",
            line: run(
                &root,
                &[],
                &["check", "--", "git", "push", "--force", "origin", "main"],
            ),
            want_deny: true,
        },
        Row {
            name: "read of an ssh private key",
            line: run(&root, &[], &["check", "--", "cat", "~/.ssh/id_ed25519"]),
            want_deny: true,
        },
    ];

    let mut log = String::from("| case | verdict | decision |\n|---|---|---|\n");
    let mut raw = String::new();
    for row in &mut rows {
        let warned = row.line.starts_with("allow\twarn\t");
        let decision = if warned {
            "WARN"
        } else if allows(&row.line) {
            "ALLOW"
        } else {
            "OTHER"
        };
        log.push_str(&format!(
            "| {} | `{}` | {} |\n",
            row.name, row.line, decision
        ));
        raw.push_str(&format!("# {}\n{}\n", row.name, row.line));
        assert!(
            row.line.starts_with("allow"),
            "{} -> {}",
            row.name,
            row.line
        );
        // A former deny is allow plus a warning. A former ask can be a
        // warning too, so a row that was never denied may still warn.
        if row.want_deny {
            assert!(warned, "{} -> {}", row.name, row.line);
            let warning = row.line.split('\t').nth(3).unwrap_or("");
            assert!(!warning.is_empty(), "{} -> {}", row.name, row.line);
        }
        if row.name.starts_with("user allow") {
            assert!(
                row.line.starts_with("allow\tuser-rule\t"),
                "{} -> {}",
                row.name,
                row.line
            );
        }
    }
    let doc = format!("{log}\n## raw log\n\n```\n{raw}```\n");
    if let Ok(path) = std::env::var("LJOS_REPLAY_MD") {
        std::fs::write(path, &doc).unwrap();
    }
    let _ = std::fs::remove_dir_all(&scratch);
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("policyd-replay-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Replay `log` with no user rules and no consent file from this machine.
fn replay_log(dir: &Path, log: &str, extra: &[(&str, &str)]) -> (i32, String, String) {
    let path = dir.join("deny.log");
    std::fs::write(&path, log).unwrap();
    let mut cmd = Command::new(bin());
    cmd.current_dir(dir)
        .args(["replay", path.to_str().unwrap()])
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir)
        .env("XDG_STATE_HOME", dir)
        .env_remove("LJOS_USER_ALLOW")
        .env_remove("LJOS_CONSENT_FILE")
        .env_remove("LJOS_POLICYD_DAEMON")
        .env_remove("LJOS_POLICYD_DENY_LOG")
        .env_remove("LJOS_POLICYD_FAULT");
    for (key, value) in extra {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("replay");
    (
        out.status.code().unwrap_or(1),
        String::from_utf8(out.stdout).expect("stdout"),
        String::from_utf8(out.stderr).expect("stderr"),
    )
}

#[test]
fn replay_summary_splits_a_warning_from_a_plain_allow() {
    let dir = scratch("summary");
    let (code, stdout, stderr) = replay_log(
        &dir,
        "1700000000\tgit-force-push\tgit push --force origin main\n\
         1700000001\tgit-force-push\tgit status\n",
        &[],
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let mut lines = stdout.lines();
    let warned = lines.next().expect("warning row");
    assert!(
        warned.starts_with("was deny\tgit-force-push\tnow allow\twarn\t"),
        "{warned}"
    );
    assert!(
        warned.contains("a force push rewrites a published branch"),
        "{warned}"
    );
    assert!(
        warned.ends_with("\tgit push --force origin main"),
        "{warned}"
    );
    assert_eq!(
        lines.next().expect("allow row"),
        "was deny\tgit-force-push\tnow allow\tgit status"
    );
    assert_eq!(
        lines.next().expect("summary"),
        "2 logged lines: 1 still warn, 1 now allow"
    );
    assert!(lines.next().is_none(), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replay_summary_names_a_rewrite_and_a_user_rule() {
    let dir = scratch("named");
    std::fs::write(dir.join("pyproject.toml"), "[project]\nname = \"x\"\n").unwrap();
    std::fs::write(dir.join("x.py"), "print(1)\n").unwrap();
    let (code, stdout, stderr) = replay_log(
        &dir,
        "1700000000\tsudo\tsudo id\n\
         1700000001\tgit-force-push\tgit status\n\
         1700000002\tgit-force-push\tgit push --force origin main\n\
         1700000003\tpython\tpython x.py\n",
        &[("LJOS_USER_ALLOW", "git push --force origin main")],
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "{stdout}");
    assert!(
        lines[0].starts_with("was deny\tsudo\tnow allow\twarn\t"),
        "{}",
        lines[0]
    );
    assert!(lines[0].ends_with("\tsudo id"), "{}", lines[0]);
    assert_eq!(lines[1], "was deny\tgit-force-push\tnow allow\tgit status");
    assert!(
        lines[2].starts_with("was deny\tgit-force-push\tnow allow\tuser-rule\t"),
        "{}",
        lines[2]
    );
    assert!(
        lines[2].ends_with("\tgit push --force origin main"),
        "{}",
        lines[2]
    );
    assert!(
        lines[3].starts_with("was deny\tpython\tnow allow\trewrite\t"),
        "{}",
        lines[3]
    );
    assert!(lines[3].ends_with("\tpython x.py"), "{}", lines[3]);
    assert_eq!(
        lines[4],
        "4 logged lines: 1 still warn, 1 now allow, 1 now rewrite, 1 now user-rule"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
