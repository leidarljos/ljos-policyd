//! The lines that blocked an approved edit, and the lines that still deny.

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
        let decision = if row.line.starts_with("deny") {
            "DENY"
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
        let denied = row.line.starts_with("deny");
        assert_eq!(denied, row.want_deny, "{} -> {}", row.name, row.line);
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
