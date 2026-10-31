//! Behaviour the seat hit and the rewrite the hook reads back.

use ljos_policyd::{check_shell, verdict};

fn words(line: &str) -> Vec<String> {
    // Enough for the lines these tests hand over as argv, not a shell split.
    line.split_whitespace().map(str::to_string).collect()
}

#[test]
fn writing_readme_is_not_an_empty_argv_denial() {
    assert_eq!(verdict(&[]), "allow");
    let line = "mkdir -p notes && printf '%s\\n' '# notes' > notes/README.md";
    let v = verdict(&["bash".into(), "-c".into(), line.into()]);
    assert!(v.starts_with("allow"), "{v}");
    assert!(!v.contains("empty argv"), "{v}");
}

#[test]
fn a_brief_that_mentions_a_path_is_allowed() {
    let root = std::env::temp_dir().join(format!("policyd-brief-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let slides = root.join("course-module-fundamentals-of-hpc/slides");
    std::fs::create_dir_all(&slides).unwrap();
    std::fs::write(
        slides.join("fundamentals-of-hpc.org"),
        "#+TITLE: Fundamentals of HPC\n* Intro\n",
    )
    .unwrap();
    let brief =
        "The notes live in course-module-fundamentals-of-hpc/slides/fundamentals-of-hpc.org.\n";
    std::fs::create_dir_all(root.join("notes")).unwrap();
    std::fs::write(root.join("notes/BRIEF.md"), brief).unwrap();
    let joined = format!("notes/BRIEF.md\n{brief}");
    let c = check_shell(&["bash".into(), "-c".into(), joined]);
    let write = format!("cat > notes/BRIEF.md << 'EOF'\n{brief}EOF");
    let w = check_shell(&["bash".into(), "-c".into(), write]);
    assert_eq!(
        c.decision,
        ljos_policyd::policy_capnp::Decision::Allow,
        "{}",
        c.token
    );
    assert!(!c.token.contains("script-unread"), "{}", c.token);
    assert_eq!(
        w.decision,
        ljos_policyd::policy_capnp::Decision::Allow,
        "{}",
        w.token
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_read_only_rg_xargs_search_is_allowed() {
    for line in [
        "rg -n pattern src | xargs rg -n pattern",
        "rg -l pattern | xargs grep pattern",
        "rg -n pattern | xargs -I {} rg pattern {}",
        "rg -l pattern | xargs -I {} sh -c 'rg -n pattern {}'",
    ] {
        let v = verdict(&["bash".into(), "-c".into(), line.into()]);
        assert!(v.starts_with("allow"), "{line}: {v}");
        assert!(!v.contains("xargs-script-unshown"), "{line}: {v}");
    }
}

#[test]
fn python_scripts_rewrite_to_uv_run() {
    let dir = std::env::temp_dir().join(format!(
        "policyd-uv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("x.py"), "print(1)\n").unwrap();
    let here = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();
    assert_eq!(verdict(&words("python x.py")), "allow", "no project file");
    assert_eq!(verdict(&words("python3 x.py")), "allow");
    std::fs::write(dir.join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
    assert_eq!(
        verdict(&words("python x.py")),
        "allow\trewrite\tuv run x.py"
    );
    assert_eq!(
        verdict(&["python3".into(), "x.py".into(), "a".into()]),
        "allow\trewrite\tuv run x.py a"
    );
    let _ = std::fs::remove_file(dir.join("pyproject.toml"));
    std::fs::write(dir.join("uv.lock"), "version = 1\n").unwrap();
    assert_eq!(
        verdict(&words("python3 x.py")),
        "allow\trewrite\tuv run x.py"
    );
    let _ = std::fs::remove_file(dir.join("uv.lock"));
    std::fs::write(
        dir.join("tool.py"),
        "# /// script\n# requires-python = \">=3.11\"\n# ///\nprint(1)\n",
    )
    .unwrap();
    assert_eq!(
        verdict(&words("python tool.py")),
        "allow\trewrite\tuv run tool.py"
    );
    std::env::set_current_dir(here).unwrap();
    let inline = verdict(&["python3".into(), "-c".into(), "print(1)".into()]);
    assert_eq!(inline, "allow");
    let ask = verdict(&[
        "python3".into(),
        "-c".into(),
        "open('/home/u/.ssh/id_rsa')".into(),
    ]);
    assert_eq!(ask, "prompt\tcredential-mention");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_deny_is_appended_to_the_deny_log() {
    let path = std::env::temp_dir().join(format!("policyd-deny-{}-b.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::env::set_var("LJOS_POLICYD_DENY_LOG", &path);
    let v = verdict(&words("sudo id"));
    std::env::remove_var("LJOS_POLICYD_DENY_LOG");
    assert_eq!(v, "deny\tsudo");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("sudo"), "{text}");
    assert!(text.contains('\t'), "{text}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn local_git_lost_work_asks() {
    for (line, token) in [
        ("git reset --hard HEAD~3", "git-reset-hard"),
        ("git clean -fd", "git-clean-force"),
        ("git clean -fdx", "git-clean-force"),
        ("git stash clear", "git-stash-clear"),
        ("git stash drop", "git-stash-drop"),
        ("git checkout -- .", "git-discard-worktree"),
        ("git restore .", "git-discard-worktree"),
    ] {
        assert_eq!(verdict(&words(line)), format!("prompt\t{token}"), "{line}");
    }
    let script = verdict(&["sh".into(), "-c".into(), "git reset --hard".into()]);
    assert_eq!(script, "prompt\tgit-reset-hard");
    assert_eq!(verdict(&words("git reset --soft HEAD~1")), "allow");
    assert!(verdict(&words("git push --force origin main")).starts_with("deny\t"));
}

fn shell(line: &str) -> Vec<String> {
    vec!["bash".into(), "-c".into(), line.into()]
}

#[test]
fn read_only_xargs_lines_are_allowed() {
    for line in [
        "rg -l foo src | xargs rg -n bar",
        "rg --files | xargs wc -l",
        "fd -e rs | xargs grep -n x",
        "fd | xargs -I{} sh -c 'grep -n x {} 2>/dev/null'",
        "printf main | xargs git push origin",
        "printf a.txt | xargs chmod 644",
    ] {
        assert_eq!(verdict(&shell(line)), "allow", "{line}");
    }
    assert_eq!(verdict(&words("git push origin main")), "allow");
    assert_eq!(verdict(&words("chmod 644 f")), "allow");
    assert_eq!(verdict(&words("mv a b")), "allow");
}

#[test]
fn xargs_into_rm_or_a_force_push_is_refused() {
    assert_eq!(
        verdict(&shell("printf x | xargs rm -rf")),
        "deny\tfeeder-rm"
    );
    assert_eq!(
        verdict(&shell("printf main | xargs git push -f origin")),
        "deny\tgit-force-push"
    );
}

#[test]
fn a_credential_path_prints_credential_mention() {
    for program in [
        "print(open('/home/u/.ssh/id_rsa').read())",
        "print(open('/tmp/fake/.pgpass').read())",
        "print(open('/tmp/fake/.secrets/gh_fake').read())",
    ] {
        assert_eq!(
            verdict(&["python3".into(), "-c".into(), program.into()]),
            "prompt\tcredential-mention",
            "{program}"
        );
    }
}

/// `git restore --staged` over the whole tree only unstages: the files
/// in the tree stay as they are, and `-S` is the same flag. With
/// `--worktree`, or `-W`, alone or clustered, it writes the tree back from
/// the index, and that is the whole-tree discard the gate asks about.
#[test]
fn unstaging_the_whole_tree_discards_nothing() {
    for argv in [
        &["git", "restore", "--staged", "."][..],
        &["git", "restore", "-S", "."],
        &["git", "-C", "repo", "restore", "--staged", ":/"],
    ] {
        let words: Vec<String> = argv.iter().map(|w| (*w).to_string()).collect();
        assert_eq!(verdict(&words), "allow", "{argv:?}");
    }
    for argv in [
        &["git", "restore", "."][..],
        &["git", "restore", "--staged", "--worktree", "."],
        &["git", "restore", "-SW", "."],
        &["git", "restore", "-W", "-S", ":/"],
    ] {
        let words: Vec<String> = argv.iter().map(|w| (*w).to_string()).collect();
        assert_eq!(verdict(&words), "prompt\tgit-discard-worktree", "{argv:?}");
    }
}

#[test]
fn find_and_feeders_do_not_hide_rm() {
    for (line, token) in [
        ("find . -delete", "find-delete"),
        ("find . -exec rm -rf {} +", "find-exec-rm"),
        ("find /tmp -execdir rm {} ;", "find-exec-rm"),
        ("xargs rm -rf", "feeder-rm"),
        ("xargs -n 1 rm", "feeder-rm"),
        ("parallel rm -rf ::: /", "feeder-rm"),
    ] {
        assert_eq!(verdict(&words(line)), format!("deny\t{token}"), "{line}");
    }
    let script = verdict(&["sh".into(), "-c".into(), "find . -delete".into()]);
    assert_eq!(script, "deny\tfind-delete");
    assert_eq!(verdict(&words("find . -name x")), "allow");
    assert_eq!(verdict(&words("xargs echo hi")), "allow");
    assert_eq!(verdict(&words("parallel echo hi")), "allow");
}

#[test]
fn mv_or_rsync_delete_outside_the_work_tree_is_refused() {
    for (line, token) in [
        ("mv ~/projects /dev/null", "mv-tree-outside"),
        ("mv -t /dev/null src", "mv-tree-outside"),
        ("rsync -a --delete empty/ ~/", "rsync-delete-outside"),
        ("rsync -a --delete-after x/ /etc/", "rsync-delete-outside"),
    ] {
        assert_eq!(verdict(&words(line)), format!("deny\t{token}"), "{line}");
    }
    let script = verdict(&[
        "sh".into(),
        "-c".into(),
        "rsync -a --delete empty/ ~/".into(),
    ]);
    assert_eq!(script, "deny\trsync-delete-outside");
    assert_eq!(verdict(&words("mv a.txt b.txt")), "allow");
    assert_eq!(verdict(&words("rsync -a src/ dest/")), "allow");
}
