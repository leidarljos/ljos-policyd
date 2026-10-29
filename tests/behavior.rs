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
    let brief = "The notes live in course-module-fundamentals-of-hpc/slides/fundamentals-of-hpc.org.\n";
    std::fs::create_dir_all(root.join("notes")).unwrap();
    std::fs::write(root.join("notes/BRIEF.md"), brief).unwrap();
    let joined = format!("notes/BRIEF.md\n{brief}");
    let c = check_shell(&["bash".into(), "-c".into(), joined]);
    let write = format!("cat > notes/BRIEF.md << 'EOF'\n{brief}EOF");
    let w = check_shell(&["bash".into(), "-c".into(), write]);
    assert_eq!(c.decision, ljos_policyd::policy_capnp::Decision::Allow, "{}", c.token);
    assert!(
        !c.token.contains("script-unread"),
        "{}",
        c.token
    );
    assert_eq!(w.decision, ljos_policyd::policy_capnp::Decision::Allow, "{}", w.token);
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
    assert_eq!(
        verdict(&words("python x.py")),
        "allow\trewrite\tuv run x.py"
    );
    assert_eq!(
        verdict(&words("python3 x.py")),
        "allow\trewrite\tuv run x.py"
    );
    assert_eq!(
        verdict(&["python3".into(), "x.py".into(), "a".into()]),
        "allow\trewrite\tuv run x.py a"
    );
    let inline = verdict(&[
        "python3".into(),
        "-c".into(),
        "print(1)".into(),
    ]);
    assert_eq!(inline, "allow");
    let ask = verdict(&[
        "python3".into(),
        "-c".into(),
        "open('/home/u/.ssh/id_rsa')".into(),
    ]);
    assert_eq!(ask, "prompt\tcredential-mention");
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
