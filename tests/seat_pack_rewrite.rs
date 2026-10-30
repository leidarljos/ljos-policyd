//! Under the seat pack, bare python is a refusal the host can fix: the
//! verdict hands back the `uv run` line. The default pack rewrites only
//! when the tree asks for uv.

#[cfg(has_phronesis)]
#[test]
fn the_seat_packs_uv_refusal_is_answered_with_the_uv_line() {
    let base = std::env::temp_dir().join(format!("ljos-policyd-seat-uv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("x.py"), "print(1)\n").unwrap();
    std::fs::write(
        work.join("tool.py"),
        "# /// script\n# requires-python = \">=3.11\"\n# ///\nprint(1)\n",
    )
    .unwrap();
    let check = |pack: Option<&str>, argv: &[&str]| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"));
        cmd.arg("check")
            .arg("--")
            .args(argv)
            .current_dir(&work)
            .env("PHRONESIS_STATE_DIR", base.join("state"))
            .env_remove("PHRONESIS_WORKSPACE")
            .env_remove("PHRONESIS_JANET_PACK");
        match pack {
            Some(p) => cmd.env("LJOS_POLICYD_PACK", p),
            None => cmd.env_remove("LJOS_POLICYD_PACK"),
        };
        let out = cmd.output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    // The default law has no uv rule, and the tree has no project file.
    assert_eq!(check(None, &["python", "x.py"]), "allow");
    // The seat pack refuses bare python; the answer is the line that meets it.
    assert_eq!(
        check(Some("seat"), &["python", "x.py"]),
        "allow\trewrite\tuv run x.py"
    );
    assert_eq!(
        check(Some("seat"), &["python3", "x.py", "--n", "3"]),
        "allow\trewrite\tuv run x.py --n 3"
    );
    // `-c` has no uv spelling, so the refusal stands.
    let inline = check(Some("seat"), &["python3", "-c", "print(1)"]);
    assert!(inline.starts_with("deny\t"), "{inline}");
    // The rewritten line meets the pack on its own: a PEP 723 script runs,
    // a bare one is still refused there, for its missing block.
    assert_eq!(check(Some("seat"), &["uv", "run", "tool.py"]), "allow");
    let bare = check(Some("seat"), &["uv", "run", "x.py"]);
    assert!(bare.starts_with("deny\t"), "{bare}");
    let _ = std::fs::remove_dir_all(&base);
}
