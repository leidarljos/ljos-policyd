//! `script-written-on-line` refuses a script the line may have written
//! before it runs it. A write it cannot place still refuses. Text that is
//! not shell code, and a path the script spells out, do not.

fn verdict(dir: &std::path::Path, argv: &[&str]) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
        .arg("check")
        .arg("--")
        .args(argv)
        .current_dir(dir)
        .env("PHRONESIS_STATE_DIR", dir.join("state"))
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_JANET_PACK")
        .env_remove("PHRONESIS_PREFIX")
        .env_remove("PHRONESIS_PACK_ROOT")
        .env_remove("CDPATH")
        .env_remove("BASH_ENV")
        .env_remove("ENV")
        .output()
        .expect("spawn check");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn sh(dir: &std::path::Path, line: &str) -> String {
    verdict(dir, &["sh", "-c", line])
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "ljos-policyd-written-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const BODY: &str = "Config is in `/srv/example/conf`; \
                    the hook keeps it in `$_ljos_seen`: `printf %s x > \"$_ljos_seen\"`";

/// An argument is text for the program. Backticks in it are markdown,
/// whether the argv comes as is or single-quoted in a shell line.
#[test]
fn quoted_prose_is_not_a_script_write() {
    let d = scratch("prose");
    let v = verdict(&d, &["ljos", "file", "--title", "x", "--body", BODY]);
    assert_eq!(v, "allow");
    let quoted = BODY.replace('\'', "");
    let v = sh(&d, &format!("ljos file --title x --body '{quoted}'"));
    assert_eq!(v, "allow");
    let v = sh(
        &d,
        "ljos file --body 'run `sh /srv/example/up.sh` > \"$x\"'",
    );
    assert_eq!(v, "allow");
    let _ = std::fs::remove_dir_all(&d);
}

/// Inside double quotes, or bare, a backtick still runs, and so does a
/// `-c` script handed over as an argv word.
#[test]
fn a_substitution_the_shell_runs_is_still_read() {
    let d = scratch("subst");
    let dq = "ljos file --body \"in `/srv/example/conf` and `printf x > \\\"$s\\\"`\"";
    let v = sh(&d, dq);
    assert!(v.starts_with("deny\tscript-written-on-line: "), "{v}");
    for line in [
        "echo `rm -rf ~/x`",
        "echo \"$(rm -rf ~/x)\"",
        "x=$(rm -rf ~/x)",
    ] {
        let v = sh(&d, line);
        assert!(v.starts_with("deny\t"), "{line}: {v}");
    }
    let v = verdict(&d, &["bash", "-c", "echo `rm -rf ~/x`"]);
    assert!(v.starts_with("deny\t"), "{v}");
    let _ = std::fs::remove_dir_all(&d);
}
