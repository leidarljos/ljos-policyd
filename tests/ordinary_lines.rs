//! Ordinary lines 0.5.1 refused. `ljos-policyd check` allows each one.

use std::fs;
use std::path::Path;
use std::process::Command;

fn check(dir: &Path, argv: &[&str]) -> String {
    fs::create_dir_all(dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
        .arg("check")
        .arg("--")
        .args(argv)
        .current_dir(dir)
        .env(
            "LJOS_POLICYD_DENY_LOG",
            dir.join("state/deny.log").to_str().unwrap(),
        )
        .env_remove("PHRONESIS_STATE_DIR")
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_JANET_PACK")
        .output()
        .expect("spawn ljos-policyd check");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn root(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("policyd-ordinary-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `bash -c 'bash /tmp/x/audit.sh'` where the script holds jq filters.
/// The filters use object literals. The check does not open the script.
#[test]
fn a_jq_script_run_by_path_is_allowed() {
    let dir = root("jq");
    let script_dir = dir.join("x");
    fs::create_dir_all(&script_dir).unwrap();
    let script = script_dir.join("audit.sh");
    fs::write(
        &script,
        "jq -n --arg a 1 '\n  {key:(\"k:\\($a)\"), sha:\"x\"}\n  | {items:{runs:1}}'\n",
    )
    .unwrap();
    let line = format!("bash {}", script.display());
    let v = check(&dir, &["bash", "-c", &line]);
    assert!(v.starts_with("allow"), "{v}");
    assert!(!v.contains("brace"), "{v}");
    let _ = fs::remove_dir_all(&dir);
}

/// `cat > .../resolve.py <<'EOF2'` then `python3` of that file.
#[test]
fn a_heredoc_python_file_that_is_then_run_is_allowed() {
    let dir = root("py");
    let pc = dir.join("pc");
    fs::create_dir_all(&pc).unwrap();
    let path = pc.join("resolve.py");
    let line = format!(
        "cat > {} <<'EOF2'\nprint(1)\nEOF2\npython3 {}",
        path.display(),
        path.display()
    );
    let v = check(&dir, &["bash", "-c", &line]);
    assert!(v.starts_with("allow"), "{v}");
    assert!(!v.contains("script-written"), "{v}");
    let _ = fs::remove_dir_all(&dir);
}

/// A parenthesised count is not a path write.
#[test]
fn a_parenthesised_count_is_not_a_path() {
    let dir = root("count");
    let v = check(
        &dir,
        &["bash", "-c", "echo \"audit done (9/9)\" && echo next"],
    );
    assert!(v.starts_with("allow"), "{v}");
    assert!(!v.contains("9/9"), "{v}");
    let _ = fs::remove_dir_all(&dir);
}

/// `printf` appends to REFUSALS.txt. The count in the text is not a path.
#[test]
fn a_printf_count_appends_only_the_named_file() {
    let dir = root("printf");
    let v = check(
        &dir,
        &["bash", "-c", "printf 'step (9/9)\\n' >> REFUSALS.txt"],
    );
    assert!(v.starts_with("allow"), "{v}");
    assert!(!v.contains("9/9"), "{v}");
    let _ = fs::remove_dir_all(&dir);
}

/// A heredoc that writes a python file and does not run it.
#[test]
fn a_heredoc_that_only_writes_a_python_file_is_allowed() {
    let dir = root("notes");
    fs::create_dir_all(dir.join("notes")).unwrap();
    let v = check(
        &dir,
        &[
            "bash",
            "-c",
            "cat > notes/lastnotes.py <<'EOF'\nprint('notes')\nEOF",
        ],
    );
    assert!(v.starts_with("allow"), "{v}");
    let _ = fs::remove_dir_all(&dir);
}
