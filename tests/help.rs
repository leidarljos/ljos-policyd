//! `help`, `--help` and `-h` print the usage lines on stdout and exit 0.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ljos-policyd")
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("run policyd");
    let code = out.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

#[test]
fn help_prints_the_usage_lines_and_exits_0() {
    let usage = "\
usage: ljos-policyd check|exec|capnp|version -- argv...
usage: ljos-policyd check-mail --config PATH [--argv [--] RECIPIENT...]
usage: ljos-policyd replay [DENY_LOG]
see the verb table in README.md
";
    for verb in ["help", "--help", "-h"] {
        let (code, stdout, stderr) = run(&[verb]);
        assert_eq!(code, 0, "{verb}");
        assert_eq!(stderr, "", "{verb}");
        assert_eq!(stdout, usage, "{verb}");
        let named: Vec<&str> = stdout
            .lines()
            .filter(|line| line.starts_with("usage: ljos-policyd"))
            .collect();
        let text = named.join("\n");
        for name in ["check", "exec", "capnp", "check-mail", "replay", "version"] {
            assert!(text.contains(name), "{verb} missing {name} in {text}");
        }
        assert!(
            stdout
                .lines()
                .any(|line| line.contains("verb table") && line.contains("README.md")),
            "{verb} stdout={stdout}"
        );
    }
}
