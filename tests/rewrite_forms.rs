//! Command forms the uv rewrite has to keep. The verdict is one line.
//! Where that line can be run with python standing in for `uv run`, the
//! program's output matches the original. A form with no such spelling is
//! the original command plus a note, and a second look does not rewrite it.

use ljos_policyd::verdict;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

const NOTE_INLINE: &str = "ljos-policyd: left as written, uv run does not take -c";
const NOTE_REPL: &str = "ljos-policyd: left as written, no script was named";
const NOTE_OPTION: &str = "ljos-policyd: left as written, that option is not a script";
const NOTE_ACTIVATE: &str = "ljos-policyd: left as written, activation is shell state";
const NOTE_PIP: &str = "ljos-policyd: left as written, uv pip has no spelling for that flag";

fn cwd_lock() -> &'static Mutex<()> {
    static CWD: Mutex<()> = Mutex::new(());
    &CWD
}

struct Project {
    dir: PathBuf,
    prev: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl Project {
    fn new() -> Self {
        let guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "policyd-forms-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".venv/bin")).unwrap();
        std::fs::write(dir.join("pyproject.toml"), "[project]\nname = \"x\"\n").unwrap();
        std::fs::write(dir.join("x.py"), "print(1)\n").unwrap();
        std::fs::write(dir.join("a b.py"), "print(1)\n").unwrap();
        std::fs::write(dir.join("requirements.txt"), "requests\n").unwrap();
        std::fs::write(dir.join(".venv/bin/activate"), "export LJOS_FORM=on\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        Self {
            dir,
            prev,
            _guard: guard,
        }
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn line(args: &[&str]) -> String {
    verdict(&args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
}

fn rewritten(v: &str) -> &str {
    assert!(!v.contains('\n'), "verdict is one line: {v:?}");
    v.strip_prefix("allow\trewrite\t")
        .unwrap_or_else(|| panic!("not a rewrite: {v}"))
}

fn bash(script: &str) -> (i32, String, String) {
    let out = Command::new("bash").arg("-c").arg(script).output().unwrap();
    let code = out.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

/// `uv` is not required here. `uv run` (and the active-env prefix) becomes
/// `python3`, which is the interpreter the original line used.
fn as_python(script: &str) -> String {
    let script = script
        .replace("uv run --active --no-sync python3", "python3")
        .replace("uv run --active --no-sync python", "python3")
        .replace("uv run --active --no-sync ", "python3 ");
    let script = script
        .replace("uv run python3", "python3")
        .replace("uv run python", "python3");
    script.replace("uv run ", "python3 ")
}

fn assert_same_program(original: &str, verdict_line: &str) {
    let (c0, o0, e0) = bash(original);
    let ran = as_python(rewritten(verdict_line));
    let (c1, o1, e1) = bash(&ran);
    assert_eq!(
        c0, c1,
        "exit {original:?} -> {c0} ({e0}) vs {ran:?} -> {c1} ({e1})"
    );
    assert_eq!(o0, o1, "stdout {original:?} vs {ran:?}");
}

/// The line a runner judges again. One `bash -c SCRIPT` wrapper comes
/// off; any other shape is the line.
fn recheck_of(command: &str) -> String {
    let Some(rest) = command.strip_prefix("bash -c ") else {
        return command.to_string();
    };
    shell_word(rest).unwrap_or_else(|| command.to_string())
}

fn shell_word(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut out = String::new();
    if b.is_empty() {
        return None;
    }
    while i < b.len() {
        if b[i] == b'\'' {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                out.push(b[i] as char);
                i += 1;
            }
            if i >= b.len() {
                return None;
            }
            i += 1;
            continue;
        }
        if b[i] == b'\\' && i + 1 < b.len() {
            out.push(b[i + 1] as char);
            i += 2;
            continue;
        }
        if b[i] == b'$' && b.get(i + 1) == Some(&b'\'') {
            i += 2;
            while i < b.len() && b[i] != b'\'' {
                if b[i] == b'\\' && b.get(i + 1) == Some(&b'n') {
                    out.push('\n');
                    i += 2;
                    continue;
                }
                out.push(b[i] as char);
                i += 1;
            }
            if i >= b.len() {
                return None;
            }
            i += 1;
            continue;
        }
        return None;
    }
    Some(out)
}

fn assert_stable(v: &str) {
    let command = rewritten(v);
    let again = line(&["bash", "-c", &recheck_of(command)]);
    assert_eq!(again, "allow", "second look at {command}: {again}");
}

#[test]
fn python_m_becomes_uv_run_m() {
    let _project = Project::new();
    let cases = [
        (&["python3", "-m", "json.tool"][..], "uv run -m json.tool"),
        (&["python", "-m", "pytest", "-q"][..], "uv run -m pytest -q"),
        (
            &["python3", "-m", "pip", "install", "-r", "requirements.txt"][..],
            "uv run -m pip install -r requirements.txt",
        ),
        (&["python3", "-u", "x.py"][..], "uv run python3 -u x.py"),
        (&["python3", "--version"][..], "uv run python3 --version"),
        (&["python3", "-mpytest"][..], "uv run python3 -mpytest"),
    ];
    for (argv, want) in cases {
        let v = line(argv);
        assert_eq!(rewritten(&v), want, "{argv:?}");
        assert_stable(&v);
    }
    let script = "printf '%s\\n' '{\"a\": 1}' | python3 -m json.tool";
    let v = line(&["bash", "-c", script]);
    assert_eq!(
        recheck_of(rewritten(&v)),
        "printf '%s\\n' '{\"a\": 1}' | uv run -m json.tool"
    );
    assert_same_program(script, &v);
    assert_stable(&v);
    let flagged = "python3 -u x.py";
    let v = line(&["bash", "-c", flagged]);
    assert_eq!(recheck_of(rewritten(&v)), "uv run python3 -u x.py");
    assert_same_program(flagged, &v);
    assert_same_program("python3 --version", &line(&["python3", "--version"]));
}

#[test]
fn pip_install_r_and_editable_become_uv_pip() {
    let _project = Project::new();
    let cases = [
        (
            &["pip", "install", "-r", "requirements.txt"][..],
            "uv pip install -r requirements.txt",
        ),
        (&["pip3", "install", "-e", "."][..], "uv pip install -e ."),
        (
            &["pip", "install", "-e", ".", "-r", "requirements.txt"][..],
            "uv pip install -e . -r requirements.txt",
        ),
        (
            &["pip", "install", "--requirement=requirements.txt"][..],
            "uv pip install --requirement=requirements.txt",
        ),
        (
            &["pip", "install", "-U", "requests"][..],
            "uv pip install -U requests",
        ),
        (
            &["bash", "-c", "pip install -r requirements.txt -e ."][..],
            "bash -c 'uv pip install -r requirements.txt -e .'",
        ),
    ];
    for (argv, want) in cases {
        let v = line(argv);
        assert_eq!(rewritten(&v), want, "{argv:?}");
        assert_stable(&v);
        let out = Command::new("bash")
            .args(["-n", "-c", rewritten(&v)])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let v = line(&["pip", "install", "--user", "requests"]);
    assert_eq!(
        rewritten(&v),
        format!("pip install --user requests # {NOTE_PIP}")
    );
    assert_stable(&v);
    let v = line(&["pip", "wheel", "requests"]);
    assert!(rewritten(&v).contains(NOTE_PIP), "{}", rewritten(&v));
    assert!(rewritten(&v).starts_with("pip wheel requests "));
    assert_stable(&v);
}

#[test]
fn venv_activation_keeps_the_shell_and_the_active_env() {
    let _project = Project::new();
    std::fs::write(
        "x.py",
        "import os\nprint(os.environ.get('LJOS_FORM', 'off'))\n",
    )
    .unwrap();
    let alone = line(&["source", ".venv/bin/activate"]);
    assert_eq!(
        rewritten(&alone),
        format!("source .venv/bin/activate # {NOTE_ACTIVATE}")
    );
    assert_stable(&alone);
    let (code, _, err) = bash(rewritten(&alone));
    assert_eq!(code, 0, "{err}");
    let dot = line(&[".", ".venv/bin/activate"]);
    assert_eq!(
        rewritten(&dot),
        format!(". .venv/bin/activate # {NOTE_ACTIVATE}")
    );
    let script = "source .venv/bin/activate && python3 x.py";
    let v = line(&["bash", "-c", script]);
    assert_eq!(
        recheck_of(rewritten(&v)),
        "source .venv/bin/activate && uv run --active --no-sync x.py"
    );
    assert_same_program(script, &v);
    assert_stable(&v);
    let piped = "source .venv/bin/activate | python3 x.py";
    let v = line(&["bash", "-c", piped]);
    // A pipe runs `source` in a subshell. `--active` would point uv at an
    // environment the python on the right never sees.
    assert_eq!(
        recheck_of(rewritten(&v)),
        "source .venv/bin/activate | uv run x.py"
    );
    assert_same_program(piped, &v);
}

#[test]
fn env_prefixes_and_quotes_round_trip() {
    let _project = Project::new();
    let cases = [
        (&["FOO=bar", "python3", "x.py"][..], "FOO=bar uv run x.py"),
        (&["FOO=a$b", "python3", "x.py"][..], "FOO='a$b' uv run x.py"),
        (
            &["env", "FOO=bar", "python3", "x.py"][..],
            "env FOO=bar uv run x.py",
        ),
        (&["python3", "a b.py"][..], "uv run 'a b.py'"),
        (&["python3", "'a b.py'"][..], "uv run 'a b.py'"),
        (
            &["sh", "-c", "python3 \"a b.py\""][..],
            "sh -c 'uv run \"a b.py\"'",
        ),
        (
            &["bash", "-c", "FOO=bar python3 x.py"][..],
            "bash -c 'FOO=bar uv run x.py'",
        ),
    ];
    for (argv, want) in cases {
        let v = line(argv);
        assert_eq!(rewritten(&v), want, "{argv:?}");
        assert_stable(&v);
    }
    assert_same_program("python3 'a b.py'", &line(&["python3", "a b.py"]));
    assert_same_program(
        "FOO='a$b' python3 x.py",
        &line(&["FOO=a$b", "python3", "x.py"]),
    );
}

#[test]
fn heredocs_run_the_same_program() {
    let _project = Project::new();
    let body = "python3 <<'EOF'\nprint(\"python x.py\")\nEOF";
    let v = line(&["bash", "-c", body]);
    let got = recheck_of(rewritten(&v));
    assert_eq!(
        got, "uv run - <<'EOF'\nprint(\"python x.py\")\nEOF",
        "{got:?}"
    );
    assert_same_program(body, &v);
    assert_stable(&v);

    let spaced = "python3 << EOF\nprint(9)\nEOF";
    let v = line(&["bash", "-c", spaced]);
    assert_eq!(recheck_of(rewritten(&v)), "uv run - << EOF\nprint(9)\nEOF");
    assert_same_program(spaced, &v);
    assert_stable(&v);

    let dashed = "python3 - <<EOF\nprint(2)\nEOF";
    let v = line(&["bash", "-c", dashed]);
    assert_eq!(recheck_of(rewritten(&v)), "uv run - <<EOF\nprint(2)\nEOF");
    assert_same_program(dashed, &v);
    assert_stable(&v);

    let flagged = "python3 -u <<EOF\nprint(3)\nEOF";
    let v = line(&["bash", "-c", flagged]);
    assert_eq!(
        recheck_of(rewritten(&v)),
        "uv run python3 -u <<EOF\nprint(3)\nEOF"
    );
    assert_same_program(flagged, &v);

    let data = "python3 x.py <<EOF\nnot a program\nEOF";
    let v = line(&["bash", "-c", data]);
    assert_eq!(
        recheck_of(rewritten(&v)),
        "uv run x.py <<EOF\nnot a program\nEOF"
    );
    assert_same_program(data, &v);
    assert_stable(&v);

    let piped = "printf '%s\\n' 'print(7)' | python3";
    let v = line(&["bash", "-c", piped]);
    assert_eq!(
        recheck_of(rewritten(&v)),
        "printf '%s\\n' 'print(7)' | uv run -"
    );
    assert_same_program(piped, &v);
    assert_stable(&v);

    let or_else = "false || python3 x.py";
    let v = line(&["bash", "-c", or_else]);
    assert_eq!(recheck_of(rewritten(&v)), "false || uv run x.py");
    assert_same_program(or_else, &v);
}

#[test]
fn forms_without_a_uv_spelling_pass_through_with_a_note() {
    let _project = Project::new();
    let inline = line(&["python3", "-c", "print(1)"]);
    assert_eq!(
        rewritten(&inline),
        format!("python3 -c 'print(1)' # {NOTE_INLINE}")
    );
    let (code, out, err) = bash(rewritten(&inline));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "1\n");
    assert_stable(&inline);

    let shell = "python3 -c 'print(4)'";
    let v = line(&["bash", "-c", shell]);
    let got = recheck_of(rewritten(&v));
    assert!(got.starts_with(shell), "{got}");
    assert!(got.contains(NOTE_INLINE), "{got}");
    assert_same_program(shell, &v);
    assert_stable(&v);

    let opt = line(&["python3", "--module", "json.tool"]);
    assert_eq!(
        rewritten(&opt),
        format!("python3 --module json.tool # {NOTE_OPTION}")
    );
    assert_stable(&opt);
    let (c0, _, _) = bash("python3 --module json.tool");
    let (c1, _, _) = bash(rewritten(&opt));
    assert_eq!(c0, c1);
    assert_ne!(c0, 0);

    let repl = line(&["python3"]);
    assert_eq!(rewritten(&repl), format!("python3 # {NOTE_REPL}"));
    assert_stable(&repl);

    let nested = "echo \"$(python3 -c 'print(5)')\"";
    let v = line(&["bash", "-c", nested]);
    let got = recheck_of(rewritten(&v));
    assert!(got.contains("$(python3 -c 'print(5)')"), "{got}");
    assert!(got.contains(NOTE_INLINE), "{got}");
    assert_same_program(nested, &v);
    assert_stable(&v);
}

#[test]
fn a_rewritten_line_is_not_rewritten_again() {
    let _project = Project::new();
    for argv in [
        &["python3", "x.py"][..],
        &["python3", "-m", "json.tool"][..],
        &["pip", "install", "-e", "."][..],
        &["python3", "-u", "x.py"][..],
        &["bash", "-c", "python3 x.py"][..],
        &["bash", "-c", "python3 <<EOF\nprint(1)\nEOF"][..],
        &["bash", "-c", "source .venv/bin/activate && python3 x.py"][..],
        &["python3", "-c", "print(1)"][..],
        &["source", ".venv/bin/activate"][..],
    ] {
        let v = line(argv);
        assert_stable(&v);
        let third = recheck_of(rewritten(&v));
        let twice = line(&["bash", "-c", &third]);
        assert_eq!(twice, "allow", "{argv:?} second {third:?} -> {twice}");
    }
}

#[test]
fn outside_a_project_these_forms_stay_allow() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("policyd-forms-out-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();
    let _back = DirBack { prev };
    for argv in [
        &["python3", "-m", "json.tool"][..],
        &["pip", "install", "-r", "requirements.txt"][..],
        &["pip", "install", "-e", "."][..],
        &["source", ".venv/bin/activate"][..],
        &["python3", "-c", "print(1)"][..],
        &["python3", "-u", "x.py"][..],
        &["bash", "-c", "python3 <<EOF\nprint(1)\nEOF"][..],
        &["bash", "-c", "python3 x.py"][..],
    ] {
        assert_eq!(line(argv), "allow", "{argv:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

struct DirBack {
    prev: PathBuf,
}

impl Drop for DirBack {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev);
    }
}
