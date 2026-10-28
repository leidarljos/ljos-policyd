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

/// A variable the script assigns only from literals is that path. The
/// tunnel script writes its log under `$D` and then runs a program the
/// guard cannot read.
#[test]
fn a_literal_variable_is_the_path_it_names() {
    let d = scratch("literal");
    let conf = d.join("tunnel");
    let tunnel = format!(
        "#!/bin/sh\nBIN=/usr/local/bin/tunneld\nD={}\nmkdir -p \"$D\"\n\
         pkill -f tunneld || true\nsleep 1\n\
         nohup $BIN -c $D/tunnel.conf >>$D/tunnel.log 2>&1 &\n\
         sleep 2\n/usr/local/libexec/ljos-test/check-tunnel\n",
        conf.display(),
    );
    std::fs::write(d.join("tunnel.sh"), &tunnel).unwrap();
    assert_eq!(verdict(&d, &["bash", "tunnel.sh"]), "allow");
    let run = format!("{}/bin/check", d.display());
    for line in [
        "D={d}/w; echo x >> $D/wp.log; {run}",
        "D={d}/w; echo x >> ${D}/wp.log; {run}",
        "D={d}/w; L=\"$D/logs\"; echo x >> \"$L/wp.log\"; {run}",
        "D='{d}/w'; F=wp; echo x >> $D/$F.log; {run}",
        "if true; then D={d}/a; else D={d}/b; fi; echo x >> $D/wp.log; {run}",
    ] {
        let line = line
            .replace("{d}", &d.to_string_lossy())
            .replace("{run}", &run);
        assert_eq!(sh(&d, &line), "allow", "{line}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// A name the line does not pin to one literal still refuses: a
/// positional, the environment, `read`, a reassignment after the
/// literal, a branch that leaves it unset or unknown, a loop, `unset`
/// and `eval`. A literal that reads such a name is not pinned either.
#[test]
fn an_unpinned_variable_still_refuses() {
    let d = scratch("unpinned");
    let run = format!("{}/bin/check", d.display());
    for line in [
        "D=$1; echo x >> $D/wp.log; {run}",
        "echo x >> $LJOS_TEST_UNSET/wp.log; {run}",
        "echo x >> $HOME/wp.log; D=$HOME; echo x >> $D/wp.log; {run}",
        "read D; echo x >> $D/wp.log; {run}",
        "D={d}/w; D=$1; echo x >> $D/wp.log; {run}",
        "D={d}/w; echo x >> $D/wp.log; D=$(cat f); {run}",
        "D={d}/w; echo x >> $D/wp.log; read D; {run}",
        "D={d}/w; if c; then D=$X; fi; echo x >> $D/wp.log; {run}",
        "if c; then D={d}/w; fi; echo x >> $D/wp.log; {run}",
        "D={d}/w; for i in 1 2; do echo x >> $D/l; D={d}/v; done; {run}",
        "D={d}/w; unset D; echo x >> $D/wp.log; {run}",
        "D={d}/w; eval \"$2\"; echo x >> $D/wp.log; {run}",
        "B=$D/x; D={d}/w; echo x >> $B; {run}",
        "D={d}/w; B=$D/x; D=$1; echo x >> $B; {run}",
        "D=\"{d}/a b\"; echo x > $D/l; {run}",
        "D={d}/*; echo x > $D/l; {run}",
    ] {
        let line = line
            .replace("{d}", &d.to_string_lossy())
            .replace("{run}", &run);
        let v = sh(&d, &line);
        assert!(
            v.starts_with("deny\tscript-written-on-line: "),
            "{line}: {v}"
        );
    }
    let v = verdict(
        &d,
        &[
            "bash",
            "-c",
            "D=$1; echo x >> $D/wp.log; /usr/local/bin/x",
            "sh",
            "/tmp",
        ],
    );
    assert!(v.starts_with("deny\t"), "{v}");
    let _ = std::fs::remove_dir_all(&d);
}

/// The path a literal variable names is judged as the line spells it:
/// a script written there and run is read as that text.
#[test]
fn a_literal_variable_script_is_judged_on_its_text() {
    let d = scratch("text");
    let p = d.join("run.sh");
    let line = format!(
        "D={}; echo 'rm -rf ~/' > $D/run.sh; sh {}",
        d.display(),
        p.display()
    );
    let v = sh(&d, &line);
    assert!(v.starts_with("deny\tscript-written-on-line: "), "{v}");
    assert!(v.contains("rm-rf"), "{v}");
    let line = format!(
        "D={}; echo 'echo ok' > $D/run.sh; sh {}",
        d.display(),
        p.display()
    );
    assert_eq!(sh(&d, &line), "allow");
    let _ = std::fs::remove_dir_all(&d);
}

/// A name set only from `mktemp` is a new private file or directory.
/// A mail wrapper spools its message there and then runs a
/// program the guard cannot read.
#[test]
fn a_mktemp_variable_is_a_fresh_path() {
    let d = scratch("mktemp");
    let wrapper = "#!/bin/sh\ntmp=$(mktemp)\ntrap 'rm -f \"$tmp\"' EXIT\ncat > \"$tmp\"\n\
                   /usr/local/libexec/ljos-test/deliver -t < \"$tmp\"\n";
    std::fs::write(d.join("mail.sh"), wrapper).unwrap();
    assert_eq!(verdict(&d, &["sh", "mail.sh"]), "allow");
    for line in [
        "tmp=`mktemp`; cat > \"$tmp\"; /usr/local/libexec/x",
        "tmp=\"$(mktemp)\"; cat > \"$tmp\"; /usr/local/libexec/x",
        "tmp=$(mktemp -d); echo x > $tmp/a; /usr/local/libexec/x",
        "tmp=$(mktemp /tmp/m.XXXXXX); echo x > $tmp; /usr/local/libexec/x",
        "tmp=$(mktemp -d ./confXXXXXX); echo x > \"$tmp/a\"; /usr/local/libexec/x",
        "tmp=$(mktemp -d); out=$tmp/o; echo x > $out; /usr/local/libexec/x",
    ] {
        assert_eq!(sh(&d, line), "allow", "{line}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Only the new file itself, or a path under it, is fresh. A temp the
/// line runs after writing it is still judged, and a name built around
/// it, reset, read, or made by a `mktemp` that may print nothing or a
/// path the line does not show still refuses.
#[test]
fn a_mktemp_variable_is_only_that_path() {
    let d = scratch("mktemp-no");
    let v = sh(
        &d,
        "tmp=$(mktemp); echo 'rm -rf ~/' > \"$tmp\"; sh \"$tmp\"",
    );
    assert!(v.starts_with("deny\t"), "{v}");
    for line in [
        "tmp=$(mktemp); echo x > $tmp.log; /usr/local/libexec/x",
        "tmp=$(mktemp) && echo x > x$tmp; /usr/local/libexec/x",
        "tmp=$(mktemp -d); echo x > $tmp/../a; /usr/local/libexec/x",
        "tmp=$(mktemp -u); echo x > $tmp; /usr/local/libexec/x",
        "tmp=$(mktemp -p /x); echo x > $tmp; /usr/local/libexec/x",
        "tmp=$(mktemp $T); echo x > $tmp; /usr/local/libexec/x",
        "tmp=$(mktemp >/dev/null); echo x > $tmp/run.sh; /run.sh",
        "tmp=$(mktemp; echo /x); echo x > $tmp; /usr/local/libexec/x",
        "tmp=$(mktemp); tmp=$1; echo x > $tmp; /usr/local/libexec/x",
        "tmp=$(mktemp); echo x > $tmp; read tmp; /usr/local/libexec/x",
        "for i in 1; do tmp=$(mktemp); done; echo x > $tmp; /usr/local/libexec/x",
    ] {
        let v = sh(&d, line);
        assert!(
            v.starts_with("deny\tscript-written-on-line: "),
            "{line}: {v}"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}
