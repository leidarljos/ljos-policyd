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

/// A checksum tool prints to stdout and writes no file, so a script the
/// line sources after it, or again in a loop, is not one it wrote. A
/// command the guard does not know still may have.
#[test]
fn a_checksum_writes_no_script() {
    let d = scratch("sums");
    std::fs::write(d.join("env.sh"), "export A=1\n").unwrap();
    std::fs::write(d.join("f.txt"), "hi\n").unwrap();
    for line in [
        ". ./env.sh; sha256sum f.txt > SUMS",
        "sha256sum f.txt > SUMS; . ./env.sh",
        "for f in a b; do . ./env.sh; sha256sum f.txt > SUMS; done",
        "f() { . ./env.sh; }; f; sha256sum f.txt > SUMS; f",
        "md5sum f.txt > SUMS; sha512sum -c SUMS; b2sum f.txt; cksum f.txt; . ./env.sh",
    ] {
        assert_eq!(sh(&d, line), "allow", "{line}");
    }
    for line in [
        "mytool f.txt > SUMS; . ./env.sh",
        "for f in a b; do . ./env.sh; mytool f.txt > SUMS; done",
        "sha256sum f.txt > env.sh; . ./env.sh",
    ] {
        let v = sh(&d, line);
        assert!(
            v.starts_with("deny\tscript-written-on-line: "),
            "{line}: {v}"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// `"$0"` in a script started by a path with a `/` runs that file in a
/// child, so it binds no name in this shell and the tunnel's log write
/// stays placed. Started as `bash tunnel`, `$0` has no `/` and may name a
/// function. `"$1"`, and `"$0"` after `eval`, may run anything.
#[test]
fn argv0_by_path_binds_nothing_here() {
    let d = scratch("argv0");
    let tunnel = d.join("tunnel");
    let body = |run: &str| {
        format!(
            "#!/bin/sh\nD={d}/w\nnohup {d}/bin/wp >>$D/wp.log 2>&1 &\n\
             case \"$1\" in\n run) {run} on >/dev/null || exit 1;;\nesac\n",
            d = d.display()
        )
    };
    std::fs::write(&tunnel, body("\"$0\"")).unwrap();
    let path = tunnel.to_str().unwrap();
    assert_eq!(verdict(&d, &[path, "on"]), "allow");
    assert_eq!(verdict(&d, &["bash", path, "run"]), "allow");
    let v = verdict(&d, &["bash", "tunnel", "on"]);
    assert!(v.starts_with("deny\tscript-written-on-line: "), "{v}");
    for run in ["\"$1\"", "eval \"$2\"; \"$0\""] {
        std::fs::write(&tunnel, body(run)).unwrap();
        let v = verdict(&d, &[path, "on"]);
        assert!(
            v.starts_with("deny\tscript-written-on-line: "),
            "{run}: {v}"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// A tunnel script as written by hand. It joins its assignments
/// with `;`, writes its log in a `case` arm under `nohup ... &` through
/// `$BIN` and `$D`, and runs itself again with `"$0"`.
const TUNNEL: &str = r#"#!/bin/bash
# On-demand egress through a userspace SOCKS5 proxy
D=/srv/example/conf; BIN=/srv/example/.local/bin/tunneld; P=127.0.0.1:1080
pid(){ pgrep -f "$BIN -c $D/tunnel.conf"; }
case "$1" in
 on) pid >/dev/null && { echo "already on"; exit 0; }
     nohup $BIN -c $D/tunnel.conf >>$D/tunnel.log 2>&1 & sleep 3; pid >/dev/null && echo "on (socks5 $P)" || { echo "failed; see $D/tunnel.log"; exit 1; };;
 off) pkill -f "$BIN -c $D/tunnel.conf" && echo off || echo "not running";;
 status) if pid >/dev/null; then echo "on pid $(pid)"; echo "exit IP: $(curl -s -m 10 --socks5-hostname $P https://example.org/ip)"; else echo off; fi;;
 run) shift; pid >/dev/null || "$0" on >/dev/null || exit 1
     U=socks5h://$P; exec env ALL_PROXY=$U all_proxy=$U HTTPS_PROXY=$U https_proxy=$U HTTP_PROXY=$U http_proxy=$U NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1 \
       GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.proxy GIT_CONFIG_VALUE_0=$U "$@";;
 *) echo "usage: tunnel on|off|status|run CMD..."; exit 2;;
esac
"#;

/// A `$BIN` command word filled in from a literal is still the command
/// this shell runs: its redirection is placed through `$D` there too.
/// A `-c` script it hands over is a new shell and does not see `$D`.
#[test]
fn the_tunnel_script_runs_as_written() {
    let d = scratch("tunnel");
    let tunnel = d.join("tunnel");
    std::fs::write(&tunnel, TUNNEL).unwrap();
    let path = tunnel.to_str().unwrap();
    for args in [&["on"][..], &["off"], &["status"], &["run", "git", "fetch"]] {
        let argv: Vec<&str> = std::iter::once(path).chain(args.iter().copied()).collect();
        assert_eq!(verdict(&d, &argv), "allow", "{args:?}");
    }
    assert_eq!(sh(&d, &format!("{path} on")), "allow");
    let w = d.join("w");
    let run = format!("{}/bin/x", d.display());
    let line = format!("D={}; BIN={run}; $BIN -c x >>$D/wp.log 2>&1", w.display());
    assert_eq!(sh(&d, &line), "allow");
    let line = format!(
        "D={}; X=sh; $X -c 'echo y >> $D/wp.log; {run}'",
        w.display()
    );
    let v = sh(&d, &line);
    assert!(v.starts_with("deny\tscript-written-on-line: "), "{v}");
    let _ = std::fs::remove_dir_all(&d);
}

/// What the ljos hook asks about a shell line: `check -- bash -c LINE`
/// from the payload's directory, stdin closed, with the seat set.
fn hook_verdict(dir: &std::path::Path, seat: &str, line: &str) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"))
        .args(["check", "--", "bash", "-c", line])
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .env("PHRONESIS_STATE_DIR", dir.join("state"))
        .env("LJOS_SEAT", seat)
        .env("LJOS_IN_HOOK", "1")
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

/// A mail wrapper's spool and sent-copy lines, as written by hand,
/// between a stub head that names the maildir and a stub mailer call.
const SPOOL: &str = r#"tmp=$(mktemp /dev/shm/out.XXXXXX); out=$(mktemp /dev/shm/out.XXXXXX)
trap 'rm -f "$tmp" "$out"' EXIT
cat > "$tmp"
"#;
const SENT: &str = r#"printf '%s' "$add" > "$out"; cat "$tmp" >> "$out"
if ! { cp "$out" "$sent/tmp/$f" && mv "$sent/tmp/$f" "$sent/cur/$f"; }; then
  echo "mailwrap: could not file the sent copy" >&2
fi
"#;

/// `mktemp` makes one new empty file or directory and writes no file
/// that was there before, as `touch` and `mkdir` do. A wrapper run
/// twice from its own directory is not one its first run wrote. A
/// command the guard does not know may still write anything there.
#[test]
fn mktemp_writes_no_script() {
    let d = scratch("mail-twice");
    let wrapper = d.join("mailwrap");
    let head = format!(
        "#!/bin/bash\nsent={}/Maildir/.Sent; f=msg.eml; add='X-Example: 1'\n",
        d.display()
    );
    let mailer = "/usr/local/libexec/ljos-test/deliver \"$@\" < \"$tmp\" || exit 1\n";
    std::fs::write(&wrapper, format!("{head}{SPOOL}{mailer}{SENT}")).unwrap();
    std::fs::write(d.join("ot.eml"), "To: ops@example.org\n\nhi\n").unwrap();
    let w = wrapper.display();
    for line in [
        "./mailwrap -t < ot.eml".to_string(),
        format!("{w} -t < ot.eml; {w} -t < ot.eml"),
        format!("{w} -t < ot.eml && ./mailwrap -t < ot.eml"),
    ] {
        assert_eq!(hook_verdict(&d, "example", &line), "allow", "{line}");
    }
    let other = SPOOL.replace("cat > \"$tmp\"", "mytool");
    std::fs::write(&wrapper, format!("{head}{other}{mailer}")).unwrap();
    let v = hook_verdict(&d, "example", &format!("{w}; {w}"));
    assert!(v.starts_with("deny\tscript-written-on-line: "), "{v}");
    let _ = std::fs::remove_dir_all(&d);
}

/// A script the line runs is a new process each time, so a loop on the
/// line around it does not make its one `mktemp` binding a rebinding.
/// Its writes still count before the loop, and a loop inside the
/// script, or a file it writes that the line runs, still refuses.
#[test]
fn a_wrapper_run_in_a_loop_keeps_its_temps() {
    let d = scratch("mail");
    let wrapper = d.join("mailwrap");
    let head = format!(
        "#!/bin/bash\nsent={}/Maildir/.Sent; f=msg.eml; add='X-Example: 1'\n",
        d.display()
    );
    let mailer = "/usr/local/libexec/ljos-test/deliver \"$@\" < \"$tmp\" || exit 1\n";
    std::fs::write(&wrapper, format!("{head}{SPOOL}{mailer}{SENT}")).unwrap();
    std::fs::write(d.join("ot.eml"), "To: ops@example.org\n\nhi\n").unwrap();
    let w = wrapper.display();
    let eml = d.join("ot.eml");
    let eml = eml.display();
    for line in [
        format!("{w} -t < {eml}"),
        format!("for m in {eml} {eml}; do {w} -t < \"$m\"; done"),
        format!("while read -r m; do {w} -t < \"$m\"; done < list"),
    ] {
        assert_eq!(hook_verdict(&d, "example", &line), "allow", "{line}");
    }
    let looped = "for i in 1 2; do tmp=$(mktemp); done\ncat > \"$tmp\"\n";
    std::fs::write(&wrapper, format!("{head}{looped}{mailer}")).unwrap();
    let v = hook_verdict(&d, "example", &format!("for i in 1 2; do {w}; done"));
    assert!(v.starts_with("deny\tscript-written-on-line: "), "{v}");
    let run = d.join("run.sh");
    std::fs::write(
        &wrapper,
        format!("{head}echo 'rm -rf ~/' > {}\n", run.display()),
    )
    .unwrap();
    let line = format!("for i in 1 2; do {w}; sh {}; done", run.display());
    let v = hook_verdict(&d, "example", &line);
    assert!(v.starts_with("deny\tscript-written-on-line: "), "{v}");
    assert!(v.contains("rm-rf"), "{v}");
    let _ = std::fs::remove_dir_all(&d);
}
