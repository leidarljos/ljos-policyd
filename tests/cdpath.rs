//! A `cd` or `pushd` to a relative name finds it through `CDPATH` as the
//! shell does, so a task runner after it is read in each directory the
//! shell may enter.

fn check(dir: &std::path::Path, cdpath: Option<&str>, line: &str) -> String {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ljos-policyd"));
    cmd.args(["check", "--", "sh", "-c", line])
        .current_dir(dir)
        .env("PHRONESIS_STATE_DIR", dir.join("state"))
        .env_remove("PHRONESIS_WORKSPACE")
        .env_remove("PHRONESIS_JANET_PACK")
        .env_remove("PHRONESIS_PREFIX")
        .env_remove("PHRONESIS_PACK_ROOT");
    match cdpath {
        Some(p) => cmd.env("CDPATH", p),
        None => cmd.env_remove("CDPATH"),
    };
    let out = cmd.output().expect("spawn check");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `work/proj` is harmless and `lib/proj` runs `rm -rf ~/`, so a line
/// from `work` that enters `proj` through `CDPATH=lib` is refused.
#[test]
fn reads_a_runner_where_cdpath_enters() {
    let base = std::env::temp_dir().join(format!("ljos-policyd-cdpath-{}", std::process::id()));
    let work = base.join("work");
    let lib = base.join("lib");
    for d in [work.join("proj"), lib.join("proj"), lib.join(".hid")] {
        std::fs::create_dir_all(&d).unwrap();
    }
    std::fs::write(work.join("proj/clean-all"), "echo clean\n").unwrap();
    std::fs::write(lib.join("proj/clean-all"), "rm -rf ~/\n").unwrap();
    std::fs::write(lib.join(".hid/clean-all"), "rm -rf ~/\n").unwrap();
    let abs = lib.to_string_lossy().into_owned();
    for (cdpath, line) in [
        (abs.as_str(), "cd proj && sh clean-all"),
        (abs.as_str(), "pushd proj && sh clean-all"),
        (abs.as_str(), "cd .hid && sh clean-all"),
        (abs.as_str(), "true ; cd proj ; sh clean-all"),
        ("/nowhere:../lib", "cd proj && sh clean-all"),
    ] {
        let v = check(&work, Some(cdpath), line);
        assert!(v.starts_with("deny\t"), "CDPATH={cdpath} {line}: {v}");
    }
    for (cdpath, line) in [
        (Some(abs.as_str()), "cd ./proj && sh clean-all"),
        (Some(abs.as_str()), "cd proj && make test"),
        (Some(abs.as_str()), "env -C proj sh clean-all"),
        (None, "cd proj && sh clean-all"),
    ] {
        assert_eq!(
            check(&work, cdpath, line),
            "allow",
            "CDPATH={cdpath:?} {line}"
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// `work/proj` is harmless and `lib/proj` runs `rm -rf ~/`, with no
/// `CDPATH` in the environment; `name` tells the runs apart.
fn work_and_lib(name: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("ljos-policyd-{name}-{}", std::process::id()));
    for d in ["work/proj", "lib/proj"] {
        std::fs::create_dir_all(base.join(d)).unwrap();
    }
    std::fs::write(base.join("work/proj/clean-all"), "echo clean\n").unwrap();
    std::fs::write(base.join("lib/proj/clean-all"), "rm -rf ~/\n").unwrap();
    base.join("work")
}

/// A `CDPATH` set in front of the `cd`, or of the shell that runs it, is
/// searched; one whose value the line does not show leaves the runner
/// after the `cd` refused.
#[test]
fn reads_a_runner_where_a_cdpath_set_on_the_cd_enters() {
    let work = work_and_lib("cdpath-cd");
    for line in [
        "CDPATH=../lib cd proj && sh clean-all",
        "CDPATH=/nowhere:../lib pushd proj && sh clean-all",
        "CDPATH=/nowhere CDPATH+=:../lib cd proj && sh clean-all",
        "if CDPATH=../lib cd proj; then sh clean-all; fi",
        "CDPATH=../lib sh -c 'cd proj && sh clean-all'",
        "env CDPATH=../lib sh -c 'cd proj && sh clean-all'",
        "CDPATH=$LIB cd proj && sh clean-all",
        "CDPATH=~/lib cd proj && sh clean-all",
    ] {
        let v = check(&work, None, line);
        assert!(v.starts_with("deny\t"), "{line}: {v}");
    }
    for line in [
        "CDPATH=../lib cd ./proj && sh clean-all",
        "CDPATH=$LIB cd ./proj && sh clean-all",
        "CDPATH=../lib true; cd proj && sh clean-all",
        "HOME=/nowhere; CDPATH=$LIB cd $HOME/proj && sh clean-all",
    ] {
        assert_eq!(check(&work, None, line), "allow", "{line}");
    }
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

/// The shell takes the first `CDPATH` entry that holds the path, and an
/// empty or `.` entry is the working directory, so a later entry is not
/// entered when the path is here.
#[test]
fn takes_the_first_cdpath_entry_that_holds_the_path() {
    let work = work_and_lib("cdpath-first");
    for line in [
        "CDPATH=:../lib cd proj && sh clean-all",
        "CDPATH=.:../lib cd proj && sh clean-all",
        "CDPATH=./:../lib pushd proj && sh clean-all",
        "CDPATH=/nowhere::../lib cd proj && sh clean-all",
    ] {
        assert_eq!(check(&work, None, line), "allow", "{line}");
    }
    for line in [
        "CDPATH=../lib:. cd proj && sh clean-all",
        "CDPATH=$LIB:. cd proj && sh clean-all",
    ] {
        let v = check(&work, None, line);
        assert!(v.starts_with("deny\t"), "{line}: {v}");
    }
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

/// A `CDPATH` the line sets earlier, alone or with `export` and the like,
/// is searched by a later `cd`, unless a subshell set it.
#[test]
fn reads_a_runner_where_a_cdpath_set_earlier_enters() {
    let work = work_and_lib("cdpath-set");
    for line in [
        "export CDPATH=../lib; cd proj && sh clean-all",
        "CDPATH=../lib; cd proj; sh clean-all",
        "{ CDPATH=../lib; }; cd proj && sh clean-all",
        "declare -x CDPATH=../lib && cd proj && sh clean-all",
        "CDPATH=/nowhere; CDPATH+=:../lib; cd proj && sh clean-all",
        "true && CDPATH=../lib; cd proj && sh clean-all",
        "false || CDPATH=../lib; cd proj && sh clean-all",
        "export CDPATH=../lib; bash -c 'cd proj && sh clean-all'",
        "CDPATH=../lib :; cd proj && sh clean-all",
        "export CDPATH=\"$PWD/../lib\"; cd proj && sh clean-all",
        "read CDPATH < list; cd proj && sh clean-all",
        ": ${CDPATH:=../lib}; cd proj && sh clean-all",
        "for CDPATH in ../lib; do cd proj && sh clean-all; done",
        "HOME=..; CDPATH=$HOME/lib; HOME=/nowhere; cd proj && sh clean-all",
        "HOME=proj; CDPATH=../lib; cd $HOME && sh clean-all",
    ] {
        let v = check(&work, None, line);
        assert!(v.starts_with("deny\t"), "{line}: {v}");
    }
    for line in [
        "CDPATH=../lib | true; cd proj && sh clean-all",
        "(CDPATH=../lib); cd proj && sh clean-all",
        "CDPATH=../lib & cd proj && sh clean-all",
        "CDPATH=../lib; unset CDPATH; cd proj && sh clean-all",
        "export CDPATH=../lib; cd ./proj && sh clean-all",
        "echo $CDPATH ${CDPATH:-none}; cd proj && sh clean-all",
    ] {
        assert_eq!(check(&work, None, line), "allow", "{line}");
    }
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}
