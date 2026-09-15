//! Argv law. Typed verdict is Cap'n `PolicyDecision`.
//!
//! `Decision`, `PolicyReason`, `PolicyDecision`, and `checkShell(argv)`
//! follow phronesis (`schema/policy.capnp` there). Copyright 2026
//! indynull, HaoZeke (MIT). Ali Akber Saifee extracted that library.

#[allow(unused_parens)]
#[path = "schema/policy_capnp.rs"]
pub mod policy_capnp;

use policy_capnp::{Decision, PolicyReason};

/// Hook line: `allow` or `deny\t<token>`.
#[must_use]
pub fn verdict(argv: &[String]) -> String {
    let d = check_shell(argv);
    match d.decision {
        Decision::Allow => "allow".into(),
        Decision::Deny => format!("deny\t{}", d.token),
        Decision::Prompt => format!("prompt\t{}", d.token),
    }
}

pub struct Checked {
    pub decision: Decision,
    pub code: PolicyReason,
    pub token: &'static str,
}

/// Typed check. Same TCB as [`verdict`].
#[must_use]
pub fn check_shell(argv: &[String]) -> Checked {
    if argv.is_empty() {
        return Checked {
            decision: Decision::Deny,
            code: PolicyReason::EmptyArgv,
            token: "empty argv",
        };
    }
    let line = argv.join(" ");
    let base = base_of(&argv[0]);
    if is_privilege(base) || argv.iter().any(|t| is_privilege(base_of(t))) {
        return Checked {
            decision: Decision::Deny,
            code: PolicyReason::ShellPrivilegeDenied,
            token: "sudo",
        };
    }
    if remote_exec(argv) {
        return Checked {
            decision: Decision::Deny,
            code: PolicyReason::ShellRemoteExec,
            token: "curl-pipe-shell",
        };
    }
    if setuid_chmod(argv) {
        return Checked {
            decision: Decision::Deny,
            code: PolicyReason::ChmodSetuid,
            token: "chmod-setuid",
        };
    }
    if raw_disk(argv) {
        return Checked {
            decision: Decision::Deny,
            code: PolicyReason::RawDisk,
            token: "raw-disk",
        };
    }
    if base == "rm" || base == "rtrash" {
        if line.contains("-rf") || line.contains("-fr") {
            let only_tmp = argv.iter().skip(1).filter(|a| !a.starts_with('-')).all(|p| {
                p == "/tmp"
                    || p.starts_with("/tmp/")
                    || p == "/var/tmp"
                    || p.starts_with("/var/tmp/")
            });
            if !only_tmp {
                return Checked {
                    decision: Decision::Deny,
                    code: PolicyReason::RmRfOutsideTmp,
                    token: "rm-rf-outside-tmp",
                };
            }
        }
    }
    if base == "git"
        && argv.iter().any(|a| a == "push")
        && argv
            .iter()
            .any(|a| a == "--force" || a == "-f" || a == "--force-with-lease")
    {
        return Checked {
            decision: Decision::Deny,
            code: PolicyReason::ShellGitDangerous,
            token: "git-force-push",
        };
    }
    Checked {
        decision: Decision::Allow,
        code: PolicyReason::Unspecified,
        token: "allow",
    }
}

/// Packed Cap'n `PolicyDecision` (phronesis result shape, no AgentId).
pub fn encode_decision(c: &Checked) -> capnp::Result<Vec<u8>> {
    let mut message = capnp::message::Builder::new_default();
    let mut root = message.init_root::<policy_capnp::policy_decision::Builder>();
    root.set_decision(c.decision);
    root.set_code(c.code);
    root.set_reason(c.token);
    let mut out = Vec::new();
    capnp::serialize::write_message(&mut out, &message)?;
    Ok(out)
}

fn base_of(tok: &str) -> &str {
    tok.rsplit('/').next().unwrap_or(tok)
}

fn is_privilege(base: &str) -> bool {
    matches!(base, "sudo" | "doas" | "su" | "pkexec" | "run0")
}

fn piped_to_shell(line: &str) -> bool {
    let bar = char::from(124);
    let a = format!("{bar} sh");
    let b = format!("{bar}sh");
    let c = format!("{bar} bash");
    let d = format!("{bar}bash");
    line.contains(&a) || line.contains(&b) || line.contains(&c) || line.contains(&d)
}

fn remote_exec(argv: &[String]) -> bool {
    let line = argv.join(" ");
    let mut fetch = false;
    let mut shell = false;
    for t in argv {
        let b = base_of(t);
        fetch |= matches!(b, "curl" | "wget" | "fetch");
        shell |= matches!(b, "sh" | "bash" | "zsh" | "dash");
    }
    let fetch_hit = line.contains("curl") || line.contains("wget") || line.contains("fetch");
    if fetch_hit && piped_to_shell(&line) {
        return true;
    }
    fetch && shell
}

fn setuid_chmod(argv: &[String]) -> bool {
    if base_of(&argv[0]) != "chmod" {
        return false;
    }
    argv.iter().any(|a| {
        a.contains("+s") || (a.starts_with('4') && a.len() >= 3 && a.chars().all(|c| c.is_ascii_digit()))
    })
}

fn raw_disk(argv: &[String]) -> bool {
    let b = base_of(&argv[0]);
    if b.starts_with("mkfs") {
        return true;
    }
    b == "dd" && argv.iter().any(|a| a.starts_with("of=/dev/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> String {
        verdict(&xs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn allows_cargo() {
        assert_eq!(v(&["cargo", "test"]), "allow");
    }

    #[test]
    fn denies_privilege() {
        assert!(v(&["sudo", "id"]).starts_with("deny"));
        assert!(v(&["pkexec", "id"]).starts_with("deny"));
    }

    #[test]
    fn capnp_round_trip_deny() {
        let c = check_shell(&["sudo".into(), "id".into()]);
        let bytes = encode_decision(&c).expect("encode");
        assert!(!bytes.is_empty());
        let mut cursor = std::io::Cursor::new(bytes);
        let msg = capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())
            .expect("read");
        let d = msg
            .get_root::<policy_capnp::policy_decision::Reader<'_>>()
            .expect("root");
        assert_eq!(d.get_decision().unwrap(), Decision::Deny);
        assert_eq!(d.get_code().unwrap(), PolicyReason::ShellPrivilegeDenied);
    }
}
