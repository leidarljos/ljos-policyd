//! Argv law. Typed verdict is Cap'n `PolicyDecision`.
//!
//! Every check calls `phronesis_check_shell`. If the library is not
//! seated (no pack, no workspace), the host argv table this crate
//! shipped is the TCB.

#[allow(dead_code, unused_parens, clippy::all)]
#[path = "schema/util_capnp.rs"]
pub mod util_capnp;

#[allow(dead_code, unused_parens, clippy::all)]
#[path = "schema/policy_capnp.rs"]
pub mod policy_capnp;

use policy_capnp::{Decision, PolicyReason};

/// Slot this CLI binds so checkShell has a workspace root.
const HOST_AGENT_LO: u64 = 1;

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

/// Typed check. Always calls `phronesis_check_shell`.
#[must_use]
pub fn check_shell(argv: &[String]) -> Checked {
    match check_shell_phronesis(argv) {
        Ok(c) if seated(&c) => c,
        _ => host_argv_table(argv),
    }
}

fn seated(c: &Checked) -> bool {
    !matches!(
        c.code,
        PolicyReason::PackMissing
            | PolicyReason::PackLoadFailed
            | PolicyReason::PackBadResult
            | PolicyReason::PackRuntimeError
            | PolicyReason::ToolsDefaultDeny
            | PolicyReason::InvalidMessage
            | PolicyReason::PathOutsideWorkspace
            | PolicyReason::ShellViewBuildFailed
    )
}

fn host_argv_table(argv: &[String]) -> Checked {
    if argv.is_empty() {
        return Checked {
            decision: Decision::Deny,
            code: PolicyReason::InvalidMessage,
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
            code: PolicyReason::ShellDangerousRunner,
            token: "chmod-setuid",
        };
    }
    if raw_disk(argv) {
        return Checked {
            decision: Decision::Deny,
            code: PolicyReason::ShellDangerousRunner,
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
                    code: PolicyReason::ShellDangerousRunner,
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

/// Packed Cap'n `PolicyDecision` (phronesis result shape).
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

fn encode_shell_check(argv: &[String], cwd: &str) -> capnp::Result<Vec<u8>> {
    let mut message = capnp::message::Builder::new_default();
    let mut root = message.init_root::<policy_capnp::shell_check::Builder>();
    {
        let mut id = root.reborrow().init_agent_id();
        id.set_hi(0);
        id.set_lo(HOST_AGENT_LO);
    }
    root.set_cwd(cwd);
    {
        let mut list = root.reborrow().init_argv(argv.len() as u32);
        for (i, a) in argv.iter().enumerate() {
            list.set(i as u32, a);
        }
    }
    let mut out = Vec::new();
    capnp::serialize::write_message(&mut out, &message)?;
    Ok(out)
}

fn token_for(code: PolicyReason, reason: &str) -> &'static str {
    match code {
        PolicyReason::InvalidMessage => "invalid-message",
        PolicyReason::ShellPrivilegeDenied => "sudo",
        PolicyReason::ShellRemoteExec => "curl-pipe-shell",
        PolicyReason::ShellGitDangerous => "git-force-push",
        PolicyReason::ShellDangerousRunner => "banned-runner",
        PolicyReason::ShellSecretInArgv => "secret-in-argv",
        PolicyReason::PythonRequiresUvRun => "python-requires-uv",
        PolicyReason::PythonDashCDenied => "python-dash-c",
        PolicyReason::PackMissing => "pack-missing",
        PolicyReason::ToolsDefaultDeny => "tools-default-deny",
        _ if !reason.is_empty() => {
            // Pack-authored text is not 'static; keep a stable token.
            "phronesis"
        }
        _ => "phronesis",
    }
}

fn decode_decision(bytes: &[u8]) -> capnp::Result<Checked> {
    let mut cursor = std::io::Cursor::new(bytes);
    let msg = capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())?;
    let d = msg.get_root::<policy_capnp::policy_decision::Reader<'_>>()?;
    let code = d.get_code()?;
    let reason = d.get_reason()?.to_str().unwrap_or("");
    Ok(Checked {
        decision: d.get_decision()?,
        code,
        token: token_for(code, reason),
    })
}

#[repr(C)]
struct Supervisor {
    _private: [u8; 0],
}

extern "C" {
    fn phronesis_supervisor_open(
        out: *mut *mut Supervisor,
        state_dir: *const libc::c_char,
        runtime_dir: *const libc::c_char,
    ) -> libc::c_int;
    fn phronesis_supervisor_bind(
        s: *mut Supervisor,
        agent_id: *const libc::c_char,
        mode: *const libc::c_char,
        workspace: *const libc::c_char,
        pid: libc::pid_t,
    ) -> libc::c_int;
    fn phronesis_check_shell(
        s: *mut Supervisor,
        input: *const u8,
        in_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    );
}

fn host_agent_hex() -> String {
    format!("{:016x}{:016x}", 0u64, HOST_AGENT_LO)
}

fn seat_dirs() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let uid = unsafe { libc::geteuid() };
            let p = std::path::PathBuf::from(format!("/run/user/{uid}"));
            p.is_dir().then_some(p)
        })?;
    let root = base.join("ljos-policyd");
    let state = root.join("state");
    let runtime = root.join("runtime");
    std::fs::create_dir_all(&state).ok()?;
    std::fs::create_dir_all(&runtime).ok()?;
    Some((state, runtime))
}

fn host_workspace() -> std::ffi::CString {
    let raw = std::env::var("PHRONESIS_WORKSPACE")
        .ok()
        .filter(|s| s.starts_with('/'))
        .unwrap_or_else(|| "/".into());
    std::ffi::CString::new(raw).unwrap_or_else(|_| std::ffi::CString::new("/").unwrap())
}

fn with_supervisor<T>(f: impl FnOnce(*mut Supervisor) -> T) -> Option<T> {
    let (state, runtime) = seat_dirs()?;
    let state_c = std::ffi::CString::new(state.to_string_lossy().as_bytes()).ok()?;
    let runtime_c = std::ffi::CString::new(runtime.to_string_lossy().as_bytes()).ok()?;
    let mut sup: *mut Supervisor = std::ptr::null_mut();
    let rc = unsafe {
        phronesis_supervisor_open(&mut sup, state_c.as_ptr(), runtime_c.as_ptr())
    };
    if rc != 0 || sup.is_null() {
        return None;
    }
    let hex = std::ffi::CString::new(host_agent_hex()).ok()?;
    let mode = std::ffi::CString::new("seat").ok()?;
    let ws = host_workspace();
    unsafe {
        let _ = phronesis_supervisor_bind(sup, hex.as_ptr(), mode.as_ptr(), ws.as_ptr(), 0);
    }
    Some(f(sup))
}

fn check_shell_phronesis(argv: &[String]) -> Result<Checked, String> {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_default();
    let input = encode_shell_check(argv, &cwd).map_err(|e| e.to_string())?;
    with_supervisor(|sup| {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        unsafe {
            phronesis_check_shell(sup, input.as_ptr(), input.len(), &mut out, &mut out_len);
        }
        if out.is_null() || out_len == 0 {
            return Err("phronesis_check_shell returned empty".into());
        }
        let bytes = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
        unsafe { libc::free(out as *mut libc::c_void) };
        decode_decision(&bytes).map_err(|e| e.to_string())
    })
    .ok_or_else(|| "supervisor open failed".to_string())?
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
    fn encodes_a_shell_check_for_phronesis() {
        let bytes = encode_shell_check(&["sudo".into(), "id".into()], "/").expect("encode");
        assert!(!bytes.is_empty());
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
