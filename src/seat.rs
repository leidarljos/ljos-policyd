//! The phronesis seat: the embedded pack, the supervisor bound to a
//! workspace, the argv the pack judges, and the token its decision prints.

#[cfg(has_phronesis)]
use std::borrow::Cow;

#[cfg(any(test, has_phronesis))]
use super::base_of;
use super::PolicyReason;
#[cfg(has_phronesis)]
use super::{
    command_after_keywords, command_roots, commands, embedded, ended_indices, expand_aliases,
    git_subcommand, harm, inner_commands_expanded, is_redirection, leaves_tree, rm_recursive,
    start_line, under_tmp, whole_tree, Checked, Decision, Place, Scratch, HOST_AGENT_LO, MAX_DEPTH,
};

#[cfg(has_phronesis)]
#[repr(C)]
struct Supervisor {
    _private: [u8; 0],
}

#[cfg(has_phronesis)]
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
    fn phronesis_supervisor_close(s: *mut Supervisor);
    fn ljos_phronesis_read_decision(
        input: *const u8,
        in_len: usize,
        decision: *mut u16,
        code: *mut u16,
        reason: *mut libc::c_char,
        reason_len: usize,
    ) -> libc::c_int;
    fn ljos_phronesis_check_shell(
        s: *mut Supervisor,
        cwd: *const libc::c_char,
        argv: *const *const libc::c_char,
        argc: libc::c_int,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> libc::c_int;
}

#[cfg(has_phronesis)]
fn host_agent_hex() -> String {
    format!("{:016x}{:016x}", 0u64, HOST_AGENT_LO)
}

/// Which embedded entry the seat loads: `shell.janet`, the default law, or
/// `seat.janet` (the default law plus package and Python rules) when
/// `LJOS_POLICYD_PACK=seat`.
#[cfg(has_phronesis)]
fn embedded_entry() -> &'static str {
    match std::env::var("LJOS_POLICYD_PACK").as_deref() {
        Ok("seat") => "seat.janet",
        _ => "shell.janet",
    }
}

/// FNV-1a: names the directories the pack and each workspace use.
#[cfg(has_phronesis)]
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The hash of the embedded pack, naming the directory it unpacks to.
#[cfg(has_phronesis)]
fn pack_hash() -> u64 {
    let mut all = Vec::new();
    for (name, body) in embedded::PACK {
        all.extend_from_slice(name.as_bytes());
        all.push(0);
        all.extend_from_slice(body);
    }
    fnv1a(&all)
}

/// True when every embedded file sits under `policy` byte for byte.
#[cfg(has_phronesis)]
fn pack_matches(policy: &std::path::Path) -> bool {
    embedded::PACK
        .iter()
        .all(|(name, body)| std::fs::read(policy.join(name)).is_ok_and(|b| b == *body))
}

/// Holds an exclusive `flock` on the state directory for the duration of
/// a pack swap. The kernel drops the lock when this file is closed.
#[cfg(has_phronesis)]
struct PackSwapLock {
    file: std::fs::File,
}

#[cfg(has_phronesis)]
impl PackSwapLock {
    fn acquire(root: &std::path::Path) -> Option<Self> {
        use std::os::fd::AsRawFd;
        std::fs::create_dir_all(root).ok()?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(".pack-swap.lock"))
            .ok()?;
        // SAFETY: `file` is open. flock uses that descriptor and does not
        // touch the rest of the process.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return None;
        }
        Some(Self { file })
    }
}

#[cfg(has_phronesis)]
impl Drop for PackSwapLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// A private directory name for one unpack. The pid keeps concurrent
/// processes apart; the counter keeps two attempts in one process apart.
#[cfg(has_phronesis)]
fn unique_pack_tmp(root: &std::path::Path, name: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    root.join(format!(".{name}.{}.{n}", std::process::id()))
}

/// Unpack the embedded pack to `root/pack-<hash>/share/phronesis/policy`
/// and return that prefix. A pack of the same content hash already there
/// is kept. Otherwise the bytes are written to a private directory and
/// renamed into place while an flock is held. The live directory is never
/// removed: another check may be reading it.
#[cfg(has_phronesis)]
fn unpack_pack(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let name = format!("pack-{:016x}", pack_hash());
    let prefix = root.join(&name);
    let rel = std::path::Path::new("share/phronesis/policy");
    let policy = prefix.join(rel);
    if pack_matches(&policy) {
        return Some(prefix);
    }
    let _lock = PackSwapLock::acquire(root)?;
    if pack_matches(&policy) {
        return Some(prefix);
    }
    let tmp = unique_pack_tmp(root, &name);
    let tmp_policy = tmp.join(rel);
    if std::fs::create_dir_all(tmp_policy.join("lib")).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        return None;
    }
    for (file, body) in embedded::PACK {
        if std::fs::write(tmp_policy.join(file), body).is_err() {
            let _ = std::fs::remove_dir_all(&tmp);
            return None;
        }
    }
    // A pack of this hash may have appeared while the private copy was
    // written. Keep that one; do not replace a directory a check may be
    // reading.
    if pack_matches(&policy) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Some(prefix);
    }
    // Rename onto an absent path is atomic. An existing directory is left
    // where it is, even when this rename fails.
    if std::fs::rename(&tmp, &prefix).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    pack_matches(&policy).then_some(prefix)
}

/// Point phronesis at the embedded pack, unless the caller named a pack
/// with `PHRONESIS_JANET_PACK` (then its own `PHRONESIS_PACK_ROOT` or
/// prefix has to be trusted, as phronesis requires). False when the
/// embedded pack could not be published.
#[cfg(has_phronesis)]
fn ensure_pack_env(root: &std::path::Path) -> bool {
    if std::env::var_os("PHRONESIS_JANET_PACK").is_some() {
        return true;
    }
    let Some(prefix) = unpack_pack(root) else {
        return false;
    };
    let share = prefix.join("share/phronesis");
    std::env::set_var("PHRONESIS_PREFIX", &prefix);
    std::env::set_var("PHRONESIS_PACK_ROOT", &share);
    std::env::set_var(
        "PHRONESIS_JANET_PACK",
        share.join("policy").join(embedded_entry()),
    );
    true
}

/// `$PHRONESIS_STATE_DIR`, else `~/.local/state/ljos-policyd`, and under
/// it the `state` and `runtime` directories for `workspace`. phronesis
/// keeps the first workspace a slot is bound to, so each workspace has
/// its own pair; one shared pair refused every line outside the first.
#[cfg(has_phronesis)]
fn seat_dirs(
    workspace: &str,
) -> Option<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let root = std::env::var_os("PHRONESIS_STATE_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".local/state/ljos-policyd"))
        })?;
    let seat = root.join(format!("ws-{:016x}", fnv1a(workspace.as_bytes())));
    let state = seat.join("state");
    let runtime = seat.join("runtime");
    std::fs::create_dir_all(&state).ok()?;
    std::fs::create_dir_all(&runtime).ok()?;
    Some((root, state, runtime))
}

/// A phronesis supervisor bound to the workspace for one hooked line.
#[cfg(has_phronesis)]
pub(crate) struct Seat {
    sup: *mut Supervisor,
    cwd: std::ffi::CString,
}

#[cfg(has_phronesis)]
impl Drop for Seat {
    fn drop(&mut self) {
        if !self.sup.is_null() {
            unsafe { phronesis_supervisor_close(self.sup) };
        }
    }
}

/// The code's name as the schema spells it, in kebab case.
#[must_use]
pub fn code_name(code: PolicyReason) -> &'static str {
    match code {
        PolicyReason::Unspecified => "unspecified",
        PolicyReason::ToolsDefaultDeny => "tools-default-deny",
        PolicyReason::PathOutsideWorkspace => "path-outside-workspace",
        PolicyReason::PathUnderWorkspaceAllow => "path-under-workspace-allow",
        PolicyReason::InvalidMessage => "invalid-message",
        PolicyReason::FieldTooLong => "field-too-long",
        PolicyReason::DenyAll => "deny-all",
        PolicyReason::HighRiskPrompt => "high-risk-prompt",
        PolicyReason::SeatBoardAllow => "seat-board-allow",
        PolicyReason::ModelStartAllow => "model-start-allow",
        PolicyReason::MissingToolAction => "missing-tool-action",
        PolicyReason::UnknownSeatAction => "unknown-seat-action",
        PolicyReason::PackMissing => "pack-missing",
        PolicyReason::PackLoadFailed => "pack-load-failed",
        PolicyReason::PackRuntimeError => "pack-runtime-error",
        PolicyReason::PackBadResult => "pack-bad-result",
        PolicyReason::ShellViewBuildFailed => "shell-view-build-failed",
        PolicyReason::PythonRequiresUvRun => "python-requires-uv-run",
        PolicyReason::PythonDashCDenied => "python-dash-c-denied",
        PolicyReason::PythonMissingPep723 => "python-missing-pep723",
        PolicyReason::ShellExecAllow => "shell-exec-allow",
        PolicyReason::PackReloaded => "pack-reloaded",
        PolicyReason::PackPathInvalid => "pack-path-invalid",
        PolicyReason::ShellDangerousRunner => "shell-dangerous-runner",
        PolicyReason::ShellRemoteExec => "shell-remote-exec",
        PolicyReason::ShellPrivilegeDenied => "shell-privilege-denied",
        PolicyReason::ShellGitDangerous => "shell-git-dangerous",
        PolicyReason::ShellSecretInArgv => "shell-secret-in-argv",
        PolicyReason::PathSensitiveDeny => "path-sensitive-deny",
        PolicyReason::SecretExportDenied => "secret-export-denied",
        PolicyReason::AudioMicOpenDeny => "audio-mic-open-deny",
        PolicyReason::AudioListenArmPrompt => "audio-listen-arm-prompt",
        PolicyReason::AudioAlwaysListenDeny => "audio-always-listen-deny",
        PolicyReason::AudioNetworkSttDeny => "audio-network-stt-deny",
        PolicyReason::AudioInjectDeny => "audio-inject-deny",
        PolicyReason::AudioFixtureAllow => "audio-fixture-allow",
        PolicyReason::AudioUnknownAction => "audio-unknown-action",
    }
}

/// `name` alone, or `name: reason` when the pack wrote text. The reason is
/// trimmed; a blank reason is the same as none.
fn named_token(name: &str, reason: &str) -> String {
    let reason = reason.trim();
    if reason.is_empty() {
        name.to_string()
    } else {
        format!("{name}: {reason}")
    }
}

/// The verdict token for a pack decision: the code's name, then the reason
/// text when one was written, as `path-outside-workspace: path outside
/// workspace` and `field-too-long: argv word exceeds 131072 bytes`. A
/// decision that wrote no text still names its code.
#[must_use]
pub fn token_for(code: PolicyReason, reason: &str) -> String {
    named_token(code_name(code), reason)
}

#[cfg(has_phronesis)]
pub(crate) fn refused(token: &'static str) -> Checked {
    Checked {
        decision: Decision::Deny,
        code: PolicyReason::InvalidMessage,
        token: Cow::Borrowed(token),
    }
}

/// Host decisions for a pack that is missing or could not be loaded.
/// Those carry an empty reason string.
#[cfg(has_phronesis)]
fn pack_load_failed(code: PolicyReason) -> bool {
    matches!(
        code,
        PolicyReason::PackMissing
            | PolicyReason::PackLoadFailed
            | PolicyReason::PackRuntimeError
            | PolicyReason::PackBadResult
            | PolicyReason::PackPathInvalid
    )
}

#[cfg(has_phronesis)]
impl Seat {
    fn open() -> Result<Self, Checked> {
        let cwd = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .filter(|s| s.starts_with('/'))
            .unwrap_or_else(|| "/".into());
        let fail = || refused("phronesis: seat could not open");
        let ws = std::env::var("PHRONESIS_WORKSPACE")
            .ok()
            .filter(|s| s.starts_with('/'))
            .unwrap_or_else(|| cwd.clone());
        let (root, state, runtime) = seat_dirs(&ws).ok_or_else(fail)?;
        if !ensure_pack_env(&root) {
            return Err(refused("pack-unavailable"));
        }
        let state_c =
            std::ffi::CString::new(state.to_string_lossy().as_bytes()).map_err(|_| fail())?;
        let runtime_c =
            std::ffi::CString::new(runtime.to_string_lossy().as_bytes()).map_err(|_| fail())?;
        let mut sup: *mut Supervisor = std::ptr::null_mut();
        let rc =
            unsafe { phronesis_supervisor_open(&mut sup, state_c.as_ptr(), runtime_c.as_ptr()) };
        if rc != 0 || sup.is_null() {
            return Err(fail());
        }
        let seat = Seat {
            sup,
            cwd: std::ffi::CString::new(cwd.as_str()).map_err(|_| fail())?,
        };
        let hex = std::ffi::CString::new(host_agent_hex()).map_err(|_| fail())?;
        let mode = std::ffi::CString::new("seat").map_err(|_| fail())?;
        let ws_c = std::ffi::CString::new(ws).map_err(|_| fail())?;
        let mut brc = unsafe {
            phronesis_supervisor_bind(seat.sup, hex.as_ptr(), mode.as_ptr(), ws_c.as_ptr(), 0)
        };
        // Several checks in one workspace bind one slot. phronesis writes it
        // through a shared temporary name, so a torn read comes back as
        // -4 (IO). The slot is already seated once the write lands
        // (-2, exists); try again until then. The pause is a few
        // milliseconds: 200 µs plus a small stagger, then 100 µs more on
        // each of 20 tries. Three immediate retries left a concurrent
        // `git add` as `allow	fail-open	bind-failed`.
        let mut tries = 0u64;
        while brc == -4 && tries < 20 {
            let pause = 200 + (u64::from(std::process::id()) % 32) * 50 + tries * 100;
            std::thread::sleep(std::time::Duration::from_micros(pause));
            brc = unsafe {
                phronesis_supervisor_bind(seat.sup, hex.as_ptr(), mode.as_ptr(), ws_c.as_ptr(), 0)
            };
            tries += 1;
        }
        if brc != 0 && brc != -2 {
            return Err(refused("bind-failed"));
        }
        Ok(seat)
    }

    /// One argv through the pack, with the decision's reason text kept.
    fn check(&self, argv: &[String]) -> Checked {
        let fail = || refused("phronesis: no decision");
        let c_args: Vec<std::ffi::CString> = argv
            .iter()
            .map(|a| {
                std::ffi::CString::new(a.as_str())
                    .unwrap_or_else(|_| std::ffi::CString::new("").unwrap())
            })
            .collect();
        let ptrs: Vec<*const libc::c_char> = c_args.iter().map(|c| c.as_ptr()).collect();
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let crc = unsafe {
            ljos_phronesis_check_shell(
                self.sup,
                self.cwd.as_ptr(),
                ptrs.as_ptr(),
                ptrs.len() as libc::c_int,
                &mut out,
                &mut out_len,
            )
        };
        if crc != 0 || out.is_null() || out_len == 0 {
            if !out.is_null() {
                unsafe { libc::free(out as *mut libc::c_void) };
            }
            return fail();
        }
        let mut dec: u16 = 0;
        let mut code: u16 = 0;
        let mut reason = [0 as libc::c_char; 512];
        let rrc = unsafe {
            ljos_phronesis_read_decision(
                out,
                out_len,
                &mut dec,
                &mut code,
                reason.as_mut_ptr(),
                reason.len(),
            )
        };
        unsafe { libc::free(out as *mut libc::c_void) };
        if rrc != 0 {
            return fail();
        }
        let decision = match dec {
            1 => Decision::Allow,
            2 => Decision::Prompt,
            _ => Decision::Deny,
        };
        let code = PolicyReason::try_from(code).unwrap_or(PolicyReason::Unspecified);
        let text = unsafe { std::ffi::CStr::from_ptr(reason.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let token = if decision == Decision::Allow {
            Cow::Borrowed("allow")
        } else if pack_load_failed(code) {
            // The host leaves the reason empty when the pack did not load.
            // Name that failure as a code is named, so the line is
            // `pack-unavailable` and never a bare `deny`.
            Cow::Owned(named_token("pack-unavailable", &text))
        } else {
            Cow::Owned(token_for(code, &text))
        };
        Checked {
            decision,
            code,
            token,
        }
    }

    /// The pack on one argv, then on every command the table reads inside
    /// it (wrappers, `sh -c` scripts, substitutions), the same walk as
    /// [`host_argv_table_at`]. `parent` is the scratch that walk has
    /// already recorded, so `rm -rf "$tmp"` inside a trap still names the
    /// temp the assignment made.
    fn check_at(&self, argv: &[String], depth: usize, parent: &Scratch, moved: bool) -> Checked {
        let mut bound = parent.clone();
        bound.observe(argv);
        let shown = argv_for_pack(argv, &bound, moved);
        let own = self.check(&shown);
        if own.decision != Decision::Allow || depth >= MAX_DEPTH {
            return own;
        }
        let expanded = expand_aliases(argv);
        let roots = command_roots(&expanded, bound.root.clone());
        for (i, inner) in inner_commands_expanded(&expanded) {
            if inner.is_empty() || inner.as_slice() == argv {
                continue;
            }
            let mut next = bound.clone();
            if let Some(root) = roots.get(i) {
                next.root = root.clone();
            }
            next.placed = false;
            // The mark belongs to the feeder. A later command on the line
            // is not that command, so its copy of the same word stays.
            if !command_is_feeder(&expanded, i) {
                next.fed_marks.clear();
            }
            let c = self.check_at(&inner, depth + 1, &next, moved);
            if c.decision != Decision::Allow {
                return c;
            }
        }
        own
    }
}

#[cfg(has_phronesis)]
type Job = (
    Vec<String>,
    std::path::PathBuf,
    std::sync::mpsc::Sender<Checked>,
);

/// phronesis keeps its Janet VM in the thread that first loaded the pack,
/// so every check in the process runs on one worker thread. The directory
/// is the one the host already checked: a relative scratch name is a
/// symlink only when that directory says so.
#[cfg(has_phronesis)]
pub(crate) fn check_shell_phronesis(argv: &[String], cwd: &std::path::Path) -> Checked {
    static WORKER: std::sync::OnceLock<Option<std::sync::mpsc::Sender<Job>>> =
        std::sync::OnceLock::new();
    let worker = WORKER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("phronesis".into())
            .spawn(move || {
                for (argv, cwd, reply) in rx {
                    start_line(&argv);
                    let parent = Scratch {
                        root: Some(cwd),
                        ..Scratch::default()
                    };
                    let c = match Seat::open() {
                        Ok(seat) => seat.check_at(&argv, 0, &parent, leaves_tree(&argv, 0)),
                        Err(c) => c,
                    };
                    let _ = reply.send(c);
                }
            })
            .ok()
            .map(|_| tx)
    });
    let Some(tx) = worker else {
        return refused("phronesis: no worker thread");
    };
    let (reply, answer) = std::sync::mpsc::channel();
    if tx.send((argv.to_vec(), cwd.to_path_buf(), reply)).is_err() {
        return refused("phronesis: worker thread gone");
    }
    // One thread answers every pack check in this process, and the
    // caller waits for that answer. The connect timeout is only for a
    // daemon that never accepts. Cutting this thread off at that timeout
    // printed `allow	fail-open	timeout` for a line the pack allows,
    // including `sh -c 'rm -rf target'` while the first pack load was
    // still queued.
    answer
        .recv()
        .unwrap_or_else(|_| refused("phronesis: no decision"))
}

/// What phronesis v0.2.5's recursive-delete rule allows on its own: a path
/// under `/tmp` or `/var/tmp`. It has no mktemp binding and no configure
/// scratch name (`conftest*`). A build directory the host already allowed
/// is rewritten to a `/tmp` name before the pack sees it.
#[cfg(has_phronesis)]
fn pack_delete_ok(p: &str, _moved: bool) -> bool {
    under_tmp(p)
}

/// The argv the pack judges. An operand the host already accepted and the
/// pack's older rule would refuse is named as `/tmp/policyd-scratch`, so
/// the pack still sees every other word. A secret or a force push on the
/// same line is unchanged. The directory is the one the command runs in
/// after `cd`, the same one [`delete_ok`] uses.
/// Whether command `i` is an `xargs` or `parallel`. Its unwrapped body
/// still carries the replace mark; a later command does not.
#[cfg(has_phronesis)]
fn command_is_feeder(argv: &[String], i: usize) -> bool {
    commands(argv).into_iter().nth(i).is_some_and(|cmd| {
        cmd.iter()
            .any(|w| matches!(base_of(w), "xargs" | "parallel"))
    })
}

/// Words a replace mark may be rewritten in. On a line, only the feeder's
/// own words. On the unwrapped command the walk hands down alone, every
/// word, because that argv is the command.
#[cfg(any(test, has_phronesis))]
pub(crate) fn mark_rewrite_mask(argv: &[String], has_marks: bool) -> Vec<bool> {
    let feed = feeder_word(argv);
    if feed.iter().any(|f| *f) || !has_marks {
        feed
    } else {
        vec![true; argv.len()]
    }
}

/// Words that belong to an `xargs` or `parallel` command. A replace mark
/// is one of those words. The same text later on the line is not.
#[cfg(any(test, has_phronesis))]
pub(crate) fn feeder_word(argv: &[String]) -> Vec<bool> {
    let mut flags = vec![false; argv.len()];
    let mut cur: Vec<usize> = Vec::new();
    let take = |cur: &mut Vec<usize>, flags: &mut [bool]| {
        let is_feeder = cur
            .iter()
            .any(|&i| matches!(base_of(argv[i].trim_end_matches(';')), "xargs" | "parallel"));
        if is_feeder {
            for &i in cur.iter() {
                flags[i] = true;
            }
        }
        cur.clear();
    };
    for (i, a) in argv.iter().enumerate() {
        if matches!(a.as_str(), ";" | "&&" | "||" | "|" | "&") {
            take(&mut cur, &mut flags);
            continue;
        }
        let closes = a.ends_with(';');
        if !a.trim_end_matches(';').is_empty() {
            cur.push(i);
        }
        if closes {
            take(&mut cur, &mut flags);
        }
    }
    take(&mut cur, &mut flags);
    flags
}

#[cfg(has_phronesis)]
/// The pack v0.2.5 refuses every `find -delete` and `find -exec rm`
/// outside `/tmp`. A cleanup the host already allowed is shown as
/// `-print` or `echo`, so a secret later on the line is still visible.
fn relax_find_for_pack(idx: &[usize], out: &mut [String]) {
    let mut i = 0;
    while i < idx.len() {
        let bare = out[idx[i]].trim_end_matches(';').to_string();
        if bare == "-delete" {
            out[idx[i]] = out[idx[i]].replace("-delete", "-print");
        }
        if matches!(bare.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
            let mut j = i + 1;
            let mut payload = false;
            while j < idx.len() {
                let w = out[idx[j]].trim_end_matches(';');
                if matches!(w, ";" | "+" | "\\;" | "\\+") {
                    break;
                }
                payload = true;
                j += 1;
            }
            if payload {
                let semi = out[idx[i + 1]].ends_with(';');
                out[idx[i + 1]] = if semi { "echo;".into() } else { "echo".into() };
                for k in i + 2..j {
                    out[idx[k]] = String::new();
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
}

#[cfg(has_phronesis)]
fn argv_for_pack(argv: &[String], bound: &Scratch, moved: bool) -> Vec<String> {
    let mut out = argv.to_vec();
    let feed = mark_rewrite_mask(argv, !bound.fed_marks.is_empty());
    for (i, w) in out.iter_mut().enumerate() {
        if !feed[i] {
            continue;
        }
        let bare = w.trim_end_matches(';');
        if bound.fed_marks.iter().any(|m| m == bare) && !pack_delete_ok(bare, moved) {
            let semi = w.ends_with(';');
            *w = if semi {
                "/tmp/policyd-scratch;".into()
            } else {
                "/tmp/policyd-scratch".into()
            };
        }
    }
    let mut place = Place::new(bound.root.clone());
    let mut prev = "";
    for (idx, end) in ended_indices(argv) {
        let in_pipe = end == "|" || prev == "|";
        let words: Vec<String> = idx
            .iter()
            .map(|&i| argv[i].trim_end_matches(';').to_string())
            .filter(|w| !w.is_empty())
            .collect();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        if refs.first().is_some_and(|w| base_of(w) == "find")
            && harm::find_action_unsafe(&refs).is_none()
        {
            relax_find_for_pack(&idx, &mut out);
        }
        if rm_recursive(command_after_keywords(&refs)) {
            for &i in &idx {
                let w = out[i].trim_end_matches(';').to_string();
                if w.is_empty() || w.starts_with('-') || is_redirection(&w) {
                    continue;
                }
                // The command word is `rm`. An operand the host already
                // accepted, and the pack's older rule would refuse, is
                // named as a temp so the pack still sees every other word.
                if matches!(base_of(&w), "rm" | "rtrash" | "srm" | "wipe") {
                    continue;
                }
                if !pack_delete_ok(&w, moved) {
                    let semi = out[i].ends_with(';');
                    out[i] = if semi {
                        "/tmp/policyd-scratch;".into()
                    } else {
                        "/tmp/policyd-scratch".into()
                    };
                }
            }
        }
        // The host already allowed this command. The pack v0.2.5 still
        // denies every `clean -f` and every whole-tree `restore`, and it
        // reads restore flags on its own. Show it the paths the table
        // parsed, so a secret later on the line is still visible.
        if harm::git_lost_work(&words).is_none() {
            if let Some((sub, rest)) = git_subcommand(&words) {
                if sub == "clean" {
                    for &i in &idx {
                        let semi = out[i].ends_with(';');
                        let bare = out[i].trim_end_matches(';');
                        let next = if bare == "--force" || bare == "-f" {
                            String::new()
                        } else if let Some(flags) = bare
                            .strip_prefix('-')
                            .filter(|c| !c.starts_with('-') && c.contains('f'))
                        {
                            let kept: String = flags.chars().filter(|c| *c != 'f').collect();
                            if kept.is_empty() {
                                String::new()
                            } else {
                                format!("-{kept}")
                            }
                        } else {
                            continue;
                        };
                        out[i] = if next.is_empty() {
                            if semi {
                                ";".into()
                            } else {
                                String::new()
                            }
                        } else if semi {
                            format!("{next};")
                        } else {
                            next
                        };
                    }
                }
                if sub == "restore" {
                    // The pack keeps its own matcher. It does not read the
                    // table's flags, so an index-only line and a path after
                    // the end of options still look like a whole-tree
                    // discard there. Rename the words that parse found.
                    let expanded: Vec<String> = rest
                        .iter()
                        .map(|w| harm::expand_long(w, harm::GIT_RESTORE_LONG).into_owned())
                        .collect();
                    let parsed = harm::parse_restore(&expanded);
                    let rest_at = words.len() - rest.len();
                    let put = |out: &mut [String], slot: usize, name: &str| {
                        let at = idx[slot];
                        let semi = out[at].ends_with(';');
                        out[at] = if semi {
                            format!("{name};")
                        } else {
                            name.to_string()
                        };
                    };
                    for (j, name) in parsed.pack_standins {
                        put(&mut out, rest_at + j, name);
                    }
                    if let Some(j) = parsed.show_as_path {
                        put(&mut out, rest_at + j, "named-file");
                    }
                } else if sub == "checkout" {
                    let expanded: Vec<String> = rest
                        .iter()
                        .map(|w| harm::expand_long(w, harm::GIT_RESTORE_LONG).into_owned())
                        .collect();
                    let staged = expanded.iter().any(|a| a == "--staged");
                    let worktree = expanded.iter().any(|a| a == "--worktree");
                    if staged && !worktree {
                        for &i in &idx {
                            let semi = out[i].ends_with(';');
                            let bare = out[i].trim_end_matches(';');
                            if whole_tree(bare) {
                                out[i] = if semi {
                                    "index-file;".into()
                                } else {
                                    "index-file".into()
                                };
                            }
                        }
                    }
                }
            }
        }
        place.finish(&refs, in_pipe);
        prev = end;
    }
    out.retain(|w| !w.is_empty());
    out
}
