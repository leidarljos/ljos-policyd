//! Argv law. Typed verdict is Cap'n `PolicyDecision`.
//!
//! Every line meets the host argv table built into this crate first. A
//! phronesis build then hands the line, and every command the table found
//! inside it, to `phronesis_check_shell` with the pack embedded at build
//! time. Without phronesis the table alone is the law.

#[allow(dead_code, unused_parens, clippy::all)]
#[path = "schema/util_capnp.rs"]
pub mod util_capnp;

#[allow(dead_code, unused_parens, clippy::all)]
#[path = "schema/policy_capnp.rs"]
pub mod policy_capnp;

mod ask;
mod client;
mod credential;
mod delete;
mod deny_log;
mod dirs;
mod disk;
mod envelope;
mod feed;
mod fetch;
mod git;
mod guard;
mod harm;
mod heredoc;
mod inner;
mod mail;
mod names;
mod open;
pub mod person;
mod pipeline;
mod read;
mod rewrite;
mod seat;
mod shells;
mod subst;
mod table;
mod words;
mod wrappers;
mod writes;

pub use client::{probe_daemon, CONNECT_TIMEOUT};

pub use deny_log::{deny_log_path, replay_argv, set_thread_deny_log};

pub use open::{allow_annotation, default_consent_path, fault, judge_bytes, missing_tool, Context};

pub use seat::{code_name, token_for};

pub use envelope::{check_mail_argv, check_mail_bytes, MailReason, MailVerdict, MAIL_MESSAGE_MAX};

use std::borrow::Cow;

use policy_capnp::{Decision, PolicyReason};

use credential::*;
use delete::*;
use deny_log::*;
use dirs::*;
use feed::*;
use fetch::*;
use git::*;
use guard::*;
use heredoc::*;
use inner::*;
use names::*;
use pipeline::*;
use read::*;
#[cfg(any(test, has_phronesis))]
use seat::*;
use shells::*;
use subst::*;
use table::*;
use words::*;
use wrappers::*;
use writes::*;

/// Exclusive time inside one judgment. A test turns it on around a check.
/// While it is off, each timed function does one relaxed read.
#[allow(dead_code)]
mod phase;

#[cfg(has_phronesis)]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/pack.rs"));
}

/// Slot this CLI binds so checkShell has a workspace root.
#[cfg(has_phronesis)]
const HOST_AGENT_LO: u64 = 1;

/// Which law this build judges with: `phronesis` when the library was
/// found at build time (`PHRONESIS_DIR` or `pkg-config phronesis`), else
/// `host table`, the argv table compiled into this crate.
#[cfg(has_phronesis)]
pub const BACKEND: &str = "phronesis";
/// Which law this build judges with: `phronesis` when the library was
/// found at build time (`PHRONESIS_DIR` or `pkg-config phronesis`), else
/// `host table`, the argv table compiled into this crate.
#[cfg(not(has_phronesis))]
pub const BACKEND: &str = "host table";

/// Hook line: `allow`, `allow\twarn\t<rule>\t<warning>`,
/// `allow\tfail-open\t<reason>`, `allow\trewrite\t<line>`, or another
/// `allow\t<kind>\t<note>`. A rule that used to deny or ask is the warn
/// line: the rule name, then one line a caller can show.
#[must_use]
pub fn verdict(argv: &[String]) -> String {
    verdict_with(argv, &open::Context::from_env())
}

/// [`verdict`] with consent, user allows, and config taken from `ctx`
/// instead of only the environment.
#[must_use]
pub fn verdict_with(argv: &[String], ctx: &open::Context) -> String {
    verdict_line(argv, &check_with(argv, ctx))
}

/// The hook line for a decision already made on `argv`. A pack note
/// that only asks for uv (`python-requires-uv-run`) is answered with the
/// line that meets it, so the hook runs `uv run x.py` in place of
/// `python x.py`. Any other deny or ask is allow, with the rule name and
/// one warning line.
fn verdict_line(argv: &[String], d: &Checked) -> String {
    if let Some((kind, rest)) = open::noted(&d.token) {
        if kind == "warn" {
            return open::allow_annotation(rest);
        }
        return format!("allow\t{kind}\t{}", one_line(rest));
    }
    match d.decision {
        Decision::Allow => match rewrite::rewrite_command(argv) {
            Some(line) => format!("allow\trewrite\t{line}"),
            None => "allow".into(),
        },
        Decision::Deny if matches!(d.code, PolicyReason::PythonRequiresUvRun) => {
            match rewrite::rewrite_for_uv_law(argv) {
                Some(line) => format!("allow\trewrite\t{line}"),
                None => open::allow_annotation(&d.token),
            }
        }
        Decision::Deny | Decision::Prompt => open::allow_annotation(&d.token),
    }
}

/// The verdict line is split on tabs and read one line at a time, so a
/// reason keeps neither.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[derive(Clone)]
pub struct Checked {
    pub decision: Decision,
    pub code: PolicyReason,
    /// The table's token (`git-force-push`), or the pack's reason text.
    pub token: Cow<'static, str>,
}

/// Typed check: the person's own allow rules first ([`person::allows`]),
/// then the table built into this crate, and with phronesis linked,
/// `phronesis_check_shell` after it on the line and on every command the
/// table reads inside it. A table hit is the line the caller sees, so
/// phronesis is not asked to clear it. A line the person allowed
/// at their own terminal is allowed without either being asked.
#[must_use]
pub fn check_shell(argv: &[String]) -> Checked {
    check_shell_logged(argv, true)
}

/// [`check_shell`] without the deny log: a replay re-judges lines the log
/// already holds, and must not write them again.
#[must_use]
pub fn check_shell_quiet(argv: &[String]) -> Checked {
    check_shell_logged(argv, false)
}

/// The hook line of [`check_shell_quiet`].
#[must_use]
pub fn verdict_quiet(argv: &[String]) -> String {
    verdict_line(argv, &check_shell_quiet(argv))
}

fn check_shell_logged(argv: &[String], log: bool) -> Checked {
    check_with_logged(argv, &open::Context::from_env(), log)
}

/// [`check_shell`] with the caller's consent file, user allows, and config.
#[must_use]
pub fn check_with(argv: &[String], ctx: &open::Context) -> Checked {
    check_with_logged(argv, ctx, true)
}

fn check_with_logged(argv: &[String], ctx: &open::Context, log: bool) -> Checked {
    if let Some(rule) = person::allows(argv) {
        return Checked {
            decision: Decision::Allow,
            code: PolicyReason::Unspecified,
            token: Cow::Owned(format!("person-allow {}", rule.id)),
        };
    }
    let gap = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open::config_gap(ctx)));
    match gap {
        Err(_) => return open::allow_checked("fail-open", "config_gap"),
        Ok(Some(why)) => return open::allow_checked("fail-open", why),
        Ok(None) => {}
    }
    let parsed =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open::script_unparsed(argv)));
    match parsed {
        Err(_) => return open::allow_checked("fail-open", "script_unparsed"),
        Ok(true) => return open::allow_checked("fail-open", "parse failure"),
        Ok(false) => {}
    }
    let owned = argv.to_vec();
    let logged = owned.clone();
    let ctx = ctx.clone();
    let checked = open::bounded(move || {
        let owned = elide_c_scripts(&owned);
        let cwd = std::env::current_dir().unwrap_or_default();
        SPELLED.with(|s| s.borrow_mut().clear());
        start_line(&owned);
        ARGV_WORDS.with(|s| {
            let mut slot = s.borrow_mut();
            slot.clear();
            slot.extend(owned.iter().filter(|w| w.contains(['$', '`'])).cloned());
        });
        bump_spell_gen();
        let raw = check_shell_in(&owned, &cwd, 0);
        open::publish(&owned, raw, &ctx)
    });
    if log && checked.decision == Decision::Deny {
        let wrote = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            log_deny(&logged, checked.token.as_ref())
        }));
        match wrote {
            Err(_) => return open::allow_checked("fail-open", "log_deny"),
            Ok(Err(_)) => return open::allow_checked("fail-open", "io"),
            Ok(Ok(())) => {}
        }
    }
    checked
}

thread_local! {
    /// Each word [`shell_words`] made during a check that holds a glob,
    /// `~`, `$`, a backtick, `(` or a newline, and whether the shell reads
    /// every one of those as itself in every place the word was split
    /// from. Glob and tilde characters need a quote, `$` and backtick a
    /// single quote or a backslash.
    static SPELLED: std::cell::RefCell<std::collections::HashMap<String, bool>> =
        std::cell::RefCell::default();
    /// Bumps when [`SPELLED`] gains a word or a quote bit flips. A reused
    /// command judgment is valid only for the map it was made under.
    static SPELL_GEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// The words of the argv being checked that hold `$` or a backtick.
    /// The program gets them as they are. No shell expands them.
    static ARGV_WORDS: std::cell::RefCell<std::collections::HashSet<String>> =
        std::cell::RefCell::default();
    /// Each here-document body [`shell_words`] read during a check: its
    /// delimiter, the words it split into, whether the body is its text
    /// as written (a quoted delimiter, or nothing to expand), and that
    /// body.
    static HEREDOC_RAW: std::cell::RefCell<Vec<HeredocRaw>> = std::cell::RefCell::default();
    /// Each word of the argv, or that [`shell_words`] made during a
    /// check, that holds a `{`, and whether one of those stood outside
    /// quotes in some place the word was split from. An argv word is
    /// passed as it is. Bash brace-expands only a word with a bare `{`.
    static BRACED: std::cell::RefCell<std::collections::HashMap<String, bool>> =
        std::cell::RefCell::default();
    /// Set when a cap stops the walk. Applied once the check has a plain
    /// allow, so a real hit is not replaced by the label.
    static CAP_LABEL: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    /// Set when a brace recognizer stops at [`words::BRACE_CAP`], then read by
    /// the caller that still has the word.
    static BRACE_OVER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A here-document body as [`HEREDOC_RAW`] keeps it.
type HeredocRaw = (String, Vec<String>, bool, String);

/// Forget the here-documents and braces of the last check on this
/// thread, and take each word of `argv` as passed.
fn start_line(argv: &[String]) {
    HEREDOC_RAW.with(|s| s.borrow_mut().clear());
    BRACED.with(|s| s.borrow_mut().clear());
    for w in argv {
        braced(w, false);
    }
}

fn braced(w: &str, bare: bool) {
    if !w.contains('{') {
        return;
    }
    BRACED.with(|s| {
        let mut s = s.borrow_mut();
        let was = s.get(w).copied();
        if was != Some(true) && was != Some(bare) {
            s.insert(w.to_string(), was.unwrap_or(false) || bare);
            bump_spell_gen();
        }
    });
}

/// The text of the literal here-document closed by `delim` whose body
/// split into `words`. Only where every body read this check with those
/// words was literal, and all of them were written alike.
fn bump_spell_gen() {
    SPELL_GEN.with(|g| g.set(g.get().wrapping_add(1)));
}

/// The characters a shell may expand in an unquoted word.
const EXPANDS: [char; 7] = ['$', '`', '*', '?', '[', '~', '\n'];

fn spelled(w: &str, quoted: bool) {
    if w.contains(EXPANDS) || w.contains('(') {
        SPELLED.with(|s| {
            let mut s = s.borrow_mut();
            if let Some(all) = s.get_mut(w) {
                let next = *all && quoted;
                if next != *all {
                    *all = next;
                    bump_spell_gen();
                }
                return;
            }
            s.insert(w.to_string(), quoted);
            bump_spell_gen();
        });
    }
}

/// How many runner levels deep (`make a` whose recipe runs `npm run b`)
/// script targets are read before the line is judged as written.
fn check_shell_in(argv: &[String], cwd: &std::path::Path, depth: usize) -> Checked {
    clear_cap_label();
    let parent = Scratch {
        root: Some(cwd.to_path_buf()),
        work: Some(cwd.to_path_buf()),
        placed: true,
        ..Scratch::default()
    };
    let table = host_argv_table_at(argv, 0, leaves_tree(argv, 0), &parent);
    // A host refusal stands, including a warning. The pack is asked only
    // for a plain allow, so it can add a refusal and cannot erase one.
    #[cfg(has_phronesis)]
    let table = if table.decision == Decision::Allow && open::noted(&table.token).is_none() {
        check_shell_phronesis(argv, cwd)
    } else {
        table
    };
    let _ = depth;
    with_cap_label(table)
}

fn clear_cap_label() {
    CAP_LABEL.with(|s| s.set(None));
    BRACE_OVER.with(|s| s.set(false));
}

pub(crate) fn note_cap_label(label: &'static str) {
    CAP_LABEL.with(|s| {
        if s.get().is_none() {
            s.set(Some(label));
        }
    });
}

/// A plain allow becomes `label` when a cap stopped the walk. A hit
/// already on the line stays: the cap is not a refusal and it does not
/// hide one.
fn with_cap_label(checked: Checked) -> Checked {
    let label = CAP_LABEL.with(|s| s.replace(None));
    match label {
        Some(label)
            if checked.decision == Decision::Allow && open::noted(&checked.token).is_none() =>
        {
            open::warn_checked(label)
        }
        _ => checked,
    }
}

pub(crate) fn mark_brace_over() {
    BRACE_OVER.with(|s| s.set(true));
}

pub(crate) fn take_brace_over() -> bool {
    BRACE_OVER.with(|s| s.replace(false))
}

/// `word` had a `{` outside quotes, so the shell would expand it.
pub(crate) fn bare_brace_word(word: &str) -> bool {
    BRACED.with(|s| s.borrow().get(word).copied().unwrap_or(false))
}

/// The typed decision is allow. A warn line keeps the rule and the warning
/// in the reason text, after the same tab the hook line uses.
fn encoded_fields(c: &Checked) -> (Decision, String) {
    if let Some((kind, rest)) = open::noted(&c.token) {
        if kind == "warn" {
            let line = open::allow_annotation(rest);
            return (Decision::Allow, line.replacen("allow\t", "", 1));
        }
        return (Decision::Allow, format!("{kind}\t{}", one_line(rest)));
    }
    match c.decision {
        Decision::Allow => (Decision::Allow, c.token.to_string()),
        Decision::Deny | Decision::Prompt => {
            let line = open::allow_annotation(&c.token);
            (Decision::Allow, line.replacen("allow\t", "", 1))
        }
    }
}

/// Packed Cap'n `PolicyDecision` (phronesis result shape).
pub fn encode_decision(c: &Checked) -> capnp::Result<Vec<u8>> {
    let mut message = capnp::message::Builder::new_default();
    let mut root = message.init_root::<policy_capnp::policy_decision::Builder>();
    let (decision, reason) = encoded_fields(c);
    root.set_decision(decision);
    root.set_code(c.code);
    root.set_reason(&reason);
    let mut out = Vec::new();
    capnp::serialize::write_message(&mut out, &message)?;
    Ok(out)
}

#[cfg(all(has_phronesis, test))]
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

#[cfg(test)]
mod tests;
