//! How a raw table hit is published.
//!
//! An internal error, a parse failure, an unknown input, or a missing
//! config allows and names the reason. Every other hit is allow too.
//! The line carries the rule name and one warning a caller can show.
//! That includes `rm-rf-outside-tmp`, `find-delete`, `find-exec-rm`,
//! `rsync-delete-outside`, `git-force-push` of a remote default branch,
//! `git-push-delete` of `main`, `master`, or `develop`,
//! `reads-credential`, and `curl-pipe-shell` (a download piped into
//! `sh`, `bash`, or `zsh`). A download piped into `python3` warns. A
//! history rewrite warns. A matching consent record, or a user allow the
//! caller passed, turns a hit into that allow. Ancestry is named in the
//! reason and does not change the verdict.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{Checked, Decision, PolicyReason};

/// What the caller handed the check beside the argv.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// Glob patterns from `ljos rule --user ... --verdict allow`.
    pub user_allow: Vec<String>,
    /// Consent file the host relay wrote. Unset reads the default path
    /// when that file is present.
    pub consent_file: Option<PathBuf>,
    /// Policy config path. Set and missing is a fail-open.
    pub config_path: Option<String>,
    /// `Some` skips the process ancestry walk. Tests use it.
    pub person_tty: Option<bool>,
}

impl Context {
    /// `LJOS_USER_ALLOW` and `LJOS_CONSENT_FILE` may be set only by
    /// policyd's parent hook config. An agent must not set them. When
    /// either value names a file, that file is ignored if the current
    /// user can write it or if it is group- or world-writable.
    /// `LJOS_USER_ALLOW` is one pattern a line when it is not a file.
    #[must_use]
    pub fn from_env() -> Self {
        let user_allow = user_allow_from_env();
        let consent_file = std::env::var_os("LJOS_CONSENT_FILE")
            .map(PathBuf::from)
            .or_else(default_consent);
        Self {
            user_allow,
            consent_file,
            config_path: None,
            person_tty: None,
        }
    }
}

fn patterns_of(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Patterns from the hook. A value that names a file is that file's
/// lines, and only when the file is not agent-writable.
fn user_allow_from_env() -> Vec<String> {
    let Ok(text) = std::env::var("LJOS_USER_ALLOW") else {
        return Vec::new();
    };
    let trimmed = text.trim();
    if !trimmed.contains('\n') {
        let path = Path::new(trimmed);
        if path.is_file() {
            match consent_file_status(path) {
                ConsentFile::Ok => {
                    return std::fs::read_to_string(path)
                        .map(|body| patterns_of(&body))
                        .unwrap_or_default();
                }
                ConsentFile::Ignored(why) => {
                    eprintln!("user allow ignored: {}: {why}", path.display());
                    return Vec::new();
                }
                ConsentFile::Missing => {}
            }
        }
    }
    patterns_of(&text)
}

fn default_consent() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    let path = base.join("ljos/consent.json");
    path.is_file().then_some(path)
}

/// How a consent or user-allow file may be read.
enum ConsentFile {
    Missing,
    Ignored(&'static str),
    Ok,
}

/// A record is read only from a file the current user cannot write, and
/// that is not group- or world-writable. Anything else is ignored.
fn consent_file_status(path: &Path) -> ConsentFile {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return ConsentFile::Missing,
    };
    if !meta.is_file() {
        return ConsentFile::Ignored("not a file");
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        return ConsentFile::Ignored("group- or world-writable");
    }
    // SAFETY: getuid reads no memory and, by POSIX, always succeeds.
    if meta.uid() == unsafe { libc::getuid() } && mode & 0o200 != 0 {
        return ConsentFile::Ignored("writable by the current user");
    }
    ConsentFile::Ok
}

/// `allow\t<kind>\t<why>` as a checked value.
#[must_use]
pub fn allow_checked(kind: &str, why: &str) -> Checked {
    Checked {
        decision: Decision::Allow,
        code: PolicyReason::Unspecified,
        token: std::borrow::Cow::Owned(format!("{kind}\t{why}")),
    }
}

/// A hit that is named and does not deny.
#[must_use]
pub fn warn_checked(token: &str) -> Checked {
    allow_checked("warn", token)
}

/// Run `work` on this thread. A panic allows and names the fault.
/// There is no second thread to wait on.
pub fn bounded<F>(work: F) -> Checked
where
    F: FnOnce() -> Checked,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
        Ok(checked) => checked,
        Err(_) => allow_checked("fail-open", "internal error"),
    }
}

/// Panic when a test arms `site`. `LJOS_POLICYD_FAULT` is read only while
/// this crate is built for tests. The release binary does not read it.
pub fn fault(site: &str) {
    #[cfg(test)]
    {
        let local = FAULT_SITE.with(|slot| slot.get());
        let from_env = std::env::var("LJOS_POLICYD_FAULT").ok();
        if local == Some(site) || from_env.as_deref() == Some(site) {
            panic!("fault {site}");
        }
    }
    #[cfg(not(test))]
    {
        let _ = site;
    }
}

#[cfg(test)]
thread_local! {
    static FAULT_SITE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

/// A config the caller named that is not a file.
#[must_use]
pub fn config_gap(ctx: &Context) -> Option<&'static str> {
    fault("config_gap");
    let path = ctx.config_path.as_deref()?;
    if path.is_empty() || !Path::new(path).is_file() {
        Some("missing config")
    } else {
        None
    }
}

/// A `sh -c` script whose quotes do not close, and that is not a
/// here-document. The body of a here-document may hold an apostrophe.
#[must_use]
pub fn script_unparsed(argv: &[String]) -> bool {
    fault("script_unparsed");
    let mut i = 0;
    while i < argv.len() {
        let base = argv[i].rsplit('/').next().unwrap_or(argv[i].as_str());
        let shell = matches!(
            base,
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "mksh" | "fish" | "ash"
        );
        if shell {
            if let Some(script) = inline_script(&argv[i + 1..]) {
                if !script.contains("<<") && !quotes_balanced(script) {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn inline_script(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-c" || a == "-lc" {
            return args.get(i + 1).map(String::as_str);
        }
        if a.starts_with('-') && !a.starts_with("--") && a.contains('c') && a != "-c" {
            return args.get(i + 1).map(String::as_str);
        }
        i += 1;
    }
    None
}

fn quotes_balanced(script: &str) -> bool {
    let bytes = script.as_bytes();
    let mut i = 0;
    let mut single = false;
    let mut double = false;
    while i < bytes.len() {
        let c = bytes[i];
        if !single && !double && c == b'#' && comment_starts(bytes, i) {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'\\' && !single {
            i = i.saturating_add(2);
            continue;
        }
        if c == b'\'' && !double {
            single = !single;
        } else if c == b'"' && !single {
            double = !double;
        }
        i += 1;
    }
    !single && !double
}

/// `#` starts a comment when it begins a word, not inside `foo#bar`.
fn comment_starts(bytes: &[u8], i: usize) -> bool {
    i == 0
        || matches!(
            bytes[i - 1],
            b' ' | b'\t' | b'\n' | b'\r' | b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>'
        )
}

/// Bytes that are not an argv frame. A bad frame allows.
#[must_use]
pub fn judge_bytes(bytes: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return line_of(&allow_checked("fail-open", "unknown input"));
    };
    let text = text.trim();
    if !text.starts_with('{') {
        return line_of(&allow_checked("fail-open", "unknown input"));
    }
    match frame_argv(text) {
        Frame::Argv(argv) => super::verdict_with(&argv, &Context::from_env()),
        Frame::Parse => line_of(&allow_checked("fail-open", "parse failure")),
        Frame::Shape => line_of(&allow_checked("fail-open", "unknown input")),
    }
}

enum Frame {
    Argv(Vec<String>),
    Parse,
    Shape,
}

fn frame_argv(text: &str) -> Frame {
    let Some(body) = object_body(text) else {
        return Frame::Parse;
    };
    let Some(raw) = json_value(body, "argv") else {
        return Frame::Shape;
    };
    let raw = raw.trim();
    if !raw.starts_with('[') {
        return Frame::Parse;
    }
    match json_string_array(raw) {
        Some(argv) => Frame::Argv(argv),
        None => Frame::Parse,
    }
}

fn object_body(text: &str) -> Option<&str> {
    let text = text.trim();
    let rest = text.strip_prefix('{')?.trim_end();
    let rest = rest.strip_suffix('}')?;
    Some(rest)
}

fn json_string_array(raw: &str) -> Option<Vec<String>> {
    let inner = raw.trim().strip_prefix('[')?.strip_suffix(']')?;
    if inner.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut rest = inner.trim();
    while !rest.is_empty() {
        rest = rest.trim_start().trim_start_matches(',');
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if !rest.starts_with('"') {
            return None;
        }
        let (value, next) = json_string_at(rest)?;
        out.push(value);
        rest = next.trim_start();
    }
    Some(out)
}

/// The printed line for a checked value that already carries its kind.
#[must_use]
pub fn line_of(checked: &Checked) -> String {
    if let Some((kind, rest)) = noted(&checked.token) {
        if kind == "warn" {
            return allow_annotation(rest);
        }
        return format!("allow\t{kind}\t{}", one_piece(rest));
    }
    match checked.decision {
        Decision::Allow => "allow".to_string(),
        Decision::Deny | Decision::Prompt => allow_annotation(&checked.token),
    }
}

/// `allow`, a tab, `warn`, a tab, the rule name, a tab, one warning.
///
/// The rule name is the table's token, including a pack detail and an
/// ancestry note. The warning is one line, so a caller can show it.
#[must_use]
pub fn allow_annotation(token: &str) -> String {
    let shown = one_field(token);
    let warning = one_field(&warning_for(&shown));
    format!("allow\twarn\t{shown}\t{warning}")
}

fn one_field(text: &str) -> String {
    one_piece(text).replace('\t', " ")
}

fn warning_for(token: &str) -> String {
    let body = token.split(" ancestry=").next().unwrap_or(token).trim();
    let name = body.split(": ").next().unwrap_or(body).trim();
    let detail = body.split_once(": ").map(|(_, d)| d.trim()).unwrap_or("");
    let sentence = sentence_for(name);
    let sentence = if sentence.is_empty() {
        name.replace('-', " ")
    } else {
        sentence.to_string()
    };
    if detail.is_empty() {
        sentence
    } else {
        format!("{sentence}: {detail}")
    }
}

/// The one line a caller shows for `name`. The words are the rule the
/// README already states, shortened to a single line.
fn sentence_for(name: &str) -> &'static str {
    match name {
        "sudo" => "a privilege runner is on the command",
        "curl-pipe-shell" => "a download is handed to a shell or an interpreter",
        "decoded-pipe-shell" => "a decoder's output is handed to a shell",
        "rm-rf-outside-tmp" => "a recursive delete reaches outside /tmp and /var/tmp",
        "find-delete" => "find -delete reaches outside /tmp and /var/tmp",
        "find-exec-rm" => "find runs rm outside /tmp and /var/tmp",
        "feeder-rm" => "a feeder runs rm",
        "rsync-delete-outside" => "rsync --delete reaches outside the work tree",
        "mv-tree-outside" => "mv replaces a tree outside the work tree",
        "git-force-push" => "a force push rewrites a published branch",
        "git-push-delete" => "a push deletes a remote branch",
        "git-reset-hard" => "git reset --hard drops uncommitted work",
        "git-clean-force" => "git clean -f deletes untracked files",
        "git-stash-drop" => "git stash drop deletes a stash entry",
        "git-stash-clear" => "git stash clear deletes every stash entry",
        "git-discard-worktree" => "git checkout or restore discards the work tree",
        "git-worktree-force-remove" => "git worktree remove --force deletes a work tree",
        "git-branch-force-delete" => "git branch -D deletes a branch that may be unmerged",
        "git-history-rewrite" => "a history rewrite changes published commits",
        "git-update-ref-delete" => "git update-ref -d deletes a ref",
        "git-reflog-expire" => "git reflog expire drops reachable history",
        "raw-disk" => "a command writes a block device",
        "credential-mention" => "a program names a credential path",
        "exec-unresolved" => "find -exec names a command the line does not show",
        "reads-credential" => "a command reads a credential file",
        "seat-guard-path" => "a command writes a seat or policy file",
        "shell-secret-in-argv" => "a secret is on the command line",
        "path-outside-workspace" => "a path is outside the workspace",
        "python-missing-pep723" => "a Python file has no PEP 723 script block",
        "python-requires-uv-run" => "Python is not run through uv",
        "python-dash-c" | "python-dash-c-denied" => "Python -c is not run through uv",
        "chmod-setuid" => "chmod or install sets the setuid or setgid bit",
        "nesting-unread" => "a nested command past the depth cap was not read",
        "brace-cap" => "a brace wider than the cap was not read",
        _ => "",
    }
}

pub(crate) fn noted(token: &str) -> Option<(&str, &str)> {
    let (kind, rest) = token.split_once('\t')?;
    matches!(kind, "warn" | "fail-open" | "consent" | "user-rule").then_some((kind, rest))
}

fn one_piece(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Apply consent, a user allow, and the fail-open rules to a table hit.
/// Ancestry is appended to the reason when a person is present. It does
/// not change the verdict.
#[must_use]
pub fn publish(argv: &[String], checked: Checked, ctx: &Context) -> Checked {
    let person = ctx.person_tty.unwrap_or_else(person_at_terminal);
    let out = publish_rules(argv, checked, ctx);
    annotate(out, person)
}

fn publish_rules(argv: &[String], checked: Checked, ctx: &Context) -> Checked {
    if checked.decision == Decision::Deny
        && matches!(checked.code, PolicyReason::PythonRequiresUvRun)
    {
        return checked;
    }
    if checked.decision == Decision::Deny && engine_fault(&checked.token) {
        return allow_checked("fail-open", &checked.token);
    }
    if checked.decision == Decision::Deny && irreversible(&checked.token) {
        if let Some(pattern) = user_hit(&ctx.user_allow, argv) {
            return allow_checked("user-rule", &pattern);
        }
        if consent_hit(ctx, argv, &checked.token) {
            return allow_checked("consent", &checked.token);
        }
        return checked;
    }
    if checked.decision == Decision::Deny {
        return warn_checked(&checked.token);
    }
    if checked.decision == Decision::Prompt && lost_work(&checked.token) {
        return warn_checked(&checked.token);
    }
    checked
}

fn annotate(checked: Checked, person: bool) -> Checked {
    if !person {
        return checked;
    }
    let token = checked.token.as_ref();
    if token.is_empty() || token == "allow" {
        return checked;
    }
    Checked {
        token: std::borrow::Cow::Owned(format!("{token} ancestry=person")),
        decision: checked.decision,
        code: checked.code,
    }
}

/// `reset --hard`, `checkout -- .`, `clean -f`, `stash drop`. The hook
/// receives `allow` and a warning. It does not exit 2.
fn lost_work(token: &str) -> bool {
    matches!(
        token,
        "git-reset-hard"
            | "git-clean-force"
            | "git-stash-drop"
            | "git-stash-clear"
            | "git-discard-worktree"
            | "git-worktree-force-remove"
            | "git-branch-force-delete"
    )
}

fn engine_fault(token: &str) -> bool {
    let token = token.trim();
    if token.is_empty() {
        return true;
    }
    let lower = token.to_ascii_lowercase();
    lower == "phronesis"
        || lower == "bind-failed"
        || lower.starts_with("pack-unavailable")
        || lower.starts_with("phronesis:")
        || lower.starts_with("field-too-long")
}

/// A hit the deny log still records. Consent or a user allow clears it.
#[must_use]
pub fn irreversible(token: &str) -> bool {
    let head = token.split(':').next().unwrap_or(token).trim();
    matches!(
        head,
        "rm-rf-outside-tmp"
            | "find-delete"
            | "find-exec-rm"
            | "rsync-delete-outside"
            | "git-force-push"
            | "git-push-delete"
            | "curl-pipe-shell"
            | "reads-credential"
            | "shell-secret-in-argv"
            | "python-missing-pep723"
            | "path-outside-workspace"
    ) || head.starts_with("reads-credential")
}

fn user_hit(patterns: &[String], argv: &[String]) -> Option<String> {
    if patterns.is_empty() || argv.is_empty() {
        return None;
    }
    let line = argv.join(" ");
    let repos = repos_of(argv);
    patterns
        .iter()
        .find(|pattern| {
            glob_match(pattern, &line)
                || repos
                    .iter()
                    .any(|repo| glob_match(pattern, repo) || same_repo(repo, pattern))
        })
        .cloned()
}

fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(pattern: &[u8], text: &[u8]) -> bool {
        let mut i = 0;
        let mut j = 0;
        while i < pattern.len() {
            if pattern[i] == b'*' {
                while i < pattern.len() && pattern[i] == b'*' {
                    i += 1;
                }
                if i == pattern.len() {
                    return true;
                }
                while j <= text.len() {
                    if rec(&pattern[i..], &text[j..]) {
                        return true;
                    }
                    if j == text.len() {
                        return false;
                    }
                    j += 1;
                }
                return false;
            }
            if j >= text.len() {
                return false;
            }
            if pattern[i] != b'?' && pattern[i] != text[j] {
                return false;
            }
            i += 1;
            j += 1;
        }
        j == text.len()
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// A consent row is honored for at most 24 hours from now.
const CONSENT_TTL_MAX: u64 = 24 * 60 * 60;

fn consent_hit(ctx: &Context, argv: &[String], action: &str) -> bool {
    let Some(path) = ctx.consent_file.as_deref() else {
        return false;
    };
    match consent_file_status(path) {
        ConsentFile::Missing => return false,
        ConsentFile::Ignored(why) => {
            eprintln!("consent ignored: {}: {why}", path.display());
            return false;
        }
        ConsentFile::Ok => {}
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("consent ignored: {}: unreadable", path.display());
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    records(&text).into_iter().any(|row| {
        if row.exp > now && row.exp.saturating_sub(now) > CONSENT_TTL_MAX {
            eprintln!("consent ignored: ttl above 24h for {}", row.repo);
            return false;
        }
        row.matches(argv, action, now)
    })
}

struct Consent {
    repo: String,
    git_ref: String,
    action: String,
    sha: Option<String>,
    exp: u64,
}

impl Consent {
    fn matches(&self, argv: &[String], action: &str, now: u64) -> bool {
        if self.exp <= now
            || self.exp.saturating_sub(now) > CONSENT_TTL_MAX
            || self.repo.is_empty()
            || self.git_ref.is_empty()
        {
            return false;
        }
        if !action_eq(&self.action, action) {
            return false;
        }
        push_sites(argv).iter().any(|site| {
            if !same_repo(&site.url, &self.repo) {
                return false;
            }
            if !site
                .dests
                .iter()
                .any(|git_ref| same_ref(git_ref, &self.git_ref))
            {
                return false;
            }
            match &self.sha {
                Some(sha) => head_sha(site.dir.as_deref()).is_some_and(|have| have == *sha),
                None => true,
            }
        })
    }
}

struct PushSite {
    dir: Option<PathBuf>,
    url: String,
    dests: Vec<String>,
}

fn action_eq(want: &str, have: &str) -> bool {
    let have = have.trim();
    let want = want.trim();
    have == want
        || have.split(':').next().unwrap_or(have) == want
        || have.starts_with(&format!("{want}:"))
}

fn same_repo(left: &str, right: &str) -> bool {
    repo_key(left) == repo_key(right)
}

fn repo_key(text: &str) -> String {
    let text = text.trim().trim_end_matches('/');
    let text = match text.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_, host)) => format!("{scheme}://{host}"),
            None => text.to_string(),
        },
        None => text.to_string(),
    };
    text.trim_end_matches(".git").to_string()
}

/// The branch `refs/remotes/<remote>/HEAD` names, without the remote prefix.
pub(crate) fn remote_head(dir: Option<&Path>, remote: &str) -> Option<String> {
    if remote.is_empty()
        || remote.contains("://")
        || remote.starts_with("git@")
        || remote.contains('@')
    {
        return None;
    }
    let spec = format!("refs/remotes/{remote}/HEAD");
    let short = git_line(&["symbolic-ref", "--short", &spec], dir)?;
    Some(short.rsplit('/').next().unwrap_or(&short).to_string())
}

fn same_ref(left: &str, right: &str) -> bool {
    ref_key(left) == ref_key(right)
}

fn ref_key(text: &str) -> String {
    text.trim()
        .strip_prefix("refs/heads/")
        .unwrap_or(text.trim())
        .to_string()
}

fn records(text: &str) -> Vec<Consent> {
    let mut out = Vec::new();
    for object in objects(text) {
        let Some(repo) = json_string(&object, "repo") else {
            continue;
        };
        let Some(git_ref) = json_string(&object, "ref") else {
            continue;
        };
        let Some(action) = json_string(&object, "action") else {
            continue;
        };
        let Some(exp) = json_exp(&object) else {
            continue;
        };
        out.push(Consent {
            repo,
            git_ref,
            action,
            sha: json_string(&object, "sha"),
            exp,
        });
    }
    out
}

fn objects(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        let start = i;
        let mut depth = 0i32;
        let mut quote = false;
        let mut escape = false;
        while i < bytes.len() {
            let c = bytes[i];
            i += 1;
            if quote {
                if escape {
                    escape = false;
                    continue;
                }
                if c == b'\\' {
                    escape = true;
                    continue;
                }
                if c == b'"' {
                    quote = false;
                }
                continue;
            }
            match c {
                b'"' => quote = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(String::from_utf8_lossy(&bytes[start..i]).into_owned());
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn json_string(object: &str, key: &str) -> Option<String> {
    let raw = json_value(object, key)?.trim();
    if raw == "null" {
        return None;
    }
    let (value, _) = json_string_at(raw)?;
    Some(value)
}

fn json_exp(object: &str) -> Option<u64> {
    for key in ["exp", "expires"] {
        let Some(raw) = json_value(object, key) else {
            continue;
        };
        let raw = raw.trim();
        let digits: String = raw.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            if let Ok(n) = digits.parse::<u64>() {
                return Some(n);
            }
        }
        if let Some((text, _)) = json_string_at(raw) {
            if let Some(n) = unix_rfc3339(&text) {
                return Some(n);
            }
            if let Ok(n) = text.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn json_value<'a>(object: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let mut rest = object;
    while let Some(at) = rest.find(&needle) {
        let after = rest[at + needle.len()..].trim_start();
        if let Some(value) = after.strip_prefix(':') {
            return Some(value.trim_start());
        }
        rest = &rest[at + needle.len()..];
    }
    None
}

fn json_string_at(raw: &str) -> Option<(String, &str)> {
    let raw = raw.trim_start();
    let bytes = raw.as_bytes();
    if bytes.first().copied() != Some(b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let next = *bytes.get(i + 1)?;
                out.push(match next {
                    b'n' => '\n',
                    b't' => '\t',
                    b'r' => '\r',
                    other => other as char,
                });
                i += 2;
            }
            b'"' => return Some((out, &raw[i + 1..])),
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    None
}

fn unix_rfc3339(text: &str) -> Option<u64> {
    let text = text.trim().trim_end_matches('Z');
    if text.len() < 19 {
        return None;
    }
    let y: i32 = text.get(0..4)?.parse().ok()?;
    let m: u32 = text.get(5..7)?.parse().ok()?;
    let d: u32 = text.get(8..10)?.parse().ok()?;
    let hh: u32 = text.get(11..13)?.parse().ok()?;
    let mm: u32 = text.get(14..16)?.parse().ok()?;
    let ss: u32 = text.get(17..19)?.parse().ok()?;
    if text.as_bytes().get(4) != Some(&b'-')
        || text.as_bytes().get(7) != Some(&b'-')
        || text.as_bytes().get(10) != Some(&b'T')
    {
        return None;
    }
    let days = days_from_civil(y, m, d);
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86400 + u64::from(hh) * 3600 + u64::from(mm) * 60 + u64::from(ss))
}

fn days_from_civil(mut y: i32, m: u32, d: u32) -> i64 {
    y -= i32::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = u64::from((153 * (m + if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1);
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    i64::from(era) * 146097 + i64::try_from(doe).unwrap_or(0) - 719468
}

fn command_words(argv: &[String]) -> Vec<String> {
    let mut words = Vec::new();
    for w in argv {
        words.push(w.clone());
        let packed = w.contains([' ', '\n', '"', '\'']);
        if packed
            && (w.contains("git") || w.contains("push") || w.contains("-C") || w.contains("://"))
        {
            words.extend(split_words(w));
        }
    }
    words
}

fn split_words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '[' | ']' | '(' | ')') {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn git_dirs(words: &[String]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if words[i] == "-C" {
            if let Some(dir) = words.get(i + 1) {
                if !dir.is_empty() && dir != "push" {
                    dirs.push(PathBuf::from(dir));
                }
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    for w in words {
        dirs.extend(quoted_cwds(w));
    }
    dirs
}

fn quoted_cwds(text: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for key in ["cwd='", "cwd=\""] {
        let mut rest = text;
        while let Some(i) = rest.find(key) {
            let after = &rest[i + key.len()..];
            let quote = if key.ends_with('\'') { '\'' } else { '"' };
            let Some(end) = after.find(quote) else {
                break;
            };
            let dir = &after[..end];
            if !dir.is_empty() {
                out.push(PathBuf::from(dir));
            }
            rest = &after[end..];
        }
    }
    out
}

fn repos_of(argv: &[String]) -> Vec<String> {
    let words = command_words(argv);
    let dirs = git_dirs(&words);
    let mut out = Vec::new();
    if dirs.is_empty() {
        if let Some(top) = git_line(&["rev-parse", "--show-toplevel"], None) {
            out.push(top);
        }
        if let Some(url) = git_line(&["remote", "get-url", "origin"], None) {
            out.push(url);
        }
    } else {
        for dir in &dirs {
            out.push(dir.to_string_lossy().into_owned());
            if let Some(top) = git_line(&["rev-parse", "--show-toplevel"], Some(dir)) {
                out.push(top);
            }
            if let Some(url) = git_line(&["remote", "get-url", "origin"], Some(dir)) {
                out.push(url);
            }
        }
    }
    for w in &words {
        if w.contains("://") || w.starts_with("git@") {
            out.push(w.clone());
        }
    }
    out
}

/// One push: the remote URL from `git -C <dir>` or from the remote
/// argument when that argument is a URL. A `://` word that is not the
/// remote is not a URL. Process cwd is not consulted when `-C` names a
/// directory.
fn push_sites(argv: &[String]) -> Vec<PushSite> {
    let words = command_words(argv);
    let mut sites = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let base = words[i].rsplit('/').next().unwrap_or(words[i].as_str());
        if base != "git" {
            i += 1;
            continue;
        }
        let mut dir: Option<PathBuf> = None;
        let mut saw_c = false;
        let mut j = i + 1;
        while j < words.len() {
            let a = words[j].as_str();
            if a == "-C" {
                saw_c = true;
                if let Some(path) = words.get(j + 1).filter(|d| !d.is_empty()) {
                    dir = Some(PathBuf::from(path));
                }
                j += 2;
                continue;
            }
            if matches!(a, "-c" | "--git-dir" | "--work-tree" | "--namespace") {
                j += 2;
                continue;
            }
            if a.starts_with('-') {
                j += 1;
                continue;
            }
            break;
        }
        if words.get(j).map(String::as_str) != Some("push") {
            i += 1;
            continue;
        }
        let rest = &words[j + 1..];
        let remote = push_remote_name(rest);
        let site_dir = if saw_c { dir } else { script_cwd(argv) };
        let url = resolve_remote(argv, remote, site_dir.as_deref());
        let mut dests = push_dests(rest);
        if dests.is_empty() {
            if let Some(name) = head_name(site_dir.as_deref()) {
                dests.push(name);
            }
        }
        if let Some(url) = url {
            sites.push(PushSite {
                dir: site_dir,
                url,
                dests,
            });
        }
        i = j + 1;
    }
    sites
}

fn remote_is_url(remote: &str) -> bool {
    remote.contains("://") || remote.starts_with("git@")
}

/// The push remote, as a URL. A name that `git remote get-url` knows wins.
/// Otherwise a variable is the one literal URL the script assigns to it.
/// Zero assignments, or more than one, do not resolve.
fn resolve_remote(argv: &[String], remote: &str, dir: Option<&Path>) -> Option<String> {
    if remote.is_empty() {
        return None;
    }
    if remote_is_url(remote) {
        return Some(remote.to_string());
    }
    if let Some(url) = git_line(&["remote", "get-url", remote], dir) {
        return Some(url);
    }
    let mut found: Vec<String> = Vec::new();
    let mut other = false;
    for text in argv {
        for assign in assignments_of(text, remote) {
            match assign {
                Assign::Url(url) => found.push(url),
                Assign::Other => other = true,
            }
        }
    }
    if other || found.len() != 1 {
        None
    } else {
        found.pop()
    }
}

enum Assign {
    Url(String),
    Other,
}

fn assignments_of(text: &str, name: &str) -> Vec<Assign> {
    if name.is_empty() || !is_ident(name) {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let name_b = name.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + name_b.len() <= bytes.len() {
        if bytes[i..].starts_with(name_b) && ident_edge(bytes, i, name_b.len()) {
            let mut j = i + name_b.len();
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if bytes.get(j) == Some(&b'=') {
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if let Some((url, next)) = literal_url_at(&text[j..]) {
                    out.push(Assign::Url(url));
                    i = j + next;
                    continue;
                }
                out.push(Assign::Other);
            }
        }
        i += 1;
    }
    out
}

fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn ident_edge(bytes: &[u8], at: usize, len: usize) -> bool {
    let before_ok = at == 0 || !is_ident_byte(bytes[at - 1]);
    let after = at + len;
    let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
    before_ok && after_ok
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn literal_url_at(text: &str) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let (body, quoted) = if matches!(bytes[0], b'"' | b'\'') {
        let quote = bytes[0];
        let rest = &text[1..];
        let end = rest.find(quote as char)?;
        (&rest[..end], true)
    } else {
        (text, false)
    };
    let url = if quoted {
        body.to_string()
    } else {
        let n = body
            .find(|c: char| c.is_whitespace() || matches!(c, ',' | ')' | ']' | ';' | '"' | '\''))
            .unwrap_or(body.len());
        body[..n].to_string()
    };
    if !remote_is_url(&url) {
        return None;
    }
    let used = if quoted { url.len() + 2 } else { url.len() };
    Some((url, used))
}

fn push_remote_name(rest: &[String]) -> &str {
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        i += 1;
        if a == "--" {
            break;
        }
        if matches!(
            a,
            "-o" | "--push-option" | "--receive-pack" | "--exec" | "--repo" | "-C"
        ) {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        return a;
    }
    ""
}

/// `cwd=` from a `subprocess.run` on the line. Used only when that git
/// call has no `-C`.
fn script_cwd(argv: &[String]) -> Option<PathBuf> {
    argv.iter()
        .find_map(|word| quoted_cwds(word).into_iter().next())
}

fn push_dests(rest: &[String]) -> Vec<String> {
    let mut words = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        i += 1;
        if a == "--" {
            words.extend(rest[i..].iter().cloned());
            break;
        }
        if matches!(
            a,
            "-o" | "--push-option" | "--receive-pack" | "--exec" | "--repo" | "-C"
        ) {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        words.push(a.to_string());
    }
    let specs = if words
        .first()
        .is_some_and(|w| !w.contains(':') && !w.starts_with('+') && !w.starts_with(':'))
    {
        &words[1..]
    } else {
        &words[..]
    };
    specs.iter().filter_map(|spec| refspec_dest(spec)).collect()
}

fn refspec_dest(spec: &str) -> Option<String> {
    let spec = spec.strip_prefix('+').unwrap_or(spec);
    let dest = spec.split_once(':').map_or(spec, |(_, dest)| dest);
    if dest.is_empty() || dest == "HEAD" || dest.contains(['$', '`', '*', '?', '[']) {
        return None;
    }
    Some(dest.trim_start_matches("refs/heads/").to_string())
}

fn head_sha(dir: Option<&Path>) -> Option<String> {
    git_line(&["rev-parse", "HEAD"], dir)
}

/// The current branch name, or the branch of `dir` when `git -C` named one.
#[must_use]
pub fn head_name(dir: Option<&Path>) -> Option<String> {
    git_line(&["rev-parse", "--abbrev-ref", "HEAD"], dir)
}

/// The work tree that contains `cwd`, when `cwd` is inside one.
#[must_use]
pub fn work_tree(cwd: &Path) -> Option<PathBuf> {
    git_line(&["rev-parse", "--show-toplevel"], Some(cwd)).map(PathBuf::from)
}

/// `git` can sit on an index lock. Past `limit` the lookup is the same
/// as git having no line, and the answer is not held.
///
/// The 10 ms poll is how soon a finished git is noticed. It is short
/// next to [`super::client::CONNECT_TIMEOUT`] and keeps the loop from
/// spinning.
fn output_within(cmd: &mut std::process::Command, limit: Duration) -> Option<std::process::Output> {
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if started.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return None,
        }
    }
}

fn git_line(args: &[&str], dir: Option<&Path>) -> Option<String> {
    let key = format!(
        "{}|{}",
        dir.map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        args.join(" ")
    );
    if let Some(hit) = git_cache().lock().ok().and_then(|g| g.get(&key).cloned()) {
        return hit;
    }
    let mut cmd = std::process::Command::new("git");
    if let Some(dir) = dir {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(args);
    let text = output_within(&mut cmd, super::client::CONNECT_TIMEOUT)
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Ok(mut cache) = git_cache().lock() {
        cache.insert(key, text.clone());
    }
    text
}

fn git_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<String, Option<String>>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// True when a parent process comm or exe is a terminal, sshd, or tmux.
/// The walk starts at the parent.
/// This process and the command text are not read.
///
/// The walk has no step cap.
/// It stops at init, at a parent it cannot read, or at a pid it read before.
/// Each step reads a pid that was alive when read and that the walk has not read.
/// So a walk reads at most as many parents as there are pids, and it always ends.
/// What a step costs is in `measurements/parent-walk-depth.md`.
#[must_use]
pub fn person_at_terminal() -> bool {
    let self_pid = std::process::id();
    let mut pid = match ppid(self_pid) {
        Some(next) if next != 0 && next != self_pid => next,
        _ => return false,
    };
    let mut seen = HashSet::new();
    while seen.insert(pid) {
        let (comm, exe) = names_of(pid);
        if ancestor_is_person(&[&comm, &exe]) {
            return true;
        }
        match ppid(pid) {
            Some(next) if next != 0 => pid = next,
            _ => break,
        }
    }
    false
}

/// `names` are parent comm and exe values, one process name each.
#[must_use]
pub fn ancestor_is_person(names: &[&str]) -> bool {
    names.iter().any(|raw| {
        let text = raw.trim_matches('\0').trim();
        term_name(text)
    })
}

/// The default consent path. Policyd only reads it. Who writes it is
/// undecided, and a file the current user can write is ignored.
#[must_use]
pub fn default_consent_path() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("ljos/consent.json")
}

fn term_name(name: &str) -> bool {
    let name = name.rsplit('/').next().unwrap_or(name);
    if name == "sshd" || name == "tmux" || name.starts_with("tmux:") || name.starts_with("tmux ") {
        return true;
    }
    const NAMES: &[&str] = &[
        "gnome-terminal",
        "gnome-terminal-server",
        "konsole",
        "xterm",
        "alacritty",
        "kitty",
        "wezterm",
        "wezterm-gui",
        "foot",
        "tilix",
        "terminator",
        "ghostty",
        "urxvt",
        "rxvt",
        "terminology",
        "mate-terminal",
        "xfce4-terminal",
        "contour",
        "rio",
        "hyper",
        "tabby",
        "st",
        // Terminal.app and iTerm2, cased as macOS reports the comm and the
        // last part of the exe path.
        "Terminal",
        "iTerm2",
    ];
    NAMES
        .iter()
        .any(|known| name == *known || (name.len() >= 15 && known.starts_with(name)))
}

/// The comm and the exe path of `pid`, each empty when it cannot be read.
#[cfg(not(target_os = "macos"))]
fn names_of(pid: u32) -> (String, String) {
    let comm = read_proc(&format!("/proc/{pid}/comm")).unwrap_or_default();
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    (comm, exe)
}

#[cfg(not(target_os = "macos"))]
fn read_proc(path: &str) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn ppid(pid: u32) -> Option<u32> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// macOS has no /proc. libproc gives the short record and the path of a
/// process of any user, so the walk passes a root `login` or `sshd`.
#[cfg(target_os = "macos")]
fn short_info(pid: u32) -> Option<libc::proc_bsdshortinfo> {
    let size = std::mem::size_of::<libc::proc_bsdshortinfo>() as libc::c_int;
    // SAFETY: an all-zero proc_bsdshortinfo is valid, and proc_pidinfo
    // writes at most `size` bytes into it.
    let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
    let got = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDT_SHORTBSDINFO,
            0,
            std::ptr::addr_of_mut!(info).cast(),
            size,
        )
    };
    (got == size).then_some(info)
}

#[cfg(target_os = "macos")]
fn ppid(pid: u32) -> Option<u32> {
    short_info(pid).map(|info| info.pbsi_ppid)
}

/// The comm and the exe path of `pid`, each empty when it cannot be read.
#[cfg(target_os = "macos")]
fn names_of(pid: u32) -> (String, String) {
    let comm = short_info(pid)
        .map(|info| {
            let bytes: Vec<u8> = info
                .pbsi_comm
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        })
        .unwrap_or_default();
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes at most `path.len()` bytes and returns
    // the length of the path, or 0 when it cannot be read.
    let len = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            path.as_mut_ptr().cast(),
            path.len() as u32,
        )
    };
    path.truncate(usize::try_from(len).unwrap_or(0));
    (comm, String::from_utf8_lossy(&path).into_owned())
}

/// The binary is not there, or the config the caller named is not there.
#[must_use]
pub fn missing_tool(binary_present: bool, config_present: bool) -> Option<&'static str> {
    if !binary_present {
        return Some("allow\tfail-open\tpolicyd missing");
    }
    if !config_present {
        return Some("allow\tfail-open\tmissing config");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_allows() {
        let checked = bounded(|| panic!("boom"));
        assert_eq!(line_of(&checked), "allow\tfail-open\tinternal error");
    }

    #[test]
    fn a_bad_frame_allows() {
        assert_eq!(judge_bytes(b"\xff\xfe"), "allow\tfail-open\tunknown input");
        assert_eq!(
            judge_bytes(br#"{"hello":1}"#),
            "allow\tfail-open\tunknown input"
        );
        assert_eq!(
            judge_bytes(br#"{"argv":"#),
            "allow\tfail-open\tparse failure"
        );
        assert_eq!(
            judge_bytes(br#"{"argv":"nope"}"#),
            "allow\tfail-open\tparse failure"
        );
    }

    #[test]
    fn a_missing_config_is_named() {
        let ctx = Context {
            config_path: Some("/no/such/ljos-policyd.conf".into()),
            ..Context::default()
        };
        assert_eq!(config_gap(&ctx), Some("missing config"));
        assert_eq!(config_gap(&Context::default()), None);
    }

    #[test]
    fn an_unbalanced_script_is_a_parse_failure() {
        let argv = [
            "bash".to_string(),
            "-c".to_string(),
            "rm -rf /home".to_string(),
        ];
        let open = [
            "bash".to_string(),
            "-c".to_string(),
            "rm -rf '/home".to_string(),
        ];
        assert!(!script_unparsed(&argv));
        assert!(script_unparsed(&open));
        let comment = [
            "bash".to_string(),
            "-c".to_string(),
            "rm -rf /srv/x # don't".to_string(),
        ];
        assert!(!script_unparsed(&comment));
    }

    #[test]
    fn a_parent_comm_or_exe_is_a_person() {
        assert!(ancestor_is_person(&["bash", "node", "tmux: server"]));
        assert!(ancestor_is_person(&["sshd"]));
        assert!(ancestor_is_person(&["gnome-terminal-server"]));
        assert!(ancestor_is_person(&["/usr/bin/foot"]));
        assert!(!ancestor_is_person(&["bash", "node", "pod-daemon"]));
        assert!(!ancestor_is_person(&["rm -rf /srv/x # tmux"]));
        assert!(!ancestor_is_person(&["cat ~/.ssh/id_ed25519; echo foot"]));
    }

    #[test]
    fn terminal_app_and_iterm2_are_a_person() {
        for name in [
            "Terminal",
            "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            "iTerm2",
            "/Applications/iTerm.app/Contents/MacOS/iTerm2",
        ] {
            assert!(ancestor_is_person(&[name]), "{name}");
        }
        assert!(!ancestor_is_person(&["-zsh", "login"]));
    }

    fn seal(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(path, perms).unwrap();
    }

    fn write_row(path: &std::path::Path, repo: &str, git_ref: &str, exp: u64) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(
            file,
            "{{\"repo\":\"{repo}\",\"ref\":\"{git_ref}\",\"action\":\"git-force-push\",\"exp\":{exp}}}"
        )
        .unwrap();
    }

    fn push_widget() -> [String; 7] {
        [
            "git",
            "-C",
            "/tmp/other-repo",
            "push",
            "--force",
            "https://example.test/widget.git",
            "HEAD:refs/heads/main",
        ]
        .map(str::to_string)
    }

    #[test]
    fn a_consent_row_matches_only_the_push_url() {
        let dir = std::env::temp_dir().join(format!("policyd-consent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("consent.json");
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        write_row(&path, "https://example.test/widget.git", "main", exp);
        seal(&path, 0o400);
        let ctx = Context {
            consent_file: Some(path.clone()),
            person_tty: Some(false),
            ..Context::default()
        };
        let argv = push_widget();
        assert!(
            consent_hit(&ctx, &argv, "git-force-push"),
            "consent should match the push url, not the cwd"
        );
        let other = [
            "git",
            "push",
            "--force",
            "https://example.test/other.git",
            "HEAD:refs/heads/main",
        ]
        .map(str::to_string);
        assert!(!consent_hit(&ctx, &other, "git-force-push"));
        let stray = [
            "bash",
            "-c",
            "echo https://example.test/widget.git; git push --force https://example.test/other.git main",
        ]
        .map(str::to_string);
        assert!(
            !consent_hit(&ctx, &stray, "git-force-push"),
            "a :// word that is not the remote does not match"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_writable_consent_file_is_ignored() {
        let dir = std::env::temp_dir().join(format!("policyd-consent-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("consent.json");
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        write_row(&path, "https://example.test/widget.git", "main", exp);
        let argv = push_widget();
        for mode in [0o644, 0o664, 0o666] {
            seal(&path, mode);
            let ctx = Context {
                consent_file: Some(path.clone()),
                person_tty: Some(false),
                ..Context::default()
            };
            assert!(
                !consent_hit(&ctx, &argv, "git-force-push"),
                "mode {mode:o} is agent-writable"
            );
        }
        seal(&path, 0o400);
        let ctx = Context {
            consent_file: Some(path),
            person_tty: Some(false),
            ..Context::default()
        };
        assert!(consent_hit(&ctx, &argv, "git-force-push"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_consent_ttl_above_24h_is_ignored() {
        let dir = std::env::temp_dir().join(format!("policyd-consent-ttl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("consent.json");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_row(
            &path,
            "https://example.test/widget.git",
            "main",
            now + 48 * 3600,
        );
        seal(&path, 0o400);
        let ctx = Context {
            consent_file: Some(path),
            person_tty: Some(false),
            ..Context::default()
        };
        let argv = push_widget();
        assert!(!consent_hit(&ctx, &argv, "git-force-push"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn push_script(body: &str) -> Vec<String> {
        vec!["python3".into(), "-c".into(), body.into()]
    }

    #[test]
    fn one_assigned_url_is_the_push_remote() {
        let dir = std::env::temp_dir().join(format!("policyd-assign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("consent.json");
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        write_row(&path, "https://github.com/example/app", "main", exp);
        seal(&path, 0o400);
        let ctx = Context {
            consent_file: Some(path),
            person_tty: Some(false),
            ..Context::default()
        };
        let one = push_script(
            "u=\"https://github.com/example/app\"\nimport subprocess\nsubprocess.run([\"git\",\"push\",\"--force\",u,\"HEAD:refs/heads/main\"])",
        );
        let bare = crate::verdict_with(
            &one,
            &Context {
                person_tty: Some(false),
                ..Context::default()
            },
        );
        assert!(bare.starts_with("allow\twarn\tgit-force-push"), "{bare}");
        let hit = crate::verdict_with(&one, &ctx);
        assert!(hit.starts_with("allow\tconsent\t"), "{hit}");
        let unresolved = push_script(
            "u=not_a_url\nimport subprocess\nsubprocess.run([\"git\",\"push\",\"--force\",u,\"HEAD:refs/heads/main\"])",
        );
        let missed = crate::verdict_with(&unresolved, &ctx);
        assert!(
            missed.starts_with("allow\twarn\tgit-force-push"),
            "{missed}"
        );
        let two = push_script(
            "u=\"https://github.com/example/app\"\nu=\"https://github.com/example/other\"\nimport subprocess\nsubprocess.run([\"git\",\"push\",\"--force\",u,\"HEAD:refs/heads/main\"])",
        );
        let both = crate::verdict_with(&two, &ctx);
        assert!(both.starts_with("allow\twarn\tgit-force-push"), "{both}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_person_does_not_change_a_deny() {
        let argv = ["rm".into(), "-rf".into(), "/srv/x".into()];
        let ctx = Context {
            person_tty: Some(true),
            ..Context::default()
        };
        let line = crate::verdict_with(&argv, &ctx);
        assert!(line.starts_with("allow\twarn\trm-rf-outside-tmp"), "{line}");
        assert!(line.contains("ancestry=person"), "{line}");
        let ctx = Context {
            person_tty: Some(false),
            ..Context::default()
        };
        assert_eq!(
            crate::verdict_with(&argv, &ctx),
            allow_annotation("rm-rf-outside-tmp")
        );
    }

    #[test]
    fn a_library_fault_allows() {
        for (site, argv) in [
            ("config_gap", vec!["true".into()]),
            ("script_unparsed", vec!["true".into()]),
            ("log_deny", vec!["rm".into(), "-rf".into(), "/srv/x".into()]),
        ] {
            FAULT_SITE.with(|slot| slot.set(Some(site)));
            let line = crate::verdict(&argv);
            FAULT_SITE.with(|slot| slot.set(None));
            assert_eq!(line, format!("allow\tfail-open\t{site}"), "{site}");
        }
    }

    #[test]
    fn a_user_pattern_and_a_consent_row_match_the_scope() {
        assert!(glob_match("git push*", "git push --force origin main"));
        assert!(!glob_match("git pull*", "git push --force origin main"));
        let row = Consent {
            repo: "example".into(),
            git_ref: "refs/heads/main".into(),
            action: "git-force-push".into(),
            sha: None,
            exp: u64::MAX,
        };
        assert!(same_ref("main", &row.git_ref));
        assert!(action_eq("git-force-push", "git-force-push"));
        assert!(unix_rfc3339("2026-12-01T00:00:00Z").is_some_and(|n| n > 1_700_000_000));
        let text = r#"{"repo":"/work","ref":"refs/heads/main","action":"git-force-push","exp":9999999999}"#;
        let rows = records(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "git-force-push");
        assert_eq!(rows[0].git_ref, "refs/heads/main");
    }
}
