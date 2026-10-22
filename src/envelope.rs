//! Outbound envelope check.
//!
//! The check only refuses. An empty reason list means `From` is the
//! configured identity and neither the deny file nor the pack-law file
//! named a header this check watches. It is not a grant to send.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use icu_casemap::{CaseMapper, CaseMapperBorrowed};
use icu_locale_core::LanguageIdentifier;
use icu_properties::props::{DefaultIgnorableCodePoint, GeneralCategory, NoncharacterCodePoint};
use icu_properties::{CodePointMapData, CodePointSetData};
use unicode_normalization::UnicodeNormalization;

use crate::mail::{self, Header, Mailbox, Message, MessageFault};

/// A message longer than this is refused before it is parsed.
pub const MAIL_MESSAGE_MAX: usize = 1024 * 1024;

pub struct MailReason {
    pub code: &'static str,
    pub detail: String,
}

pub struct MailVerdict {
    pub reasons: Vec<MailReason>,
}

impl MailVerdict {
    pub fn refusal(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            reasons: vec![MailReason {
                code,
                detail: detail.into(),
            }],
        }
    }

    pub fn is_refused(&self) -> bool {
        !self.reasons.is_empty()
    }

    /// One JSON object. `allow` means this check found nothing to refuse.
    pub fn json(&self) -> String {
        let verdict = if self.is_refused() { "deny" } else { "allow" };
        let mut out = format!("{{\"verdict\":\"{verdict}\",\"reasons\":[");
        for (i, reason) in self.reasons.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"code\":");
            push_json_str(&mut out, reason.code);
            out.push_str(",\"detail\":");
            push_json_str(&mut out, &reason.detail);
            out.push('}');
        }
        out.push_str("]}");
        out
    }
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn reason(code: &'static str, detail: impl Into<String>) -> MailReason {
    MailReason {
        code,
        detail: detail.into(),
    }
}

/// `message` is the RFC 5322 bytes. `config_path` names the identity, the
/// deny file and the pack-law file.
pub fn check_mail_bytes(message: &[u8], config_path: &Path) -> MailVerdict {
    check_mail_inner(message, config_path, &[])
}

/// `recipients` are the addresses a caller would have passed to
/// `sendmail -t` beside the message. This check does not see those
/// unless they are passed here. An empty list judges the message only.
pub fn check_mail_argv(message: &[u8], config_path: &Path, recipients: &[String]) -> MailVerdict {
    check_mail_inner(message, config_path, recipients)
}

fn check_mail_inner(message: &[u8], config_path: &Path, recipients: &[String]) -> MailVerdict {
    if message.len() > MAIL_MESSAGE_MAX {
        return MailVerdict::refusal(
            "message-too-large",
            format!("message exceeds {MAIL_MESSAGE_MAX} bytes"),
        );
    }
    let Ok(text) = std::str::from_utf8(message) else {
        return MailVerdict::refusal("message-invalid", "message is not utf-8");
    };
    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(reason) => {
            return MailVerdict {
                reasons: vec![reason],
            }
        }
    };
    let message = match mail::parse_message(text) {
        Ok(message) => message,
        Err(MessageFault::Control) => {
            return MailVerdict::refusal("header-control", "header block");
        }
        Err(MessageFault::LineEnding) => {
            return MailVerdict::refusal("header-line-ending", "header block");
        }
        Err(MessageFault::LineTooLong) => {
            return MailVerdict::refusal("header-line-too-long", "header block");
        }
        Err(MessageFault::Structure) => {
            return MailVerdict::refusal("message-invalid", "header block");
        }
    };
    let mut reasons = Vec::new();
    check_from(&message, &config.identity, &mut reasons);
    check_identity_headers(&message, &config, &mut reasons);
    check_recipients(&message, &config, &mut reasons);
    check_resent(&message, &mut reasons);
    check_apparently_to(&message, &mut reasons);
    check_argv_recipients(&config, recipients, &mut reasons);
    MailVerdict { reasons }
}

/// Command-line recipients are not in the header block. Each one is
/// judged as a recipient: a route character, a denied address, or a
/// denied domain is a refusal.
fn check_argv_recipients(config: &Config, recipients: &[String], reasons: &mut Vec<MailReason>) {
    for raw in recipients {
        let list = match mail::mailboxes(raw) {
            Ok(list) if list.len() == 1 => list,
            _ => {
                reasons.push(reason("argv-recipient-unparsed", raw.clone()));
                continue;
            }
        };
        let Some(addr) = normalize_mailbox(&list[0]) else {
            reasons.push(reason("argv-recipient-unparsed", raw.clone()));
            continue;
        };
        if let Some(shown) = mixed_script_domain(&addr.domain) {
            reasons.push(reason("mixed-script", format!("argv {shown}")));
        }
        if address_denied(&addr, config) {
            reasons.push(reason("argv-recipient-denied", addr.key()));
        }
        if domain_denied(&addr.domain, &config.deny_domains, &config.aliases)
            || domain_denied(&addr.domain, &config.pack_domains, &config.aliases)
        {
            reasons.push(reason("argv-recipient-denied", addr.domain));
        }
    }
}

#[derive(Clone)]
struct NormAddr {
    /// Deny-file form: NFKC, a zero-width space or braille blank removed,
    /// local part lowercased, domain in IDNA ASCII. A closed code point
    /// is not a form.
    local: String,
    domain: String,
    /// The mailbox as written, before that folding. `From` is compared
    /// in this form.
    raw_local: String,
    raw_domain: String,
}

impl NormAddr {
    fn key(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }
}

#[derive(Clone)]
struct Config {
    identity: NormAddr,
    deny_addresses: BTreeSet<String>,
    /// Rules whose own skeleton is long enough for the prefix match.
    /// A shorter rule stays in `deny_addresses` only.
    deny_prefixes: BTreeSet<String>,
    deny_domains: BTreeSet<String>,
    pack_domains: BTreeSet<String>,
    /// Characters that split a local part into a mailbox and a tag.
    /// Default `+-=`. An address rule for the mailbox covers the tag.
    subaddress: String,
    aliases: Vec<AliasFamily>,
}

fn load_config(path: &Path) -> Result<Config, MailReason> {
    // One deny file judged for every code point re-reads the same bytes.
    // Parsing them again does not change the verdict. The bytes are the
    // key, so a test that rewrites a file still loads the new text.
    #[cfg(test)]
    if let Some(config) = cached_config(path) {
        return Ok(config);
    }
    let config = load_config_uncached(path)?;
    #[cfg(test)]
    store_cached_config(path, &config);
    Ok(config)
}

#[cfg(test)]
struct ConfigCache {
    conf_path: PathBuf,
    conf: Vec<u8>,
    deny_path: PathBuf,
    deny: Vec<u8>,
    law_path: PathBuf,
    law: Vec<u8>,
    config: Config,
}

#[cfg(test)]
fn config_cache() -> &'static std::thread::LocalKey<std::cell::RefCell<Option<ConfigCache>>> {
    thread_local! {
        static CACHE: std::cell::RefCell<Option<ConfigCache>> = const { std::cell::RefCell::new(None) };
    }
    &CACHE
}

#[cfg(test)]
fn cached_config(path: &Path) -> Option<Config> {
    let conf = std::fs::read(path).ok()?;
    let (deny_path, law_path) = config_cache().with(|slot| {
        let slot = slot.borrow();
        let slot = slot.as_ref()?;
        if slot.conf_path == path && slot.conf == conf {
            Some((slot.deny_path.clone(), slot.law_path.clone()))
        } else {
            None
        }
    })?;
    let deny = std::fs::read(&deny_path).ok()?;
    let law = std::fs::read(&law_path).ok()?;
    config_cache().with(|slot| {
        let slot = slot.borrow();
        let slot = slot.as_ref()?;
        if slot.conf_path == path && slot.conf == conf && slot.deny == deny && slot.law == law {
            Some(slot.config.clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
fn store_cached_config(path: &Path, config: &Config) {
    let Ok(conf) = std::fs::read(path) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(&conf) else {
        return;
    };
    let Some((deny_path, law_path)) = side_files(text, path) else {
        return;
    };
    let Ok(deny) = std::fs::read(&deny_path) else {
        return;
    };
    let Ok(law) = std::fs::read(&law_path) else {
        return;
    };
    config_cache().with(|slot| {
        *slot.borrow_mut() = Some(ConfigCache {
            conf_path: path.to_path_buf(),
            conf,
            deny_path,
            deny,
            law_path,
            law,
            config: config.clone(),
        });
    });
}

/// The deny file and the pack-law file named by a config that has
/// already loaded. A line this cannot read is not cached.
#[cfg(test)]
fn side_files(text: &str, config: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut deny = None;
    let mut law = None;
    for line in text.lines() {
        let Some((key, value)) = rule_line(line).ok().flatten() else {
            continue;
        };
        match key {
            "deny-file" => deny = Some(resolve(config, value)),
            "pack-law" => law = Some(resolve(config, value)),
            _ => {}
        }
    }
    Some((deny?, law?))
}

fn load_config_uncached(path: &Path) -> Result<Config, MailReason> {
    let text = read_text(path).map_err(|()| reason("config-unreadable", "config"))?;
    let mut identity = None;
    let mut deny_file = None;
    let mut pack_law = None;
    let mut subaddress = None;
    let mut aliases = builtin_families().ok_or_else(|| reason("config-invalid", "config"))?;
    for line in text.lines() {
        let Some((key, value)) =
            rule_line(line).map_err(|()| reason("config-invalid", "config"))?
        else {
            continue;
        };
        // Repeatable, and added to the built-in families: a config line
        // can widen an alias match and cannot remove one.
        if key == "alias" {
            aliases.push(alias_family(value).ok_or_else(|| reason("config-invalid", "config"))?);
            continue;
        }
        let slot = match key {
            "identity" => &mut identity,
            "deny-file" => &mut deny_file,
            "pack-law" => &mut pack_law,
            "subaddress" => &mut subaddress,
            _ => return Err(reason("config-invalid", "config")),
        };
        if slot.is_some() || value.is_empty() {
            return Err(reason("config-invalid", "config"));
        }
        *slot = Some(value.to_string());
    }
    let (Some(identity), Some(deny_file), Some(pack_law)) = (identity, deny_file, pack_law) else {
        return Err(reason("config-invalid", "config"));
    };
    // Absent means the default. A present line that is not a list of
    // separator characters would match nothing, or match the wrong cut,
    // so the config is refused.
    let subaddress = match subaddress {
        Some(value) if valid_separators(&value) => value,
        Some(_) => return Err(reason("config-invalid", "config")),
        None => "+-=".to_string(),
    };
    let identity =
        normalize_identity(&identity).ok_or_else(|| reason("identity-invalid", "identity"))?;
    let loaded = load_deny(&resolve(path, &deny_file), &aliases)?;
    let pack_domains = load_pack_law(&resolve(path, &pack_law))?;
    Ok(Config {
        identity,
        deny_addresses: loaded.addresses,
        deny_prefixes: loaded.prefixes,
        deny_domains: loaded.domains,
        pack_domains,
        subaddress,
        aliases,
    })
}

/// Separators are ASCII punctuation that can occur in a local part.
/// `.` is not one: gmail ignores dots instead of cutting on them. `@`,
/// `%` and `!` are routes, not tags.
fn valid_separators(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|c| {
            matches!(
                c,
                '#' | '$'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '/'
                    | '='
                    | '?'
                    | '^'
                    | '_'
                    | '`'
                    | '{'
                    | '|'
                    | '}'
                    | '~'
            )
        })
}

fn normalize_identity(value: &str) -> Option<NormAddr> {
    let list = mail::mailboxes(value).ok()?;
    if list.len() != 1 {
        return None;
    }
    normalize_mailbox(&list[0])
}

struct LoadedDeny {
    addresses: BTreeSet<String>,
    prefixes: BTreeSet<String>,
    domains: BTreeSet<String>,
}

fn load_deny(path: &Path, aliases: &[AliasFamily]) -> Result<LoadedDeny, MailReason> {
    let text = read_text(path).map_err(|()| reason("deny-file-unreadable", "deny-file"))?;
    let mut addresses = BTreeSet::new();
    let mut prefixes = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let Some((key, value)) =
            rule_line(line).map_err(|()| reason("deny-file-invalid", format!("line {line_no}")))?
        else {
            continue;
        };
        match key {
            "address" => {
                let list = mail::mailboxes(value)
                    .map_err(|_| reason("deny-file-invalid", format!("line {line_no}")))?;
                if list.len() != 1 {
                    return Err(reason("deny-file-invalid", format!("line {line_no}")));
                }
                // A star, or a character a parsed recipient cannot carry,
                // loads and then matches nothing. So does a domain that
                // is not a hostname. The line is refused. The detail
                // names it and not the value, and the failed load denies
                // every send.
                let addr = normalize_mailbox(&list[0])
                    .filter(|addr| address_rule_can_match(&list[0], addr))
                    .ok_or_else(|| reason("deny-file-invalid", format!("line {line_no}")))?;
                // An empty skeleton matches every local part, because
                // `starts_with("")` is true. Refuse that line. One or
                // two characters are a real mailbox (`jo@`, `x@user`),
                // so they keep exact and subaddress matching. The
                // prefix, which would cover most of a domain, does not
                // apply to them. The detail names the line and not the
                // address, and the failed load denies every send.
                let skel_len = skeleton(&addr.local).chars().count();
                if skel_len == 0 {
                    return Err(reason("deny-file-invalid", format!("line {line_no}")));
                }
                for (local, domain) in alias_forms(&addr.local, &addr.domain, aliases) {
                    let key = format!("{local}@{domain}");
                    if skel_len >= MIN_SKELETON {
                        prefixes.insert(key.clone());
                    }
                    addresses.insert(key);
                }
            }
            "domain" => {
                let domain = rule_domain(value)
                    .ok_or_else(|| reason("deny-file-invalid", format!("line {line_no}")))?;
                domains.insert(domain);
            }
            "handle" | "term" => {
                if value.is_empty() {
                    return Err(reason("deny-file-invalid", format!("line {line_no}")));
                }
            }
            "pair" => {
                let mut parts = value.split_whitespace();
                if parts.next().is_none() || parts.next().is_none() {
                    return Err(reason("deny-file-invalid", format!("line {line_no}")));
                }
            }
            _ => return Err(reason("deny-file-invalid", format!("line {line_no}"))),
        }
    }
    Ok(LoadedDeny {
        addresses,
        prefixes,
        domains,
    })
}

fn load_pack_law(path: &Path) -> Result<BTreeSet<String>, MailReason> {
    let text = read_text(path).map_err(|()| reason("pack-law-unreadable", "pack-law"))?;
    let mut domains = BTreeSet::new();
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let Some((key, value)) =
            rule_line(line).map_err(|()| reason("pack-law-invalid", format!("line {line_no}")))?
        else {
            continue;
        };
        // A line that would allow a domain is not a rule this check can
        // apply. The file is refused so an allow cannot override a deny.
        if key != "deny-domain" || value.is_empty() {
            return Err(reason("pack-law-invalid", format!("line {line_no}")));
        }
        let domain = rule_domain(value)
            .ok_or_else(|| reason("pack-law-invalid", format!("line {line_no}")))?;
        domains.insert(domain);
    }
    Ok(domains)
}

/// `None` is a blank line or a comment. A line with no value is an error.
fn rule_line(line: &str) -> Result<Option<(&str, &str)>, ()> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let key = parts.next().ok_or(())?;
    let value = parts.next().unwrap_or("").trim();
    if value.is_empty() {
        return Err(());
    }
    Ok(Some((key, value)))
}

fn resolve(config: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config.parent().unwrap_or(Path::new(".")).join(path)
    }
}

fn read_text(path: &Path) -> Result<String, ()> {
    let file = File::open(path).map_err(|_| ())?;
    let mut buf = Vec::new();
    file.take(MAIL_MESSAGE_MAX as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| ())?;
    if buf.len() > MAIL_MESSAGE_MAX || buf.contains(&0) {
        return Err(());
    }
    String::from_utf8(buf).map_err(|_| ())
}

fn check_from(message: &Message, identity: &NormAddr, reasons: &mut Vec<MailReason>) {
    let froms: Vec<&Header> = message
        .headers
        .iter()
        .filter(|h| h.name == "from")
        .collect();
    if froms.is_empty() {
        reasons.push(reason("from-missing", "From"));
        return;
    }
    if froms.len() > 1 {
        reasons.push(reason("duplicate-from", "From"));
    }
    let mut encoded = false;
    let mut unparsed = false;
    let mut grouped = false;
    let mut not_identity = false;
    for header in froms {
        match read_mailboxes(header) {
            Parsed::EncodedWord => encoded = true,
            Parsed::Unparsed => unparsed = true,
            Parsed::Mailboxes(list) => {
                // A group is not a From, even when its only mailbox is
                // the identity. Receivers do not agree on the syntax.
                match mail::contains_group(&header.raw) {
                    Ok(true) | Err(_) => grouped = true,
                    Ok(false) => {}
                }
                if list.len() != 1 || !same(&list[0], identity) {
                    not_identity = true;
                }
            }
        }
    }
    if encoded {
        reasons.push(reason("encoded-word", "From"));
    }
    if unparsed {
        reasons.push(reason("from-unparsed", "From"));
    }
    if grouped {
        reasons.push(reason("from-group", "From"));
    }
    if not_identity {
        reasons.push(reason("from-not-identity", "From"));
    }
}

fn check_identity_headers(message: &Message, config: &Config, reasons: &mut Vec<MailReason>) {
    for (name, unparsed, denied, not_identity) in [
        ("reply-to", "reply-to-unparsed", "reply-to-denied", None),
        (
            "sender",
            "sender-unparsed",
            "sender-denied",
            Some("sender-not-identity"),
        ),
        (
            "return-path",
            "return-path-unparsed",
            "return-path-denied",
            Some("return-path-not-identity"),
        ),
        (
            "errors-to",
            "errors-to-unparsed",
            "errors-to-denied",
            Some("errors-to-not-identity"),
        ),
        (
            "disposition-notification-to",
            "disposition-notification-to-unparsed",
            "disposition-notification-to-denied",
            None,
        ),
        (
            "return-receipt-to",
            "return-receipt-to-unparsed",
            "return-receipt-to-denied",
            None,
        ),
        (
            "delivery-receipt-to",
            "delivery-receipt-to-unparsed",
            "delivery-receipt-to-denied",
            None,
        ),
        (
            "mail-followup-to",
            "mail-followup-to-unparsed",
            "mail-followup-to-denied",
            None,
        ),
        (
            "mail-reply-to",
            "mail-reply-to-unparsed",
            "mail-reply-to-denied",
            None,
        ),
    ] {
        check_named(
            message,
            name,
            unparsed,
            denied,
            not_identity,
            config,
            reasons,
        );
    }
}

fn check_named(
    message: &Message,
    name: &str,
    unparsed_code: &'static str,
    denied_code: &'static str,
    not_identity: Option<&'static str>,
    config: &Config,
    reasons: &mut Vec<MailReason>,
) {
    let mut encoded = false;
    let mut unparsed = false;
    let mut mismatch = false;
    let mut hits = Vec::new();
    for header in message.headers.iter().filter(|h| h.name == name) {
        match read_mailboxes(header) {
            Parsed::EncodedWord => encoded = true,
            Parsed::Unparsed => unparsed = true,
            Parsed::Mailboxes(list) => {
                // Sender, Errors-To and Return-Path, when present, have to
                // be the identity under the same rule as From. A group, an
                // empty path, or a spelling NFKC would change is not it.
                if not_identity.is_some() && !one_identity(header, &list, &config.identity) {
                    mismatch = true;
                }
                for addr in list {
                    if let Some(shown) = mixed_script_domain(&addr.domain) {
                        hits.push((true, format!("{name} {shown}")));
                    }
                    if address_denied(&addr, config)
                        || domain_denied(&addr.domain, &config.deny_domains, &config.aliases)
                        || domain_denied(&addr.domain, &config.pack_domains, &config.aliases)
                    {
                        hits.push((false, addr.key()));
                    }
                }
            }
        }
    }
    if encoded {
        reasons.push(reason("encoded-word", name));
    }
    if unparsed {
        reasons.push(reason(unparsed_code, name));
    }
    if let Some(code) = not_identity.filter(|_| mismatch) {
        reasons.push(reason(code, name));
    }
    for (mixed, hit) in hits {
        if mixed {
            reasons.push(reason("mixed-script", hit));
        } else {
            reasons.push(reason(denied_code, hit));
        }
    }
}

/// `Resent-*` replaces the envelope after the message was checked.
/// The header is a refusal on its own; the name is the detail.
fn check_resent(message: &Message, reasons: &mut Vec<MailReason>) {
    for header in &message.headers {
        if header.name.starts_with("resent-") {
            reasons.push(reason("resent-header", header.name.as_str()));
        }
    }
}

/// Sendmail `-t` delivers to `Apparently-To`. The header is a refusal
/// on its own, whatever address it names.
fn check_apparently_to(message: &Message, reasons: &mut Vec<MailReason>) {
    for header in &message.headers {
        if header.name == "apparently-to" {
            reasons.push(reason("apparently-to", header.name.as_str()));
        }
    }
}

fn check_recipients(message: &Message, config: &Config, reasons: &mut Vec<MailReason>) {
    for name in ["to", "cc", "bcc"] {
        for header in message.headers.iter().filter(|h| h.name == name) {
            match read_mailboxes(header) {
                Parsed::EncodedWord => reasons.push(reason("encoded-word", name)),
                Parsed::Unparsed => reasons.push(reason("recipient-unparsed", name)),
                Parsed::Mailboxes(list) => {
                    for addr in list {
                        if let Some(shown) = mixed_script_domain(&addr.domain) {
                            reasons.push(reason("mixed-script", format!("{name} {shown}")));
                        }
                        if address_denied(&addr, config) {
                            reasons.push(reason(
                                "recipient-address-denied",
                                format!("{name} {}", addr.key()),
                            ));
                        }
                        if domain_denied(&addr.domain, &config.deny_domains, &config.aliases)
                            || domain_denied(&addr.domain, &config.pack_domains, &config.aliases)
                        {
                            reasons.push(reason(
                                "recipient-domain-denied",
                                format!("{name} {}", addr.domain),
                            ));
                        }
                    }
                }
            }
        }
    }
}

enum Parsed {
    EncodedWord,
    Unparsed,
    Mailboxes(Vec<NormAddr>),
}

fn read_mailboxes(header: &Header) -> Parsed {
    // `raw` is the address. `value` has decoded display names and is not
    // parsed: a decoded parenthesis would hide the mailbox in a comment.
    if header.value.is_err() {
        return Parsed::EncodedWord;
    }
    match mail::mailboxes(&header.raw) {
        Err(_) => Parsed::Unparsed,
        Ok(list) => {
            let mut out = Vec::with_capacity(list.len());
            for mailbox in list {
                match normalize_mailbox(&mailbox) {
                    Some(addr) => out.push(addr),
                    None => return Parsed::Unparsed,
                }
            }
            Parsed::Mailboxes(out)
        }
    }
}

/// `From` equals the identity after ASCII case folding only. A local
/// part or domain that NFKC, or the removal of a zero-width space or a
/// braille blank, would change is a different mailbox on the wire, so
/// it does not match. A closed code point never reaches this: the
/// mailbox is refused first.
fn one_identity(header: &Header, list: &[NormAddr], identity: &NormAddr) -> bool {
    matches!(mail::contains_group(&header.raw), Ok(false))
        && list.len() == 1
        && same(&list[0], identity)
}

fn same(addr: &NormAddr, identity: &NormAddr) -> bool {
    if wire_rewritten(&addr.raw_local) || wire_rewritten(&addr.raw_domain) {
        return false;
    }
    addr.raw_local.eq_ignore_ascii_case(&identity.raw_local)
        && addr.raw_domain.eq_ignore_ascii_case(&identity.raw_domain)
}

fn wire_rewritten(raw: &str) -> bool {
    let stripped: String = raw.chars().filter(|c| !is_documented_fold(*c)).collect();
    if stripped != raw {
        return true;
    }
    let folded: String = raw.nfkc().collect();
    folded != raw
}

/// An `address` rule names that mailbox and `<local><sep><anything>`.
/// The separators are the config's, or `+-=` when the line is omitted,
/// and those of every alias family naming the domain.
///
/// Alias families fold both the rule and the recipient. A domain rule
/// only follows `shared` families, and `From` does not use them.
///
/// The skeleton match is checked beside that, and either one denies.
fn address_denied(addr: &NormAddr, config: &Config) -> bool {
    for (local, domain) in alias_forms(&addr.local, &addr.domain, &config.aliases) {
        let seps = separators(&domain, config);
        let cut = families_of(&domain, &config.aliases).any(|f| f.cut);
        let local_skeleton = skeleton(&local);
        for rule in &config.deny_addresses {
            let Some((rule_local, rule_domain)) = rule.split_once('@') else {
                continue;
            };
            let rule_skeleton = skeleton(rule_local);
            // Equal skeletons on this domain still meet when the rule
            // is short, so transparent characters and case folding
            // compare. The prefix does not: `jo` is not `john`, and a
            // short rule does not cross to another domain in the family.
            let equal_here = local_skeleton == rule_skeleton && domain == rule_domain;
            if same_family(&domain, rule_domain, &config.aliases)
                && !rule_skeleton.is_empty()
                && local_skeleton.starts_with(&rule_skeleton)
                && (equal_here || config.deny_prefixes.contains(rule))
            {
                return true;
            }
            if domain != rule_domain {
                continue;
            }
            let base = match rule_local.find(|c| cut && seps.contains(c)) {
                Some(at) => &rule_local[..at],
                None => rule_local,
            };
            if local == rule_local || local == base || is_subaddress(base, &local, &seps) {
                return true;
            }
        }
    }
    false
}

/// Characters a provider may ignore or cut on in a local part.
const TRANSPARENT: &[char] = &['.', '_', '-', '+', '='];

/// Shorter than this, an address rule does not use the skeleton prefix.
/// An empty skeleton is refused at load: `starts_with("")` is true.
const MIN_SKELETON: usize = 3;

/// NFD, nonspacing marks (Mn) and enclosing marks (Me) removed, case
/// folded twice, marks removed again, then NFC, with every
/// `TRANSPARENT` character removed and nothing cut. `normalize_local`
/// has already composed, so the decomposition runs here on the rule
/// and the recipient: `abc` + U+0301 + `x` is `abćx` by then, and the
/// mark has to come off or the prefix never sees `abc`. An enclosing
/// mark such as U+20DD or U+0488 does not decompose, and leaving it in
/// the skeleton made `oth<U+20DD>er` miss a rule for `other`. Case
/// folding İ produces i and U+0307, so the second strip is what makes
/// that one skeleton with i. One upper-then-lower leaves capital sharp
/// s as ß, so the fold runs again and ß becomes ss. A recipient whose
/// skeleton starts with a rule's skeleton, at that domain or one in
/// the same family, is denied. This over-blocks on purpose: `john`
/// also denies `johnny` and `jo.hn-x`, so a provider that ignores a
/// character no family lists cannot deliver a denied mailbox.
fn skeleton(local: &str) -> String {
    let folded = casefold(&casefold(&strip_marks(local)));
    let composed: String = strip_marks(&folded).nfc().collect();
    composed
        .chars()
        .filter(|c| !TRANSPARENT.contains(c))
        .collect()
}

fn strip_marks(local: &str) -> String {
    let category = CodePointMapData::<GeneralCategory>::new();
    local
        .nfd()
        .filter(|c| {
            !matches!(
                category.get(*c),
                GeneralCategory::NonspacingMark | GeneralCategory::EnclosingMark
            )
        })
        .collect()
}

/// A spacing mark (Mc) whose base is an ASCII character. The skeleton
/// keeps Mc, so U+0903 after `h` is a different local part from `h`
/// and misses the rule. Devanagari and other non-ASCII bases keep the
/// mark: it is part of that spelling.
fn spacing_mark_on_ascii(local: &str) -> bool {
    let category = CodePointMapData::<GeneralCategory>::new();
    let mut ascii_base = false;
    for c in local.chars() {
        match category.get(c) {
            GeneralCategory::SpacingMark if ascii_base => return true,
            GeneralCategory::NonspacingMark
            | GeneralCategory::EnclosingMark
            | GeneralCategory::SpacingMark => {}
            _ => ascii_base = c.is_ascii() && !c.is_ascii_control(),
        }
    }
    false
}

/// NFKC, then uppercase, then lowercase, then NFKC again.
///
/// Case mapping is ICU's full mapping for the root locale, not
/// `char::to_lowercase`. The toolchain's tables are an older Unicode
/// and leave letters such as U+A7DD unchanged.
fn casefold(local: &str) -> String {
    let nfkc: String = local.nfkc().collect();
    let folded = icu_lower(&icu_upper(&nfkc));
    folded.nfkc().collect()
}

fn icu_upper(s: &str) -> String {
    icu_map(s, |cm, ch| {
        cm.uppercase_to_string(ch, &LanguageIdentifier::UNKNOWN)
    })
}

fn icu_lower(s: &str) -> String {
    icu_map(s, |cm, ch| {
        cm.lowercase_to_string(ch, &LanguageIdentifier::UNKNOWN)
    })
}

/// One character at a time. The string mapping is context sensitive, so
/// a final sigma and a medial one become different letters and a rule
/// for `abσ` misses `abσx`. The per-character mapping is what the
/// skeleton already compared, and it still folds a letter the
/// toolchain leaves unchanged.
fn icu_map(
    s: &str,
    map: impl for<'a> Fn(CaseMapperBorrowed<'static>, &'a str) -> std::borrow::Cow<'a, str>,
) -> String {
    let cm = CaseMapper::new();
    let mut out = String::with_capacity(s.len());
    let mut buf = [0u8; 4];
    for ch in s.chars() {
        out.push_str(&map(cm, ch.encode_utf8(&mut buf)));
    }
    out
}

fn same_family(domain: &str, other: &str, families: &[AliasFamily]) -> bool {
    domain == other || families_of(domain, families).any(|f| f.has(other))
}

fn separators(domain: &str, config: &Config) -> String {
    let mut seps = config.subaddress.clone();
    for family in families_of(domain, &config.aliases) {
        seps.push_str(&family.separators);
    }
    seps
}

fn is_subaddress(rule_local: &str, local: &str, seps: &str) -> bool {
    let Some(rest) = local.strip_prefix(rule_local) else {
        return false;
    };
    rest.chars().next().is_some_and(|c| seps.contains(c))
}

/// Provider alias families, one per line in the form of a config `alias`
/// value, which adds a family to these: `<domain>[,<domain>...] <separators> [flag...]`. The
/// separators are added to the `subaddress` line on those domains.
/// `<label>.*` is every domain whose first label is `<label>`, so
/// `yahoo.*` covers `yahoo.com.br` and any other country suffix. It
/// also covers `yahoo.example.test`, which can only over-block.
/// `shared` makes the domains one mailbox, `dots` ignores dots in the
/// local part, and `subdomain` reads `<local>@<user>.<domain>` as
/// `<user><sep><local>@<domain>`, `<sep>` being the first of the
/// family's separators. `cut` also cuts the rule's own local part at the
/// first separator, so a rule naming one disposable address covers
/// every address with that base. Every entry only widens what an address rule
/// covers, so a wrong entry over-blocks and cannot allow a recipient.
const ALIAS_FAMILIES: &[&str] = &[
    // Dots do not matter, and gmail.com and googlemail.com are the same:
    // https://support.google.com/mail/answer/7436150
    // https://support.google.com/mail/answer/10313
    "gmail.com,googlemail.com + shared dots",
    // Plus and subdomain addressing, one subdomain level only:
    // https://www.fastmail.help/hc/en-us/articles/360060591053-Plus-addressing-and-subdomain-addressing
    "fastmail.com + subdomain",
    // Plus addressing only. The domains are separate mailboxes, so none
    // of them is shared and an exact or subaddress match stays on the
    // domain the rule names. The skeleton prefix still crosses the
    // family: john@outlook.com also denies john@hotmail.com,
    // john@live.com, john@msn.com and john@outlook.de.
    // https://support.microsoft.com/en-us/outlook/send-email-from-a-different-address-in-outlook-com
    "outlook.*,hotmail.*,live.*,msn.* +",
    // One account across the four Proton domains, with plus aliases:
    // https://proton.me/support/mail
    // https://proton.me/support/addresses-and-aliases
    "proton.me,protonmail.com,protonmail.ch,pm.me + shared",
    // One account across the three Apple domains. Apple does not
    // document plus addressing, and + is cut anyway, which can only
    // over-block:
    // https://support.apple.com/en-us/118230
    "icloud.com,me.com,mac.com + shared",
    // Disposable addresses are `<base>-<keyword>`, so a denied
    // disposable address denies its base and every keyword on it:
    // https://help.yahoo.com/kb/SLN36718.html
    "yahoo.* - cut",
    "ymail.*,rocketmail.com - cut",
];

#[derive(Clone)]
struct AliasFamily {
    domains: Vec<String>,
    separators: String,
    shared: bool,
    dots: bool,
    subdomain: bool,
    cut: bool,
}

fn builtin_families() -> Option<Vec<AliasFamily>> {
    ALIAS_FAMILIES
        .iter()
        .map(|line| alias_family(line))
        .collect()
}

/// `None` for a line that names no domain, a separator `subaddress`
/// would refuse, or an unknown flag, and for a domain or a flag named
/// twice, which is a typo for something else.
fn alias_family(value: &str) -> Option<AliasFamily> {
    let mut parts = value.split_whitespace();
    let domains = parts
        .next()?
        .split(',')
        .map(alias_domain)
        .collect::<Option<Vec<_>>>()?;
    if domains.iter().collect::<BTreeSet<_>>().len() != domains.len() {
        return None;
    }
    let separators = parts.next()?.to_string();
    if !valid_separators(&separators) {
        return None;
    }
    let mut family = AliasFamily {
        domains,
        separators,
        shared: false,
        dots: false,
        subdomain: false,
        cut: false,
    };
    for flag in parts {
        let slot = match flag {
            "shared" => &mut family.shared,
            "dots" => &mut family.dots,
            "subdomain" => &mut family.subdomain,
            "cut" => &mut family.cut,
            _ => return None,
        };
        if *slot {
            return None;
        }
        *slot = true;
    }
    Some(family)
}

/// A domain, or `<label>.*` with one label before the `.*`.
fn alias_domain(value: &str) -> Option<String> {
    let (name, pattern) = match value.strip_suffix(".*") {
        Some(label) => (label, true),
        None => (value, false),
    };
    let name = normalize_domain(name).filter(|n| !n.contains('*'))?;
    match pattern {
        true if name.contains('.') => None,
        true => Some(format!("{name}.*")),
        false => Some(name),
    }
}

fn member_matches(member: &str, domain: &str) -> bool {
    match member.strip_suffix(".*") {
        Some(label) => domain
            .split_once('.')
            .is_some_and(|(first, rest)| first == label && !rest.is_empty()),
        None => member == domain,
    }
}

impl AliasFamily {
    fn has(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| member_matches(d, domain))
    }

    /// The domains a fold can name, which leaves out the patterns.
    fn literal_domains(&self) -> impl Iterator<Item = &String> {
        self.domains.iter().filter(|d| !d.ends_with(".*"))
    }
}

fn families_of<'a>(
    domain: &'a str,
    families: &'a [AliasFamily],
) -> impl Iterator<Item = &'a AliasFamily> {
    families.iter().filter(move |f| f.has(domain))
}

/// Every `(local, domain)` the families make of one mailbox, itself
/// first. Each form is folded again until nothing new appears, so a
/// domain named by two families gets both, and a subdomain of a `shared`
/// domain is also that subdomain of every other domain in the family.
/// `subdomain` reads `<local>@<user>.<domain>` as
/// `<user><sep><local>@<domain>`, with the family's first separator,
/// and the result is folded again, so `dots` also reaches the user.
/// The user is every label in front of the domain, and is not cut on a
/// separator: a hyphen there is part of the user name.
fn alias_forms(local: &str, domain: &str, families: &[AliasFamily]) -> Vec<(String, String)> {
    let mut forms = vec![(local.to_string(), domain.to_string())];
    let mut i = 0;
    while i < forms.len() {
        let (local, domain) = forms[i].clone();
        for family in families_of(&domain, families) {
            if family.dots {
                let bare = local.chars().filter(|c| *c != '.').collect();
                push_form(&mut forms, bare, domain.clone());
            }
            if family.shared {
                for other in family.literal_domains() {
                    push_form(&mut forms, local.clone(), other.clone());
                }
            }
        }
        for family in families.iter().filter(|f| f.shared || f.subdomain) {
            for base in family.literal_domains() {
                let Some(user) = domain
                    .strip_suffix(base.as_str())
                    .and_then(|rest| rest.strip_suffix('.'))
                    .filter(|u| !u.is_empty())
                else {
                    continue;
                };
                if family.shared {
                    for other in family.literal_domains() {
                        push_form(&mut forms, local.clone(), format!("{user}.{other}"));
                    }
                }
                if let Some(sep) = family
                    .separators
                    .chars()
                    .next()
                    .filter(|_| family.subdomain)
                {
                    for user in subdomain_users(user) {
                        push_form(&mut forms, format!("{user}{sep}{local}"), base.clone());
                    }
                }
            }
        }
        i += 1;
    }
    forms
}

/// The domain is IDNA ASCII and the local part is Unicode, so the user
/// label is decoded and folded as a local part. The ASCII label is kept
/// as well, and a label that does not decode is only that.
fn subdomain_users(label: &str) -> Vec<String> {
    let mut users = vec![label.to_string()];
    let (unicode, result) = idna::domain_to_unicode(label);
    if let Some(user) = result.ok().and_then(|()| normalize_local(&unicode)) {
        if user != label {
            users.push(user);
        }
    }
    users
}

fn push_form(forms: &mut Vec<(String, String)>, local: String, domain: String) {
    if !forms.iter().any(|(l, d)| *l == local && *d == domain) {
        forms.push((local, domain));
    }
}

/// A domain rule covers that domain and its subdomains, and so does a
/// rule on any other domain of a `shared` family it is in.
fn domain_denied(domain: &str, denied: &BTreeSet<String>, families: &[AliasFamily]) -> bool {
    let mut suffix = Some(domain);
    while let Some(name) = suffix {
        if denied.iter().any(|rule| {
            name == rule
                || families
                    .iter()
                    .any(|f| f.shared && f.has(name) && f.has(rule))
        }) {
            return true;
        }
        suffix = name.split_once('.').map(|(_, parent)| parent);
    }
    false
}

fn normalize_mailbox(mailbox: &Mailbox) -> Option<NormAddr> {
    let local = normalize_local(&mailbox.local)?;
    let domain = normalize_domain(&mailbox.domain)?;
    Some(NormAddr {
        local,
        domain,
        raw_local: mailbox.local.clone(),
        raw_domain: mailbox.domain.clone(),
    })
}

/// A zero-width space and a braille blank come off. Those two folds are
/// the ones the reference names. Every other closed code point refuses
/// the local part, before NFKC and after it: U+2000 to U+200A become a
/// plain space, and a space the parser let through a quoted local part
/// is still closed.
fn normalize_local(raw: &str) -> Option<String> {
    let sets = unicode_sets();
    let stripped: String = raw.chars().filter(|c| !is_documented_fold(*c)).collect();
    if stripped.chars().any(|c| local_closed(&sets, c)) {
        return None;
    }
    let folded: String = stripped
        .nfkc()
        .filter(|c| !is_documented_fold(*c))
        .collect();
    if folded
        .chars()
        .any(|c| local_closed(&sets, c) || mail::unicode_control(c))
    {
        return None;
    }
    // After NFKC, so a compatibility form that opens into an ASCII base
    // plus a spacing mark is caught too. The pre-NFKC spelling is
    // checked as well: composition must not hide the mark.
    if spacing_mark_on_ascii(&stripped) || spacing_mark_on_ascii(&folded) {
        return None;
    }
    let lower = icu_lower(&folded);
    if lower.is_empty() {
        return None;
    }
    Some(lower)
}

/// A deny-file or pack-law domain. `None` when a recipient domain could
/// not be written the same way. A star, a colon, a slash or a dotted
/// quad would load and then match no real recipient. A domain rule
/// already covers its subdomains, so a wildcard is not another way to
/// write it.
fn rule_domain(raw: &str) -> Option<String> {
    if raw.chars().any(forbidden_in_domain) {
        return None;
    }
    let bare = mail::parse_domain(raw).ok()?;
    normalize_domain(&bare)
}

fn forbidden_in_domain(c: char) -> bool {
    matches!(c, '*' | ':' | '/' | '@') || mail::unicode_space(c)
}

/// LDH labels of 1 to 63 characters, no leading or trailing hyphen, and
/// the whole name at most 253. That is a hostname after IDNA. A rule
/// and a recipient both have to be one, so every recipient domain is a
/// domain a rule can name.
fn is_hostname(ascii: &str) -> bool {
    if ascii.is_empty() || ascii.len() > 253 || ascii.starts_with('.') || ascii.ends_with('.') {
        return false;
    }
    ascii.split('.').all(is_hostname_label)
}

fn is_hostname_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    if bytes.len() > 63 || first == b'-' || last == b'-' {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// An address rule has to be a mailbox a parsed recipient can be.
/// A star is a wildcard a reader might write, and it matches only a
/// mailbox that itself contains a star.
fn address_rule_can_match(mailbox: &Mailbox, addr: &NormAddr) -> bool {
    if mailbox.local.contains('*')
        || mailbox.domain.contains('*')
        || addr.local.contains('*')
        || addr.domain.contains('*')
    {
        return false;
    }
    if mailbox.domain.chars().any(forbidden_in_domain)
        || addr.domain.chars().any(forbidden_in_domain)
    {
        return false;
    }
    mailbox.local.chars().all(recipient_local_char) && addr.local.chars().all(recipient_local_char)
}

/// `@`, `%` and `!` are routes the parser refuses. A control other than
/// a tab cannot be in a parsed local part either.
fn recipient_local_char(c: char) -> bool {
    !matches!(c, '@' | '%' | '!' | '*') && (!mail::unicode_control(c) || c == '\t')
}

/// NFKC, then IDNA, so a fullwidth label and a punycode label of the same
/// domain compare equal. A trailing dot is the same name. A homoglyph that
/// NFKC leaves alone stays a different domain. Rules and recipients are
/// both read here, and a name that is not a hostname after IDNA is
/// `None` for both: a recipient at an underscore or edge-hyphen label is
/// refused, because no rule could name it.
///
/// Each label then gets the case fold of the local-part skeleton, so ß
/// is ss and dotless ı and dotted İ are i. Marks are kept, and a label
/// wholly in Cyrillic or Greek is not mapped to the Latin it looks like:
/// it is a different domain, and only Latin mixed with either script in
/// one label is refused as `mixed-script`.
fn normalize_domain(raw: &str) -> Option<String> {
    if raw.contains('@') {
        return None;
    }
    let sets = unicode_sets();
    let folded: String = raw.nfkc().filter(|c| !domain_skips(&sets, *c)).collect();
    let folded = folded.trim().trim_end_matches('.');
    if folded.is_empty() || folded.starts_with('.') || folded.contains("..") {
        return None;
    }
    if folded
        .chars()
        .any(|c| mail::unicode_control(c) || mail::unicode_space(c) || domain_closed(&sets, c))
    {
        return None;
    }
    // A domain literal is not a name. NFKC cannot turn the brackets into
    // one, and the address is refused instead of compared.
    if folded.contains('[') || folded.contains(']') {
        return None;
    }
    let ascii = idna::domain_to_ascii(folded).ok()?;
    let (unicode, result) = idna::domain_to_unicode(&ascii);
    result.ok()?;
    let folded = casefold(&casefold(&unicode)).replace("i\u{0307}", "i");
    idna::domain_to_ascii(&folded)
        .ok()
        .filter(|d| is_hostname(d))
}

/// Latin together with Cyrillic or Greek in one label, after NFKC and
/// IDNA. `domain` is the ASCII form, so a punycode label is decoded
/// before the scripts are read. The returned string is the Unicode
/// form, for the reason.
fn mixed_script_domain(domain: &str) -> Option<String> {
    let (unicode, result) = idna::domain_to_unicode(domain);
    if result.is_err() {
        return Some(domain.to_string());
    }
    if unicode.split('.').any(label_mixes_latin) {
        Some(if unicode.is_empty() {
            domain.to_string()
        } else {
            unicode
        })
    } else {
        None
    }
}

fn label_mixes_latin(label: &str) -> bool {
    let mut latin = false;
    let mut other = false;
    for c in label.chars() {
        if is_latin_letter(c) {
            latin = true;
        } else if is_greek_letter(c) || is_cyrillic_letter(c) {
            other = true;
        }
        if latin && other {
            return true;
        }
    }
    false
}

fn is_latin_letter(c: char) -> bool {
    c.is_alphabetic()
        && matches!(
            c,
            'A'..='Z'
                | 'a'..='z'
                | '\u{00C0}'..='\u{00D6}'
                | '\u{00D8}'..='\u{00F6}'
                | '\u{00F8}'..='\u{024F}'
                | '\u{0250}'..='\u{02AF}'
                | '\u{1E00}'..='\u{1EFF}'
                | '\u{2C60}'..='\u{2C7F}'
                | '\u{A720}'..='\u{A7FF}'
                | '\u{AB30}'..='\u{AB6F}'
        )
}

fn is_greek_letter(c: char) -> bool {
    c.is_alphabetic() && matches!(c, '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}')
}

fn is_cyrillic_letter(c: char) -> bool {
    c.is_alphabetic()
        && matches!(
            c,
            '\u{0400}'..='\u{04FF}'
                | '\u{0500}'..='\u{052F}'
                | '\u{1C80}'..='\u{1C8F}'
                | '\u{2DE0}'..='\u{2DFF}'
                | '\u{A640}'..='\u{A69F}'
        )
}

struct UnicodeSets {
    category: icu_properties::CodePointMapDataBorrowed<'static, GeneralCategory>,
    ignorable: icu_properties::CodePointSetDataBorrowed<'static>,
    noncharacter: icu_properties::CodePointSetDataBorrowed<'static>,
}

fn unicode_sets() -> UnicodeSets {
    UnicodeSets {
        category: CodePointMapData::<GeneralCategory>::new(),
        ignorable: CodePointSetData::new::<DefaultIgnorableCodePoint>(),
        noncharacter: CodePointSetData::new::<NoncharacterCodePoint>(),
    }
}

/// Removed, not refused. The reference names these two and no other
/// local-part fold. ZWJ is a format character and is refused with the
/// rest: no name fold in this check depends on it.
fn is_documented_fold(c: char) -> bool {
    matches!(c, '\u{200B}' | '\u{2800}')
}

/// A recipient local part that contains one of these is refused. The
/// parser already rejects some of them in an atom. A quoted local part
/// still carries the others, including a space separator, so the check
/// is here and not in the parser. A hand list of ranges is what left
/// U+FFF0..U+FFF8 in place.
fn local_closed(sets: &UnicodeSets, c: char) -> bool {
    if is_documented_fold(c) {
        return false;
    }
    sets.ignorable.contains(c)
        || sets.noncharacter.contains(c)
        || matches!(
            sets.category.get(c),
            GeneralCategory::Unassigned
                | GeneralCategory::PrivateUse
                | GeneralCategory::Surrogate
                | GeneralCategory::Format
                | GeneralCategory::Control
                | GeneralCategory::SpaceSeparator
        )
}

/// A domain comparison still removes a character a reader skips. It
/// does not remove an unassigned, private-use, or noncharacter code
/// point: that would turn a name IDNA rejects into one that can be
/// delivered.
fn domain_skips(sets: &UnicodeSets, c: char) -> bool {
    if sets.noncharacter.contains(c)
        || matches!(
            sets.category.get(c),
            GeneralCategory::Unassigned
                | GeneralCategory::PrivateUse
                | GeneralCategory::Surrogate
                | GeneralCategory::Control
        )
    {
        return false;
    }
    is_documented_fold(c) || sets.ignorable.contains(c)
}

fn domain_closed(sets: &UnicodeSets, c: char) -> bool {
    if domain_skips(sets, c) {
        return false;
    }
    sets.noncharacter.contains(c)
        || matches!(
            sets.category.get(c),
            GeneralCategory::Unassigned
                | GeneralCategory::PrivateUse
                | GeneralCategory::Surrogate
                | GeneralCategory::Control
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: &str = "mailseat@example.test";

    fn codes(message: &str, deny: &str, law: &str) -> Vec<String> {
        verdict(message, deny, law)
            .reasons
            .into_iter()
            .map(|r| r.code.to_string())
            .collect()
    }

    fn details(message: &str, deny: &str, law: &str) -> Vec<String> {
        verdict(message, deny, law)
            .reasons
            .into_iter()
            .map(|r| r.detail)
            .collect()
    }

    fn verdict(message: &str, deny: &str, law: &str) -> MailVerdict {
        verdict_with(message, deny, law, "")
    }

    fn verdict_with(message: &str, deny: &str, law: &str, extra: &str) -> MailVerdict {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "policyd-env-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deny.txt"), deny).unwrap();
        std::fs::write(dir.join("law.txt"), law).unwrap();
        std::fs::write(
            dir.join("mail.conf"),
            format!("identity {IDENTITY}\ndeny-file deny.txt\npack-law law.txt\n{extra}"),
        )
        .unwrap();
        let got = check_mail_bytes(message.as_bytes(), &dir.join("mail.conf"));
        let _ = std::fs::remove_dir_all(&dir);
        got
    }

    fn codes_argv(message: &str, deny: &str, law: &str, recipients: &[&str]) -> Vec<String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "policyd-env-argv-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deny.txt"), deny).unwrap();
        std::fs::write(dir.join("law.txt"), law).unwrap();
        std::fs::write(
            dir.join("mail.conf"),
            format!("identity {IDENTITY}\ndeny-file deny.txt\npack-law law.txt\n"),
        )
        .unwrap();
        let recipients: Vec<String> = recipients.iter().map(|s| (*s).to_string()).collect();
        let got = check_mail_argv(message.as_bytes(), &dir.join("mail.conf"), &recipients);
        let _ = std::fs::remove_dir_all(&dir);
        got.reasons
            .into_iter()
            .map(|r| r.code.to_string())
            .collect()
    }

    fn codes_with(message: &str, deny: &str, law: &str, extra: &str) -> Vec<String> {
        verdict_with(message, deny, law, extra)
            .reasons
            .into_iter()
            .map(|r| r.code.to_string())
            .collect()
    }

    fn plain(extra: &str) -> String {
        format!("From: {IDENTITY}\r\n{extra}")
    }

    #[test]
    fn a_matching_from_is_not_refused() {
        let v = verdict(&plain(""), "", "");
        assert!(!v.is_refused());
        assert_eq!(v.json(), r#"{"verdict":"allow","reasons":[]}"#);
        assert!(!v.json().contains("approv"));
    }

    #[test]
    fn a_folded_from_matches_the_identity() {
        let raw = "From: Mail Seat\r\n <mailseat@example.test>\r\n";
        assert!(codes(raw, "", "").is_empty());
    }

    #[test]
    fn a_fold_inside_the_address_is_not_the_identity() {
        let raw = "From: mailseat\r\n @example.test\r\n";
        assert_eq!(codes(raw, "", ""), vec!["from-unparsed"]);
    }

    #[test]
    fn an_encoded_word_from_matches_the_identity() {
        let raw = "From: =?utf-8?q?Mail_Seat?= <mailseat@example.test>\r\n";
        assert!(codes(raw, "", "").is_empty());
        let raw = "From: =?utf-8?b?TWFpbCBTZWF0?= <mailseat@example.test>\r\n";
        assert!(codes(raw, "", "").is_empty());
        let raw = "From: =?utf-8?q?mailseat?=\r\n =?utf-8?q?=40example=2etest?=\r\n";
        assert_eq!(codes(raw, "", ""), vec!["from-unparsed"]);
    }

    /// A decoded parenthesis is comment syntax. The mailbox has to be read
    /// from the raw value, or the address inside the constructed comment
    /// is never compared.
    #[test]
    fn an_encoded_parenthesis_does_not_hide_a_mailbox() {
        let deny = "domain blocked.test\naddress evil@example.test\n";
        let law = "deny-domain packblocked.test\n";
        let to = "\
From: mailseat@example.test\r\n\
To: =?utf-8?q?=28?= <a@blocked.test> (=?utf-8?q?=29?=)\r\n";
        assert_eq!(codes(to, deny, law), vec!["recipient-domain-denied"]);
        assert_eq!(details(to, deny, law), vec!["to blocked.test"]);
        let to_b = "\
From: mailseat@example.test\r\n\
To: =?utf-8?b?KA==?= <a@blocked.test> (=?utf-8?b?KQ==?=)\r\n";
        assert_eq!(codes(to_b, deny, law), vec!["recipient-domain-denied"]);
        assert_eq!(details(to_b, deny, law), vec!["to blocked.test"]);
        let bcc = "\
From: mailseat@example.test\r\n\
Bcc: =?utf-8?b?KA==?= <a@packblocked.test> (=?utf-8?b?KQ==?=)\r\n";
        assert_eq!(codes(bcc, deny, law), vec!["recipient-domain-denied"]);
        assert_eq!(details(bcc, deny, law), vec!["bcc packblocked.test"]);
        let reply = "\
From: mailseat@example.test\r\n\
Reply-To: =?utf-8?q?=28?= <evil@example.test> (=?utf-8?q?=29?=)\r\n";
        assert_eq!(codes(reply, deny, law), vec!["reply-to-denied"]);
        let from = "\
From: =?utf-8?q?=28?= <other@evil.test> (=?utf-8?q?=29?= =?utf-8?q?=29?= mailseat@example.test =?utf-8?q?=28?=)\r\n";
        assert_eq!(codes(from, deny, law), vec!["from-not-identity"]);
    }

    #[test]
    fn the_angle_address_is_what_from_must_equal() {
        let spoof = "From: other@example.test <mailseat@example.test>\r\n";
        assert!(codes(spoof, "", "").is_empty());
        let hidden = "From: =?utf-8?q?mailseat=40example=2etest?= <other@example.test>\r\n";
        assert_eq!(codes(hidden, "", ""), vec!["from-not-identity"]);
    }

    #[test]
    fn a_group_in_from_is_refused() {
        let raw = "From: G: mailseat@example.test;";
        assert_eq!(codes(raw, "", ""), vec!["from-group"]);
        let raw = "From: G: <mailseat@example.test>;\r\n";
        assert_eq!(codes(raw, "", ""), vec!["from-group"]);
        let raw = "From: G: other@example.test;\r\n";
        assert_eq!(codes(raw, "", ""), vec!["from-group", "from-not-identity"]);
        let raw = "From: \"G: H\" <mailseat@example.test>\r\n";
        assert!(codes(raw, "", "").is_empty(), "{:?}", details(raw, "", ""));
        assert!(codes(&plain("To: Friends: a@example.test;\r\n"), "", "").is_empty());
    }

    #[test]
    fn a_second_from_is_refused() {
        let same = "\
From: mailseat@example.test\r\n\
From: mailseat@example.test\r\n";
        assert_eq!(codes(same, "", ""), vec!["duplicate-from"]);
        let other = "\
From: mailseat@example.test\r\n\
From: other@example.test\r\n";
        assert_eq!(
            codes(other, "", ""),
            vec!["duplicate-from", "from-not-identity"]
        );
    }

    /// ASCII case is the same mailbox. A form NFKC or ignorable
    /// stripping would change is a different mailbox on the wire.
    #[test]
    fn from_matches_the_identity_in_ascii_case_only() {
        let raw = "From: MailSeat@Example.Test\r\n";
        assert!(codes(raw, "", "").is_empty(), "{:?}", details(raw, "", ""));
        let raw = "From: MAILSEAT@example.test\r\n";
        assert!(codes(raw, "", "").is_empty(), "{:?}", details(raw, "", ""));
        let raw = "From: \u{FF4D}\u{FF41}\u{FF49}\u{FF4C}\u{FF53}\u{FF45}\u{FF41}\u{FF54}@example.test\r\n";
        assert_eq!(codes(raw, "", ""), vec!["from-not-identity"]);
        let raw = "From: mail\u{200B}seat@example.test\r\n";
        assert_eq!(codes(raw, "", ""), vec!["from-not-identity"]);
    }

    #[test]
    fn a_label_that_mixes_latin_with_cyrillic_or_greek_is_refused() {
        let cyr = "ex\u{0430}mple.test";
        let raw = plain(&format!("To: a@{cyr}\r\n"));
        assert_eq!(codes(&raw, "", ""), vec!["mixed-script"]);
        assert!(details(&raw, "", "")[0].starts_with("to "));
        let greek = "ex\u{03B1}mple.test";
        let raw = plain(&format!("Reply-To: a@{greek}\r\n"));
        assert_eq!(codes(&raw, "", ""), vec!["mixed-script"]);
        let puny = idna::domain_to_ascii("ex\u{0430}mple.test").unwrap();
        let raw = plain(&format!("Cc: a@{puny}\r\n"));
        assert_eq!(codes(&raw, "", ""), vec!["mixed-script"]);
        let raw = plain(&format!("Errors-To: a@{greek}\r\n"));
        assert_eq!(
            codes(&raw, "", ""),
            vec!["errors-to-not-identity", "mixed-script"]
        );
        // One script in the label is not this refusal. A Cyrillic label
        // beside a Latin label is two labels.
        let raw = plain("To: a@\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.test\r\n");
        assert!(
            codes(&raw, "", "").is_empty(),
            "{:?}",
            details(&raw, "", "")
        );
        let raw = plain("To: a@b\u{00FC}cher.test\r\n");
        assert!(
            codes(&raw, "", "").is_empty(),
            "{:?}",
            details(&raw, "", "")
        );
        let raw = plain("To: a@\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.example.test\r\n");
        assert!(
            codes(&raw, "", "").is_empty(),
            "{:?}",
            details(&raw, "", "")
        );
    }

    #[test]
    fn a_cyrillic_lookalike_domain_is_not_the_identity() {
        // U+0430 is Cyrillic a. NFKC leaves it, and IDNA punycode is not
        // example.test, so the From is a different address.
        let raw = "From: mailseat@ex\u{0430}mple.test\r\n";
        assert_eq!(codes(raw, "", ""), vec!["from-not-identity"]);
    }

    #[test]
    fn a_fullwidth_recipient_domain_hits_the_deny_file() {
        let deny = "domain blocked.test\n";
        let full = "\u{FF42}\u{FF4C}\u{FF4F}\u{FF43}\u{FF4B}\u{FF45}\u{FF44}.test";
        let raw = plain(&format!("To: person@{full}\r\n"));
        assert_eq!(codes(&raw, deny, ""), vec!["recipient-domain-denied"]);
        assert_eq!(details(&raw, deny, ""), vec!["to blocked.test"]);
    }

    #[test]
    fn punycode_and_unicode_are_the_same_denied_domain() {
        let raw = plain("To: person@xn--bcher-kva.test\r\n");
        assert_eq!(
            codes(&raw, "domain bücher.test\n", ""),
            vec!["recipient-domain-denied"]
        );
        assert_eq!(
            details(&raw, "domain bücher.test\n", ""),
            vec!["to xn--bcher-kva.test"]
        );
        let raw = plain("To: person@bücher.test\r\n");
        assert_eq!(
            codes(&raw, "domain xn--bcher-kva.test\n", ""),
            vec!["recipient-domain-denied"]
        );
    }

    /// The recipient parser takes any atext in a domain, and IDNA does
    /// not check hyphens or lengths. A domain no rule can name is
    /// refused, not allowed.
    #[test]
    fn a_recipient_domain_no_rule_can_name_is_refused() {
        let a61 = "a".repeat(61);
        let a62 = "a".repeat(62);
        let a63 = "a".repeat(63);
        let a64 = "a".repeat(64);
        let refused = [
            "foo_bar.test".to_string(),
            "_under.test".to_string(),
            "-lead.test".to_string(),
            "trail-.test".to_string(),
            "a.-lead.test".to_string(),
            format!("{a64}.test"),
            format!("{a63}.{a63}.{a63}.{a62}"),
            "a!b.test".to_string(),
            "a*b.test".to_string(),
            "a+b.test".to_string(),
            "a%b.test".to_string(),
            "a$b.test".to_string(),
        ];
        for domain in &refused {
            let to = format!("user@{domain}");
            assert_eq!(
                codes(&plain(&format!("To: {to}\r\n")), "", ""),
                vec!["recipient-unparsed"],
                "{to}"
            );
            assert_eq!(
                codes_argv(&plain(""), "", "", &[&to]),
                vec!["argv-recipient-unparsed"],
                "{to}"
            );
        }
        for domain in [
            "a-b.test".to_string(),
            format!("{a63}.test"),
            format!("{a63}.{a63}.{a63}.{a61}"),
        ] {
            let to = plain(&format!("To: user@{domain}\r\n"));
            assert!(codes(&to, "", "").is_empty(), "{domain}");
            assert_eq!(
                codes(&to, &format!("domain {domain}\n"), ""),
                vec!["recipient-domain-denied"],
                "{domain}"
            );
        }
    }

    /// A domain label gets the case fold a local part does: ß, ẞ, ı
    /// and İ compare with ss and i, each way round.
    #[test]
    fn a_domain_label_is_case_folded_like_a_local_part() {
        for (written, plain_form) in [
            ("stra\u{DF}e.test", "strasse.test"),
            ("STRA\u{1E9E}E.test", "strasse.test"),
            ("\u{0131}nfo.test", "info.test"),
            ("\u{0130}nfo.test", "info.test"),
        ] {
            for (to, rule) in [(written, plain_form), (plain_form, written)] {
                let raw = plain(&format!("To: a@{to}\r\n"));
                assert_eq!(
                    codes(&raw, &format!("domain {rule}\n"), ""),
                    vec!["recipient-domain-denied"],
                    "{to} {rule}"
                );
                assert_eq!(
                    codes(&raw, "", &format!("deny-domain {rule}\n")),
                    vec!["recipient-domain-denied"],
                    "{to} {rule}"
                );
                assert_eq!(
                    codes(&raw, &format!("address a@{rule}\n"), ""),
                    vec!["recipient-address-denied"],
                    "{to} {rule}"
                );
            }
        }
        assert_eq!(
            codes(
                &plain("To: a@mail.\u{0130}nfo.test\r\n"),
                "domain info.test\n",
                ""
            ),
            vec!["recipient-domain-denied"]
        );
    }

    #[test]
    fn percent_hack_and_bang_path_locals_are_refused() {
        let deny = "address evil@example.test\ndomain blocked.test\n";
        let law = "deny-domain packblocked.test\n";
        let percent = "From: mailseat@example.test\r\nTo: a%blocked.test@localhost\r\n\r\n";
        assert_eq!(codes(percent, deny, law), vec!["recipient-unparsed"]);
        let bang = "From: mailseat@example.test\r\nTo: blocked.test!a@localhost\r\n\r\n";
        assert_eq!(codes(bang, deny, law), vec!["recipient-unparsed"]);
        assert_eq!(
            codes(&plain("Cc: a%blocked.test@localhost\r\n"), deny, law),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Reply-To: a!b@example.test\r\n"), deny, law),
            vec!["reply-to-unparsed"]
        );
        // Postfix opens the quotes and routes on the character, including
        // a backslash escape. The quoted form is the same refusal.
        assert_eq!(
            codes(&plain("To: \"a%blocked.test\"@localhost\r\n"), deny, law),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("To: \"blocked.test!a\"@localhost\r\n"), deny, law),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Bcc: \"a@blocked.test\"@localhost\r\n"), deny, law),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(
                &plain("To: \"a\\@blocked.test\"@example.test\r\n"),
                deny,
                law
            ),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(
                &plain("Reply-To: \"evil@example.test\"@localhost\r\n"),
                deny,
                law
            ),
            vec!["reply-to-unparsed"]
        );
        assert_eq!(
            codes(
                &plain("Disposition-Notification-To: \"a@blocked.test\"@localhost\r\n"),
                deny,
                law
            ),
            vec!["disposition-notification-to-unparsed"]
        );
    }

    /// Fullwidth punctuation NFKC-folds to ASCII. The local part is a
    /// refusal before that fold can be read as `@`, `%`, `!` or another
    /// mark.
    #[test]
    fn a_fullwidth_route_character_in_the_local_part_is_refused() {
        assert_eq!(
            codes(&plain("To: a\u{FF05}blocked.test@localhost\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("To: a\u{FF20}blocked.test@localhost\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("To: a\u{FF01}b@localhost\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Cc: a\u{FF0B}b@example.test\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert!(codes(&plain("To: a+b@example.test\r\n"), "", "").is_empty());
    }

    #[test]
    fn a_source_route_is_refused() {
        let deny = "address evil@example.test\ndomain blocked.test\n";
        let law = "deny-domain packblocked.test\n";
        let raw = "From: mailseat@example.test\r\nTo: <@blocked.test:a@ok.test>\r\n\r\n";
        assert_eq!(codes(raw, deny, law), vec!["recipient-unparsed"]);
        assert_eq!(
            codes(
                &plain("Cc: <@relay.example.test:person@ok.test>\r\n"),
                deny,
                law
            ),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Reply-To: <@blocked.test:a@ok.test>\r\n"), deny, law),
            vec!["reply-to-unparsed"]
        );
        assert_eq!(
            codes("From: <@example.test:mailseat@example.test>\r\n", "", ""),
            vec!["from-unparsed"]
        );
    }

    #[test]
    fn an_all_numeric_domain_is_refused() {
        let raw = "From: mailseat@example.test\r\nTo: a@192.0.2.1\r\n\r\n";
        assert_eq!(codes(raw, "", ""), vec!["recipient-unparsed"]);
        assert_eq!(
            codes(&plain("Cc: a@192.0.2\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Bcc: a@192.000.002.001\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("To: a@10.0.0.1.2\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        let full = "\u{FF11}\u{FF19}\u{FF12}.\u{FF10}.\u{FF12}.\u{FF11}";
        assert_eq!(
            codes(&plain(&format!("To: a@{full}\r\n")), "", ""),
            vec!["recipient-unparsed"]
        );
        let ideographic = "192\u{3002}0\u{3002}2\u{3002}1";
        assert_eq!(
            codes(&plain(&format!("To: a@{ideographic}\r\n")), "", ""),
            vec!["recipient-unparsed"]
        );
        let halfwidth = "192\u{FF61}0\u{FF61}2\u{FF61}1";
        assert_eq!(
            codes(&plain(&format!("To: a@{halfwidth}\r\n")), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("To: a@0x7f.1\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("To: a@0x7f.example.test\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Cc: a@0177.example.test\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert!(codes(&plain("To: a@mx1.example.test\r\n"), "", "").is_empty());
        assert!(codes(&plain("To: a@192.0.2.example.test\r\n"), "", "").is_empty());
    }

    #[test]
    fn a_domain_literal_is_refused() {
        let deny = "domain blocked.test\n";
        assert_eq!(
            codes(&plain("To: a@[blocked.test]\r\n"), deny, ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Cc: a@[mx.blocked.test]\r\n"), deny, ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Bcc: a@[blocked.test]\r\n"), deny, ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes(&plain("Reply-To: x@[blocked.test]\r\n"), deny, ""),
            vec!["reply-to-unparsed"]
        );
        assert_eq!(
            codes(&plain("Sender: a@[blocked.test]\r\n"), deny, ""),
            vec!["sender-unparsed"]
        );
        assert_eq!(
            codes(&plain("Return-Path: <a@[blocked.test]>\r\n"), deny, ""),
            vec!["return-path-unparsed"]
        );
        assert_eq!(
            codes(&plain("To: a@[192.000.002.001]\r\n"), "", ""),
            vec!["recipient-unparsed"]
        );
        assert_eq!(
            codes("From: mailseat@[example.test]\r\n", "", ""),
            vec!["from-unparsed"]
        );
    }

    #[test]
    fn a_denied_domain_covers_subdomains_only() {
        let deny = "domain blocked.test\n";
        assert_eq!(
            codes(&plain("To: a@sub.blocked.test\r\n"), deny, ""),
            vec!["recipient-domain-denied"]
        );
        assert!(codes(&plain("To: a@notblocked.test\r\n"), deny, "").is_empty());
        assert!(codes(&plain("To: a@blocked.test.example.test\r\n"), deny, "").is_empty());
    }

    /// A star, a URL, a port or any other non-hostname loads and then
    /// matches no recipient. The file is refused, and the detail is the
    /// line, not the value. `domain example.test` already covers
    /// subdomains, which is what a wildcard would have been for.
    #[test]
    fn a_domain_rule_that_matches_nothing_refuses_the_file() {
        let clean = "From: mailseat@example.test\r\nTo: john@example.test\r\n";
        let cases: &[(&str, &str, usize, &str)] = &[
            ("domain *.example.test\n", "", 1, "*.example.test"),
            ("domain *\n", "", 1, "*"),
            ("domain http://example.test\n", "", 1, "http://"),
            ("domain example.test:25\n", "", 1, ":25"),
            ("domain example.test/path\n", "", 1, "/path"),
            ("domain user@example.test\n", "", 1, "user@"),
            ("domain exam ple.test\n", "", 1, "exam ple"),
            ("domain _under.test\n", "", 1, "_under"),
            ("domain -bad.test\n", "", 1, "-bad"),
            ("domain bad-.test\n", "", 1, "bad-"),
            ("# note\n\ndomain *.example.test\n", "", 3, "*.example.test"),
            (
                "domain \u{FF0A}.example.test\n",
                "",
                1,
                "\u{FF0A}.example.test",
            ),
            ("", "deny-domain *.example.test\n", 1, "*.example.test"),
            ("", "deny-domain http://example.test\n", 1, "http://"),
            ("", "deny-domain example.test:25\n", 1, ":25"),
            ("", "deny-domain example.test/path\n", 1, "/path"),
            ("", "#\n\ndeny-domain *\n", 3, "*"),
            ("domain 192.0.2.1\n", "", 1, "192.0.2.1"),
            ("domain 0x7f.example.test\n", "", 1, "0x7f"),
            ("", "deny-domain 192.0.2.1\n", 1, "192.0.2.1"),
            ("", "# note\ndeny-domain 0177.example.test\n", 2, "0177"),
            ("address john@192.0.2.1\n", "", 1, "192.0.2.1"),
            ("address *john@example.test\n", "", 1, "*john"),
            ("address john@*.example.test\n", "", 1, "*."),
            ("address \"*john\"@example.test\n", "", 1, "*john"),
            ("address john@ex/ample.test\n", "", 1, "ex/ample"),
            ("address john@example.test:25\n", "", 1, ":25"),
            ("address john@http://example.test\n", "", 1, "http://"),
        ];
        for (deny, law, line, value) in cases {
            let v = verdict(clean, deny, law);
            let code = if law.is_empty() {
                "deny-file-invalid"
            } else {
                "pack-law-invalid"
            };
            assert_eq!(v.reasons.len(), 1, "{deny:?} {law:?}");
            assert_eq!(v.reasons[0].code, code, "{deny:?} {law:?}");
            assert_eq!(
                v.reasons[0].detail,
                format!("line {line}"),
                "{deny:?} {law:?}"
            );
            assert!(!v.reasons[0].detail.contains(value), "{deny:?} {law:?}");
            assert!(!v.json().contains(value), "{deny:?} {law:?}");
            assert!(v.is_refused());
        }
        assert_eq!(
            codes(
                &plain("To: a@b.example.test\r\n"),
                "domain example.test\n",
                ""
            ),
            vec!["recipient-domain-denied"]
        );
        assert_eq!(
            codes(
                &plain("To: a@example.test\r\n"),
                "domain example.test.\n",
                ""
            ),
            vec!["recipient-domain-denied"]
        );
        assert_eq!(
            codes(
                &plain("To: a@sub.blocked.test\r\n"),
                "",
                "deny-domain blocked.test\n"
            ),
            vec!["recipient-domain-denied"]
        );
    }

    /// A rule that loads refuses a recipient at its own domain. A rule
    /// that is refused names a domain a recipient cannot have: with no
    /// rule at all, that recipient is refused as unparsed. A rule that
    /// loads and matches nothing is a deny that is not there; a refused
    /// rule whose recipient is allowed is a recipient no rule can deny.
    #[test]
    fn a_rule_loads_only_when_a_recipient_at_its_domain_matches() {
        let a61 = "a".repeat(61);
        let a62 = "a".repeat(62);
        let a63 = "a".repeat(63);
        let a64 = "a".repeat(64);
        let long = [
            format!("{a63}.test"),
            format!("{a64}.test"),
            format!("{a63}.{a63}.{a63}.{a61}"),
            format!("{a63}.{a63}.{a63}.{a62}"),
        ];
        let domains = [
            "foo_bar.test",
            "_under.test",
            "-lead.test",
            "trail-.test",
            "a.-lead.test",
            "a-b.test",
            long[0].as_str(),
            long[1].as_str(),
            long[2].as_str(),
            long[3].as_str(),
            "xn--a.test",
            "xn--ls8h-.test",
            "xn--bcher-kva-.test",
            "p\u{0430}ypal.test",
            "xn--pypal-4ve.test",
            "\u{0440}\u{0430}\u{0443}\u{0440}\u{0430}l.test",
            "a!b.test",
            "a#b.test",
            "a$b.test",
            "a%b.test",
            "a&b.test",
            "a'b.test",
            "a*b.test",
            "a+b.test",
            "a/b.test",
            "a=b.test",
            "a?b.test",
            "a^b.test",
            "a`b.test",
            "a{b.test",
            "a|b.test",
            "a}b.test",
            "a~b.test",
            "192.0.2.1",
            "192.0.2",
            "127.1",
            "10.0.0.1.2",
            "\u{FF11}\u{FF19}\u{FF12}.\u{FF10}.\u{FF12}.\u{FF11}",
            "192\u{3002}0\u{3002}2\u{3002}1",
            "0x7f.example.test",
            "0177.example.test",
            "example.123",
            "192.0.2.example.test",
            "mx1.example.test",
            "b\u{FC}cher.example",
            "xn--bcher-kva.example",
            "\u{FF42}locked.test",
            "blocked.test.",
            "[blocked.test]",
            "[192.0.2.1]",
        ];
        let mut loaded = 0;
        for domain in domains {
            let to = plain(&format!("To: user@{domain}\r\n"));
            let rules = [
                (
                    format!("domain {domain}\n"),
                    String::new(),
                    "deny-file-invalid",
                    "recipient-domain-denied",
                ),
                (
                    String::new(),
                    format!("deny-domain {domain}\n"),
                    "pack-law-invalid",
                    "recipient-domain-denied",
                ),
                (
                    format!("address user@{domain}\n"),
                    String::new(),
                    "deny-file-invalid",
                    "recipient-address-denied",
                ),
            ];
            for (deny, law, invalid, denied) in rules {
                let load = codes(&plain(""), &deny, &law);
                let matched = codes(&to, &deny, &law).iter().any(|c| c == denied);
                if load.is_empty() {
                    loaded += 1;
                    assert!(matched, "{deny:?} {law:?} loads and matches nothing");
                } else {
                    assert_eq!(load, vec![invalid], "{deny:?} {law:?}");
                    assert_eq!(
                        codes(&to, "", ""),
                        vec!["recipient-unparsed"],
                        "{deny:?} {law:?} refused but a recipient at it is allowed"
                    );
                    assert!(
                        !mail::mailboxes(&format!("user@{domain}"))
                            .is_ok_and(|list| normalize_mailbox(&list[0]).is_some()),
                        "{deny:?} {law:?} refused but a recipient parses"
                    );
                }
            }
        }
        assert!(loaded > 0 && loaded < domains.len() * 3);
    }

    /// The detail is the line, for a bad key as well as a bad value, and
    /// it does not repeat the value.
    #[test]
    fn every_invalid_deny_line_names_its_line() {
        let clean = "From: mailseat@example.test\r\n";
        let deny_cases: &[(&str, usize, &str)] = &[
            ("address\n", 1, "address"),
            ("nope evil@example.test\n", 1, "nope"),
            ("handle\n", 1, "handle"),
            ("term\n", 1, "term"),
            ("pair onlyone\n", 1, "onlyone"),
            ("# c\naddress\n", 2, "address"),
            ("address two@example.test two@example.test\n", 1, "two@"),
            ("domain\n", 1, "domain"),
        ];
        for (deny, line, value) in deny_cases {
            let v = verdict(clean, deny, "");
            assert_eq!(v.reasons.len(), 1, "{deny:?}");
            assert_eq!(v.reasons[0].code, "deny-file-invalid", "{deny:?}");
            assert_eq!(v.reasons[0].detail, format!("line {line}"), "{deny:?}");
            assert!(!v.json().contains(value), "{deny:?} {}", v.json());
        }
        let law_cases: &[(&str, usize, &str)] = &[
            ("allow-domain blocked.test\n", 1, "allow-domain"),
            ("deny-domain\n", 1, "deny-domain"),
            ("#\n\nnot-a-rule x\n", 3, "not-a-rule"),
        ];
        for (law, line, value) in law_cases {
            let v = verdict(clean, "", law);
            assert_eq!(v.reasons.len(), 1, "{law:?}");
            assert_eq!(v.reasons[0].code, "pack-law-invalid", "{law:?}");
            assert_eq!(v.reasons[0].detail, format!("line {line}"), "{law:?}");
            assert!(!v.json().contains(value), "{law:?} {}", v.json());
        }
    }

    /// A domain rule on one domain of a shared family is the whole
    /// family. Microsoft domains are not shared, so they stay apart.
    #[test]
    fn a_domain_rule_covers_its_shared_family() {
        let refused = |to: &str, deny: &str, law: &str| {
            codes(&plain(&format!("To: {to}\r\n")), deny, law) == vec!["recipient-domain-denied"]
        };
        for (rule, to) in [
            ("gmail.com", "a@googlemail.com"),
            ("googlemail.com", "a@gmail.com"),
            ("pm.me", "a@proton.me"),
            ("pm.me", "a@protonmail.com"),
            ("protonmail.ch", "a@pm.me"),
            ("icloud.com", "a@me.com"),
            ("icloud.com", "a@mac.com"),
            ("mac.com", "a@icloud.com"),
            ("gmail.com", "a@sub.googlemail.com"),
            ("gmail.com", "a@GoogleMail\u{FF0E}COM"),
        ] {
            assert!(refused(to, &format!("domain {rule}\n"), ""), "{rule} {to}");
            assert!(
                refused(to, "", &format!("deny-domain {rule}\n")),
                "{rule} {to}"
            );
        }
        assert_eq!(
            codes_argv(&plain(""), "domain pm.me\n", "", &["a@proton.me"]),
            vec!["argv-recipient-denied"]
        );
        assert!(!refused("a@hotmail.com", "domain outlook.com\n", ""));
        assert!(!refused("a@gmail.com", "domain pm.me\n", ""));
        assert!(!refused(
            "a@googlemail.com.example.test",
            "domain gmail.com\n",
            ""
        ));
        let extra = "alias mail.test,post.test + shared\n";
        assert_eq!(
            codes_with(
                &plain("To: a@post.test\r\n"),
                "domain mail.test\n",
                "",
                extra
            ),
            vec!["recipient-domain-denied"]
        );
    }

    #[test]
    fn reply_to_sender_and_return_path_stay_clear_of_deny_identities() {
        let deny = "\
address other@example.test
domain blocked.test
handle someone
term a term
pair left right
";
        assert_eq!(
            codes(&plain("Reply-To: other@example.test\r\n"), deny, ""),
            vec!["reply-to-denied"]
        );
        assert_eq!(
            codes(&plain("Sender: person@blocked.test\r\n"), deny, ""),
            vec!["sender-not-identity", "sender-denied"]
        );
        assert_eq!(
            codes(&plain("Return-Path: <other@example.test>\r\n"), deny, ""),
            vec!["return-path-not-identity", "return-path-denied"]
        );
        assert!(codes(&plain("Reply-To: mailseat@example.test\r\n"), deny, "").is_empty());
        assert_eq!(
            codes(&plain("Return-Path: <>\r\n"), deny, ""),
            vec!["return-path-not-identity"]
        );
    }

    /// Sender, Errors-To and Return-Path name the operator. When the
    /// header is present it has to be the identity, ASCII case only.
    #[test]
    fn sender_errors_to_and_return_path_must_be_the_identity() {
        assert_eq!(
            codes(&plain("Sender: someone@else.test\r\n"), "", ""),
            vec!["sender-not-identity"]
        );
        assert_eq!(
            codes(&plain("Errors-To: someone@else.test\r\n"), "", ""),
            vec!["errors-to-not-identity"]
        );
        assert_eq!(
            codes(&plain("Return-Path: <someone@else.test>\r\n"), "", ""),
            vec!["return-path-not-identity"]
        );
        assert_eq!(
            codes(&plain("Return-Path: <>\r\n"), "", ""),
            vec!["return-path-not-identity"]
        );
        assert!(codes(&plain("Sender: MailSeat@Example.Test\r\n"), "", "").is_empty());
        assert!(codes(&plain("Errors-To: mailseat@example.test\r\n"), "", "").is_empty());
        assert!(codes(&plain("Return-Path: <mailseat@example.test>\r\n"), "", "").is_empty());
        let wide = "\u{FF4D}ailseat@example.test";
        assert_eq!(
            codes(&plain(&format!("Sender: {wide}\r\n")), "", ""),
            vec!["sender-not-identity"]
        );
        assert_eq!(
            codes(&plain("Sender: G: mailseat@example.test;\r\n"), "", ""),
            vec!["sender-not-identity"]
        );
        assert!(codes(&plain("Reply-To: someone@else.test\r\n"), "", "").is_empty());
        assert!(codes(&plain(""), "", "").is_empty());
    }

    /// An address entry is that mailbox. It does not deny every recipient
    /// at the same domain.
    #[test]
    fn a_resent_header_is_refused() {
        assert_eq!(
            codes(&plain("Resent-From: mailseat@example.test\r\n"), "", ""),
            vec!["resent-header"]
        );
        assert_eq!(
            details(&plain("Resent-To: person@example.test\r\n"), "", ""),
            vec!["resent-to"]
        );
        let both = plain("Resent-From: mailseat@example.test\r\nResent-Cc: a@example.test\r\n");
        assert_eq!(codes(&both, "", ""), vec!["resent-header", "resent-header"]);
    }

    /// Sendmail `-t` treats Apparently-To as a recipient, and a MUA
    /// follows Mail-Followup-To and Mail-Reply-To. Apparently-To is a
    /// refusal on its own. The other three are deny-file identities,
    /// the same way Reply-To is.
    #[test]
    fn headers_outside_to_cc_bcc_cannot_name_a_denied_mailbox() {
        let deny = "address evil@example.test\ndomain blocked.test\n";
        let law = "deny-domain packblocked.test\n";
        let apparent = "From: mailseat@example.test\r\nApparently-To: a@blocked.test\r\n\r\n";
        assert_eq!(codes(apparent, deny, law), vec!["apparently-to"]);
        let apparent_self =
            "From: mailseat@example.test\r\nApparently-To: mailseat@example.test\r\n\r\n";
        assert_eq!(codes(apparent_self, deny, law), vec!["apparently-to"]);
        let receipt =
            "From: mailseat@example.test\r\nDelivery-Receipt-To: evil@example.test\r\n\r\n";
        assert_eq!(
            codes(receipt, deny, law),
            vec!["delivery-receipt-to-denied"]
        );
        let followup = "From: mailseat@example.test\r\nMail-Followup-To: evil@example.test\r\n\r\n";
        assert_eq!(codes(followup, deny, law), vec!["mail-followup-to-denied"]);
        let reply = "From: mailseat@example.test\r\nMail-Reply-To: evil@example.test\r\n\r\n";
        assert_eq!(codes(reply, deny, law), vec!["mail-reply-to-denied"]);
        let domain = "From: mailseat@example.test\r\nDelivery-Receipt-To: a@blocked.test\r\n\r\n";
        assert_eq!(codes(domain, deny, law), vec!["delivery-receipt-to-denied"]);
        assert!(codes(
            "From: mailseat@example.test\r\nMail-Reply-To: mailseat@example.test\r\n\r\n",
            deny,
            law
        )
        .is_empty());
        assert_eq!(
            codes(
                "From: mailseat@example.test\r\nMail-Followup-To: not-an-address\r\n\r\n",
                "",
                ""
            ),
            vec!["mail-followup-to-unparsed"]
        );
    }

    #[test]
    fn notification_headers_stay_clear_of_deny_identities() {
        let deny = "address evil@example.test\ndomain blocked.test\n";
        assert_eq!(
            codes(&plain("Errors-To: evil@example.test\r\n"), deny, ""),
            vec!["errors-to-not-identity", "errors-to-denied"]
        );
        assert_eq!(
            codes(
                &plain("Disposition-Notification-To: a@blocked.test\r\n"),
                deny,
                ""
            ),
            vec!["disposition-notification-to-denied"]
        );
        assert_eq!(
            codes(&plain("Return-Receipt-To: evil@example.test\r\n"), deny, ""),
            vec!["return-receipt-to-denied"]
        );
        assert!(codes(&plain("Errors-To: mailseat@example.test\r\n"), deny, "").is_empty());
        assert!(codes(
            &plain("Disposition-Notification-To: mailseat@example.test\r\n"),
            deny,
            ""
        )
        .is_empty());
        assert!(codes(&plain("Return-Receipt-To: <>\r\n"), deny, "").is_empty());
        assert_eq!(
            codes(&plain("Errors-To: not-an-address\r\n"), "", ""),
            vec!["errors-to-unparsed"]
        );
        assert_eq!(
            codes(&plain("Return-Receipt-To: a@[blocked.test]\r\n"), "", ""),
            vec!["return-receipt-to-unparsed"]
        );
    }

    /// The address is that mailbox in To, Cc and Bcc. A different
    /// mailbox at the same domain is not this rule.
    #[test]
    fn an_address_rule_blocks_that_recipient() {
        let deny = "address evil@example.test\n";
        let raw = "From: mailseat@example.test\r\nTo: evil@example.test\r\n\r\n";
        assert_eq!(codes(raw, deny, ""), vec!["recipient-address-denied"]);
        assert_eq!(details(raw, deny, ""), vec!["to evil@example.test"]);
        assert_eq!(
            codes(&plain("Cc: evil@example.test\r\n"), deny, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(&plain("Bcc: Evil@Example.test\r\n"), deny, ""),
            vec!["recipient-address-denied"]
        );
        assert!(codes(&plain("To: person@example.test\r\n"), deny, "").is_empty());
        let deny = "address other@blocked.test\n";
        assert!(codes(&plain("To: person@blocked.test\r\n"), deny, "").is_empty());
        assert_eq!(
            codes(&plain("To: other@blocked.test\r\n"), deny, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(&plain("Reply-To: Other@Blocked.test\r\n"), deny, ""),
            vec!["reply-to-denied"]
        );
    }

    /// `local+tag` is delivered to `local` at most providers. The
    /// address rule covers that subaddress.
    #[test]
    fn an_address_rule_covers_a_subaddress() {
        let deny = "address evil@example.test\n";
        let raw = "From: mailseat@example.test\r\nReply-To: evil+x@example.test\r\n\r\n";
        assert_eq!(codes(raw, deny, ""), vec!["reply-to-denied"]);
        assert_eq!(
            codes(&plain("To: evil+x@example.test\r\n"), deny, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(&plain("Bcc: Evil+Tag@Example.test\r\n"), deny, ""),
            vec!["recipient-address-denied"]
        );
        assert!(codes(&plain("To: notevil+x@example.test\r\n"), deny, "").is_empty());
    }

    /// The skeleton drops `. _ - + =` and compares a prefix, so it
    /// over-blocks a longer name that starts with the rule.
    #[test]
    fn the_skeleton_covers_every_transparent_spelling() {
        let denied = |to: &str, deny: &str, extra: &str| {
            codes_with(&plain(&format!("To: {to}\r\n")), deny, "", extra)
                == vec!["recipient-address-denied"]
        };
        let proton = "address johndoe@proton.me\n";
        for to in [
            "john.doe@pm.me",
            "john_doe@protonmail.com",
            "john-doe@proton.me",
            "john.doe+tag@protonmail.ch",
            "john_doe@pm.me",
            "john-doe@protonmail.ch",
            "John.Doe+Tag@PM.ME",
        ] {
            assert!(denied(to, proton, ""), "{to}");
            assert!(denied(to, proton, "subaddress =\n"), "{to}");
        }
        assert!(denied("jo-hn@proton.me", "address john@proton.me\n", ""));
        assert!(!denied("jane.doe@pm.me", proton, ""));
        assert!(!denied("johndoe@gmail.com", proton, ""));
        let custom = "address hannah.martin@example.test\n";
        assert!(denied("hannah_martin@example.test", custom, ""));
        assert!(denied(
            "evilx@example.test",
            "address evil@example.test\n",
            ""
        ));
        assert!(denied(
            "stra\u{DF}e@example.test",
            "address strasse@example.test\n",
            ""
        ));
    }

    /// `starts_with("")` matches every local part, so an empty skeleton
    /// refuses the file. A one or two character skeleton is a real
    /// mailbox: it matches exactly, as a subaddress and as an equal
    /// skeleton, and it does not prefix a longer name.
    #[test]
    fn a_short_skeleton_matches_exactly_and_an_empty_one_refuses() {
        let clean = "From: mailseat@example.test\r\nTo: person@ok.test\r\n";
        let empty: &[(&str, usize, &str)] = &[
            ("address +@example.test\n", 1, "+@example.test"),
            ("address ++@example.test\n", 1, "++@example.test"),
            ("address +-=@example.test\n", 1, "+-=@example.test"),
            ("address \".+_\"@example.test\n", 1, "\".+_\"@example.test"),
            (
                "address abc@example.test\naddress +@example.test\n",
                2,
                "+@example.test",
            ),
            ("address +@example.test\r\n", 1, "+@example.test"),
        ];
        for (deny, line, addr) in empty {
            let v = verdict(clean, deny, "");
            assert_eq!(v.reasons.len(), 1, "{deny:?}");
            assert_eq!(v.reasons[0].code, "deny-file-invalid", "{deny:?}");
            assert_eq!(v.reasons[0].detail, format!("line {line}"), "{deny:?}");
            assert!(!v.reasons[0].detail.contains(addr), "{deny:?}");
            assert!(!v.reasons[0].detail.contains('@'), "{deny:?}");
            assert!(!v.json().contains(addr), "{deny:?}");
            assert!(v.is_refused());
        }
        let denied = |to: &str, deny: &str| {
            codes(&plain(&format!("To: {to}\r\n")), deny, "") == vec!["recipient-address-denied"]
        };
        let allowed =
            |to: &str, deny: &str| codes(&plain(&format!("To: {to}\r\n")), deny, "").is_empty();
        let a = "address a@example.test\n";
        assert!(denied("a@example.test", a));
        assert!(denied("A@Example.test", a));
        assert!(denied("a+tag@example.test", a));
        assert!(denied("a-tag@example.test", a));
        assert!(allowed("ax@example.test", a));
        assert!(allowed("abc@example.test", a));
        assert!(allowed("b@example.test", a));
        let ab = "address ab@example.test\n";
        assert!(denied("ab@example.test", ab));
        assert!(denied("a.b@example.test", ab));
        assert!(denied("ab+tag@example.test", ab));
        assert!(allowed("abc@example.test", ab));
        assert!(allowed("abx@example.test", ab));
        assert!(allowed("xab@example.test", ab));
        assert!(denied("ab@example.test", "address a.b@example.test\n"));
        assert!(denied("a+b@example.test", "address ab@example.test\n"));
        assert!(allowed("abc@example.test", "address a+b@example.test\n"));
        assert!(denied(
            "ab@example.test",
            "address a\u{200B}b@example.test\n"
        ));
        assert!(codes("From: mailseat@example.test\r\n", a, "").is_empty());
        assert_eq!(
            codes(
                &plain("To: person@blocked.test\r\n"),
                "domain blocked.test\naddress a@example.test\n",
                ""
            ),
            vec!["recipient-domain-denied"]
        );
        assert!(codes_argv(
            "From: mailseat@example.test\r\nTo: person@ok.test\r\n",
            ab,
            "",
            &["person@ok.test"]
        )
        .is_empty());
        assert_eq!(
            codes_argv(
                "From: mailseat@example.test\r\n",
                a,
                "",
                &["a+x@example.test"]
            ),
            vec!["argv-recipient-denied"]
        );
        assert_eq!(
            codes(
                &plain("To: abcd@example.test\r\n"),
                "address abc@example.test\n",
                ""
            ),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(
                &plain("To: a.b.c@example.test\r\n"),
                "address a+b=c@example.test\n",
                ""
            ),
            vec!["recipient-address-denied"]
        );
        assert!(allowed("person@ok.test", "address a.b.c@example.test\n"));
        assert!(denied(
            "abcx@example.test",
            "address a\u{200B}bc@example.test\n"
        ));
        assert!(denied(
            "abc@example.test",
            "address abc@example.test\naddress a@example.test\n"
        ));
        assert!(allowed(
            "ax@example.test",
            "address abc@example.test\naddress a@example.test\n"
        ));
        let gmail = "address a@gmail.com\n";
        assert!(denied("a@googlemail.com", gmail));
        assert!(denied("a+x@gmail.com", gmail));
        assert!(allowed("ab@gmail.com", gmail));
        assert!(allowed("ax@googlemail.com", gmail));
    }

    /// The prefix check has to meet on both spellings. A rule written
    /// with one form of a casefold pair denies a recipient written with
    /// the other, including a longer local part, and the reverse rule
    /// does too. A form that only matches from one side would let the
    /// other spelling through.
    #[test]
    fn skeleton_prefix_matches_casefold_edges_both_ways() {
        let hit = |to: &str, rule: &str| {
            codes(
                &plain(&format!("To: {to}\r\n")),
                &format!("address {rule}\n"),
                "",
            ) == vec!["recipient-address-denied"]
        };
        let groups: &[&[&str]] = &[
            &[
                "mai",
                "ma\u{0131}",
                "ma\u{0130}",
                "maI",
                "MA\u{0130}",
                "mai\u{0307}",
            ],
            &["ab\u{03C3}", "ab\u{03C2}", "ab\u{03A3}", "AB\u{03C2}"],
            &["\u{03C3}ab", "\u{03C2}ab", "\u{03A3}AB"],
            &["a\u{03C3}b", "a\u{03C2}b", "a\u{03A3}b"],
            &[
                "strasse",
                "stra\u{00DF}e",
                "stra\u{1E9E}e",
                "STRASSE",
                "STRA\u{1E9E}E",
            ],
            &[
                "abc",
                "\u{FF41}\u{FF42}\u{FF43}",
                "\u{FF21}\u{FF22}\u{FF23}",
                "\u{FF41}Bc",
            ],
            &["office", "o\u{FB03}ce"],
            &["filex", "\u{FB01}lex"],
            &["star", "\u{FB06}ar"],
            &["mark", "mar\u{212A}"],
            &["ivan", "\u{2163}an"],
            &["abc", "\u{24B6}bc"],
            &["kgx", "\u{338F}x"],
            &["\u{00B5}sec", "\u{03BC}sec"],
        ];
        for group in groups {
            for rule_local in *group {
                for recip in *group {
                    let rule = format!("{rule_local}@example.test");
                    assert!(
                        hit(&format!("{recip}@example.test"), &rule),
                        "rule {rule_local} recipient {recip}"
                    );
                    assert!(
                        hit(&format!("{recip}x@example.test"), &rule),
                        "rule {rule_local} recipient {recip}x"
                    );
                    assert!(
                        codes(
                            &plain(&format!("To: {recip}@other.test\r\n")),
                            &format!("address {rule}\n"),
                            ""
                        )
                        .is_empty(),
                        "rule {rule_local} other domain {recip}"
                    );
                }
            }
            let first = group[0];
            assert!(
                codes(
                    &plain(&format!("To: x{first}@example.test\r\n")),
                    &format!("address {first}@example.test\n"),
                    ""
                )
                .is_empty(),
                "prefix is at the start: {first}"
            );
        }
        assert!(hit("mai@pm.me", "ma\u{0130}@proton.me"));
        assert!(hit("ma\u{0130}@proton.me", "mai@pm.me"));
        assert!(hit("strassex@pm.me", "stra\u{00DF}e@proton.me"));
        assert!(hit("stra\u{1E9E}e@protonmail.com", "strasse@pm.me"));
        assert!(hit("ab\u{03C2}x@pm.me", "ab\u{03C3}@proton.me"));
        assert!(codes(
            &plain("To: mai@gmail.com\r\n"),
            "address ma\u{0130}@proton.me\n",
            ""
        )
        .is_empty());
        // These skeletons are shorter than three, so the file loads and
        // the equal fold matches. A longer local part does not.
        for (short, folded) in [
            ("\u{0130}", "i"),
            ("\u{1E9E}", "ss"),
            ("\u{00DF}", "ss"),
            ("\u{03C2}", "\u{03C3}"),
        ] {
            assert!(
                hit(
                    &format!("{short}@example.test"),
                    &format!("{short}@example.test")
                ),
                "{short}"
            );
            assert!(
                hit(
                    &format!("{folded}@example.test"),
                    &format!("{short}@example.test")
                ),
                "{short}"
            );
            assert!(
                codes(
                    &plain(&format!("To: {short}x@example.test\r\n")),
                    &format!("address {short}@example.test\n"),
                    ""
                )
                .is_empty(),
                "{short}x"
            );
        }
    }

    /// A mark that composes with the letter before it used to leave the
    /// skeleton as a different letter. NFD takes the mark off again, on
    /// the rule and the recipient.
    #[test]
    fn a_combining_mark_does_not_escape_the_skeleton() {
        let denied = |to: &str, deny: &str| {
            codes(&plain(&format!("To: {to}\r\n")), deny, "") == vec!["recipient-address-denied"]
        };
        let abc = "address abc@example.test\n";
        assert!(denied("abc\u{0301}x@example.test", abc));
        assert!(denied("ab\u{0107}x@example.test", abc));
        assert!(denied("ab\u{0307}c@example.test", abc));
        assert!(denied(
            "abc@example.test",
            "address ab\u{0107}@example.test\n"
        ));
        let grave = "i\u{0307}\u{0300}";
        assert!(denied(
            &format!("{grave}@example.test"),
            "address \u{00EC}@example.test\n"
        ));
        assert!(denied(
            "\u{00EC}@example.test",
            &format!("address {grave}@example.test\n")
        ));
        assert!(denied(
            &format!("{grave}x@example.test"),
            "address \u{00EC}x@example.test\n"
        ));
        assert!(!denied("abd@example.test", abc));
    }

    /// The default separators are `+-=`. Gmail and Googlemail are one
    /// domain with dots ignored, and `x@user.fastmail.com` is the user
    /// at fastmail.com. A `subaddress` line replaces the default.
    #[test]
    fn address_rules_cover_subaddresses_and_provider_aliases() {
        let deny = "address evil@example.test\n";
        assert_eq!(
            codes(&plain("To: evil-x@example.test\r\n"), deny, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(&plain("To: evil=x@example.test\r\n"), deny, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(&plain("To: \"evil-x\"@example.test\r\n"), deny, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes_with(
                &plain("To: evil+x@example.test\r\n"),
                deny,
                "",
                "subaddress +\n"
            ),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes_with(&plain(""), "", "", "subaddress .\n"),
            vec!["config-invalid"]
        );
        let gmail = "address bad@gmail.com\n";
        assert_eq!(
            codes(&plain("To: b.a.d@gmail.com\r\n"), gmail, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(&plain("To: bad@googlemail.com\r\n"), gmail, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(&plain("To: b.a.d+x@googlemail.com\r\n"), gmail, ""),
            vec!["recipient-address-denied"]
        );
        assert!(codes(&plain("To: bax@gmail.com\r\n"), gmail, "").is_empty());
        assert_eq!(
            codes_with(
                &plain("To: bad+x@gmail.com\r\n"),
                gmail,
                "",
                "subaddress -\n"
            ),
            vec!["recipient-address-denied"]
        );
        let fast = "address user@fastmail.com\n";
        assert_eq!(
            codes(&plain("To: x@user.fastmail.com\r\n"), fast, ""),
            vec!["recipient-address-denied"]
        );
        assert_eq!(
            codes(&plain("To: X@User.Fastmail.Com\r\n"), fast, ""),
            vec!["recipient-address-denied"]
        );
        assert!(codes(&plain("To: x@a.user.fastmail.com\r\n"), fast, "").is_empty());
        assert!(codes(&plain("To: other@fastmail.com\r\n"), fast, "").is_empty());
    }

    /// Proton and Apple domains are one mailbox each. Microsoft domains
    /// are not, and the skeleton still covers the whole family. A Yahoo
    /// rule covers every disposable address on its base.
    #[test]
    fn provider_alias_families_cover_their_aliases() {
        let denied = |to: &str, deny: &str| {
            codes_with(&plain(&format!("To: {to}\r\n")), deny, "", "subaddress =\n")
                == vec!["recipient-address-denied"]
        };
        let proton = "address bad@proton.me\n";
        for to in ["bad@pm.me", "bad+x@protonmail.ch", "bad+x@protonmail.com"] {
            assert!(denied(to, proton), "{to}");
        }
        assert!(!denied("bad@gmail.com", proton));
        let apple = "address bad@me.com\n";
        for to in ["bad@icloud.com", "bad+x@mac.com"] {
            assert!(denied(to, apple), "{to}");
        }
        let outlook = "address bad@outlook.com\n";
        assert!(denied("bad+x@outlook.com", outlook));
        assert!(denied("bad-x@outlook.com", outlook));
        assert!(denied("bad@hotmail.com", outlook));
        assert!(denied("bad@live.com", outlook));
        assert!(denied("bad@msn.com", outlook));
        assert!(denied("bad@outlook.de", outlook));
        assert!(!denied("bad@gmail.com", outlook));
        assert!(!denied("other@hotmail.com", outlook));
        // A short rule does not use the prefix, so it does not cross.
        let short = "address ed@outlook.com\n";
        assert!(denied("ed@outlook.com", short));
        assert!(denied("ed+x@outlook.com", short));
        assert!(!denied("ed@hotmail.com", short));
        assert!(!denied("ed@outlook.de", short));
        assert!(denied("bad+x@hotmail.co.uk", "address bad@hotmail.co.uk\n"));
        let yahoo = "address base-shop@yahoo.com\n";
        for to in [
            "base-shop@yahoo.com",
            "base-other@yahoo.com",
            "base@yahoo.com",
        ] {
            assert!(denied(to, yahoo), "{to}");
        }
        assert!(!denied("based-x@yahoo.com", yahoo));
        assert!(!denied("base-x@ymail.com", yahoo));
        assert!(denied("bad-x@yahoo.co.uk", "address bad@yahoo.co.uk\n"));
        let fast = "address user@fastmail.com\n";
        assert!(denied("user+x@fastmail.com", fast));
        assert!(denied("x@user.fastmail.com", fast));
    }

    /// Fastmail delivers `shop@user.fastmail.com` to `user+shop`, so the
    /// two spellings are one rule and other tags stay outside it.
    #[test]
    fn a_fastmail_subdomain_is_the_plus_form() {
        let denied = |to: &str, deny: &str, extra: &str| {
            codes_with(&plain(&format!("To: {to}\r\n")), deny, "", extra)
                == vec!["recipient-address-denied"]
        };
        let plus = "address user+shop@fastmail.com\n";
        for to in [
            "shop@user.fastmail.com",
            "\"shop\"@user.fastmail.com",
            "Shop@User.FastMail.com",
            "user+shop@fastmail.com",
        ] {
            assert!(denied(to, plus, ""), "{to}");
        }
        let sub = "address shop@user.fastmail.com\n";
        for to in ["user+shop@fastmail.com", "shop@user.fastmail.com"] {
            assert!(denied(to, sub, ""), "{to}");
        }
        for to in [
            "user@fastmail.com",
            "user+other@fastmail.com",
            "other@user.fastmail.com",
        ] {
            assert!(!denied(to, sub, ""), "{to}");
            assert!(!denied(to, plus, ""), "{to}");
        }
        let fm = "alias fastmail.com,fastmail.fm + shared\n";
        assert!(denied("shop@user.fastmail.fm", plus, fm));
        assert!(denied("user+shop@fastmail.fm", sub, fm));
        let unicode = "address b\u{FC}cher@fastmail.com\n";
        for to in [
            "x@b\u{FC}cher.fastmail.com",
            "x@xn--bcher-kva.fastmail.com",
            "x@B\u{DC}CHER.fastmail.com",
        ] {
            assert!(denied(to, unicode, ""), "{to}");
        }
        // A one-character tag is exact, including the plus form Fastmail
        // delivers. It does not prefix a longer tag.
        let label = "address x@b\u{FC}cher.fastmail.com\n";
        for to in [
            "b\u{FC}cher+x@fastmail.com",
            "x@xn--bcher-kva.fastmail.com",
            "x@b\u{FC}cher.fastmail.com",
        ] {
            assert!(denied(to, label, ""), "{to}");
        }
        assert!(!denied("xy@b\u{FC}cher.fastmail.com", label, ""));
        assert!(!denied("b\u{FC}cher+xy@fastmail.com", label, ""));
        assert!(!denied("b\u{FC}cher+xshop@fastmail.com", label, ""));
        // ü is u plus a combining diaeresis, so the skeletons are equal.
        assert!(denied("bucher+x@fastmail.com", label, ""));
        let dotted = "alias example.test + dots subdomain\n";
        for deny in [
            "address jdoe@example.test\n",
            "address tag@jdoe.example.test\n",
        ] {
            assert!(denied("tag@j.doe.example.test", deny, dotted), "{deny}");
            assert!(!denied("tag@j.doe.example.test", deny, ""), "{deny}");
        }
    }

    /// `yahoo.*` and the Microsoft patterns name every country suffix,
    /// so a domain the table never listed still gets the family, even
    /// when `subaddress` leaves the family separator out.
    #[test]
    fn a_family_pattern_covers_every_country_suffix() {
        let denied = |to: &str, deny: &str, extra: &str| {
            codes_with(&plain(&format!("To: {to}\r\n")), deny, "", extra)
                == vec!["recipient-address-denied"]
        };
        for suffix in ["com.br", "co.in", "com.sg", "com.hk", "com.mx", "co.nz"] {
            let deny = format!("address base-shop@yahoo.{suffix}\n");
            for local in ["base", "base-other", "base-shop"] {
                let to = format!("{local}@yahoo.{suffix}");
                assert!(denied(&to, &deny, "subaddress +\n"), "{to}");
            }
            assert!(!denied(&format!("based-x@yahoo.{suffix}"), &deny, ""));
        }
        for domain in [
            "outlook.co.uk",
            "outlook.com.au",
            "hotmail.com.br",
            "live.co.za",
        ] {
            let deny = format!("address bad@{domain}\n");
            let to = format!("bad+x@{domain}");
            assert!(denied(&to, &deny, "subaddress -\n"), "{to}");
        }
        let extra = "alias mailhost.* ~ cut\n";
        let deny = "address base~shop@mailhost.test\n";
        assert!(denied("base~other@mailhost.test", deny, extra));
        assert!(!denied("base~other@mailhost.test", deny, ""));
        assert!(denied(
            "bad@mailhost.example",
            "address bad@mailhost.test\n",
            extra
        ));
        for bad in [
            "alias *.test +\n",
            "alias a.b.* +\n",
            "alias * +\n",
            "alias .* +\n",
        ] {
            assert_eq!(
                codes_with(&plain(""), "", "", bad),
                vec!["config-invalid"],
                "{bad}"
            );
        }
    }

    /// An `alias` line in the config adds a family. A line the parser
    /// cannot read refuses the config instead of being skipped.
    #[test]
    fn a_config_alias_line_adds_a_family() {
        let deny = "address bad@mail.test\n";
        let to = |addr: &str| plain(&format!("To: {addr}\r\n"));
        let extra = "alias mail.test,post.test ~ shared dots\n";
        for addr in ["b.a.d@post.test", "bad~x@mail.test", "bad+x@post.test"] {
            assert_eq!(
                codes_with(&to(addr), deny, "", extra),
                vec!["recipient-address-denied"],
                "{addr}"
            );
        }
        assert!(codes(&to("bad@post.test"), deny, "").is_empty());
        let gmail = "address bad@gmail.com\n";
        assert_eq!(
            codes_with(&to("b.ad@googlemail.com"), gmail, "", "alias gmail.com -\n"),
            vec!["recipient-address-denied"]
        );
        for bad in [
            "alias mail.test\n",
            "alias mail.test . shared\n",
            "alias mail.test + always\n",
            "alias mail.test,[1.2.3.4] +\n",
            "alias mail.test + shared shared\n",
            "alias mail.test + dots subdomain dots\n",
            "alias mail.test,mail.test +\n",
            "alias mail.test,MAIL\u{FF0E}test +\n",
            "alias yahoo.*,Yahoo.* -\n",
        ] {
            assert_eq!(
                codes_with(&plain(""), "", "", bad),
                vec!["config-invalid"],
                "{bad}"
            );
        }
    }

    /// U+FF0E is a full stop after NFKC, and an alias domain is matched
    /// after case folding, on the rule and on the recipient.
    #[test]
    fn a_fullwidth_stop_or_mixed_case_does_not_hide_an_alias() {
        let denied = |to: &str, deny: &str| {
            codes(&plain(&format!("To: {to}\r\n")), deny, "") == vec!["recipient-address-denied"]
        };
        let gmail = "address bad@gmail.com\n";
        for to in [
            "b.ad@googlemail\u{FF0E}com",
            "bad+x@gmail\u{FF0E}com",
            "b.AD@GoogleMail.COM",
            "Bad+X@GMAIL.com",
        ] {
            assert!(denied(to, gmail), "{to}");
        }
        assert!(denied(
            "bad@gmail.com",
            "address b.ad@GoogleMail\u{FF0E}COM\n"
        ));
        let proton = "address bad@proton.me\n";
        for to in ["bad@PM.ME", "Bad+x@pm\u{FF0E}me", "bad@ProtonMail.CH"] {
            assert!(denied(to, proton), "{to}");
        }
        assert!(denied("bad@proton.me", "address bad@PM\u{FF0E}ME\n"));
        let fast = "address user@fastmail.com\n";
        assert!(denied("x@User\u{FF0E}FastMail.COM", fast));
        assert!(!denied("bad@pm\u{FF0E}me\u{FF0E}test", proton));
    }

    /// Case, a fullwidth stop, dots and a tag in one address, and the
    /// same address quoted, still meet the gmail rule. A fullwidth stop
    /// in the local part is refused before any rule is read.
    #[test]
    fn folds_combine_in_one_address() {
        let gmail = "address bad@gmail.com\n";
        let to = |addr: &str| plain(&format!("To: {addr}\r\n"));
        for addr in [
            "bad+t.ag@gmail.com",
            "\"b.ad+x\"@googlemail.com",
            "B.a.D+T.aG@GoogleMail\u{FF0E}COM",
            "\"B.a.D+T.aG\"@GMail\u{FF0E}com",
        ] {
            assert_eq!(
                codes(&to(addr), gmail, ""),
                vec!["recipient-address-denied"],
                "{addr}"
            );
        }
        let wide = to("b\u{FF0E}ad+x@gmail.com");
        assert!(!codes(&wide, gmail, "").is_empty());
        assert!(!codes(&wide, "", "").is_empty());
        assert!(codes(&to("b.a+x@gmail.com"), gmail, "").is_empty());
    }

    #[test]
    fn a_zero_width_character_does_not_hide_a_denied_address() {
        let deny = "address other@example.test\n";
        let raw = plain("Reply-To: oth\u{200B}er@example.test\r\n");
        assert_eq!(codes(&raw, deny, ""), vec!["reply-to-denied"]);
    }

    /// A zero-width space and a braille blank are removed, so the rule
    /// matches. Every other blank is refused, including an unassigned
    /// code point in the specials block.
    #[test]
    fn a_blank_character_does_not_hide_a_denied_address() {
        let deny = "address other@example.test\n";
        for blank in ['\u{200B}', '\u{2800}'] {
            let raw = plain(&format!("To: oth{blank}er@example.test\r\n"));
            assert_eq!(
                codes(&raw, deny, ""),
                vec!["recipient-address-denied"],
                "U+{:04X}",
                u32::from(blank)
            );
        }
        for blank in [
            '\u{115F}',
            '\u{1160}',
            '\u{3164}',
            '\u{FFA0}',
            '\u{2000}',
            '\u{2003}',
            '\u{200A}',
            '\u{2065}',
            '\u{FEFF}',
            '\u{E0001}',
            '\u{E0FFF}',
            '\u{FFF0}',
            '\u{FFF8}',
            '\u{FFF9}',
        ] {
            let to = if blank.is_whitespace() {
                format!("\"oth{blank}er\"@example.test")
            } else {
                format!("oth{blank}er@example.test")
            };
            let raw = plain(&format!("To: {to}\r\n"));
            assert_eq!(
                codes(&raw, deny, ""),
                vec!["recipient-unparsed"],
                "U+{:04X}",
                u32::from(blank)
            );
        }
    }

    /// An enclosing mark stays in the local part and used to miss the
    /// rule. It comes off in the skeleton, so the rule matches. A
    /// spacing mark on an ASCII base is not that letter, and is refused.
    /// The same mark on a Devanagari base is part of the spelling.
    #[test]
    fn an_enclosing_or_spacing_mark_does_not_hide_a_denied_address() {
        let deny = "address other@example.test\n";
        for mark in ['\u{20DD}', '\u{0488}'] {
            let raw = plain(&format!("To: oth{mark}er@example.test\r\n"));
            assert_eq!(
                codes(&raw, deny, ""),
                vec!["recipient-address-denied"],
                "U+{:04X}",
                u32::from(mark)
            );
            assert!(
                codes(&plain(&format!("To: oth{mark}er@example.test\r\n")), "", "").is_empty(),
                "U+{:04X} refused when nothing is denied",
                u32::from(mark)
            );
        }
        let visarga = plain("To: oth\u{0903}er@example.test\r\n");
        assert_eq!(codes(&visarga, deny, ""), vec!["recipient-unparsed"]);
        assert_eq!(codes(&visarga, "", ""), vec!["recipient-unparsed"]);
        let devanagari = plain("To: \u{0915}\u{0903}@example.test\r\n");
        assert!(
            codes(&devanagari, "", "").is_empty(),
            "{:?}",
            details(&devanagari, "", "")
        );
    }

    /// Every scalar is placed in a local part and judged by
    /// `check_mail_bytes` against one deny file, `address
    /// other@example.test`. An allow is only a letter, number,
    /// punctuation or symbol in the general category. That category
    /// comes from ICU, not from `local_closed`. A surrogate is not a
    /// scalar, so the UTF-8 decoder refuses those bytes.
    #[test]
    fn every_code_point_in_a_local_part_is_refused_or_visible() {
        use icu_properties::props::GeneralCategoryGroup;
        let visible = GeneralCategoryGroup::Letter
            .union(GeneralCategoryGroup::Number)
            .union(GeneralCategoryGroup::Punctuation)
            .union(GeneralCategoryGroup::Symbol);
        let category = CodePointMapData::<GeneralCategory>::new();
        let dir = std::env::temp_dir().join(format!("policyd-cps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deny.txt"), "address other@example.test\n").unwrap();
        std::fs::write(dir.join("law.txt"), "").unwrap();
        std::fs::write(
            dir.join("mail.conf"),
            format!("identity {IDENTITY}\ndeny-file deny.txt\npack-law law.txt\n"),
        )
        .unwrap();
        let conf = dir.join("mail.conf");
        let allowed = check_mail_bytes(
            b"From: mailseat@example.test\r\nTo: othxer@example.test\r\n\r\n",
            &conf,
        );
        assert!(
            !allowed.is_refused(),
            "deny file did not load: {:?}",
            allowed.reasons.iter().map(|r| r.code).collect::<Vec<_>>()
        );
        let mut msg = String::new();
        for cp in 0..=0x10FFFF {
            let Some(ch) = char::from_u32(cp) else {
                let v = check_mail_bytes(&surrogate_message(cp), &conf);
                assert_eq!(v.reasons[0].code, "message-invalid", "U+{cp:04X}");
                continue;
            };
            msg.clear();
            msg.push_str("From: mailseat@example.test\r\nTo: ");
            // Quote when the atom parser would not keep the character, so
            // the deny path sees it in the local part. `"`, `\`, CR and
            // LF cannot sit inside quotes; the header or the parser
            // refuses those bytes on their own.
            let quote = !local_atom_char(ch) && !matches!(ch, '"' | '\\' | '\r' | '\n');
            if quote {
                msg.push('"');
            }
            msg.push_str("oth");
            msg.push(ch);
            msg.push_str("er");
            if quote {
                msg.push('"');
            }
            msg.push_str("@example.test\r\n\r\n");
            let v = check_mail_bytes(msg.as_bytes(), &conf);
            if v.is_refused() {
                continue;
            }
            let cat = category.get(ch);
            assert!(
                visible.contains(cat),
                "U+{cp:04X} {cat:?} accepted and not denied"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same shape `is_atext` keeps in an unquoted local part, plus
    /// `.`, which a dot-atom keeps between the letters.
    fn local_atom_char(ch: char) -> bool {
        if ch.is_ascii() {
            return ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~'
                );
        }
        !mail::unicode_control(ch) && !mail::unicode_space(ch)
    }

    fn surrogate_message(cp: u32) -> Vec<u8> {
        let bytes = [
            0xE0 | ((cp >> 12) as u8),
            0x80 | (((cp >> 6) & 0x3F) as u8),
            0x80 | ((cp & 0x3F) as u8),
        ];
        let mut msg = Vec::from(&b"From: mailseat@example.test\r\nTo: oth"[..]);
        msg.extend_from_slice(&bytes);
        msg.extend_from_slice(b"er@example.test\r\n\r\n");
        msg
    }

    #[test]
    fn pack_law_refuses_a_recipient_domain_and_cannot_allow_one() {
        let raw = plain("To: person@blocked.test\r\n");
        assert_eq!(
            codes(&raw, "", "deny-domain blocked.test\n"),
            vec!["recipient-domain-denied"]
        );
        // Pack law is every watched header, not only To, Cc and Bcc. A
        // reply or a receipt to that domain leaves the seat.
        let reply = plain("Reply-To: person@blocked.test\r\nTo: person@ok.test\r\n");
        assert_eq!(
            codes(&reply, "", "deny-domain blocked.test\n"),
            vec!["reply-to-denied"]
        );
        assert_eq!(
            codes(&plain(""), "", "allow-domain blocked.test\n"),
            vec!["pack-law-invalid"]
        );
    }

    /// A pack-law domain on a reply, receipt or follow-up header is the
    /// same refusal as on To. The recipient's mailer will use it.
    #[test]
    fn pack_law_covers_every_watched_header() {
        let law = "deny-domain packblocked.test\n";
        for (header, code) in [
            ("Reply-To", "reply-to-denied"),
            ("Sender", "sender-denied"),
            ("Return-Path", "return-path-denied"),
            ("Errors-To", "errors-to-denied"),
            (
                "Disposition-Notification-To",
                "disposition-notification-to-denied",
            ),
            ("Return-Receipt-To", "return-receipt-to-denied"),
            ("Delivery-Receipt-To", "delivery-receipt-to-denied"),
            ("Mail-Followup-To", "mail-followup-to-denied"),
            ("Mail-Reply-To", "mail-reply-to-denied"),
        ] {
            let mut expect = Vec::new();
            match header {
                "Sender" => expect.push("sender-not-identity".to_string()),
                "Return-Path" => expect.push("return-path-not-identity".to_string()),
                "Errors-To" => expect.push("errors-to-not-identity".to_string()),
                _ => {}
            }
            expect.push(code.to_string());
            let raw = plain(&format!("{header}: a@packblocked.test\r\n"));
            assert_eq!(codes(&raw, "", law), expect, "{header}");
            let sub = plain(&format!("{header}: a@sub.packblocked.test\r\n"));
            assert_eq!(codes(&sub, "", law), expect, "{header} sub");
        }
    }

    /// `sendmail -t recipient` adds the command-line address to the
    /// header recipients. The message on stdin does not carry it.
    #[test]
    fn argv_recipients_are_refused_when_the_headers_are_clean() {
        let msg = "From: mailseat@example.test\r\nTo: person@ok.test\r\n\r\n";
        let deny = "domain blocked.test\naddress evil@example.test\n";
        let law = "deny-domain packblocked.test\n";
        assert!(codes_argv(msg, deny, law, &[]).is_empty());
        assert_eq!(
            codes_argv(msg, deny, law, &["evil@blocked.test"]),
            vec!["argv-recipient-denied"]
        );
        assert_eq!(
            codes_argv(msg, deny, law, &["a@packblocked.test"]),
            vec!["argv-recipient-denied"]
        );
        assert_eq!(
            codes_argv(msg, deny, law, &["evil+x@example.test"]),
            vec!["argv-recipient-denied"]
        );
        assert_eq!(
            codes_argv(msg, deny, law, &["\"a%blocked.test\"@localhost"]),
            vec!["argv-recipient-unparsed"]
        );
        assert!(codes_argv(msg, deny, law, &["person@ok.test"]).is_empty());
    }

    #[test]
    fn a_missing_or_broken_config_refuses() {
        let dir = std::env::temp_dir().join(format!("policyd-env-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("no.conf");
        let v = check_mail_bytes(b"From: mailseat@example.test\r\n", &missing);
        assert_eq!(v.reasons[0].code, "config-unreadable");
        std::fs::write(dir.join("mail.conf"), "identity mailseat@example.test\n").unwrap();
        let v = check_mail_bytes(b"From: mailseat@example.test\r\n", &dir.join("mail.conf"));
        assert_eq!(v.reasons[0].code, "config-invalid");
        std::fs::write(
            dir.join("mail.conf"),
            "identity mailseat@example.test\ndeny-file missing.txt\npack-law law.txt\n",
        )
        .unwrap();
        std::fs::write(dir.join("law.txt"), "").unwrap();
        let v = check_mail_bytes(b"From: mailseat@example.test\r\n", &dir.join("mail.conf"));
        assert_eq!(v.reasons[0].code, "deny-file-unreadable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_header_line_over_998_octets_is_refused() {
        let deny = "domain blocked.test\n";
        let mut line = String::from("Subject: ");
        while line.len() < 998 {
            line.push('a');
        }
        line.push_str("Bcc: a@blocked.test");
        let raw = format!("From: mailseat@example.test\r\n{line}\r\n\r\n");
        assert_eq!(codes(&raw, deny, ""), vec!["header-line-too-long"]);
        let mut ok = String::from("Subject: ");
        while ok.len() < 998 {
            ok.push('b');
        }
        let raw = format!("From: mailseat@example.test\r\n{ok}\r\n\r\n");
        assert!(
            codes(&raw, deny, "").is_empty(),
            "{:?}",
            details(&raw, deny, "")
        );
    }

    #[test]
    fn mixed_header_line_endings_are_refused() {
        let hidden = "From: mailseat@example.test\n\nBcc: a@blocked.test\r\n\r\n";
        assert_eq!(
            codes(hidden, "domain blocked.test\n", ""),
            vec!["header-line-ending"]
        );
        let mixed = "From: mailseat@example.test\r\nTo: a@example.test\n";
        assert_eq!(codes(mixed, "", ""), vec!["header-line-ending"]);
        let bare_blank = "From: mailseat@example.test\r\nTo: a@example.test\n\n";
        assert_eq!(codes(bare_blank, "", ""), vec!["header-line-ending"]);
        let crlf_then_body = "From: mailseat@example.test\r\n\r\npara\n\nmore\r\n";
        assert!(codes(crlf_then_body, "", "").is_empty());
        assert!(codes("From: mailseat@example.test\r\n", "", "").is_empty());
        assert!(codes("From: mailseat@example.test\n", "", "").is_empty());
    }

    #[test]
    fn unicode_line_separators_in_the_header_are_refused() {
        let deny = "domain blocked.test\n";
        let raw = "From: mailseat@example.test\r\nSubject: x\u{0085}Bcc: a@blocked.test\r\n\r\n";
        assert_eq!(codes(raw, deny, ""), vec!["header-control"]);
        let raw = "From: mailseat@example.test\r\nSubject: x\u{2028}Bcc: a@blocked.test\r\n\r\n";
        assert_eq!(codes(raw, deny, ""), vec!["header-control"]);
        let raw = "From: mailseat@example.test\r\nSubject: x\u{2029}Bcc: a@blocked.test\r\n\r\n";
        assert_eq!(codes(raw, deny, ""), vec!["header-control"]);
        let raw = "From: mailseat@example.test\r\n\r\nx\u{0085}y\r\n";
        assert!(codes(raw, "", "").is_empty(), "{:?}", details(raw, "", ""));
    }

    #[test]
    fn a_control_or_an_overlong_message_is_refused() {
        let raw = "From: mailseat@example.test\r\nSubject: a\u{0001}b\r\n";
        assert_eq!(codes(raw, "", ""), vec!["header-control"]);
        let mut big = b"From: mailseat@example.test\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAIL_MESSAGE_MAX));
        let dir = std::env::temp_dir().join(format!("policyd-env-big-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deny.txt"), "").unwrap();
        std::fs::write(dir.join("law.txt"), "").unwrap();
        std::fs::write(
            dir.join("mail.conf"),
            "identity mailseat@example.test\ndeny-file deny.txt\npack-law law.txt\n",
        )
        .unwrap();
        let v = check_mail_bytes(&big, &dir.join("mail.conf"));
        assert_eq!(v.reasons[0].code, "message-too-large");
        let v = check_mail_bytes(&[0xff, 0xfe], &dir.join("mail.conf"));
        assert_eq!(v.reasons[0].code, "message-invalid");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ICU properties, `unicode-normalization` and the case mapping are
    /// Unicode 18.0.0. The toolchain's `char` tables are not read on
    /// this path: they leave these letters unchanged.
    #[test]
    fn the_deny_path_uses_unicode_18() {
        assert_eq!(icu_properties_data::unicode_tag!(), "18.0.0");
        assert_eq!(unicode_normalization::UNICODE_VERSION, (18, 0, 0));
        for (upper, lower) in [
            ('\u{A7DD}', "\u{0277}"),
            ('\u{AB6C}', "\u{AB4B}"),
            ('\u{1DF40}', "\u{1DF41}"),
        ] {
            let cp = u32::from(upper);
            assert_eq!(icu_lower(&upper.to_string()), lower, "U+{cp:04X}");
            assert_eq!(casefold(&upper.to_string()), lower, "U+{cp:04X}");
        }
    }

    #[test]
    fn several_refusals_are_all_reported() {
        let raw = "\
From: other@example.test\r\n\
Reply-To: other@example.test\r\n\
To: person@blocked.test\r\n";
        assert_eq!(
            codes(raw, "address other@example.test\ndomain blocked.test\n", ""),
            vec![
                "from-not-identity",
                "reply-to-denied",
                "recipient-domain-denied"
            ]
        );
    }
}
