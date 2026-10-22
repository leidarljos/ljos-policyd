//! Outbound envelope check.
//!
//! The check only refuses. An empty reason list means `From` is the
//! configured identity and neither the deny file nor the pack-law file
//! named a header this check watches. It is not a grant to send.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

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
        if domain_denied(&addr.domain, &config.deny_domains)
            || domain_denied(&addr.domain, &config.pack_domains)
        {
            reasons.push(reason("argv-recipient-denied", addr.domain));
        }
    }
}

struct NormAddr {
    /// Deny-file form: NFKC, ignorables removed, local part lowercased,
    /// domain in IDNA ASCII.
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

struct Config {
    identity: NormAddr,
    deny_addresses: BTreeSet<String>,
    deny_domains: BTreeSet<String>,
    pack_domains: BTreeSet<String>,
    /// Characters that split a local part into a mailbox and a tag.
    /// Default `+-=`. An address rule for the mailbox covers the tag.
    subaddress: String,
    aliases: Vec<AliasFamily>,
}

fn load_config(path: &Path) -> Result<Config, MailReason> {
    let text = read_text(path).map_err(|()| reason("config-unreadable", "config"))?;
    let mut identity = None;
    let mut deny_file = None;
    let mut pack_law = None;
    let mut subaddress = None;
    for line in text.lines() {
        let Some((key, value)) =
            rule_line(line).map_err(|()| reason("config-invalid", "config"))?
        else {
            continue;
        };
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
    let aliases = builtin_families().ok_or_else(|| reason("config-invalid", "config"))?;
    let identity =
        normalize_identity(&identity).ok_or_else(|| reason("identity-invalid", "identity"))?;
    let (deny_addresses, deny_domains) = load_deny(&resolve(path, &deny_file), &aliases)?;
    let pack_domains = load_pack_law(&resolve(path, &pack_law))?;
    Ok(Config {
        identity,
        deny_addresses,
        deny_domains,
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

fn load_deny(
    path: &Path,
    aliases: &[AliasFamily],
) -> Result<(BTreeSet<String>, BTreeSet<String>), MailReason> {
    let text = read_text(path).map_err(|()| reason("deny-file-unreadable", "deny-file"))?;
    let mut addresses = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for line in text.lines() {
        let Some((key, value)) =
            rule_line(line).map_err(|()| reason("deny-file-invalid", "deny-file"))?
        else {
            continue;
        };
        match key {
            "address" => {
                let list =
                    mail::mailboxes(value).map_err(|_| reason("deny-file-invalid", "deny-file"))?;
                if list.len() != 1 {
                    return Err(reason("deny-file-invalid", "deny-file"));
                }
                let addr = normalize_mailbox(&list[0])
                    .ok_or_else(|| reason("deny-file-invalid", "deny-file"))?;
                for (local, domain) in alias_forms(&addr.local, &addr.domain, aliases) {
                    addresses.insert(format!("{local}@{domain}"));
                }
            }
            "domain" => {
                let domain = normalize_domain(value)
                    .ok_or_else(|| reason("deny-file-invalid", "deny-file"))?;
                domains.insert(domain);
            }
            "handle" | "term" => {
                if value.is_empty() {
                    return Err(reason("deny-file-invalid", "deny-file"));
                }
            }
            "pair" => {
                let mut parts = value.split_whitespace();
                if parts.next().is_none() || parts.next().is_none() {
                    return Err(reason("deny-file-invalid", "deny-file"));
                }
            }
            _ => return Err(reason("deny-file-invalid", "deny-file")),
        }
    }
    Ok((addresses, domains))
}

fn load_pack_law(path: &Path) -> Result<BTreeSet<String>, MailReason> {
    let text = read_text(path).map_err(|()| reason("pack-law-unreadable", "pack-law"))?;
    let mut domains = BTreeSet::new();
    for line in text.lines() {
        let Some((key, value)) =
            rule_line(line).map_err(|()| reason("pack-law-invalid", "pack-law"))?
        else {
            continue;
        };
        // A line that would allow a domain is not a rule this check can
        // apply. The file is refused so an allow cannot override a deny.
        if key != "deny-domain" || value.is_empty() {
            return Err(reason("pack-law-invalid", "pack-law"));
        }
        let domain =
            normalize_domain(value).ok_or_else(|| reason("pack-law-invalid", "pack-law"))?;
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
                        || domain_denied(&addr.domain, &config.deny_domains)
                        || domain_denied(&addr.domain, &config.pack_domains)
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
                        if domain_denied(&addr.domain, &config.deny_domains)
                            || domain_denied(&addr.domain, &config.pack_domains)
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
/// part or domain that NFKC or ignorable-stripping would change is a
/// different mailbox on the wire, so it does not match.
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
    let stripped: String = raw.chars().filter(|c| !is_ignorable(*c)).collect();
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
/// Alias families fold both the rule and the recipient, and only here.
/// A domain rule and `From` do not use them.
fn address_denied(addr: &NormAddr, config: &Config) -> bool {
    for (local, domain) in alias_forms(&addr.local, &addr.domain, &config.aliases) {
        let seps = separators(&domain, config);
        let cut = families_of(&domain, &config.aliases).any(|f| f.cut);
        for rule in &config.deny_addresses {
            let Some((rule_local, rule_domain)) = rule.split_once('@') else {
                continue;
            };
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
/// value: `<domain>[,<domain>...] <separators> [flag...]`. The
/// separators are added to the `subaddress` line on those domains.
/// `shared` makes the domains one mailbox, `dots` ignores dots in the
/// local part, and `subdomain` reads `<anything>@<user>.<domain>` as
/// `<user>@<domain>`. `cut` also cuts the rule's own local part at the
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
    // Plus addressing only. The domains and their country variants are
    // separate mailboxes, so none of them is shared:
    // https://support.microsoft.com/en-us/outlook/send-email-from-a-different-address-in-outlook-com
    "outlook.com,hotmail.com,live.com,msn.com +",
    "outlook.fr,outlook.de,outlook.es,outlook.it,outlook.jp +",
    "hotmail.co.uk,hotmail.fr,hotmail.de,hotmail.es,hotmail.it +",
    "live.co.uk,live.fr,live.de,live.it,live.nl,live.ca +",
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
    "yahoo.com,yahoo.co.uk,yahoo.fr,yahoo.de,yahoo.es,yahoo.it,yahoo.ca,yahoo.com.au - cut",
    "ymail.com,rocketmail.com - cut",
];

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
/// would refuse, or an unknown flag.
fn alias_family(value: &str) -> Option<AliasFamily> {
    let mut parts = value.split_whitespace();
    let domains = parts
        .next()?
        .split(',')
        .map(normalize_domain)
        .collect::<Option<Vec<_>>>()?;
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
        *slot = true;
    }
    Some(family)
}

fn families_of<'a>(
    domain: &'a str,
    families: &'a [AliasFamily],
) -> impl Iterator<Item = &'a AliasFamily> {
    families
        .iter()
        .filter(move |f| f.domains.iter().any(|d| d == domain))
}

/// Every `(local, domain)` the families make of one mailbox, itself
/// first. Each form is folded again until nothing new appears, so a
/// domain named by two families gets both. The subdomain label is not
/// cut on a separator: a hyphen there is part of the user name.
fn alias_forms(local: &str, domain: &str, families: &[AliasFamily]) -> Vec<(String, String)> {
    let mut forms = vec![(local.to_string(), domain.to_string())];
    for family in families.iter().filter(|f| f.subdomain) {
        for base in &family.domains {
            let user = domain
                .strip_suffix(base.as_str())
                .and_then(|rest| rest.strip_suffix('.'));
            if let Some(user) = user.filter(|u| !u.is_empty() && !u.contains('.')) {
                push_form(&mut forms, user.to_string(), base.clone());
            }
        }
    }
    let mut i = 0;
    while i < forms.len() {
        let (local, domain) = forms[i].clone();
        for family in families_of(&domain, families) {
            if family.dots {
                let bare = local.chars().filter(|c| *c != '.').collect();
                push_form(&mut forms, bare, domain.clone());
            }
            if family.shared {
                for other in &family.domains {
                    push_form(&mut forms, local.clone(), other.clone());
                }
            }
        }
        i += 1;
    }
    forms
}

fn push_form(forms: &mut Vec<(String, String)>, local: String, domain: String) {
    if !forms.iter().any(|(l, d)| *l == local && *d == domain) {
        forms.push((local, domain));
    }
}

fn domain_denied(domain: &str, denied: &BTreeSet<String>) -> bool {
    denied
        .iter()
        .any(|rule| domain == rule || domain.ends_with(&format!(".{rule}")))
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

fn normalize_local(raw: &str) -> Option<String> {
    let folded: String = raw.nfkc().filter(|c| !is_ignorable(*c)).collect();
    if folded.chars().any(|c| c.is_control()) {
        return None;
    }
    let lower: String = folded.chars().flat_map(|c| c.to_lowercase()).collect();
    if lower.is_empty() {
        return None;
    }
    Some(lower)
}

/// NFKC, then IDNA, so a fullwidth label and a punycode label of the same
/// domain compare equal. A trailing dot is the same name. A homoglyph that
/// NFKC leaves alone stays a different domain.
fn normalize_domain(raw: &str) -> Option<String> {
    if raw.contains('@') {
        return None;
    }
    let folded: String = raw.nfkc().filter(|c| !is_ignorable(*c)).collect();
    let folded = folded.trim().trim_end_matches('.');
    if folded.is_empty() || folded.starts_with('.') || folded.contains("..") {
        return None;
    }
    if folded.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    // A domain literal is not a name. NFKC cannot turn the brackets into
    // one, and the address is refused instead of compared.
    if folded.contains('[') || folded.contains(']') {
        return None;
    }
    idna::domain_to_ascii(folded).ok().filter(|d| !d.is_empty())
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

/// Characters a reader skips. A deny-file comparison removes them so
/// they cannot hide an address. `From` does not: a mailbox these
/// change is a different address on the wire and is refused.
fn is_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{180E}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180D}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
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
        assert!(codes(&plain("Reply-To: evilx@example.test\r\n"), deny, "").is_empty());
        assert!(codes(&plain("To: notevil+x@example.test\r\n"), deny, "").is_empty());
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
        assert!(codes_with(
            &plain("To: evil-x@example.test\r\n"),
            deny,
            "",
            "subaddress +\n"
        )
        .is_empty());
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
        assert!(codes(&plain("To: badx@gmail.com\r\n"), gmail, "").is_empty());
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
    /// are not, and only cut on `+`. A Yahoo rule covers every
    /// disposable address on its base.
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
        assert!(!denied("bad@hotmail.com", outlook));
        assert!(!denied("bad-x@outlook.com", outlook));
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

    #[test]
    fn a_zero_width_character_does_not_hide_a_denied_address() {
        let deny = "address other@example.test\n";
        let raw = plain("Reply-To: oth\u{200B}er@example.test\r\n");
        assert_eq!(codes(&raw, deny, ""), vec!["reply-to-denied"]);
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
