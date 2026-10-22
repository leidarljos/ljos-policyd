//! RFC 5322 header block for an outbound envelope.
//!
//! The fold is part of the header it continues, and a second `From` stays
//! a second header. An encoded-word in a display name is the text it
//! names, for display only. The mailbox is read from the raw unfolded
//! value, so a decoded parenthesis cannot become a comment. The envelope
//! check refuses from what this read; it does not decide the address by
//! which copy of `From` a later reader might keep.

use unicode_normalization::UnicodeNormalization;

/// A header whose value is unfolded. The name is lower case.
#[derive(Debug)]
pub(crate) struct Header {
    pub name: String,
    /// Unfolded field body. Mailbox extraction reads this and not `value`.
    pub raw: String,
    /// Display-name encoded-words decoded, for display only, or why an
    /// encoded-word cannot be trusted.
    pub value: Result<String, HeaderFault>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderFault {
    /// An encoded-word did not decode. Comparing the raw word would miss
    /// the address it hides, so the header is refused instead.
    EncodedWord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageFault {
    /// A control character in the header block can hide text from a reader
    /// that drops it and still be part of the address for one that keeps it.
    Control,
    /// The block is not a header list, so there is no envelope to read.
    Structure,
    /// CRLF and a bare LF in the same header block. One reader splits the
    /// body at the earlier blank line and drops the headers between them.
    LineEnding,
    /// A header line over 998 octets. A hop that wraps it without
    /// folding turns the tail into a new header.
    LineTooLong,
}

/// RFC 5322 limit, excluding the CRLF.
const HEADER_LINE_MAX: usize = 998;

#[derive(Debug)]
pub(crate) struct Message {
    pub headers: Vec<Header>,
}

/// One mailbox. `local` and `domain` are the raw addr-spec pieces, before
/// NFKC and IDNA. The caller normalizes both before comparing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mailbox {
    pub local: String,
    pub domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressFault;

/// Headers of `input`, split from the body at the first blank line.
/// A message with no blank line is all headers.
pub(crate) fn parse_message(input: &str) -> Result<Message, MessageFault> {
    let block = header_block(input)?;
    if has_bad_control(block) {
        return Err(MessageFault::Control);
    }
    if header_line_too_long(block) {
        return Err(MessageFault::LineTooLong);
    }
    let fields = split_headers(block)?;
    let mut headers = Vec::with_capacity(fields.len());
    for (name, raw) in fields {
        let value = display_value(&raw).map_err(|()| HeaderFault::EncodedWord);
        headers.push(Header { name, raw, value });
    }
    Ok(Message { headers })
}

/// Mailboxes in one raw unfolded header value.
///
/// Encoded-words are not decoded. A parenthesis that exists only as an
/// encoded-word is not a comment, and an encoded addr-spec is not a
/// mailbox. `<>` is the empty return path and contributes no mailbox. A
/// group such as `Friends: a@example.test;` contributes the mailboxes and
/// not the group name. The address in angle brackets is the mailbox; a
/// phrase that looks like an address is not.
pub(crate) fn mailboxes(value: &str) -> Result<Vec<Mailbox>, AddressFault> {
    let text = strip_comments(value)?;
    let mut out = Vec::new();
    for segment in split_list(&text)? {
        if let Some(mailbox) = mailbox_segment(&segment)? {
            out.push(mailbox);
        }
    }
    Ok(out)
}

fn header_block(message: &str) -> Result<&str, MessageFault> {
    let crlf = message.find("\r\n\r\n");
    let lf = message.find("\n\n");
    match (crlf, lf) {
        // A bare LF blank before the CRLF blank hides every header between
        // them from the reader that stops at the earlier one.
        (Some(i), Some(j)) if j < i => Err(MessageFault::LineEnding),
        (Some(i), _) => {
            let block = &message[..i];
            if has_bare_lf(block) {
                Err(MessageFault::LineEnding)
            } else {
                Ok(block)
            }
        }
        (None, Some(j)) => {
            let block = &message[..j];
            if has_crlf(block) || block.ends_with('\r') {
                Err(MessageFault::LineEnding)
            } else {
                Ok(block)
            }
        }
        (None, None) => {
            let end = message.trim_end_matches(['\r', '\n']).len();
            let block = &message[..end];
            let tail = &message[end..];
            if (has_bare_lf(block) || has_bare_lf(tail))
                && (has_crlf(block) || tail.contains("\r\n"))
            {
                Err(MessageFault::LineEnding)
            } else {
                Ok(block)
            }
        }
    }
}

fn has_crlf(s: &str) -> bool {
    s.contains("\r\n")
}

fn has_bare_lf(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(i, c)| *c == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
}

fn header_line_too_long(block: &str) -> bool {
    block.lines().any(|line| line.len() > HEADER_LINE_MAX)
}

fn has_bad_control(block: &str) -> bool {
    // U+0085, U+2028 and U+2029 are not C0 controls. A reader that
    // splits lines on them, as Python's str.splitlines does, sees a
    // new header. The bytes below never match those characters.
    if block
        .chars()
        .any(|c| matches!(c, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return true;
    }
    let bytes = block.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' | b'\t' => i += 1,
            b'\r' if bytes.get(i + 1) == Some(&b'\n') => i += 2,
            c if c < 0x20 || c == 0x7f => return true,
            _ => i += 1,
        }
    }
    false
}

fn split_headers(block: &str) -> Result<Vec<(String, String)>, MessageFault> {
    let mut headers = Vec::new();
    let mut name: Option<String> = None;
    let mut value = String::new();
    for line in block.lines() {
        if line.is_empty() {
            return Err(MessageFault::Structure);
        }
        if line.starts_with([' ', '\t']) {
            if name.is_none() {
                return Err(MessageFault::Structure);
            }
            // Unfolding drops the line break and keeps this whitespace, so
            // a fold is the same header and the space in the middle of an
            // address stays a space.
            value.push_str(line);
            continue;
        }
        if let Some(n) = name.take() {
            headers.push((n, std::mem::take(&mut value)));
        }
        let Some((field, rest)) = line.split_once(':') else {
            return Err(MessageFault::Structure);
        };
        if !is_field_name(field) {
            return Err(MessageFault::Structure);
        }
        name = Some(field.to_ascii_lowercase());
        value = rest.trim_start_matches([' ', '\t']).to_string();
    }
    if let Some(n) = name {
        headers.push((n, value));
    }
    Ok(headers)
}

fn is_field_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

/// `=?charset?Q|B?text?=`, and the whitespace between two of them, which
/// RFC 2047 drops when the words are joined.
fn decode_encoded_words(input: &str) -> Result<String, ()> {
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && bytes.get(i + 1) == Some(&b'?') {
            let (word, n) = take_encoded_word(&input[i..])?;
            out.push_str(&word);
            i += n;
            if let Some(skip) = whitespace_before_encoded_word(&input[i..]) {
                i += skip;
            }
            continue;
        }
        let ch = input[i..].chars().next().ok_or(())?;
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

/// Display text. Encoded-words in a display name become the text they
/// name. An addr-spec is left encoded, and so is a word whose text would
/// be address syntax, so this string is not a second parse of the mailbox.
fn display_value(raw: &str) -> Result<String, ()> {
    if !encoded_words_well_formed(raw) {
        return Err(());
    }
    let Ok(segments) = split_list(raw) else {
        return Ok(raw.to_string());
    };
    let mut out = String::new();
    for (i, segment) in segments.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&decode_segment_display(segment));
    }
    Ok(out)
}

fn encoded_words_well_formed(input: &str) -> bool {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && bytes.get(i + 1) == Some(&b'?') {
            let Ok((_, n)) = take_encoded_word(&input[i..]) else {
                return false;
            };
            if n == 0 {
                return false;
            }
            i += n;
            continue;
        }
        let Some(ch) = input[i..].chars().next() else {
            return false;
        };
        i += ch.len_utf8();
    }
    true
}

fn decode_segment_display(segment: &str) -> String {
    let Some(idx) = display_name_end(segment) else {
        return segment.to_string();
    };
    let phrase = &segment[..idx];
    let rest = &segment[idx..];
    let decoded = match decode_span_for_display(phrase) {
        Ok(text) => text,
        Err(()) => phrase.to_string(),
    };
    let mut out = decoded;
    out.push_str(rest);
    out
}

/// Byte index of the `<` that opens a name-addr, when this segment has one.
fn display_name_end(segment: &str) -> Option<usize> {
    let mut quote = false;
    let mut escape = false;
    let mut comment = 0i32;
    for (i, c) in segment.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote {
            match c {
                '\\' => escape = true,
                '"' => quote = false,
                _ => {}
            }
            continue;
        }
        if comment > 0 {
            match c {
                '\\' => escape = true,
                '(' => comment += 1,
                ')' => comment -= 1,
                _ => {}
            }
            continue;
        }
        match c {
            '\\' => escape = true,
            '"' => quote = true,
            '(' => comment = 1,
            '<' => return Some(i),
            _ => {}
        }
    }
    None
}

fn decode_span_for_display(span: &str) -> Result<String, ()> {
    if !encoded_words_are_display_safe(span)? {
        return Ok(span.to_string());
    }
    decode_encoded_words(span)
}

/// A word that decodes to address syntax stays encoded. Decoding it into
/// the display string would make a later parse see a different mailbox.
fn encoded_words_are_display_safe(span: &str) -> Result<bool, ()> {
    let bytes = span.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && bytes.get(i + 1) == Some(&b'?') {
            let (word, n) = take_encoded_word(&span[i..])?;
            if word.chars().any(|c| is_addr_special(c) || c.is_control()) {
                return Ok(false);
            }
            i += n;
            continue;
        }
        let Some(ch) = span[i..].chars().next() else {
            return Err(());
        };
        i += ch.len_utf8();
    }
    Ok(true)
}

fn is_addr_special(c: char) -> bool {
    matches!(
        c,
        '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '"'
    )
}

fn contains_encoded_word(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && bytes.get(i + 1) == Some(&b'?') && take_encoded_word(&s[i..]).is_ok()
        {
            return true;
        }
        i += 1;
    }
    false
}

fn whitespace_before_encoded_word(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while bytes.get(i).is_some_and(|c| *c == b' ' || *c == b'\t') {
        i += 1;
    }
    if i > 0 && bytes.get(i) == Some(&b'=') && bytes.get(i + 1) == Some(&b'?') {
        Some(i)
    } else {
        None
    }
}

fn take_encoded_word(s: &str) -> Result<(String, usize), ()> {
    let bytes = s.as_bytes();
    if bytes.len() < 8 || bytes[0] != b'=' || bytes[1] != b'?' {
        return Err(());
    }
    let rest = &s[2..];
    let q1 = rest.find('?').ok_or(())?;
    let charset = &rest[..q1];
    if charset.is_empty()
        || !charset
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    {
        return Err(());
    }
    let rest = &rest[q1 + 1..];
    let q2 = rest.find('?').ok_or(())?;
    let encoding = &rest[..q2];
    if encoding.len() != 1 {
        return Err(());
    }
    let rest = &rest[q2 + 1..];
    let end = rest.find("?=").ok_or(())?;
    let text = &rest[..end];
    if text.as_bytes().contains(&b'?') {
        return Err(());
    }
    let raw = match encoding.to_ascii_lowercase().as_bytes() {
        b"q" => q_decode(text)?,
        b"b" => b64_decode(text)?,
        _ => return Err(()),
    };
    let word = decode_charset(charset, &raw)?;
    let consumed = 2 + charset.len() + 1 + encoding.len() + 1 + text.len() + 2;
    Ok((word, consumed))
}

fn q_decode(text: &str) -> Result<Vec<u8>, ()> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                out.push(b' ');
                i += 1;
            }
            b'=' => {
                if i + 2 >= bytes.len() {
                    return Err(());
                }
                let hi = hex_digit(bytes[i + 1])?;
                let lo = hex_digit(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            c if (0x21..=0x7e).contains(&c) && c != b'?' => {
                out.push(c);
                i += 1;
            }
            _ => return Err(()),
        }
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

fn b64_decode(text: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Result<u8, ()> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    }
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let (a, b, c, d) = (chunk[0], chunk[1], chunk[2], chunk[3]);
        if c == b'=' && d != b'=' {
            return Err(());
        }
        let pads = u8::from(c == b'=') + u8::from(d == b'=');
        let av = val(a)?;
        let bv = val(b)?;
        let cv = if c == b'=' { 0 } else { val(c)? };
        let dv = if d == b'=' { 0 } else { val(d)? };
        out.push((av << 2) | (bv >> 4));
        if pads < 2 {
            out.push((bv << 4) | (cv >> 2));
        }
        if pads < 1 {
            out.push((cv << 6) | dv);
        }
    }
    Ok(out)
}

fn decode_charset(charset: &str, bytes: &[u8]) -> Result<String, ()> {
    match charset.to_ascii_lowercase().as_str() {
        "utf-8" | "utf8" => String::from_utf8(bytes.to_vec()).map_err(|_| ()),
        "us-ascii" | "ascii" => {
            if bytes.iter().any(|b| *b >= 0x80) {
                return Err(());
            }
            String::from_utf8(bytes.to_vec()).map_err(|_| ())
        }
        "iso-8859-1" | "iso8859-1" | "latin1" | "latin-1" => {
            Ok(bytes.iter().copied().map(char::from).collect())
        }
        _ => Err(()),
    }
}

fn strip_comments(input: &str) -> Result<String, AddressFault> {
    let mut out = String::new();
    let mut quote = false;
    let mut escape = false;
    let mut depth = 0i32;
    for c in input.chars() {
        if depth > 0 {
            if escape {
                escape = false;
                continue;
            }
            match c {
                '\\' => escape = true,
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            continue;
        }
        if quote {
            out.push(c);
            if escape {
                escape = false;
                continue;
            }
            match c {
                '\\' => escape = true,
                '"' => quote = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                quote = true;
                out.push(c);
            }
            '(' => depth = 1,
            ')' => return Err(AddressFault),
            _ => out.push(c),
        }
    }
    if quote || depth != 0 || escape {
        return Err(AddressFault);
    }
    Ok(out)
}

fn split_list(input: &str) -> Result<Vec<String>, AddressFault> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = false;
    let mut escape = false;
    let mut angle = 0i32;
    for c in input.chars() {
        if escape {
            cur.push(c);
            escape = false;
            continue;
        }
        if quote {
            cur.push(c);
            match c {
                '\\' => escape = true,
                '"' => quote = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                quote = true;
                cur.push(c);
            }
            '<' => {
                angle += 1;
                cur.push(c);
            }
            '>' => {
                if angle == 0 {
                    return Err(AddressFault);
                }
                angle -= 1;
                cur.push(c);
            }
            ',' if angle == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if quote || angle != 0 || escape {
        return Err(AddressFault);
    }
    out.push(cur);
    Ok(out)
}

/// True when `value` uses group syntax (`name: addr;`). The colon is
/// outside quotes and angle brackets. A group in `From` is not a
/// mailbox RFC 5322 allows there.
pub(crate) fn contains_group(value: &str) -> Result<bool, AddressFault> {
    let text = strip_comments(value)?;
    Ok(group_colon(text.trim())?.is_some())
}

fn mailbox_segment(segment: &str) -> Result<Option<Mailbox>, AddressFault> {
    let segment = strip_group(segment.trim())?;
    let segment = segment.trim();
    if segment.is_empty() {
        return Ok(None);
    }
    let spec = match angle_contents(segment)? {
        Some("") => return Ok(None),
        Some(inner) => {
            // An encoded-word is not an addr-spec. Decoding it would name
            // a mailbox the raw text does not.
            if contains_encoded_word(inner) {
                return Err(AddressFault);
            }
            route_addr(inner)?
        }
        None => {
            if contains_encoded_word(segment) {
                return Err(AddressFault);
            }
            segment
        }
    };
    parse_addr_spec(spec).map(Some)
}

/// A trailing `;` ends a group. A `name:` in front of an address, outside
/// quotes and angles, is the group name.
fn strip_group(segment: &str) -> Result<&str, AddressFault> {
    let mut end = segment.len();
    let bytes = segment.as_bytes();
    if bytes.last() == Some(&b';') && !in_quotes_or_angles(segment, end - 1)? {
        end -= 1;
    }
    let segment = &segment[..end];
    if let Some(idx) = group_colon(segment)? {
        let name = segment[..idx].trim();
        if name.contains('@') {
            return Err(AddressFault);
        }
        return Ok(&segment[idx + 1..]);
    }
    Ok(segment)
}

fn group_colon(segment: &str) -> Result<Option<usize>, AddressFault> {
    let mut quote = false;
    let mut escape = false;
    let mut angle = 0i32;
    for (i, c) in segment.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote {
            match c {
                '\\' => escape = true,
                '"' => quote = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => quote = true,
            '<' => angle += 1,
            '>' => {
                if angle == 0 {
                    return Err(AddressFault);
                }
                angle -= 1;
            }
            ':' if angle == 0 => return Ok(Some(i)),
            _ => {}
        }
    }
    if quote || angle != 0 || escape {
        return Err(AddressFault);
    }
    Ok(None)
}

fn in_quotes_or_angles(segment: &str, at: usize) -> Result<bool, AddressFault> {
    let mut quote = false;
    let mut escape = false;
    let mut angle = 0i32;
    for (i, c) in segment.char_indices() {
        if i >= at {
            break;
        }
        if escape {
            escape = false;
            continue;
        }
        if quote {
            match c {
                '\\' => escape = true,
                '"' => quote = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => quote = true,
            '<' => angle += 1,
            '>' => {
                if angle == 0 {
                    return Err(AddressFault);
                }
                angle -= 1;
            }
            _ => {}
        }
    }
    Ok(quote || angle > 0)
}

fn angle_contents(segment: &str) -> Result<Option<&str>, AddressFault> {
    let Some(start) = segment.find('<') else {
        return Ok(None);
    };
    let Some(end) = segment.rfind('>') else {
        return Err(AddressFault);
    };
    if start >= end {
        return Err(AddressFault);
    }
    let inner = &segment[start + 1..end];
    if inner.contains(['<', '>'])
        || segment[..start].contains('>')
        || !segment[end + 1..].trim().is_empty()
    {
        return Err(AddressFault);
    }
    Ok(Some(inner.trim()))
}

/// A source route (`@host:addr`) is not the addr-spec. An MTA that
/// honours the route relays through those hosts, so the final mailbox
/// is the wrong address to judge. The route is a refusal.
fn route_addr(inner: &str) -> Result<&str, AddressFault> {
    let inner = inner.trim();
    if inner.starts_with('@') {
        return Err(AddressFault);
    }
    Ok(inner)
}

fn parse_addr_spec(spec: &str) -> Result<Mailbox, AddressFault> {
    let spec = spec.trim();
    let (local, at) = if spec.starts_with('"') {
        parse_quoted(spec)?
    } else {
        parse_dot_atom(spec)?
    };
    let rest = spec.get(at..).ok_or(AddressFault)?;
    let rest = rest.strip_prefix('@').ok_or(AddressFault)?;
    let domain = parse_domain(rest)?;
    if local.is_empty() {
        return Err(AddressFault);
    }
    Ok(Mailbox { local, domain })
}

fn parse_quoted(s: &str) -> Result<(String, usize), AddressFault> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err(AddressFault);
    }
    let mut local = String::new();
    let mut i = 1;
    let mut escape = false;
    while i < bytes.len() {
        let c = bytes[i];
        if escape {
            if c < 0x20 && c != b'\t' {
                return Err(AddressFault);
            }
            if c >= 0x80 {
                return Err(AddressFault);
            }
            // A quoted-pair is still the character. Postfix opens the
            // quotes and routes on it, so the escape is not a hiding place.
            if is_route_byte(c) {
                return Err(AddressFault);
            }
            local.push(c as char);
            escape = false;
            i += 1;
            continue;
        }
        match c {
            b'\\' => {
                escape = true;
                i += 1;
            }
            b'"' => {
                if local.is_empty() || nfkc_to_ascii_punctuation(&local) {
                    return Err(AddressFault);
                }
                return Ok((local, i + 1));
            }
            c if c < 0x20 && c != b'\t' => return Err(AddressFault),
            c if is_route_byte(c) => return Err(AddressFault),
            c if c < 0x80 => {
                local.push(c as char);
                i += 1;
            }
            _ => {
                let ch = s[i..].chars().next().ok_or(AddressFault)?;
                local.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    Err(AddressFault)
}

fn parse_dot_atom(s: &str) -> Result<(String, usize), AddressFault> {
    let mut local = String::new();
    let mut prev_dot = false;
    let mut any = false;
    for (i, c) in s.char_indices() {
        if c == '@' {
            if !any || prev_dot || nfkc_to_ascii_punctuation(&local) {
                return Err(AddressFault);
            }
            return Ok((local, i));
        }
        if c == '.' {
            if !any || prev_dot {
                return Err(AddressFault);
            }
            prev_dot = true;
            local.push('.');
            continue;
        }
        // `%` is the percent hack and `!` is a bang path. Postfix
        // rewrites both when the domain is local and then relays to
        // the rewritten address. The quoted form is refused in
        // `parse_quoted`, including a backslash escape: Postfix opens
        // the quotes before it routes.
        if c == '%' || c == '!' {
            return Err(AddressFault);
        }
        if !is_atext(c) {
            return Err(AddressFault);
        }
        prev_dot = false;
        any = true;
        local.push(c);
    }
    Err(AddressFault)
}

fn parse_domain(s: &str) -> Result<String, AddressFault> {
    let s = s.trim_end();
    // A domain literal (`@[ ... ]`) is not a name this check can compare.
    // Accepting the brackets lets the same host through in another shape.
    if s.is_empty() || s.contains('[') || s.contains(']') {
        return Err(AddressFault);
    }
    let bare = s.strip_suffix('.').unwrap_or(s);
    if bare.is_empty() {
        return Err(AddressFault);
    }
    let mut prev_dot = false;
    let mut any = false;
    for c in bare.chars() {
        if c == '.' {
            if !any || prev_dot {
                return Err(AddressFault);
            }
            prev_dot = true;
            any = true;
            continue;
        }
        if !is_atext(c) {
            return Err(AddressFault);
        }
        prev_dot = false;
        any = true;
    }
    if !any || prev_dot {
        return Err(AddressFault);
    }
    // A dotted quad, or any domain a resolver will connect to, is not a
    // name this check can compare. The shape is read after IDNA: NFKC
    // leaves U+3002 and U+FF61 in place, and IDNA turns both into `.`.
    if numeric_domain(bare) {
        return Err(AddressFault);
    }
    Ok(bare.to_string())
}

fn numeric_domain(bare: &str) -> bool {
    let folded: String = bare.nfkc().collect();
    let folded = folded.trim_end_matches('.');
    if folded.is_empty() {
        return false;
    }
    if is_numeric_or_inet(folded) {
        return true;
    }
    match idna::domain_to_ascii(folded) {
        Ok(ascii) => {
            let ascii = ascii.trim_end_matches('.');
            !ascii.is_empty() && ascii != folded && is_numeric_or_inet(ascii)
        }
        Err(_) => false,
    }
}

/// All-decimal labels of any count, a hex (`0x`) or leading-zero label,
/// or a string `inet_aton` accepts. A leading zero is refused even when
/// a later digit is 8 or 9: it is still an octal-shaped number.
fn is_numeric_or_inet(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|label| label.is_empty()) {
        return false;
    }
    if labels
        .iter()
        .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
    {
        return true;
    }
    if labels
        .iter()
        .any(|label| is_hex_label(label) || is_octal_label(label))
    {
        return true;
    }
    inet_aton(host)
}

fn is_hex_label(label: &str) -> bool {
    let Some(rest) = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_octal_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    bytes.len() >= 2 && bytes[0] == b'0' && bytes[1..].iter().all(|b| b.is_ascii_digit())
}

fn inet_aton(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }
    let mut values = [0u64; 4];
    for (i, part) in parts.iter().enumerate() {
        let Some(value) = c_number(part) else {
            return false;
        };
        values[i] = value;
    }
    let n = parts.len();
    for value in values.iter().take(n - 1) {
        if *value > 0xff {
            return false;
        }
    }
    let max = match n {
        1 => 0xffff_ffff,
        2 => 0x00ff_ffff,
        3 => 0x0000_ffff,
        4 => 0x0000_00ff,
        _ => return false,
    };
    values[n - 1] <= max
}

/// A C integer: `0x` hex, a leading `0` octal, otherwise decimal.
fn c_number(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    let (base, digits) =
        if let Some(rest) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            if rest.is_empty() {
                return None;
            }
            (16u64, rest)
        } else if part.as_bytes()[0] == b'0' && part.len() > 1 {
            (8u64, part)
        } else {
            (10u64, part)
        };
    let mut value = 0u64;
    for c in digits.chars() {
        let digit = match c {
            '0'..='9' => u64::from(c as u8 - b'0'),
            'a'..='f' if base == 16 => u64::from(c as u8 - b'a' + 10),
            'A'..='F' if base == 16 => u64::from(c as u8 - b'A' + 10),
            _ => return None,
        };
        if digit >= base {
            return None;
        }
        value = value.checked_mul(base)?.checked_add(digit)?;
    }
    Some(value)
}

/// `@` routes inside a quoted local part once the quotes are removed,
/// the same way `%` and `!` do. Postfix does this with
/// `resolve_dequoted` on, which is the default.
fn is_route_byte(c: u8) -> bool {
    matches!(c, b'@' | b'%' | b'!')
}

/// NFKC of a fullwidth punctuation mark is the ASCII mark. A local
/// part that changes into `@`, `%`, `!` or any other ASCII punctuation
/// is not the mailbox a later comparison would read.
fn nfkc_to_ascii_punctuation(local: &str) -> bool {
    local.chars().any(|c| {
        let folded: String = c.nfkc().collect();
        folded != c.to_string() && folded.chars().any(|d| d.is_ascii_punctuation())
    })
}

fn is_atext(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#'
                    | '$'
                    | '%'
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
            );
    }
    !c.is_control() && !c.is_whitespace()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn froms(raw: &str) -> Vec<Result<String, HeaderFault>> {
        parse_message(raw)
            .unwrap()
            .headers
            .into_iter()
            .filter(|h| h.name == "from")
            .map(|h| h.value)
            .collect()
    }

    #[test]
    fn a_folded_from_is_one_header() {
        let raw = "From: Mail\r\n Seat <mailseat@example.test>\r\n\r\nbody\r\n";
        let got = froms(raw);
        assert_eq!(got.len(), 1);
        let value = got[0].as_ref().unwrap();
        assert_eq!(
            mailboxes(value).unwrap(),
            vec![Mailbox {
                local: "mailseat".into(),
                domain: "example.test".into(),
            }]
        );
    }

    /// The space that unfolding keeps is still a space, so a fold in the
    /// middle of an addr-spec does not join the two halves.
    #[test]
    fn a_fold_inside_an_address_keeps_the_space() {
        let raw = "From: mailseat\r\n @example.test\r\n\r\n";
        let value = froms(raw)[0].as_ref().unwrap().clone();
        assert!(value.contains(' '));
        assert!(mailboxes(&value).is_err());
    }

    /// A continuation is not a header of its own. Without the leading
    /// space the same text would be `Bcc`.
    #[test]
    fn a_folded_line_does_not_become_another_header() {
        let raw = "From: mailseat@example.test\r\n bcc: hidden@example.test\r\n\r\n";
        let msg = parse_message(raw).unwrap();
        assert_eq!(msg.headers.len(), 1);
        assert!(msg.headers[0].value.as_ref().unwrap().contains("bcc:"));
    }

    #[test]
    fn an_encoded_word_from_decodes_the_display_name() {
        let raw = "From: =?utf-8?q?Mail_Seat?= <mailseat@example.test>\r\n\r\n";
        let value = froms(raw)[0].as_ref().unwrap().clone();
        assert_eq!(value, "Mail Seat <mailseat@example.test>");
        assert_eq!(
            mailboxes(&value).unwrap(),
            vec![Mailbox {
                local: "mailseat".into(),
                domain: "example.test".into(),
            }]
        );
    }

    #[test]
    fn a_base64_encoded_word_decodes() {
        let raw = "From: =?utf-8?b?TWFpbCBTZWF0?= <mailseat@example.test>\n";
        let value = froms(raw)[0].as_ref().unwrap().clone();
        assert_eq!(value, "Mail Seat <mailseat@example.test>");
    }

    /// An encoded addr-spec is not a mailbox. Decoding it first would
    /// accept the address the words spell.
    #[test]
    fn an_encoded_addr_spec_is_not_a_mailbox() {
        let raw = "From: =?utf-8?q?mailseat?=\r\n =?utf-8?q?=40example=2etest?=\r\n\r\n";
        let value = froms(raw)[0].as_ref().unwrap().clone();
        assert!(mailboxes(&value).is_err());
    }

    #[test]
    fn a_second_from_stays_a_second_header() {
        let raw = "\
From: mailseat@example.test\r\n\
From: other@example.test\r\n\
\r\n";
        let got = froms(raw);
        assert_eq!(got.len(), 2);
        assert_eq!(
            mailboxes(got[0].as_ref().unwrap()).unwrap()[0].local,
            "mailseat"
        );
        assert_eq!(
            mailboxes(got[1].as_ref().unwrap()).unwrap()[0].local,
            "other"
        );
    }

    /// The phrase can look like the identity. The mailbox is the address
    /// in angle brackets.
    #[test]
    fn the_angle_address_is_the_mailbox() {
        let value = "mailseat@example.test <other@example.test>";
        assert_eq!(
            mailboxes(value).unwrap(),
            vec![Mailbox {
                local: "other".into(),
                domain: "example.test".into(),
            }]
        );
    }

    #[test]
    fn a_comment_is_not_an_address() {
        let value = "mailseat@example.test (not other@example.test)";
        assert_eq!(
            mailboxes(value).unwrap(),
            vec![Mailbox {
                local: "mailseat".into(),
                domain: "example.test".into(),
            }]
        );
    }

    #[test]
    fn a_group_colon_marks_a_group() {
        assert!(contains_group("G: mailseat@example.test;").unwrap());
        assert!(contains_group("G: <mailseat@example.test>;").unwrap());
        assert!(!contains_group("\"G: H\" <mailseat@example.test>").unwrap());
        assert!(!contains_group("mailseat@example.test").unwrap());
        assert_eq!(
            mailboxes("Friends: one@example.test;").unwrap()[0].local,
            "one"
        );
    }

    #[test]
    fn a_list_and_a_group_yield_each_mailbox() {
        let value = "Friends: one@example.test, \"Two Three\"@example.test;";
        assert_eq!(
            mailboxes(value).unwrap(),
            vec![
                Mailbox {
                    local: "one".into(),
                    domain: "example.test".into(),
                },
                Mailbox {
                    local: "Two Three".into(),
                    domain: "example.test".into(),
                },
            ]
        );
    }

    #[test]
    fn an_empty_return_path_has_no_mailbox() {
        assert!(mailboxes("<>").unwrap().is_empty());
    }

    #[test]
    fn an_all_numeric_domain_is_not_a_mailbox() {
        assert!(mailboxes("a@192.0.2.1").is_err());
        assert!(mailboxes("a@192.0.2").is_err());
        assert!(mailboxes("a@10.0.0.1.2").is_err());
        assert!(mailboxes("<a@192.000.002.001>").is_err());
        let full = "\u{FF11}\u{FF19}\u{FF12}.\u{FF10}.\u{FF12}.\u{FF11}";
        assert!(mailboxes(&format!("a@{full}")).is_err());
        let ideographic = "192\u{3002}0\u{3002}2\u{3002}1";
        assert!(mailboxes(&format!("a@{ideographic}")).is_err());
        let halfwidth = "192\u{FF61}0\u{FF61}2\u{FF61}1";
        assert!(mailboxes(&format!("a@{halfwidth}")).is_err());
        assert!(mailboxes("a@0x7f.1").is_err());
        assert!(mailboxes("a@0X7F000001").is_err());
        assert!(mailboxes("a@0177.0.0.1").is_err());
        assert!(mailboxes("a@0177.example.test").is_err());
        assert!(mailboxes("a@0x7f.example.test").is_err());
        assert!(mailboxes("a@127.1").is_err());
        assert!(mailboxes("a@mx1.example.test").is_ok());
        assert!(mailboxes("a@192.0.2.example.test").is_ok());
    }

    #[test]
    fn a_domain_literal_is_not_a_mailbox() {
        assert!(mailboxes("a@[blocked.test]").is_err());
        assert!(mailboxes("a@[192.000.002.001]").is_err());
        assert!(mailboxes("<a@[mx.blocked.test]>").is_err());
        assert!(mailboxes("<@[192.0.2.1]:a@example.test>").is_err());
    }

    #[test]
    fn an_unquoted_percent_or_bang_is_not_a_mailbox() {
        assert!(mailboxes("a%blocked.test@localhost").is_err());
        assert!(mailboxes("blocked.test!a@localhost").is_err());
        assert!(mailboxes("<a%b@example.test>").is_err());
        assert!(mailboxes("\"a%b\"@example.test").is_err());
        assert!(mailboxes("\"a!b\"@example.test").is_err());
        assert!(mailboxes("\"a@b\"@example.test").is_err());
        assert!(mailboxes("\"a\\@blocked.test\"@example.test").is_err());
        assert!(mailboxes("\"a\\%blocked.test\"@localhost").is_err());
        assert!(mailboxes("\"blocked.test\\!a\"@localhost").is_err());
        assert!(mailboxes("\"Two Three\"@example.test").is_ok());
    }

    #[test]
    fn a_local_part_nfkc_folds_to_ascii_punctuation_is_not_a_mailbox() {
        assert!(mailboxes("a\u{FF05}blocked.test@localhost").is_err());
        assert!(mailboxes("a\u{FF20}blocked.test@localhost").is_err());
        assert!(mailboxes("a\u{FF01}b@localhost").is_err());
        assert!(mailboxes("a\u{FF0B}b@example.test").is_err());
        assert!(mailboxes("\"a\u{FF05}b\"@example.test").is_err());
        assert!(mailboxes("a+b@example.test").is_ok());
        assert!(mailboxes("\u{FF41}@example.test").is_ok());
    }

    #[test]
    fn a_source_route_is_not_a_mailbox() {
        assert!(mailboxes("<@relay.example.test:mailseat@example.test>").is_err());
        assert!(mailboxes("<@blocked.test:a@ok.test>").is_err());
        assert!(mailboxes("<@a.example,@b.example:a@ok.test>").is_err());
    }

    #[test]
    fn a_broken_encoded_word_is_not_read_as_text() {
        let raw = "From: =?utf-8?q?unterminated <mailseat@example.test>\r\n\r\n";
        assert_eq!(froms(raw), vec![Err(HeaderFault::EncodedWord)]);
    }

    #[test]
    fn a_header_line_over_998_octets_is_refused() {
        let mut line = String::from("Subject: ");
        while line.len() < 998 {
            line.push('a');
        }
        line.push_str("Bcc: a@example.test");
        let raw = format!("From: mailseat@example.test\r\n{line}\r\n\r\n");
        assert_eq!(parse_message(&raw).unwrap_err(), MessageFault::LineTooLong);
        let mut ok = String::from("Subject: ");
        while ok.len() < 998 {
            ok.push('b');
        }
        let raw = format!("From: mailseat@example.test\r\n{ok}\r\n\r\n");
        assert!(parse_message(&raw).is_ok());
    }

    #[test]
    fn mixed_line_endings_are_refused() {
        let raw = "From: mailseat@example.test\n\nBcc: hidden@example.test\r\n\r\n";
        assert_eq!(parse_message(raw).unwrap_err(), MessageFault::LineEnding);
        let raw = "From: mailseat@example.test\r\nTo: a@example.test\n";
        assert_eq!(parse_message(raw).unwrap_err(), MessageFault::LineEnding);
    }

    #[test]
    fn a_unicode_line_separator_in_the_header_is_refused() {
        for sep in ['\u{0085}', '\u{2028}', '\u{2029}'] {
            let raw = format!(
                "From: mailseat@example.test\r\nSubject: x{sep}Bcc: a@example.test\r\n\r\n"
            );
            assert_eq!(parse_message(&raw).unwrap_err(), MessageFault::Control);
        }
        let raw = "From: mailseat@example.test\r\n\r\nx\u{0085}y\r\n";
        assert!(parse_message(raw).is_ok());
    }

    #[test]
    fn a_control_in_the_header_block_is_refused() {
        let raw = "From: mailseat@example.test\r\nSubject: hi\u{0008}there\r\n\r\n";
        assert_eq!(parse_message(raw).unwrap_err(), MessageFault::Control);
    }
}
