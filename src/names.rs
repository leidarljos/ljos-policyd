//! Names a command binds or may change in the shell that runs it.

use super::{
    assignment_of, base_of, commands, default_assign, is_assignment, is_redirection,
    peel_cd_command_word, quoted_body, redirection_body, shell_words, EXPANDS, INTERPRETERS,
};

/// The text of each command's here-document, when every word of it is
/// literal: the commands after it, up to the one that is its delimiter.
/// With it, which commands are lines of a here-document something other
/// than a shell reads, which are data and run nothing.
pub(crate) fn may_set(w: &str, name: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    w.match_indices(name).any(|(i, _)| {
        let (pre, post) = (&w[..i], &w[i + name.len()..]);
        !pre.ends_with(ident)
            && !post.starts_with(ident)
            && (!pre.ends_with(['$', '{']) || post.starts_with('=') || post.starts_with(":="))
    })
}

/// Whether the command `cmd` runs, in the shell that runs it, what the
/// walk does not follow: `eval`, `source` or `.`, or a command word the
/// line does not show (`$c dir`), which may be `cd`, or a `trap` whose
/// action [`trap_moves`]. After one nothing is known of where the line is
/// or what `CDPATH`, `HOME` and `PWD` hold.
/// A `source` or `.` of a literal path is not this: [`sourced`] reads the
/// file and keeps the line when the text cannot move the shell.
pub(crate) fn command_parts(cmd: &[&str]) -> (Vec<String>, String, Vec<String>) {
    let words = operands(cmd);
    let front = (0..words.len())
        .take_while(|&i| is_assignment(words[i]) || keyword_at(&words, i))
        .count();
    let rest = peel_cd_command_word(&words[front..]);
    let name = rest.first().copied().map(base_of).unwrap_or("").to_string();
    let args = rest
        .get(1..)
        .unwrap_or(&[])
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let prefixes = words[..front]
        .iter()
        .copied()
        .filter(|w| is_assignment(w))
        .map(str::to_string)
        .collect();
    (prefixes, name, args)
}

/// `NAME`, `NAME=value` or `NAME+=value`. A flag is not a name.
fn binding_name(w: &str) -> Option<&str> {
    if w.starts_with(['-', '+']) {
        return None;
    }
    if let Some((name, _, _)) = assignment_of(w) {
        return Some(name);
    }
    is_name(w).then_some(w)
}

/// The name `let` assigns in one argument (`x=1`, `++x`, `x++`).
fn let_name(arg: &str) -> Option<String> {
    let arg = arg.trim_start_matches(['+', '-']);
    let end = arg
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(arg.len());
    let name = &arg[..end];
    is_name(name).then(|| name.to_string())
}

/// The word after `flag`, or the text stuck to it (`-vname`).
fn flag_name<'a>(args: &'a [&'a str], flag: &str) -> Option<&'a str> {
    for (i, a) in args.iter().enumerate() {
        let Some(rest) = a.strip_prefix(flag) else {
            continue;
        };
        if rest.is_empty() {
            return args.get(i + 1).copied().filter(|n| is_name(n));
        }
        return is_name(rest).then_some(rest);
    }
    None
}

/// Names an arithmetic assignment writes (`((x=1))`, `$((x+=1))`).
fn arith_targets(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut names = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] != b'(' || b[i + 1] != b'(' {
            i += 1;
            continue;
        }
        let mut depth = 0;
        let mut j = i;
        while j + 1 < b.len() {
            if b[j] == b'(' && b[j + 1] == b'(' {
                depth += 1;
                j += 2;
                continue;
            }
            if b[j] == b')' && b[j + 1] == b')' {
                depth -= 1;
                j += 2;
                if depth == 0 {
                    break;
                }
                continue;
            }
            j += 1;
        }
        let body = &text[i..j.min(text.len())];
        let bytes = body.as_bytes();
        let mut k = 0;
        while k < bytes.len() {
            if bytes[k].is_ascii_alphabetic() || bytes[k] == b'_' {
                let start = k;
                k += 1;
                while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
                    k += 1;
                }
                let name = &body[start..k];
                if is_name(name) && arith_writes(body, name) && !names.iter().any(|n| n == name) {
                    names.push(name.to_string());
                }
                continue;
            }
            k += 1;
        }
        i = j.max(i + 2);
    }
    names
}

/// The name `for NAME in a b` binds, and the words it takes in turn,
/// when each one is a literal the shell does not split, glob or expand.
pub(crate) fn for_literal_list(cmd: &[&str]) -> Option<(String, Vec<String>)> {
    let [head, name, kw, list @ ..] = cmd else {
        return None;
    };
    let plain = |w: &&str| {
        let w = w.strip_prefix("~/").unwrap_or(w);
        !w.is_empty()
            && !w.contains(EXPANDS)
            && !w.contains(['(', '"', '\''])
            && !w.contains(char::is_whitespace)
    };
    let fits = *head == "for" && *kw == "in" && is_name(name);
    (fits && !list.is_empty() && list.len() <= 8 && list.iter().all(plain)).then(|| {
        (
            name.to_string(),
            list.iter().map(|w| w.to_string()).collect(),
        )
    })
}

/// `names` with each `for` name in `each` that `cmd` reads bound to every
/// word of its list in turn. Past 64 ways the names stay as they are.
pub(crate) fn loop_variants(
    names: &[(String, String)],
    each: &[(String, Vec<String>)],
    cmd: &[&str],
) -> Vec<Vec<(String, String)>> {
    let mut out = vec![names.to_vec()];
    for (name, list) in each {
        let (bare, braced) = (format!("${name}"), format!("${{{name}}}"));
        if !cmd.iter().any(|w| w.contains(&bare) || w.contains(&braced)) {
            continue;
        }
        out = out
            .iter()
            .flat_map(|v| {
                list.iter().map(move |word| {
                    let mut v = v.clone();
                    v.push((name.clone(), word.clone()));
                    v
                })
            })
            .collect();
        if out.len() > 64 {
            return vec![names.to_vec()];
        }
    }
    out
}

/// A `for` name that `cmd` binds again no longer takes its list.
pub(crate) fn forget_loop_names(cmd: &[&str], each: &mut Vec<(String, Vec<String>)>) {
    let mut bound = opaque_bound(cmd);
    bound.extend(default_bound(cmd));
    bound.extend(
        cmd.iter()
            .filter_map(|w| assignment_of(w).map(|(n, _, _)| n.to_string())),
    );
    each.retain(|(n, _)| !bound.contains(n));
}

/// Names this command binds other than by a plain `NAME=value`. The value
/// is not what the line shows.
pub(crate) fn opaque_bound(cmd: &[&str]) -> Vec<String> {
    let (prefixes, name, args) = command_parts(cmd);
    let mut out = Vec::new();
    const SPECIAL: &[&str] = &[
        ":", ".", "source", "eval", "exec", "exit", "export", "readonly", "return", "set", "shift",
        "times", "trap", "unset", "break", "continue",
    ];
    let name = name.as_str();
    let arg_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let args = arg_ref.as_slice();
    if SPECIAL.contains(&name) {
        for w in &prefixes {
            if let Some((n, _, _)) = assignment_of(w) {
                out.push(n.to_string());
            }
        }
    }
    if matches!(
        name,
        "export" | "readonly" | "declare" | "typeset" | "local"
    ) {
        for a in args {
            if let Some(n) = binding_name(a) {
                out.push(n.to_string());
            }
        }
    }
    match name {
        "read" | "mapfile" | "readarray" => {
            let found: Vec<String> = args
                .iter()
                .copied()
                .filter(|a| is_name(a))
                .map(str::to_string)
                .collect();
            if found.is_empty() {
                out.push(if name == "read" {
                    "REPLY".into()
                } else {
                    "MAPFILE".into()
                });
            } else {
                out.extend(found);
            }
        }
        "getopts" => {
            let mut i = 0;
            while i < args.len() {
                let a = args[i];
                if a == "--" {
                    i += 1;
                    break;
                }
                if a == "-o" || a.starts_with('-') {
                    i += 1;
                    continue;
                }
                break;
            }
            i += 1;
            while i < args.len() {
                if is_name(args[i]) {
                    out.push(args[i].to_string());
                }
                i += 1;
            }
        }
        "for" | "select" => {
            if let Some(n) = args.first().copied().filter(|a| is_name(a)) {
                out.push(n.to_string());
            }
        }
        "printf" | "wait" => {
            let flag = if name == "printf" { "-v" } else { "-p" };
            if let Some(n) = flag_name(args, flag) {
                out.push(n.to_string());
            }
        }
        "let" => {
            for a in args {
                if let Some(n) = let_name(a) {
                    out.push(n);
                }
            }
        }
        "coproc" => {
            out.push("COPROC".into());
            if let Some(n) = args.first().copied().filter(|a| is_name(a)) {
                out.push(n.to_string());
            }
        }
        _ => {}
    }
    for w in cmd {
        for n in arith_targets(w) {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// Names `${name=value}` or `${name:=value}` assigns. The line does not
/// show that the name was unset, so the value is not known.
fn default_bound(cmd: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for w in cmd {
        let bytes = w.as_bytes();
        let mut i = 0;
        while i + 2 < bytes.len() {
            if bytes[i] == b'$' && bytes[i + 1] == b'{' {
                if let Some(end) = w[i + 2..].find('}') {
                    let body = &w[i + 2..i + 2 + end];
                    if let Some((name, _)) = default_assign(body) {
                        if !out.iter().any(|n| n == name) {
                            out.push(name.to_string());
                        }
                    }
                    i += end + 3;
                    continue;
                }
            }
            i += 1;
        }
    }
    out
}

/// `IFS` is set, unset or bound. A later expansion can split on it.
pub(crate) fn command_sets_ifs(cmd: &[&str]) -> bool {
    let (prefixes, name, args) = command_parts(cmd);
    if name == "unset" && args.iter().any(|a| a == "IFS") {
        return true;
    }
    if prefixes
        .iter()
        .any(|w| assignment_of(w).is_some_and(|(n, _, _)| n == "IFS"))
    {
        return true;
    }
    opaque_bound(cmd).iter().any(|n| n == "IFS")
}

/// `eval` or `trap` can change `$0`, and so can any binding of `BASH_ARGV0`.
pub(crate) fn var_command_name(w: &str) -> Option<&str> {
    let w = quoted_body(w);
    let rest = w.strip_prefix('$')?;
    if let Some(name) = rest.strip_prefix('{') {
        let name = name.strip_suffix('}')?;
        return var_name(name);
    }
    var_name(rest).filter(|_| rest.len() + 1 == w.len())
}

fn var_name(name: &str) -> Option<&str> {
    (!name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then_some(name)
}

/// Empty, or a shell name. Either may stand in for `$name` inside `eval`.
/// `cd`, a space, or `$` may be a command, so those stay unshown.
pub(crate) fn interpreter_flag(name: &str) -> Option<&'static str> {
    let b = name
        .split(|c: char| c.is_ascii_digit())
        .next()
        .unwrap_or(name);
    INTERPRETERS
        .iter()
        .find(|(n, _)| n.trim_end_matches(|c: char| c.is_ascii_digit()) == b)
        .map(|(_, f)| *f)
}

/// Whether the script `text`, read by a shell that holds `aliases`,
/// leaves the shell where it was. `words` is that text with the aliases
/// expanded, function bodies still in place.
pub(crate) fn is_name(w: &str) -> bool {
    let mut chars = w.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(crate) fn may_set_lastpipe(cmd: &[&str]) -> bool {
    let unshown = |w: &&str| w.contains(['$', '`', '*', '?', '[', '{']);
    let words = operands(cmd);
    let front = (0..words.len())
        .take_while(|&i| is_assignment(words[i]) || keyword_at(&words, i))
        .count();
    let Some((w, args)) = peel_cd_command_word(&words[front..]).split_first() else {
        return false;
    };
    let flag = |a: &str, c| a.starts_with('-') && !a.starts_with("--") && a.contains(c);
    match base_of(w) {
        "shopt" => {
            args.iter().any(unshown)
                || (args.iter().any(|a| flag(a, 's')) && args.contains(&"lastpipe"))
        }
        "set" => {
            let opts: Vec<&str> = args.iter().copied().take_while(|a| *a != "--").collect();
            opts.iter().any(unshown)
                || opts
                    .windows(2)
                    .any(|p| flag(p[0], 'o') && p[1] == "lastpipe")
        }
        "eval" => commands(&shell_words(&args.join(" ")))
            .iter()
            .any(|c| may_set_lastpipe(c)),
        _ => unshown(w),
    }
}

/// `w` with each `$PWD` and `${PWD}` in it read as `pwd`, the one
/// directory the line is in when it shows that.
pub(crate) const KEYWORDS: [&str; 10] = [
    "!", "{", "if", "then", "else", "elif", "while", "until", "do", "time",
];

/// Whether `words[i]` is a keyword, or the `-p` of a `time` before it.
pub(crate) fn keyword_at(words: &[&str], i: usize) -> bool {
    KEYWORDS.contains(&words[i]) || (words[i] == "-p" && i > 0 && words[i - 1] == "time")
}

/// Apply to `vars` what the command `cmd` leaves set in the shell that
/// runs it: assignments alone set themselves, `export`, `declare` and the
/// like with plain flags set theirs, and `unset` unsets. A command that
/// writes one some other way ([`written`], `${CDPATH:=dir}`, `{HOME}>f`) leaves it
/// not shown, as do `let` and `eval` naming it and an assignment in front
/// of a special builtin, which some shells keep (`CDPATH=dir :`). A word
/// that only names one (`grep HOME`, `env HOME=dir cmd`) sets nothing.
fn arith_writes(w: &str, name: &str) -> bool {
    const OPS: [&str; 10] = ["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="];
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    w.match_indices(name).any(|(i, _)| {
        let (pre, post) = (&w[..i], &w[i + name.len()..]);
        if pre.ends_with(ident) || post.starts_with(ident) {
            return false;
        }
        let pre = pre.trim_end();
        let mut post = post.trim_start();
        if post.starts_with('[') {
            // A subscript that does not close may hide anything.
            let Some(j) = post.find(']') else {
                return true;
            };
            post = post[j + 1..].trim_start();
        }
        pre.ends_with("++")
            || pre.ends_with("--")
            || post.starts_with("++")
            || post.starts_with("--")
            || (post.starts_with('=') && !post.starts_with("=="))
            || OPS.iter().any(|op| post.starts_with(op))
    })
}

/// The words naming what the command `name` with `args` writes in the
/// shell that runs it: the names `read`, `mapfile`, `getopts` and a
/// `declare` with other than plain flags take, the one after `printf -v`
/// or `wait -p`, and the loop variable of `for` and `select`.
pub(crate) fn operands<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut words = args.iter();
    while let Some(&a) = words.next() {
        if !is_redirection(a) {
            out.push(a);
            continue;
        }
        // The `-` of `2>&-` closes the descriptor and is the whole target;
        // only the heredoc `<<-` still wants the next word.
        let rest = redirection_body(a);
        if rest == "<<-" || rest.chars().all(|c| matches!(c, '>' | '<' | '&' | '|')) {
            words.next();
        }
    }
    out
}
