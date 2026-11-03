//! What `xargs` and `parallel` read, and the commands they build from it.

use super::{
    base_of, echo_text, ended_commands, git_subcommand, literal_text, split_env_strings, under_tmp,
    unwrap_wrappers, TRASHERS,
};

/// A `find` on the line whose `-exec` payload does not show its command.
/// Some word names one of `names`, or a packed string holds that name.
/// Callers that split every command use this to skip that split.
pub(crate) fn mentions(argv: &[String], names: &[&str]) -> bool {
    argv.iter().any(|w| {
        w.split(char::is_whitespace)
            .any(|p| !p.is_empty() && names.contains(&base_of(p)))
    })
}

/// A command whose allow or deny turns on an operand or a flag the line
/// may not show. `grep`, `cat` and `wc` are not among them: every extra
/// word leaves the same verdict.
pub(crate) fn fed_sensitive(cmd: &[String]) -> bool {
    let Some(head) = cmd.first() else {
        return false;
    };
    let b = base_of(head);
    if matches!(
        b,
        "rm" | "srm"
            | "wipe"
            | "rmdir"
            | "unlink"
            | "shred"
            | "dd"
            | "truncate"
            | "mv"
            | "cp"
            | "chmod"
            | "chown"
            | "chgrp"
            | "setfacl"
            | "rsync"
            | "find"
    ) || TRASHERS.contains(&b)
        || (b == "gio" && cmd.get(1).map(String::as_str) == Some("trash"))
    {
        return true;
    }
    if b != "git" {
        return false;
    }
    // No subcommand yet: the words still to come can be `push -f`.
    matches!(
        git_subcommand(cmd).map(|(s, _)| s),
        Some("clean" | "push" | "reset" | "checkout") | None
    )
}

/// How `xargs` or `parallel` turns the text it reads into arguments.
#[derive(Clone)]
struct FeedSplit {
    /// `Blank` is the default. `-0` is a NUL. `-d` is one character.
    /// A replace string takes whole lines.
    nul: bool,
    delim: Option<char>,
    lines: bool,
    /// `Some(n)` keeps `n` arguments for each invocation. `None` appends
    /// every argument to one invocation, which is what `xargs` does.
    group: Option<usize>,
    replace: Option<String>,
    /// `-a FILE` reads a file the line does not show.
    argfile: bool,
    /// `parallel --arg-sep SEP`. The inputs start at the next `SEP`.
    argsep: Option<String>,
}

/// The text a literal `printf` writes, reusing its format while arguments
/// remain. `\0` is a NUL. Any other conversion is not this text.
fn printf_feed(args: &[String]) -> Option<String> {
    let args = if args.first().is_some_and(|a| a == "--") {
        &args[1..]
    } else {
        args
    };
    if args.first().is_some_and(|a| a.starts_with('-')) {
        return None;
    }
    let (fmt, mut rest) = args.split_first()?;
    if !literal_text(fmt) || rest.iter().any(|a| !literal_text(a)) {
        return None;
    }
    let mut out = String::new();
    loop {
        let (piece, used) = printf_feed_once(fmt, rest)?;
        out.push_str(&piece);
        if used == 0 || used >= rest.len() {
            break;
        }
        rest = &rest[used..];
    }
    Some(out)
}

fn printf_feed_once(fmt: &str, args: &[String]) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut chars = fmt.chars();
    let mut ai = 0;
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some('0') => out.push('\0'),
                _ => return None,
            }
            continue;
        }
        if c == '%' {
            match chars.next() {
                Some('%') => out.push('%'),
                Some('s') => {
                    out.push_str(args.get(ai)?);
                    ai += 1;
                }
                _ => return None,
            }
            continue;
        }
        out.push(c);
    }
    Some((out, ai))
}

/// The words `text` contributes. A trailing separator does not add an
/// empty word. Blank-separated input drops empty fields.
fn split_feed(text: &str, spec: &FeedSplit) -> Vec<String> {
    let mut parts: Vec<String> = if spec.nul {
        text.split('\0').map(str::to_string).collect()
    } else if let Some(c) = spec.delim {
        text.split(c).map(str::to_string).collect()
    } else if spec.lines {
        text.split('\n').map(str::to_string).collect()
    } else {
        return text.split_whitespace().map(str::to_string).collect();
    };
    if parts.last().is_some_and(|s| s.is_empty()) {
        parts.pop();
    }
    parts
}

/// Flags of one `xargs` or `parallel` that say where its arguments come
/// from. `None` when a flag could hide that, so the input is not taken
/// as shown.
fn parse_feed_flags(flags: &[String]) -> Option<FeedSplit> {
    let mut spec = FeedSplit {
        nul: false,
        delim: None,
        lines: false,
        group: None,
        replace: None,
        argfile: false,
        argsep: None,
    };
    let mut i = 0;
    while i < flags.len() {
        let a = flags[i].as_str();
        if a == "--" {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let mut take = |inline: Option<String>| -> Option<String> {
                if inline.is_some() {
                    inline
                } else {
                    i += 1;
                    flags.get(i).cloned()
                }
            };
            match name {
                "null" => spec.nul = true,
                "delimiter" => {
                    let v = take(inline)?;
                    spec.delim = Some(v.chars().next().filter(|_| v.chars().count() == 1)?);
                }
                "replace" => spec.replace = Some(inline.unwrap_or_else(|| "{}".into())),
                "max-args" | "max-lines" => {
                    spec.group = Some(take(inline)?.parse().ok()?);
                }
                "arg-file" => {
                    spec.argfile = true;
                    if inline.is_none() {
                        i += 1;
                    }
                }
                "env" | "results" | "tmpdir" => {
                    take(inline)?;
                }
                "arg-sep" | "argsep" => spec.argsep = Some(take(inline)?),
                "max-procs" | "eof" | "no-run-if-empty" | "exit" | "verbose" | "interactive"
                | "show-limits" | "process-slot-var" | "help" | "version" | "jobs" => {
                    if matches!(name, "max-procs" | "eof" | "process-slot-var" | "jobs")
                        && inline.is_none()
                    {
                        i += 1;
                    }
                }
                _ => return None,
            }
            i += 1;
            continue;
        }
        let cluster = a.strip_prefix('-').filter(|s| !s.is_empty())?;
        let chars: Vec<char> = cluster.chars().collect();
        let mut k = 0;
        while k < chars.len() {
            let c = chars[k];
            k += 1;
            let rest: String = chars[k..].iter().collect();
            let mut need = |rest: String| -> Option<String> {
                if rest.is_empty() {
                    i += 1;
                    flags.get(i).cloned()
                } else {
                    k = chars.len();
                    Some(rest)
                }
            };
            match c {
                '0' => spec.nul = true,
                'd' => {
                    let v = need(rest)?;
                    spec.delim = Some(v.chars().next().filter(|_| v.chars().count() == 1)?);
                }
                'I' | 'J' => spec.replace = Some(need(rest)?),
                'R' | 'S' => {
                    need(rest)?;
                }
                'i' => {
                    spec.replace = Some(if rest.is_empty() {
                        "{}".into()
                    } else {
                        k = chars.len();
                        rest
                    });
                }
                'n' | 'L' => spec.group = Some(need(rest)?.parse().ok()?),
                'a' => {
                    spec.argfile = true;
                    need(rest)?;
                }
                'P' | 'E' | 's' => {
                    need(rest)?;
                }
                'j' => {
                    if rest.is_empty() && flags.get(i + 1).is_some_and(|w| !w.starts_with('-')) {
                        i += 1;
                    } else {
                        k = chars.len();
                    }
                }
                'r' | 't' | 'p' | 'x' => {}
                _ => return None,
            }
        }
        i += 1;
    }
    if spec.replace.is_some() {
        spec.lines = !spec.nul && spec.delim.is_none();
        spec.group = Some(1);
    }
    Some(spec)
}

pub(crate) fn producer_text(cmd: &[String]) -> Option<String> {
    let owned = split_env_strings(cmd).into_owned();
    let run = unwrap_wrappers(&owned).0;
    let (head, args) = run.split_first()?;
    match base_of(head) {
        "echo" => echo_text(args),
        "printf" => printf_feed(args),
        _ => None,
    }
}

pub(crate) fn ended_owned(argv: &[String]) -> Vec<(Vec<String>, String)> {
    ended_commands(argv)
        .into_iter()
        .map(|(c, s)| (c.iter().map(|w| (*w).to_string()).collect(), s.to_string()))
        .collect()
}

fn feed_end(run: &[String], sep: Option<&str>) -> usize {
    run.iter()
        .position(|w| w == ":::" || w == "::::" || sep.is_some_and(|s| !s.is_empty() && w == s))
        .unwrap_or(run.len())
}

fn parallel_inputs(run: &[String], sep: Option<&str>) -> Option<Result<Vec<String>, ()>> {
    let at = run
        .iter()
        .position(|w| w == ":::" || w == "::::" || sep.is_some_and(|s| !s.is_empty() && w == s))?;
    if run[at] == "::::" || run[at..].iter().any(|w| w == "::::") {
        return Some(Err(()));
    }
    let args = &run[at + 1..];
    if args.iter().any(|a| !literal_text(a)) {
        return Some(Err(()));
    }
    Some(Ok(args.to_vec()))
}

fn parallel_mark(template: &[String], explicit: Option<String>) -> Option<String> {
    if explicit.is_some() {
        return explicit;
    }
    let slot = |w: &str| {
        w.match_indices('{').any(|(i, _)| {
            w[i + 1..].starts_with(|c: char| "}./#%=".contains(c) || c.is_ascii_digit())
        })
    };
    template.iter().any(|w| slot(w)).then(|| "{}".into())
}

pub(crate) fn here_string(cmd: &[String]) -> Option<String> {
    for (i, w) in cmd.iter().enumerate() {
        let Some(rest) = w.strip_prefix("<<<") else {
            continue;
        };
        if rest.is_empty() {
            let next = cmd.get(i + 1)?;
            return literal_text(next).then(|| next.clone());
        }
        return literal_text(rest).then(|| rest.to_string());
    }
    None
}

/// Replace marks of an `xargs` or `parallel` whose shown inputs are all
/// under `/tmp`. The mark is the word the pack would refuse.
pub(crate) fn temp_fed_marks(argv: &[String]) -> Vec<String> {
    if !mentions(argv, &["xargs", "parallel"]) {
        return Vec::new();
    }
    let ended = ended_owned(argv);
    let mut out = Vec::new();
    for (i, (cmd, _)) in ended.iter().enumerate() {
        let owned = split_env_strings(cmd).into_owned();
        let run_all = unwrap_wrappers(&owned).0;
        if run_all.is_empty() {
            continue;
        }
        let wrappers = &owned[..owned.len() - run_all.len()];
        let Some(at) = wrappers
            .iter()
            .rposition(|w| matches!(base_of(w), "xargs" | "parallel"))
        else {
            continue;
        };
        let parallel = base_of(&wrappers[at]) == "parallel";
        let parsed = parse_feed_flags(&wrappers[at + 1..]);
        let opaque = parsed.is_none();
        let argsep = parsed.as_ref().and_then(|s| s.argsep.clone());
        let end = feed_end(run_all, argsep.as_deref());
        let template = &run_all[..end];
        let mut spec = parsed.unwrap_or(FeedSplit {
            nul: false,
            delim: None,
            lines: false,
            group: None,
            replace: None,
            argfile: false,
            argsep: None,
        });
        if parallel {
            spec.group = spec.group.or(Some(1));
            if spec.replace.is_none() {
                spec.replace = parallel_mark(template, None);
            }
            if spec.replace.is_some() {
                spec.lines = !spec.nul && spec.delim.is_none();
            }
        }
        let Some(mark) = spec.replace.clone() else {
            continue;
        };
        if mark.is_empty() || spec.argfile {
            continue;
        }
        let colon = parallel_inputs(run_all, argsep.as_deref());
        let producer = i.checked_sub(1).filter(|&p| ended[p].1 == "|");
        let inputs = if let Some(found) = colon {
            found.ok()
        } else if opaque {
            None
        } else {
            producer.and_then(|p| producer_text(&ended[p].0).map(|t| split_feed(&t, &spec)))
        };
        let Some(inputs) = inputs else {
            continue;
        };
        if !inputs.is_empty() && inputs.iter().all(|p| under_tmp(p)) {
            out.push(mark);
        }
    }
    out
}
