//! The files a command writes: archives, patches, in-place edits, copies,
//! redirections, and inline programs.

use super::{
    bare_words, base_of, cmd_head, command_at, disk, expand_guard, fetched_paths, follow_links,
    inline_program, landed, quoted_strings, redirect_targets_of, saved_name, unquote, GuardLook,
};

/// Paths a `tar` extract writes into, or the archive a `tar -c` creates.
/// A named member is joined onto the `-C` directory in effect for it.
pub(crate) fn tar_paths(args: &[&str]) -> Vec<String> {
    let mut extract = false;
    let mut create = false;
    let mut dirs = Vec::new();
    let mut archive = None;
    let mut cur = ".".to_string();
    let mut members = Vec::new();
    let mut first = true;
    let mut it = args.iter().copied();
    while let Some(a) = it.next() {
        if a == "--extract" || a == "--get" {
            extract = true;
            first = false;
            continue;
        }
        if a == "--create" {
            create = true;
            first = false;
            continue;
        }
        if a == "-C" || a == "--directory" {
            if let Some(d) = it.next() {
                cur = d.to_string();
                dirs.push(d.to_string());
            }
            first = false;
            continue;
        }
        if let Some(d) = a.strip_prefix("--directory=") {
            cur = d.to_string();
            dirs.push(d.to_string());
            first = false;
            continue;
        }
        if a == "-f" || a == "--file" {
            archive = it.next().map(str::to_string);
            first = false;
            continue;
        }
        if let Some(f) = a.strip_prefix("--file=") {
            archive = Some(f.to_string());
            first = false;
            continue;
        }
        if let Some(cluster) = a
            .strip_prefix('-')
            .filter(|c| !c.is_empty() && !c.starts_with('-'))
        {
            extract |= cluster.contains('x');
            create |= cluster.contains('c');
            if let Some(i) = cluster.find('f') {
                let rest = &cluster[i + 1..];
                archive = if rest.is_empty() {
                    it.next().map(str::to_string)
                } else {
                    Some(rest.to_string())
                };
            }
            if let Some(i) = cluster.find('C') {
                let rest = &cluster[i + 1..];
                if rest.is_empty() {
                    if let Some(d) = it.next() {
                        cur = d.to_string();
                        dirs.push(d.to_string());
                    }
                } else {
                    cur = rest.to_string();
                    dirs.push(rest.to_string());
                }
            }
            first = false;
            continue;
        }
        if first
            && a.chars().all(|c| "xtczfjJhvOp".contains(c))
            && (a.contains('x') || a.contains('c'))
        {
            extract |= a.contains('x');
            create |= a.contains('c');
            first = false;
            continue;
        }
        first = false;
        members.push(join_member(&cur, a));
    }
    if extract {
        if members.is_empty() {
            if dirs.is_empty() {
                vec![".".to_string()]
            } else {
                dirs
            }
        } else {
            members
        }
    } else if create {
        archive.into_iter().collect()
    } else {
        Vec::new()
    }
}

fn join_member(dir: &str, member: &str) -> String {
    if member.starts_with('/') || member.starts_with('~') || member.starts_with('$') {
        return member.to_string();
    }
    if dir == "." {
        return member.to_string();
    }
    format!(
        "{}/{}",
        dir.trim_end_matches('/'),
        member.trim_start_matches("./")
    )
}

pub(crate) fn unzip_paths(args: &[&str]) -> Vec<String> {
    let mut dir = ".".to_string();
    let mut members = Vec::new();
    let mut zip = true;
    let mut it = args.iter().copied();
    while let Some(a) = it.next() {
        if a == "-d" {
            if let Some(d) = it.next() {
                dir = d.to_string();
            }
            continue;
        }
        if let Some(d) = a.strip_prefix("-d").filter(|d| !d.is_empty()) {
            dir = d.to_string();
            continue;
        }
        if a.starts_with('-') && a != "-" {
            continue;
        }
        if zip {
            zip = false;
            continue;
        }
        members.push(a.to_string());
    }
    if members.is_empty() {
        vec![dir]
    } else {
        members.iter().map(|m| join_member(&dir, m)).collect()
    }
}

pub(crate) fn patch_paths(args: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter().copied();
    let mut saw_dir = false;
    while let Some(a) = it.next() {
        if matches!(a, "-o" | "-d" | "--output" | "--directory") {
            if let Some(p) = it.next() {
                saw_dir |= a == "-d" || a == "--directory";
                out.push(p.to_string());
            }
            continue;
        }
        if let Some(p) = a
            .strip_prefix("--output=")
            .or_else(|| a.strip_prefix("--directory="))
        {
            saw_dir |= a.starts_with("--directory=");
            out.push(p.to_string());
            continue;
        }
        if a.starts_with('-') && a != "-" {
            continue;
        }
        out.push(a.to_string());
    }
    if out.is_empty() && !saw_dir {
        out.push(".".to_string());
    }
    out
}

pub(crate) fn awk_inplace(args: &[&str]) -> bool {
    args.windows(2).any(|w| w[0] == "-i" && w[1] == "inplace")
        || args.iter().any(|a| *a == "-iinplace" || *a == "--inplace")
}

pub(crate) fn awk_files(args: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter().copied();
    let mut program = false;
    while let Some(a) = it.next() {
        if a == "--" {
            out.extend(it.map(str::to_string));
            break;
        }
        if matches!(a, "-e" | "-f" | "--source" | "--file" | "-v" | "--assign") {
            program |= matches!(a, "-e" | "-f" | "--source" | "--file");
            it.next();
            continue;
        }
        if a == "-i" || a == "--include" {
            it.next();
            continue;
        }
        if a.starts_with('-') && a != "-" {
            continue;
        }
        if !program {
            program = true;
            continue;
        }
        out.push(a.to_string());
    }
    out
}

pub(crate) fn chown_paths(args: &[&str]) -> Vec<String> {
    let mut paths = bare_words(args, "", &["reference", "from"]);
    if paths
        .first()
        .is_some_and(|p| !p.contains('/') && !p.starts_with(['~', '$', '.']))
    {
        paths.remove(0);
    }
    paths.into_iter().map(str::to_string).collect()
}

/// The files `cmd` writes the content of, each with what writes it: a
/// redirection, `tee`, the target of `cp`, `mv`, `install` and `rsync`,
/// `dd of=`, the files of `sed -i`, `perl -i` and `awk -i inplace`, a
/// file an awk program prints into, what `curl` and `wget` save, the link
/// `ln` makes, a file `truncate` sizes, where `tar` extracts or the
/// archive it creates, and the paths an inline `perl -e`, `node -e` or
/// `ruby -e` program that writes files spells out.
fn content_writes<'a>(cmd: &[&'a str]) -> Vec<(&'a str, String)> {
    let mut out: Vec<(&str, String)> = redirect_targets_of(cmd)
        .into_iter()
        .map(|t| (">", t.to_string()))
        .collect();
    let Some((head, args)) = cmd_head(cmd) else {
        return out;
    };
    let paths = match head {
        "tee" | "sponge" => bare_words(&args, "", &[])
            .into_iter()
            .map(str::to_string)
            .collect(),
        "cp" | "install" | "mv" | "rsync" => copy_target(&args, false, &|_| false),
        "ln" => copy_target(&args, true, &|_| false),
        "curl" | "wget" => {
            let owned: Vec<String> = cmd.iter().map(|s| (*s).to_string()).collect();
            fetched_paths(&owned)
        }
        "truncate" => bare_words(&args, "sr", &["size", "reference"])
            .into_iter()
            .map(str::to_string)
            .collect(),
        "tar" => tar_paths(&args),
        "dd" => args
            .iter()
            .filter_map(|a| a.strip_prefix("of="))
            .map(str::to_string)
            .collect(),
        "sed" if sed_in_place(&args) => {
            let given = args.iter().any(|a| {
                matches!(*a, "--expression" | "--file")
                    || a.starts_with("--expression=")
                    || a.starts_with("--file=")
                    || a.strip_prefix('-')
                        .filter(|f| !f.starts_with('-'))
                        .and_then(|f| f.chars().find(|c| matches!(c, 'e' | 'f' | 'l')))
                        .is_some_and(|c| c != 'l')
            });
            let files = sed_files(&args);
            files.into_iter().skip(usize::from(!given)).collect()
        }
        "perl" if perl_in_place(&args) => {
            let given = args.iter().any(|a| {
                a.strip_prefix('-')
                    .filter(|f| !f.starts_with('-'))
                    .is_some_and(|f| perl_cluster(f).1)
            });
            let files = perl_files(&args);
            files.into_iter().skip(usize::from(!given)).collect()
        }
        "perl" | "node" | "ruby" => {
            let run: Vec<String> = std::iter::once(head)
                .chain(args.iter().copied())
                .map(str::to_string)
                .collect();
            inline_program(&run)
                .map(|code| inline_written_paths(unquote(code)))
                .unwrap_or_default()
        }
        "awk" | "gawk" | "mawk" => {
            let mut t = if awk_inplace(&args) {
                awk_files(&args)
            } else {
                Vec::new()
            };
            t.extend(awk_printed_files(&args));
            t
        }
        _ => Vec::new(),
    };
    out.extend(paths.into_iter().map(|p| (head, p)));
    out
}

/// Names in an inline perl, node or ruby program that may make, change
/// or remove a file.
const INLINE_WRITE_CALLS: &[&str] = &[
    "open",
    "rename",
    "link",
    "unlink",
    "mkdir",
    "rmdir",
    "truncate",
    "copy",
    "move",
    "chmod",
    "utime",
    "write",
    "append",
    "FileUtils",
    "rm_",
    "rmSync",
    "cpSync",
    "mkpath",
    "make_path",
];

/// The paths an inline program spells when it may write files: each
/// quoted string that, past a perl open mode such as `>` or `+<`, starts
/// at `/` or `~` or climbs with `..`. A path the program builds is not
/// placed, as for a shell write.
pub(crate) fn inline_written_paths(code: &str) -> Vec<String> {
    if !INLINE_WRITE_CALLS.iter().any(|c| code.contains(c)) {
        return Vec::new();
    }
    program_literals(code)
        .into_iter()
        .map(|s| {
            s.trim_start_matches(['+', '<', '>', '|'])
                .trim()
                .to_string()
        })
        .filter(|s| {
            ((s.starts_with('/') || s.starts_with('~')) && s.chars().any(char::is_alphanumeric))
                || s.split('/').any(|p| p == "..")
        })
        .collect()
}

/// The string literals an inline program spells: each quoted string, and
/// the body of a perl `q`, `qq` or `qw` or a ruby `%q`, `%Q`, `%w` or
/// `%W`, with any delimiter. A paired delimiter such as `{}` nests. A
/// `qw` or `%w` list gives each of its words.
fn program_literals(code: &str) -> Vec<String> {
    let mut out = quoted_strings(code);
    let chars: Vec<char> = code.chars().collect();
    let word = |c: char| c.is_alphanumeric() || matches!(c, '_' | '$' | '@' | '%' | '&');
    let mut i = 0;
    while i < chars.len() {
        if i > 0 && word(chars[i - 1]) {
            i += 1;
            continue;
        }
        let rest: String = chars[i..chars.len().min(i + 2)].iter().collect();
        let (len, words, spaced) = if rest == "qq" {
            (2, false, true)
        } else if rest == "qw" {
            (2, true, true)
        } else if rest.starts_with('q') {
            (1, false, true)
        } else if matches!(rest.as_str(), "%q" | "%Q") {
            (2, false, false)
        } else if matches!(rest.as_str(), "%w" | "%W") {
            (2, true, false)
        } else {
            i += 1;
            continue;
        };
        let mut j = i + len;
        while spaced && chars.get(j).is_some_and(|c| *c == ' ') {
            j += 1;
        }
        let Some(&open) = chars.get(j) else {
            break;
        };
        if open.is_alphanumeric() || open.is_whitespace() || "_,;=)]}>".contains(open) {
            i += 1;
            continue;
        }
        let close = match open {
            '(' => ')',
            '[' => ']',
            '{' => '}',
            '<' => '>',
            c => c,
        };
        let mut depth = 0;
        let mut body = String::new();
        let mut k = j + 1;
        while k < chars.len() {
            let c = chars[k];
            if c == '\\' && k + 1 < chars.len() {
                body.push(chars[k + 1]);
                k += 2;
                continue;
            }
            if c == close && depth == 0 {
                break;
            }
            if open != close && c == open {
                depth += 1;
            } else if open != close && c == close {
                depth -= 1;
            }
            body.push(c);
            k += 1;
        }
        if words {
            out.extend(body.split_whitespace().map(str::to_string));
        } else {
            out.push(body);
        }
        i = k + 1;
    }
    out
}

/// The literal files an awk program prints into: `print > "f"` and
/// `printf ... >> "f"`. A `>` before a string is read as one even where
/// it compares, so a program never hides a write as a comparison.
fn awk_printed_files(args: &[&str]) -> Vec<String> {
    let program = args
        .iter()
        .position(|a| matches!(*a, "-e" | "--source"))
        .and_then(|i| args.get(i + 1))
        .or_else(|| args.iter().find(|a| !a.starts_with('-')));
    let Some(program) = program else {
        return Vec::new();
    };
    let program = unquote(program);
    let mut out = Vec::new();
    let mut rest = program;
    while let Some(i) = rest.find('>') {
        let after = rest[i + 1..].trim_start_matches('>').trim_start();
        rest = &rest[i + 1..];
        if let Some(body) = after.strip_prefix('"') {
            if let Some(end) = body.find('"') {
                out.push(body[..end].to_string());
            }
        }
    }
    out
}

/// The first content write of `cmd` that goes out of `work`, with what
/// writes it and the path it writes. A target the line does not spell out,
/// or a relative one where the directory is not known, is not placed.
pub(crate) fn outside_content_write(
    cmd: &[&str],
    look: &GuardLook<'_>,
    links: &[(String, String)],
    work: &std::path::Path,
) -> Option<(String, String)> {
    content_writes(cmd).into_iter().find_map(|(by, word)| {
        let expanded = expand_guard(&word, look.names, look.home, look.cfg, look.data);
        if expanded.starts_with('~') {
            return Some((by.to_string(), expanded));
        }
        let at = landed(&expanded, look.cwd)?;
        // The link `ln` makes is the write, not the file it points at.
        let abs = if by == "ln" {
            at
        } else {
            follow_links(&at, links)
        };
        disk::writes_outside(std::path::Path::new(&abs), Some(work)).then(|| (by.to_string(), abs))
    })
}

/// The file a stdout redirection writes: `> i.sh`, `>i.sh`, `>>i.sh`,
/// `2> i.sh`, `>|i.sh`, and `>&i.sh`, which writes stdout and stderr
/// there. `>&1`, `2>&1` and `>&-` duplicate or close a descriptor.
pub(crate) fn output_target<'a>(word: &'a str, next: Option<&'a str>) -> Option<(&'a str, bool)> {
    let fd = |t: &str| t == "-" || (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()));
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit());
    let rest = rest.strip_prefix("&>").or_else(|| rest.strip_prefix('>'))?;
    if let Some(dup) = rest.strip_prefix('&') {
        if dup.is_empty() {
            let target = next.filter(|t| !fd(t) && !matches!(*t, "|" | ">" | ">>"))?;
            return Some((target, true));
        }
        return (!fd(dup)).then_some((dup, false));
    }
    let rest = rest.trim_start_matches(['>', '|']);
    if rest.is_empty() {
        let target = next.filter(|t| !t.starts_with('&') && !matches!(*t, "|" | ">" | ">>"))?;
        return Some((target, true));
    }
    Some((rest, false))
}

/// Files a command's stdout redirections name, by last path part.
pub(crate) fn redirection_files(argv: &[String]) -> Vec<String> {
    redirection_targets(argv)
        .into_iter()
        .filter_map(saved_name)
        .collect()
}

/// The words a command's output redirections name as the file.
fn redirection_targets(argv: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let next = argv.get(i + 1).map(String::as_str);
        if let Some((target, ate)) = output_target(&argv[i], next) {
            if saved_name(target).is_some() {
                out.push(target);
            }
            if ate {
                i += 1;
            }
        }
        i += 1;
    }
    out
}

/// Files `tee` writes, by last path part. Flags are not files.
pub(crate) fn tee_files(cmd: &[String]) -> Vec<String> {
    tee_paths(cmd).into_iter().filter_map(saved_name).collect()
}

/// The words that name the files `tee` writes.
fn tee_paths(cmd: &[String]) -> Vec<&str> {
    let Some(at) = command_at(cmd) else {
        return Vec::new();
    };
    if base_of(&cmd[at]) != "tee" {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut args = cmd[at + 1..].iter().map(String::as_str);
    while let Some(a) = args.next() {
        if a == "--" {
            out.extend(args.filter(|a| saved_name(a).is_some()));
            break;
        }
        if !a.starts_with('-') && saved_name(a).is_some() {
            out.push(a);
        }
    }
    out
}

/// Commands known to change no file but by a redirection the line
/// shows, or only by removing one or changing its mode, which leaves
/// no script with new text.
pub(crate) fn perl_in_place(args: &[&str]) -> bool {
    args.iter()
        .take_while(|a| **a != "--")
        .filter_map(|a| a.strip_prefix('-').filter(|f| !f.starts_with('-')))
        .any(|f| perl_cluster(f).0)
}

/// Whether a `perl` switch cluster edits in place, and whether the word
/// after it is the program `-e` or `-E` takes. A switch with a value
/// (`-i.bak`, `-Mstrict`, `-I lib`) ends the cluster.
fn perl_cluster(cluster: &str) -> (bool, bool) {
    for (k, c) in cluster.char_indices() {
        match c {
            'i' => return (true, false),
            'e' | 'E' => return (false, k + 1 == cluster.len()),
            'I' | 'M' | 'm' | 'x' | 'C' | 'd' | 'D' | '0' | 'l' => return (false, false),
            _ => {}
        }
    }
    (false, false)
}

/// The operands of a `perl`, past the program `-e` or `-E` takes, alone
/// or at the end of a cluster (`-pe`). With no `-e` the first is the
/// program file, which is kept: a path no script is run from.
pub(crate) fn perl_files(args: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut words = args.iter().copied();
    let mut end = false;
    while let Some(a) = words.next() {
        if end || !a.starts_with('-') || a == "-" {
            out.push(a.to_string());
        } else if a == "--" {
            end = true;
        } else if perl_cluster(&a[1..]).1 {
            words.next();
        }
    }
    out
}

/// The paths a `cp`, `mv`, `ln` or `install` writes. Into a directory
/// (`-t`, a trailing `/`, several sources, or one `is_dir` names) each
/// source lands as `dir/name`, unless the copy is recursive and may
/// fill the directory. An `ln` with one operand makes a link of that
/// name where it runs.
pub(crate) fn copy_target(args: &[&str], ln: bool, is_dir: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut ops = Vec::new();
    let mut target = None;
    let mut no_target = false;
    let mut recursive = false;
    let mut words = args.iter().copied();
    let mut end = false;
    while let Some(a) = words.next() {
        if end || !a.starts_with('-') || a == "-" {
            ops.push(a);
            continue;
        }
        if a == "--" {
            end = true;
        } else if let Some(t) = a.strip_prefix("--target-directory") {
            target = t.strip_prefix('=').or_else(|| words.next());
        } else if matches!(a, "--suffix" | "--mode" | "--owner" | "--group") {
            words.next();
        } else if a == "--no-target-directory" {
            no_target = true;
        } else if matches!(a, "--recursive" | "--archive") {
            recursive = true;
        } else if let Some(f) = a.strip_prefix('-').filter(|f| !f.starts_with('-')) {
            for (k, c) in f.char_indices() {
                no_target |= c == 'T';
                recursive |= matches!(c, 'r' | 'R' | 'a');
                if matches!(c, 't' | 'S' | 'm' | 'o' | 'g') {
                    let v = &f[k + 1..];
                    let v = if v.is_empty() { words.next() } else { Some(v) };
                    if c == 't' {
                        target = v;
                    }
                    break;
                }
            }
        }
    }
    let name = |src: &str| base_of(src.trim_end_matches('/')).to_string();
    let (dir, sources) = match (target, ops.as_slice()) {
        (Some(t), _) => (t, &ops[..]),
        (None, [one]) if ln => return vec![name(one)],
        (None, [srcs @ .., last]) if !srcs.is_empty() => {
            let into = !no_target && (srcs.len() > 1 || last.ends_with('/') || is_dir(last));
            if !into {
                return vec![(*last).to_string()];
            }
            (*last, srcs)
        }
        _ => return Vec::new(),
    };
    if recursive {
        return vec![dir.to_string()];
    }
    let dir = dir.trim_end_matches('/');
    sources
        .iter()
        .map(|s| format!("{dir}/{}", name(s)))
        .collect()
}

/// Whether a `sed` with `args` edits its files in place.
pub(crate) fn sed_in_place(args: &[&str]) -> bool {
    args.iter().any(|a| {
        a.starts_with("--in-place")
            || a.strip_prefix('-')
                .filter(|f| !f.starts_with('-'))
                .is_some_and(|f| f.split(['e', 'f', 'l']).next().unwrap_or("").contains('i'))
    })
}

/// The operands of a `sed`, past the script and option values. With no
/// `-e` or `-f` the first is the script, which is kept: a path it might
/// name is still no file the line runs.
pub(crate) fn sed_files(args: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut words = args.iter().copied();
    while let Some(a) = words.next() {
        if matches!(a, "--expression" | "--file" | "--line-length") {
            words.next();
        } else if let Some(f) = a
            .strip_prefix('-')
            .filter(|f| !f.starts_with('-') && !f.is_empty())
        {
            if f.find(['e', 'f', 'l']).is_some_and(|k| k + 1 == f.len()) {
                words.next();
            }
        } else if !a.starts_with("--") {
            out.push(a.to_string());
        }
    }
    out
}
