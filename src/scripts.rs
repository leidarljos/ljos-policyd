//! Script targets: what `make clean-all` or `npm run nuke` would run.
//!
//! A task runner hands its recipe to a shell, so the line the guard sees
//! names a target and not the command that runs.
//! This module reads the recipe from the file the runner would read, in
//! the working directory, and returns each line it would run.
//! Nothing is spawned; each file is parsed once per mtime and size.
//! A missing or unreadable runner file yields no lines, so the line is
//! judged as written. An included makefile that cannot be read does not:
//! the recipes it would add are unknown, and the line is refused.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// How many dependency levels a Makefile, justfile or Makefile.toml target
/// is followed through. Makefile `include` nesting stops at the same bound.
const DEP_DEPTH: usize = 8;

/// What [`resolved`] found. `Closed` is a file the guard cannot judge:
/// the line is refused rather than read as if that file were absent.
pub(crate) enum Recipes {
    Lines(Vec<String>),
    Closed(&'static str),
}

/// Lines a runner invocation would hand to a shell, and the directory
/// they run in. `cwd` is where the runner was started. `make -C dir`
/// reads the makefile in `dir` and its recipes run there. Nothing when
/// `run` names no runner this module reads, or its file is missing. An
/// included makefile that cannot be read is [`Recipes::Closed`].
pub(crate) fn resolved_at(run: &[String], cwd: &Path) -> (Recipes, PathBuf) {
    resolved_with(run, cwd, &[])
}

#[cfg(test)]
fn resolved(run: &[String], cwd: &Path) -> Recipes {
    resolved_at(run, cwd).0
}

/// [`resolved_at`], with `env` supplying `MAKEFLAGS`, `MFLAGS` and
/// `GNUMAKEFLAGS` in place of the process environment for those names.
fn resolved_with(run: &[String], cwd: &Path, env: &[(&str, &str)]) -> (Recipes, PathBuf) {
    let here = cwd.to_path_buf();
    let (assigned, run) = split_make_assignments(run);
    let Some(first) = run.first() else {
        return (Recipes::Lines(Vec::new()), here);
    };
    let base = first.rsplit('/').next().unwrap_or(first);
    let rest = &run[1..];
    match base {
        "make" | "gmake" => make(rest, cwd, &assigned, env),
        "npm" => (Recipes::Lines(node("npm", rest, cwd)), here),
        "pnpm" => (Recipes::Lines(node("pnpm", rest, cwd)), here),
        "yarn" => (Recipes::Lines(node("yarn", rest, cwd)), here),
        "bun" => (Recipes::Lines(node("bun", rest, cwd)), here),
        "just" => (Recipes::Lines(just(rest, cwd)), here),
        "cargo" if rest.first().map(String::as_str) == Some("make") => {
            (Recipes::Lines(cargo_make(&rest[1..], cwd)), here)
        }
        "cargo-make" | "makers" => (Recipes::Lines(cargo_make(rest, cwd)), here),
        _ => (Recipes::Lines(Vec::new()), here),
    }
}

/// Whether `run` names one of the runners [`resolved`] reads a file for,
/// whatever its target.
pub(crate) fn runner(run: &[String]) -> bool {
    let (_, run) = split_make_assignments(run);
    let Some(first) = run.first() else {
        return false;
    };
    match first.rsplit('/').next().unwrap_or(first) {
        "make" | "gmake" | "npm" | "pnpm" | "yarn" | "bun" | "just" | "cargo-make" | "makers" => {
            true
        }
        "cargo" => run.get(1).is_some_and(|a| a == "make"),
        _ => false,
    }
}

// ---------------------------------------------------------------- cache

enum Parsed {
    Scripts(HashMap<String, String>),
    Just(Makefile),
    Toml(HashMap<String, Task>),
}

type Cache = Mutex<HashMap<PathBuf, (SystemTime, u64, Arc<Parsed>)>>;

fn load(path: &Path, parse: fn(&str) -> Parsed) -> Option<Arc<Parsed>> {
    static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let stamp = (meta.modified().ok()?, meta.len());
    let cache = CACHE.get_or_init(Cache::default);
    if let Ok(map) = cache.lock() {
        if let Some((m, l, p)) = map.get(path) {
            if (*m, *l) == stamp {
                return Some(p.clone());
            }
        }
    }
    let text = std::fs::read_to_string(path).ok()?;
    let parsed = Arc::new(parse(&text));
    if let Ok(mut map) = cache.lock() {
        map.insert(path.to_path_buf(), (stamp.0, stamp.1, parsed.clone()));
    }
    Some(parsed)
}

fn first_file(dir: &Path, names: &[&str]) -> Option<PathBuf> {
    names.iter().map(|n| dir.join(n)).find(|p| p.is_file())
}

fn join_dir(cwd: &Path, d: &str) -> PathBuf {
    let p = Path::new(d);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

// ----------------------------------------------------------------- make

#[derive(Default)]
struct Makefile {
    vars: HashMap<String, String>,
    rules: HashMap<String, (Vec<String>, Vec<String>)>,
    default: Option<String>,
}

const MAKE_FLAG_TOKEN: &str = "make-flags-unshown";

struct MakeCmd {
    dir: PathBuf,
    files: Vec<PathBuf>,
    includes: Vec<PathBuf>,
    targets: Vec<String>,
    overrides: HashMap<String, String>,
}

fn is_make_flag_name(name: &str) -> bool {
    matches!(name, "MAKEFLAGS" | "MFLAGS" | "GNUMAKEFLAGS")
}

/// Leading `MAKEFLAGS=...` words a shell put in front of the runner.
fn split_make_assignments(run: &[String]) -> (Vec<&str>, &[String]) {
    let n = run
        .iter()
        .take_while(|w| w.split_once('=').is_some_and(|(k, _)| is_make_flag_name(k)))
        .count();
    (run[..n].iter().map(String::as_str).collect(), &run[n..])
}

fn env_flag_value(name: &str, env: &[(&str, &str)]) -> Option<String> {
    if let Some((_, value)) = env.iter().rev().find(|(k, _)| *k == name) {
        return (!value.is_empty()).then(|| (*value).to_string());
    }
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The flag string make would read for `name`: the environment, then a
/// shell assignment in front of the command, then `name=value` on the
/// make command itself. The last one wins.
fn effective_flag<'a>(
    name: &str,
    assigned: &'a [&str],
    args: &'a [String],
    env: &[(&str, &str)],
) -> Option<String> {
    let mut value = env_flag_value(name, env);
    for word in assigned
        .iter()
        .copied()
        .chain(args.iter().map(String::as_str))
    {
        if let Some((k, v)) = word.split_once('=') {
            if !word.starts_with('-') && k == name {
                value = (!v.is_empty()).then(|| v.to_string());
            }
        }
    }
    value
}

fn apply_make_flag_vars(
    state: &mut MakeCmd,
    assigned: &[&str],
    args: &[String],
    env: &[(&str, &str)],
) -> Result<(), &'static str> {
    for name in ["GNUMAKEFLAGS", "MAKEFLAGS", "MFLAGS"] {
        let Some(value) = effective_flag(name, assigned, args, env) else {
            continue;
        };
        let words = split_flag_text(&value)?;
        apply_make_words(&words, false, state)?;
    }
    Ok(())
}

/// `value` as make stores a flag string. A first word with no dash is
/// single-letter options (`ks` is `-k -s`). A letter that takes an
/// argument cannot sit in that word: there is no place for the argument.
fn split_flag_text(value: &str) -> Result<Vec<String>, &'static str> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quote = None;
    for c in value.chars() {
        if quote == Some(c) {
            quote = None;
            continue;
        }
        if quote.is_some() {
            cur.push(c);
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            continue;
        }
        if c.is_whitespace() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            continue;
        }
        cur.push(c);
    }
    if quote.is_some() {
        return Err(MAKE_FLAG_TOKEN);
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    let Some(first) = words.first() else {
        return Ok(words);
    };
    if first.starts_with('-') {
        return Ok(words);
    }
    if !first.chars().all(|c| c.is_ascii_alphanumeric())
        || first.chars().any(|c| "CfIjoOWl".contains(c))
    {
        return Err(MAKE_FLAG_TOKEN);
    }
    let mut out: Vec<String> = first.chars().map(|c| format!("-{c}")).collect();
    out.extend(words.into_iter().skip(1));
    Ok(out)
}

fn apply_make_words(
    words: &[String],
    allow_targets: bool,
    state: &mut MakeCmd,
) -> Result<(), &'static str> {
    let mut i = 0;
    while i < words.len() {
        let a = words[i].as_str();
        // `make {-Cbld,all}` is `make -C bld` after brace expansion. The
        // directory is not the word make was given.
        if super::brace_expands(a) {
            return Err("make-directory-unshown");
        }
        if a == "--" {
            if !allow_targets {
                return Err(MAKE_FLAG_TOKEN);
            }
            state.targets.extend(words[i + 1..].iter().cloned());
            return Ok(());
        }
        if let Some(rest) = a.strip_prefix("--") {
            let (name, inline) = match rest.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (rest, None),
            };
            let (canon, kind) = long_option(name)?;
            match kind {
                LongOpt::Flag => {
                    if inline.is_some() {
                        return Err(MAKE_FLAG_TOKEN);
                    }
                }
                LongOpt::Reject => return Err(MAKE_FLAG_TOKEN),
                LongOpt::Value => {
                    let arg = if let Some(value) = inline {
                        value.to_string()
                    } else {
                        i += 1;
                        words.get(i).ok_or(MAKE_FLAG_TOKEN)?.clone()
                    };
                    apply_long(canon, &arg, state)?;
                }
                LongOpt::Optional => {
                    if let Some(value) = inline {
                        let _ = value;
                    } else if matches!(canon, "jobs" | "load-average")
                        && words
                            .get(i + 1)
                            .is_some_and(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit()))
                    {
                        i += 1;
                    }
                }
            }
            i += 1;
            continue;
        }
        if let Some(cluster) = a.strip_prefix('-').filter(|c| !c.is_empty()) {
            if apply_short(cluster, words.get(i + 1).map(String::as_str), state)? {
                i += 1;
            }
            i += 1;
            continue;
        }
        if let Some((k, v)) = a.split_once('=') {
            if !is_make_flag_name(k) {
                state.overrides.insert(k.to_string(), v.to_string());
            }
            i += 1;
            continue;
        }
        if !allow_targets {
            return Err(MAKE_FLAG_TOKEN);
        }
        state.targets.push(a.to_string());
        i += 1;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum LongOpt {
    Flag,
    Value,
    Optional,
    Reject,
}

/// GNU make's long options. A prefix make accepts has to name one of
/// these. `jobserver-auth` and `jobserver-fds` are how make records the
/// jobserver in `MAKEFLAGS`. `shuffle` and `jobserver-style` are the
/// names a newer make adds; this make does not know them, and a
/// `MAKEFLAGS` from one must not close the read.
const MAKE_LONG: &[(&str, LongOpt)] = &[
    ("help", LongOpt::Flag),
    ("version", LongOpt::Flag),
    ("silent", LongOpt::Flag),
    ("quiet", LongOpt::Flag),
    ("no-silent", LongOpt::Flag),
    ("keep-going", LongOpt::Flag),
    ("stop", LongOpt::Flag),
    ("no-keep-going", LongOpt::Flag),
    ("ignore-errors", LongOpt::Flag),
    ("just-print", LongOpt::Flag),
    ("dry-run", LongOpt::Flag),
    ("recon", LongOpt::Flag),
    ("question", LongOpt::Flag),
    ("touch", LongOpt::Flag),
    ("always-make", LongOpt::Flag),
    ("print-data-base", LongOpt::Flag),
    ("warn-undefined-variables", LongOpt::Flag),
    ("no-builtin-rules", LongOpt::Flag),
    ("no-builtin-variables", LongOpt::Flag),
    ("print-directory", LongOpt::Flag),
    ("no-print-directory", LongOpt::Flag),
    ("check-symlink-times", LongOpt::Flag),
    ("trace", LongOpt::Flag),
    ("file", LongOpt::Value),
    ("makefile", LongOpt::Value),
    ("directory", LongOpt::Value),
    ("include-dir", LongOpt::Value),
    ("jobs", LongOpt::Optional),
    ("load-average", LongOpt::Optional),
    ("max-load", LongOpt::Optional),
    ("output-sync", LongOpt::Optional),
    ("debug", LongOpt::Optional),
    ("jobserver-auth", LongOpt::Optional),
    ("jobserver-fds", LongOpt::Optional),
    ("jobserver-style", LongOpt::Optional),
    ("shuffle", LongOpt::Optional),
    ("eval", LongOpt::Reject),
    ("environment-overrides", LongOpt::Reject),
    ("assume-old", LongOpt::Reject),
    ("assume-new", LongOpt::Reject),
    ("old-file", LongOpt::Reject),
    ("new-file", LongOpt::Reject),
    ("what-if", LongOpt::Reject),
];

/// The long option `name` is. Make takes an unambiguous prefix of a
/// name (`--tr` is `--trace`). A prefix of an option that names a file,
/// a directory or a recipe is refused: the guard would be guessing which
/// file that prefix meant. An unknown name, or two names that share the
/// prefix, is refused too.
fn long_option(name: &str) -> Result<(&'static str, LongOpt), &'static str> {
    if let Some((canon, kind)) = MAKE_LONG.iter().find(|(n, _)| *n == name) {
        return Ok((*canon, *kind));
    }
    let mut hits = MAKE_LONG
        .iter()
        .filter(|(n, _)| !name.is_empty() && n.starts_with(name));
    let Some((canon, kind)) = hits.next() else {
        return Err(MAKE_FLAG_TOKEN);
    };
    if hits.next().is_some() {
        return Err(MAKE_FLAG_TOKEN);
    }
    match kind {
        LongOpt::Value | LongOpt::Reject => Err(MAKE_FLAG_TOKEN),
        _ => Ok((*canon, *kind)),
    }
}

fn apply_long(name: &str, arg: &str, state: &mut MakeCmd) -> Result<(), &'static str> {
    match name {
        "directory" => {
            shown_dir(arg)?;
            state.dir = join_dir(&state.dir, arg);
        }
        "file" | "makefile" => state.files.push(join_dir(&state.dir, arg)),
        "include-dir" => state.includes.push(join_dir(&state.dir, arg)),
        _ => {}
    }
    Ok(())
}

/// A `make -C` directory the line spells out. A variable, a substitution
/// or a glob is not that directory, and an empty one is not either.
fn shown_dir(arg: &str) -> Result<(), &'static str> {
    if arg.is_empty()
        || arg.contains(['$', '`', '*', '?', '[', '~', '{'])
        || super::brace_expands(arg)
    {
        Err("make-directory-unshown")
    } else {
        Ok(())
    }
}

fn apply_short(
    cluster: &str,
    next: Option<&str>,
    state: &mut MakeCmd,
) -> Result<bool, &'static str> {
    let chars: Vec<char> = cluster.chars().collect();
    let mut n = 0;
    let mut consumed = false;
    while n < chars.len() {
        let c = chars[n];
        n += 1;
        match c {
            'b' | 'B' | 'd' | 'h' | 'i' | 'k' | 'L' | 'm' | 'n' | 'p' | 'q' | 'r' | 'R' | 's'
            | 'S' | 't' | 'v' | 'w' => {}
            // These choose which recipes run. The letter is enough; the
            // operand does not have to be read to refuse them.
            'e' | 'E' | 'o' | 'W' => return Err(MAKE_FLAG_TOKEN),
            'C' | 'f' | 'I' | 'O' => {
                let arg = if n < chars.len() {
                    chars[n..].iter().collect()
                } else {
                    consumed = true;
                    next.ok_or(MAKE_FLAG_TOKEN)?.to_string()
                };
                match c {
                    'C' => {
                        shown_dir(&arg)?;
                        state.dir = join_dir(&state.dir, &arg);
                    }
                    'f' => state.files.push(join_dir(&state.dir, &arg)),
                    'I' => state.includes.push(join_dir(&state.dir, &arg)),
                    _ => {}
                }
                break;
            }
            'j' | 'l' => {
                if n < chars.len() {
                    break;
                }
                if next.is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())) {
                    consumed = true;
                }
            }
            _ => return Err(MAKE_FLAG_TOKEN),
        }
    }
    Ok(consumed)
}

fn make(
    args: &[String],
    cwd: &Path,
    assigned: &[&str],
    env: &[(&str, &str)],
) -> (Recipes, PathBuf) {
    let mut state = MakeCmd {
        dir: cwd.to_path_buf(),
        files: Vec::new(),
        includes: Vec::new(),
        targets: Vec::new(),
        overrides: HashMap::new(),
    };
    if let Err(token) = apply_make_flag_vars(&mut state, assigned, args, env) {
        return (Recipes::Closed(token), state.dir);
    }
    if let Err(token) = apply_make_words(args, true, &mut state) {
        return (Recipes::Closed(token), state.dir);
    }
    let dir = state.dir;
    let mut targets = state.targets;
    let overrides = state.overrides;
    let includes = state.includes;
    let named = !state.files.is_empty();
    let paths = if named {
        state.files
    } else {
        first_file(&dir, &["GNUmakefile", "makefile", "Makefile"])
            .into_iter()
            .collect()
    };
    if paths.is_empty() {
        return (Recipes::Lines(Vec::new()), dir);
    }
    let mut mf = Makefile::default();
    let mut stack = Vec::new();
    for path in &paths {
        let text = match read_make_text(path) {
            ReadMake::Text(t) => t,
            // No makefile where make looks by default: the line is judged
            // as written. A file `-f` named and cannot be read is not.
            ReadMake::Missing | ReadMake::Unreadable if !named => {
                return (Recipes::Lines(Vec::new()), dir);
            }
            ReadMake::Missing | ReadMake::Unreadable => {
                return (Recipes::Closed("make-file-unread"), dir);
            }
        };
        stack.push(path.clone());
        match parse_makefile_in(&text, &dir, &includes, 0, &mut stack) {
            Ok(inner) => merge_makefile(&mut mf, inner),
            Err(token) => return (Recipes::Closed(token), dir),
        }
        stack.pop();
    }
    let mut vars = mf.vars.clone();
    vars.extend(overrides);
    vars.entry("MAKE".into()).or_insert_with(|| "make".into());
    vars.entry("RM".into()).or_insert_with(|| "rm -f".into());
    if targets.is_empty() {
        targets.extend(mf.default.clone());
    }
    let mut out = Vec::new();
    let mut seen = Vec::new();
    for t in &targets {
        walk(&mf, t, 0, &mut seen, &mut out);
    }
    (
        Recipes::Lines(out.iter().map(|l| expand(l, &vars, 0)).collect()),
        dir,
    )
}

/// Dependencies first, then the target's own recipe, as make runs them.
fn walk(mf: &Makefile, target: &str, depth: usize, seen: &mut Vec<String>, out: &mut Vec<String>) {
    if depth > DEP_DEPTH || seen.iter().any(|s| s == target) {
        return;
    }
    seen.push(target.to_string());
    if let Some((deps, recipe)) = mf.rules.get(target) {
        for d in deps {
            walk(mf, d, depth + 1, seen, out);
        }
        out.extend(recipe.iter().cloned());
    }
}

/// What opening an included makefile found.
enum ReadMake {
    Text(String),
    /// No file at that path.
    Missing,
    /// There, but not a regular file the guard can read: a directory, a
    /// link loop, or a file that will not open.
    Unreadable,
}

fn read_make_text(path: &Path) -> ReadMake {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ReadMake::Missing,
        Err(_) => ReadMake::Unreadable,
        Ok(meta) if !meta.is_file() => ReadMake::Unreadable,
        Ok(_) => match std::fs::read_to_string(path) {
            Ok(text) => ReadMake::Text(text),
            Err(_) => ReadMake::Unreadable,
        },
    }
}

/// `include`, `-include` or `sinclude`, and the files it names. `included`
/// is not this. An empty list is the directive with no file.
fn include_directive(code: &str) -> Option<(bool, Vec<String>)> {
    let code = code.trim();
    let (optional, rest) = [("include", false), ("-include", true), ("sinclude", true)]
        .into_iter()
        .find_map(|(word, optional)| {
            code.strip_prefix(word)
                .filter(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
                .map(|rest| (optional, rest))
        })?;
    Some((
        optional,
        rest.split_whitespace().map(str::to_string).collect(),
    ))
}

/// `name` relative to `dir`. A name with no slash that is not there is
/// looked up in `-I` directories. A name with a slash is only `dir`.
fn find_include(name: &str, dir: &Path, includes: &[PathBuf]) -> PathBuf {
    let path = Path::new(name);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    let at = dir.join(path);
    if name.contains('/') || at.exists() {
        return at;
    }
    for include in includes {
        let candidate = include.join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    at
}

fn merge_makefile(into: &mut Makefile, from: Makefile) {
    for (name, value) in from.vars {
        into.vars.insert(name, value);
    }
    if into.default.is_none() {
        into.default = from.default;
    }
    for (name, (deps, recipe)) in from.rules {
        let rule = into.rules.entry(name).or_default();
        rule.0.extend(deps);
        rule.1.extend(recipe);
    }
}

/// `text` as a makefile whose `include` paths are relative to `dir`, the
/// directory make is running in. `stack` is the files already being read,
/// so a cycle is not followed. Past [`DEP_DEPTH`] includes, or an include
/// that is missing when it is required or unreadable either way, the
/// makefile cannot be judged.
fn parse_makefile_in(
    text: &str,
    dir: &Path,
    includes: &[PathBuf],
    depth: usize,
    stack: &mut Vec<PathBuf>,
) -> Result<Makefile, &'static str> {
    let mut mf = Makefile::default();
    let mut current: Vec<String> = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(raw) = lines.next() {
        let mut line = raw.to_string();
        while line.ends_with('\\') {
            line.pop();
            match lines.next() {
                Some(n) => line.push_str(n.trim_start()),
                None => break,
            }
        }
        if let Some(body) = line.strip_prefix('\t') {
            let body = body.trim_start_matches(['@', '-', '+', ' ', '\t']);
            if !body.is_empty() {
                for t in &current {
                    if let Some(r) = mf.rules.get_mut(t) {
                        r.1.push(body.to_string());
                    }
                }
            }
            continue;
        }
        let code = line.split('#').next().unwrap_or("").trim_end();
        if code.trim().is_empty() {
            continue;
        }
        if let Some((optional, names)) = include_directive(code) {
            if depth >= DEP_DEPTH {
                return Err("makefile-include-unread");
            }
            for name in names {
                let name = expand(&name, &mf.vars, 0);
                if name.is_empty() || name.contains('$') {
                    if optional {
                        continue;
                    }
                    return Err("makefile-include-unread");
                }
                let path = find_include(&name, dir, includes);
                if stack.iter().any(|seen| seen == &path) {
                    return Err("makefile-include-unread");
                }
                match read_make_text(&path) {
                    ReadMake::Missing if optional => {}
                    ReadMake::Missing | ReadMake::Unreadable => {
                        return Err("makefile-include-unread");
                    }
                    ReadMake::Text(inner) => {
                        stack.push(path);
                        let included = parse_makefile_in(&inner, dir, includes, depth + 1, stack)?;
                        stack.pop();
                        merge_makefile(&mut mf, included);
                    }
                }
            }
            current.clear();
            continue;
        }
        let colon = code.find(':');
        if let Some(eq) = code.find('=') {
            // `X = y`, `X := y`, `X ::= y`, `X ?= y`, `X += y`; a `:` that
            // is not part of the operator makes it a rule.
            let op_start = code[..eq].trim_end_matches([':', '?', '+', '!']).len();
            if colon.is_none_or(|c| c >= op_start) {
                let name = code[..op_start].trim();
                let name = name.strip_prefix("export ").unwrap_or(name).trim();
                let op = &code[op_start..eq];
                let value = code[eq + 1..].trim();
                if op == "+" {
                    let e = mf.vars.entry(name.to_string()).or_default();
                    e.push(' ');
                    e.push_str(value);
                } else if !(op == "?" && mf.vars.contains_key(name)) {
                    mf.vars.insert(name.to_string(), value.to_string());
                }
                current.clear();
                continue;
            }
        }
        let Some(c) = colon else {
            current.clear();
            continue;
        };
        let names: Vec<String> = code[..c].split_whitespace().map(str::to_string).collect();
        let after = code[c..].trim_start_matches(':');
        let (deps, inline) = match after.split_once(';') {
            Some((d, r)) => (d, Some(r.trim())),
            None => (after, None),
        };
        let deps: Vec<String> = deps
            .split('|')
            .flat_map(str::split_whitespace)
            .map(str::to_string)
            .collect();
        current.clear();
        for n in names {
            if n.starts_with('.') && !n.contains('/') {
                continue;
            }
            if mf.default.is_none() && !n.contains('%') {
                mf.default = Some(n.clone());
            }
            let r = mf.rules.entry(n.clone()).or_default();
            r.0.extend(deps.iter().cloned());
            if let Some(i) = inline.filter(|i| !i.is_empty()) {
                r.1.push(i.to_string());
            }
            current.push(n);
        }
    }
    Ok(mf)
}

/// `$(VAR)` and `${VAR}` from the file's own assignments, `$$` as `$`.
/// A name the file does not set stays as written.
fn expand(s: &str, vars: &HashMap<String, String>, depth: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            let c = chars[i + 1];
            if c == '$' {
                out.push('$');
                i += 2;
                continue;
            }
            if c == '(' || c == '{' {
                let close = if c == '(' { ')' } else { '}' };
                if let Some(end) = chars[i + 2..].iter().position(|&x| x == close) {
                    let name: String = chars[i + 2..i + 2 + end].iter().collect();
                    if let Some(v) = vars.get(name.trim()).filter(|_| depth < 4) {
                        out.push_str(&expand(v, vars, depth + 1));
                        i += 3 + end;
                        continue;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

// ----------------------------------------------------- npm, pnpm, yarn

/// npm commands that are not scripts, so `npm install` is never read as
/// `npm run install`.
const NPM_BUILTINS: &[&str] = &[
    "access",
    "adduser",
    "audit",
    "bugs",
    "cache",
    "ci",
    "completion",
    "config",
    "dedupe",
    "deprecate",
    "diff",
    "dist-tag",
    "docs",
    "doctor",
    "edit",
    "exec",
    "explain",
    "explore",
    "find-dupes",
    "fund",
    "help",
    "hook",
    "init",
    "install",
    "install-ci-test",
    "install-test",
    "link",
    "ll",
    "login",
    "logout",
    "ls",
    "org",
    "outdated",
    "owner",
    "pack",
    "ping",
    "pkg",
    "prefix",
    "profile",
    "prune",
    "publish",
    "query",
    "rebuild",
    "repo",
    "root",
    "search",
    "set",
    "shrinkwrap",
    "star",
    "stars",
    "team",
    "token",
    "uninstall",
    "unpublish",
    "unstar",
    "update",
    "version",
    "view",
    "whoami",
    "i",
    "add",
    "remove",
    "rm",
    "up",
    "upgrade",
    "un",
    "x",
    "dlx",
    "create",
    "why",
    "list",
    "info",
    "outdated",
    "store",
    "env",
    "import",
    "workspace",
    "workspaces",
    "plugin",
    "policies",
    "npm",
    "node",
    "bin",
    "global",
    "patch",
    "patch-commit",
    "fetch",
    "licenses",
    "dedupe",
    "setup",
    "self-update",
];

fn node(tool: &str, args: &[String], cwd: &Path) -> Vec<String> {
    let mut dir = cwd.to_path_buf();
    let mut words = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let dir_flag = matches!(
            (tool, a),
            ("npm", "--prefix") | ("pnpm", "-C") | ("pnpm", "--dir") | ("yarn" | "bun", "--cwd")
        );
        if dir_flag {
            i += 1;
            if let Some(d) = args.get(i) {
                dir = join_dir(&dir, d);
            }
        } else if let Some(d) = a
            .strip_prefix("--prefix=")
            .or_else(|| a.strip_prefix("--dir="))
            .or_else(|| a.strip_prefix("--cwd="))
        {
            dir = join_dir(&dir, d);
        } else if a == "--" {
            break;
        } else if !a.starts_with('-') {
            words.push(a);
        }
        i += 1;
    }
    // A bare `bun build` or `bun test` is bun's own bundler or test
    // runner, so bun is read only through `run`.
    let script = match words.as_slice() {
        ["run" | "run-script" | "rs" | "urn", s, ..] => *s,
        [s, ..] if tool != "bun" && !NPM_BUILTINS.contains(s) => *s,
        _ => return Vec::new(),
    };
    let Some(parsed) = load(&dir.join("package.json"), |t| {
        Parsed::Scripts(package_scripts(t).unwrap_or_default())
    }) else {
        return Vec::new();
    };
    let Parsed::Scripts(scripts) = parsed.as_ref() else {
        return Vec::new();
    };
    // npm and pnpm (with enable-pre-post-scripts) run `pre<name>` and
    // `post<name>` around the script, so both are read.
    [
        format!("pre{script}"),
        script.to_string(),
        format!("post{script}"),
    ]
    .iter()
    .filter_map(|k| scripts.get(k).cloned())
    .collect()
}

/// The `scripts` object of a package.json, string values only.
fn package_scripts(text: &str) -> Option<HashMap<String, String>> {
    let mut p = Json {
        s: text.as_bytes(),
        i: 0,
    };
    p.ws();
    p.eat(b'{')?;
    let mut out = HashMap::new();
    loop {
        p.ws();
        if p.eat(b'}').is_some() {
            return Some(out);
        }
        let key = p.string()?;
        p.ws();
        p.eat(b':')?;
        p.ws();
        if key == "scripts" && p.peek() == Some(b'{') {
            p.i += 1;
            loop {
                p.ws();
                if p.eat(b'}').is_some() {
                    break;
                }
                let k = p.string()?;
                p.ws();
                p.eat(b':')?;
                p.ws();
                if p.peek() == Some(b'"') {
                    let v = p.string()?;
                    out.insert(k, v);
                } else {
                    p.skip()?;
                }
                p.ws();
                p.eat(b',');
            }
        } else {
            p.skip()?;
        }
        p.ws();
        p.eat(b',');
    }
}

struct Json<'a> {
    s: &'a [u8],
    i: usize,
}

impl Json<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> Option<()> {
        (self.peek() == Some(c)).then(|| self.i += 1)
    }
    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' | b'f' => out.push(b' '),
                        b'u' => {
                            let hex = std::str::from_utf8(self.s.get(self.i..self.i + 4)?).ok()?;
                            self.i += 4;
                            let ch =
                                char::from_u32(u32::from_str_radix(hex, 16).ok()?).unwrap_or('?');
                            out.extend(ch.to_string().bytes());
                        }
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
    }
    fn skip(&mut self) -> Option<()> {
        self.ws();
        match self.peek()? {
            b'"' => self.string().map(|_| ()),
            open @ (b'{' | b'[') => {
                let close = if open == b'{' { b'}' } else { b']' };
                self.i += 1;
                loop {
                    self.ws();
                    if self.eat(close).is_some() {
                        return Some(());
                    }
                    self.skip()?;
                    self.ws();
                    if self.eat(b':').is_some() {
                        self.skip()?;
                    }
                    self.ws();
                    self.eat(b',');
                }
            }
            _ => {
                while !matches!(self.peek(), None | Some(b',' | b'}' | b']')) {
                    self.i += 1;
                }
                Some(())
            }
        }
    }
}

// ----------------------------------------------------------------- just

fn just(args: &[String], cwd: &Path) -> Vec<String> {
    let mut dir = cwd.to_path_buf();
    let mut file = None;
    let mut target = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-d" || a == "--working-directory" {
            i += 1;
            if let Some(d) = args.get(i) {
                dir = join_dir(&dir, d);
            }
        } else if a == "-f" || a == "--justfile" {
            i += 1;
            file = args.get(i).map(|f| join_dir(cwd, f));
        } else if !a.starts_with('-') && !a.contains('=') && target.is_none() {
            target = Some(a.to_string());
        }
        i += 1;
    }
    let Some(path) = file.or_else(|| first_file(&dir, &["justfile", "Justfile", ".justfile"]))
    else {
        return Vec::new();
    };
    let Some(parsed) = load(&path, |t| Parsed::Just(parse_justfile(t))) else {
        return Vec::new();
    };
    let Parsed::Just(jf) = parsed.as_ref() else {
        return Vec::new();
    };
    let Some(target) = target.or_else(|| jf.default.clone()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk(jf, &target, 0, &mut Vec::new(), &mut out);
    out
}

fn parse_justfile(text: &str) -> Makefile {
    let mut jf = Makefile::default();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            let body = line.trim().trim_start_matches(['@', '-']);
            if let (Some(c), false) = (&current, body.is_empty() || body.starts_with('#')) {
                if let Some(r) = jf.rules.get_mut(c) {
                    r.1.push(body.to_string());
                }
            }
            continue;
        }
        current = None;
        let code = line.trim();
        if code.is_empty() || code.starts_with('#') || code.starts_with('[') {
            continue;
        }
        let Some(c) = code.find(':') else { continue };
        if code[c..].starts_with(":=") || code.starts_with("set ") || code.starts_with("alias ") {
            continue;
        }
        let head = code[..c].trim().trim_start_matches('@');
        let Some(name) = head.split_whitespace().next() else {
            continue;
        };
        let deps = code[c + 1..]
            .split_whitespace()
            .filter(|d| *d != "&&")
            .map(|d| d.trim_start_matches('(').to_string())
            .filter(|d| !d.is_empty() && !d.ends_with(')'))
            .collect();
        if jf.default.is_none() {
            jf.default = Some(name.to_string());
        }
        jf.rules.insert(name.to_string(), (deps, Vec::new()));
        current = Some(name.to_string());
    }
    jf
}

// ----------------------------------------------------------- cargo make

#[derive(Default)]
struct Task {
    deps: Vec<String>,
    lines: Vec<String>,
}

fn cargo_make(args: &[String], cwd: &Path) -> Vec<String> {
    let target = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| "default".into());
    let Some(parsed) = load(&cwd.join("Makefile.toml"), |t| Parsed::Toml(parse_tasks(t))) else {
        return Vec::new();
    };
    let Parsed::Toml(tasks) = parsed.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = Vec::new();
    task_walk(tasks, &target, 0, &mut seen, &mut out);
    out
}

fn task_walk(
    tasks: &HashMap<String, Task>,
    name: &str,
    depth: usize,
    seen: &mut Vec<String>,
    out: &mut Vec<String>,
) {
    if depth > DEP_DEPTH || seen.iter().any(|s| s == name) {
        return;
    }
    seen.push(name.to_string());
    if let Some(t) = tasks.get(name) {
        for d in &t.deps {
            task_walk(tasks, d, depth + 1, seen, out);
        }
        out.extend(t.lines.iter().cloned());
    }
}

/// `[tasks.<name>]` tables: `command` with `args`, `script` as a string or
/// a list, and `dependencies`. Enough TOML for the common shapes.
fn parse_tasks(text: &str) -> HashMap<String, Task> {
    let mut tasks: HashMap<String, Task> = HashMap::new();
    let mut current: Option<String> = None;
    let mut command: Option<String> = None;
    let mut lines = text.lines();
    let flush = |tasks: &mut HashMap<String, Task>,
                 cur: &Option<String>,
                 cmd: &mut Option<String>,
                 args: &[String]| {
        if let (Some(c), Some(cm)) = (cur, cmd.take()) {
            let mut l = cm;
            for a in args {
                l.push(' ');
                l.push_str(a);
            }
            tasks.entry(c.clone()).or_default().lines.push(l);
        }
    };
    let mut args: Vec<String> = Vec::new();
    while let Some(line) = lines.next() {
        let t = line.trim();
        if t.starts_with('[') {
            flush(&mut tasks, &current, &mut command, &args);
            args.clear();
            current = t
                .trim_matches(['[', ']'])
                .strip_prefix("tasks.")
                .map(|n| n.trim_matches('"').to_string());
            if let Some(c) = &current {
                tasks.entry(c.clone()).or_default();
            }
            continue;
        }
        let Some(cur) = current.clone() else { continue };
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let (k, mut v) = (k.trim(), v.trim().to_string());
        // Multi-line strings and arrays run until they close.
        for (open, close) in [("'''", "'''"), ("\"\"\"", "\"\"\""), ("[", "]")] {
            if v.starts_with(open) && !(v.len() > open.len() && v[open.len()..].contains(close)) {
                for more in lines.by_ref() {
                    v.push('\n');
                    v.push_str(more);
                    if more.contains(close) {
                        break;
                    }
                }
            }
        }
        let strings = toml_strings(&v);
        match k {
            "command" => command = strings.into_iter().next(),
            "args" => args = strings,
            "dependencies" => tasks.entry(cur).or_default().deps = strings,
            "script" => {
                let task = tasks.entry(cur).or_default();
                for s in strings {
                    task.lines.extend(
                        s.lines()
                            .map(str::trim)
                            .filter(|l| !l.is_empty())
                            .map(str::to_string),
                    );
                }
            }
            _ => {}
        }
    }
    flush(&mut tasks, &current, &mut command, &args);
    tasks
}

fn toml_strings(v: &str) -> Vec<String> {
    for q in ["'''", "\"\"\""] {
        if let Some(rest) = v.strip_prefix(q) {
            return vec![rest.split(q).next().unwrap_or("").to_string()];
        }
    }
    let mut out = Vec::new();
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' {
            let mut s = String::new();
            while let Some(d) = chars.next() {
                if d == c {
                    break;
                }
                if d == '\\' && c == '"' {
                    if let Some(e) = chars.next() {
                        s.push(e);
                    }
                    continue;
                }
                s.push(d);
            }
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("policyd-scripts-{}-{name}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        for (f, body) in files {
            std::fs::write(d.join(f), body).expect("write");
        }
        d
    }

    fn argv(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    fn recipes(run: &[String], cwd: &Path) -> Vec<String> {
        recipes_env(run, cwd, &[])
    }

    fn recipes_env(run: &[String], cwd: &Path, env: &[(&str, &str)]) -> Vec<String> {
        match resolved_with(run, cwd, env).0 {
            Recipes::Lines(lines) => lines,
            Recipes::Closed(token) => panic!("closed: {token}"),
        }
    }

    #[test]
    fn reads_a_make_target_and_its_dependencies() {
        let d = dir(
            "make",
            &[(
                "Makefile",
                "BUILD := build\n.PHONY: clean-all\nall: build\nclean: ; rm -rf $(BUILD)\nclean-all: clean distclean\n\t@echo done\ndistclean:\n\t-rm -rf ~ \\\n\t  /opt\n",
            )],
        );
        let lines = recipes(&argv(&["make", "clean-all"]), &d);
        assert_eq!(lines, ["rm -rf build", "rm -rf ~ /opt", "echo done"]);
        assert_eq!(
            recipes(&argv(&["make", "-C", ".", "distclean"]), &d),
            ["rm -rf ~ /opt"]
        );
    }

    #[test]
    fn stops_on_a_dependency_cycle() {
        let d = dir("cycle", &[("Makefile", "a: b\n\techo a\nb: a\n\techo b\n")]);
        assert_eq!(recipes(&argv(&["make", "a"]), &d), ["echo b", "echo a"]);
    }

    #[test]
    fn reads_package_scripts_with_pre_and_post() {
        let d = dir(
            "npm",
            &[(
                "package.json",
                r#"{"name":"x","dependencies":{"a":"1"},"scripts":{"prenuke":"echo \"go\"","nuke":"rm -rf / --no-preserve-root","build":"tsc"}}"#,
            )],
        );
        assert_eq!(
            recipes(&argv(&["npm", "run", "nuke"]), &d),
            ["echo \"go\"", "rm -rf / --no-preserve-root"]
        );
        assert_eq!(recipes(&argv(&["yarn", "nuke"]), &d).len(), 2);
        assert_eq!(recipes(&argv(&["pnpm", "build"]), &d), ["tsc"]);
        assert!(recipes(&argv(&["npm", "install"]), &d).is_empty());
        assert_eq!(recipes(&argv(&["bun", "run", "nuke"]), &d).len(), 2);
        let at = d.to_string_lossy();
        assert_eq!(
            recipes(
                &argv(&["bun", "--cwd", &at, "run", "build"]),
                Path::new("/")
            ),
            ["tsc"]
        );
        assert!(recipes(&argv(&["bun", "build"]), &d).is_empty());
    }

    #[test]
    fn reads_just_and_cargo_make() {
        let d = dir(
            "just",
            &[
                ("justfile", "default: build\nbuild:\n    cargo build\nwipe: build\n    rm -rf /\n"),
                (
                    "Makefile.toml",
                    "[tasks.wipe]\ndependencies = [\"pre\"]\ncommand = \"rm\"\nargs = [\"-rf\", \"/\"]\n[tasks.pre]\nscript = '''\necho hi\n'''\n",
                ),
            ],
        );
        assert_eq!(
            recipes(&argv(&["just", "wipe"]), &d),
            ["cargo build", "rm -rf /"]
        );
        assert_eq!(
            recipes(&argv(&["cargo", "make", "wipe"]), &d),
            ["echo hi", "rm -rf /"]
        );
    }

    #[test]
    fn a_missing_file_yields_nothing() {
        let d = dir("empty", &[]);
        assert!(recipes(&argv(&["make", "clean-all"]), &d).is_empty());
        assert!(recipes(&argv(&["npm", "run", "nuke"]), &d).is_empty());
    }

    /// A recipe that lives in an included makefile is the one make runs.
    #[test]
    fn follows_a_makefile_include() {
        let d = dir(
            "inc",
            &[
                ("Makefile", "include extra.mk\nall:\n\techo top\n"),
                ("extra.mk", "clean-all:\n\trm -rf ~\n"),
            ],
        );
        assert_eq!(recipes(&argv(&["make", "clean-all"]), &d), ["rm -rf ~"]);
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("Makefile"), "include extra.mk\n").unwrap();
        std::fs::write(sub.join("extra.mk"), "clean-all:\n\trm -rf ~\n").unwrap();
        assert_eq!(
            recipes(&argv(&["make", "-C", "sub", "clean-all"]), &d),
            ["rm -rf ~"]
        );
    }

    /// A required include that is missing, and an include that is there
    /// but cannot be read, hide whatever recipe make would run.
    #[test]
    fn an_unreadable_include_fails_closed() {
        let d = dir(
            "inc-miss",
            &[("Makefile", "include missing.mk\nclean-all:\n\techo ok\n")],
        );
        assert!(matches!(
            resolved(&argv(&["make", "clean-all"]), &d),
            Recipes::Closed("makefile-include-unread")
        ));
        let d = dir(
            "inc-dir",
            &[("Makefile", "include nested\nclean-all:\n\techo ok\n")],
        );
        std::fs::create_dir_all(d.join("nested")).unwrap();
        assert!(matches!(
            resolved(&argv(&["make", "clean-all"]), &d),
            Recipes::Closed("makefile-include-unread")
        ));
        let d = dir(
            "inc-opt-dir",
            &[("Makefile", "-include nested\nclean-all:\n\techo ok\n")],
        );
        std::fs::create_dir_all(d.join("nested")).unwrap();
        assert!(matches!(
            resolved(&argv(&["make", "clean-all"]), &d),
            Recipes::Closed("makefile-include-unread")
        ));
        let d = dir(
            "inc-opt",
            &[("Makefile", "-include missing.mk\nclean-all:\n\techo ok\n")],
        );
        assert_eq!(recipes(&argv(&["make", "clean-all"]), &d), ["echo ok"]);
        let d = dir(
            "inc-s",
            &[("Makefile", "sinclude missing.mk\nclean-all:\n\techo ok\n")],
        );
        assert_eq!(recipes(&argv(&["make", "clean-all"]), &d), ["echo ok"]);
    }

    #[test]
    fn an_include_cycle_or_a_deep_chain_fails_closed() {
        let d = dir(
            "inc-cycle",
            &[
                ("Makefile", "include a.mk\n"),
                ("a.mk", "include Makefile\nclean-all:\n\techo ok\n"),
            ],
        );
        assert!(matches!(
            resolved(&argv(&["make", "clean-all"]), &d),
            Recipes::Closed("makefile-include-unread")
        ));
        let d = dir("inc-deep", &[]);
        std::fs::write(d.join("n9.mk"), "clean-all:\n\techo ok\n").unwrap();
        for i in (0..9).rev() {
            std::fs::write(
                d.join(format!("n{i}.mk")),
                format!("include n{}.mk\n", i + 1),
            )
            .unwrap();
        }
        std::fs::write(d.join("Makefile"), "include n0.mk\n").unwrap();
        assert!(matches!(
            resolved(&argv(&["make", "clean-all"]), &d),
            Recipes::Closed("makefile-include-unread")
        ));
    }

    /// MAKEFLAGS, on the command line, names the makefile the way `-f`
    /// does. A flag string that does not parse is not a makefile the
    /// guard can choose.
    #[test]
    fn reads_make_flags_from_the_command() {
        let d = dir(
            "mflags",
            &[
                ("Makefile", "clean-all:\n\techo main\n"),
                ("evil.mk", "clean-all:\n\trm -rf ~\n"),
            ],
        );
        assert_eq!(
            recipes(
                &argv(&["make", "MAKEFLAGS=--file=evil.mk", "clean-all"]),
                &d
            ),
            ["rm -rf ~"]
        );
        assert_eq!(
            recipes(&argv(&["make", "MAKEFLAGS=-fevil.mk", "clean-all"]), &d),
            ["rm -rf ~"]
        );
        assert_eq!(
            recipes_env(
                &argv(&["make", "clean-all"]),
                &d,
                &[("MAKEFLAGS", "--file=evil.mk")]
            ),
            ["rm -rf ~"]
        );
        let inc = d.join("inc");
        std::fs::create_dir_all(&inc).unwrap();
        std::fs::write(inc.join("extra.mk"), "clean-all:\n\trm -rf /opt\n").unwrap();
        std::fs::write(d.join("Makefile"), "include extra.mk\n").unwrap();
        assert_eq!(
            recipes(&argv(&["make", "--include-dir", "inc", "clean-all"]), &d),
            ["rm -rf /opt"]
        );
        // Job, output and diagnostic flags do not choose a makefile.
        // `--tr` is `--trace`. A flag that changes which recipes run, or
        // a name make does not have, is not that recipe.
        std::fs::write(d.join("Makefile"), "clean-all:\n\techo main\n").unwrap();
        for flags in [
            " -j8 --jobserver-auth=fifo:/tmp/x -Otarget",
            "w -j8 -Otarget --jobserver-auth=3,4",
            "ks -j2 --jobserver-auth=3,4 --no-print-directory",
            "w --trace",
            "--tr",
            "L",
            "--check-symlink-times",
            "--no-silent",
            "--max-load=2",
            "--jobserver-style=pipe",
            "--shuffle",
        ] {
            assert_eq!(
                recipes(
                    &argv(&["make", &format!("MAKEFLAGS={flags}"), "clean-all"]),
                    &d
                ),
                ["echo main"],
                "{flags}"
            );
        }
        for flags in [
            "-e",
            "e",
            "--environment-overrides",
            "-ofoo",
            "--old-file=foo",
            "--assume-old=foo",
            "-Wfoo",
            "--what-if=foo",
            "--new-file=foo",
            "--assume-new=foo",
            "--eval=$(info hi)",
            "-E$(info hi)",
            "-Z",
            "--not-a-real-flag",
            "--not-a-real-flag=1",
            "--fi=evil.mk",
            "--makef=evil.mk",
            "--dir=sub",
            "--ev=$(shell rm -rf ~)",
            "--environment",
            "--what=all",
        ] {
            assert!(
                matches!(
                    resolved(
                        &argv(&["make", &format!("MAKEFLAGS={flags}"), "clean-all"]),
                        &d
                    ),
                    Recipes::Closed("make-flags-unshown")
                ),
                "{flags}"
            );
        }
        for args in [
            &["make", "--fi=evil.mk", "all"][..],
            &["make", "--makef", "evil.mk"],
            &["make", "--dir=sub"],
            &["make", "--direc", "sub"],
            &["make", "--ev=$(shell rm -rf ~)"],
            &["make", "--environment"],
            &["make", "--what=all"],
        ] {
            assert!(
                matches!(
                    resolved(&argv(args), &d),
                    Recipes::Closed("make-flags-unshown")
                ),
                "{args:?}"
            );
        }
    }
}
