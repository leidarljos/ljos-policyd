//! Script targets: what `make clean-all` or `npm run nuke` would run.
//!
//! A task runner hands its recipe to a shell, so the line the guard sees
//! names a target and not the command that runs.
//! This module reads the recipe from the file the runner would read, in
//! the working directory, and returns each line it would run.
//! Nothing is spawned; each file is parsed once per mtime and size.
//! A missing or unreadable file yields no lines, so the line is judged as
//! written, as before.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// How many dependency levels a Makefile, justfile or Makefile.toml target
/// is followed through.
const DEP_DEPTH: usize = 8;

/// Lines a runner invocation would hand to a shell, with `cwd` as the
/// working directory, or nothing when `run` names no runner the module
/// reads or its file is missing.
pub(crate) fn resolved(run: &[String], cwd: &Path) -> Vec<String> {
    let Some(first) = run.first() else {
        return Vec::new();
    };
    let base = first.rsplit('/').next().unwrap_or(first);
    let rest = &run[1..];
    match base {
        "make" | "gmake" => make(rest, cwd),
        "npm" => node("npm", rest, cwd),
        "pnpm" => node("pnpm", rest, cwd),
        "yarn" => node("yarn", rest, cwd),
        "bun" => node("bun", rest, cwd),
        "just" => just(rest, cwd),
        "cargo" if rest.first().map(String::as_str) == Some("make") => cargo_make(&rest[1..], cwd),
        "cargo-make" | "makers" => cargo_make(rest, cwd),
        _ => Vec::new(),
    }
}

/// Whether `run` names one of the runners [`resolved`] reads a file for,
/// whatever its target.
pub(crate) fn runner(run: &[String]) -> bool {
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
    Make(Makefile),
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

fn make(args: &[String], cwd: &Path) -> Vec<String> {
    let mut dir = cwd.to_path_buf();
    let mut file: Option<PathBuf> = None;
    let mut targets = Vec::new();
    let mut overrides = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let value = |i: &mut usize, short: &str, long: &str| -> Option<String> {
            if a == short || a == long {
                *i += 1;
                return args.get(*i).cloned();
            }
            if let Some(v) = a.strip_prefix(&format!("{long}=")) {
                return Some(v.to_string());
            }
            a.strip_prefix(short)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        if let Some(d) = value(&mut i, "-C", "--directory") {
            dir = join_dir(&dir, &d);
        } else if let Some(f) = value(&mut i, "-f", "--file") {
            file = Some(join_dir(&dir, &f));
        } else if a.starts_with('-') {
        } else if let Some((k, v)) = a.split_once('=') {
            overrides.insert(k.to_string(), v.to_string());
        } else {
            targets.push(a.to_string());
        }
        i += 1;
    }
    let Some(path) = file.or_else(|| first_file(&dir, &["GNUmakefile", "makefile", "Makefile"]))
    else {
        return Vec::new();
    };
    let Some(parsed) = load(&path, |t| Parsed::Make(parse_makefile(t))) else {
        return Vec::new();
    };
    let Parsed::Make(mf) = parsed.as_ref() else {
        return Vec::new();
    };
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
        walk(mf, t, 0, &mut seen, &mut out);
    }
    out.iter().map(|l| expand(l, &vars, 0)).collect()
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

fn parse_makefile(text: &str) -> Makefile {
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
    mf
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

    #[test]
    fn reads_a_make_target_and_its_dependencies() {
        let d = dir(
            "make",
            &[(
                "Makefile",
                "BUILD := build\n.PHONY: clean-all\nall: build\nclean: ; rm -rf $(BUILD)\nclean-all: clean distclean\n\t@echo done\ndistclean:\n\t-rm -rf ~ \\\n\t  /opt\n",
            )],
        );
        let lines = resolved(&argv(&["make", "clean-all"]), &d);
        assert_eq!(lines, ["rm -rf build", "rm -rf ~ /opt", "echo done"]);
        assert_eq!(
            resolved(&argv(&["make", "-C", ".", "distclean"]), &d),
            ["rm -rf ~ /opt"]
        );
    }

    #[test]
    fn stops_on_a_dependency_cycle() {
        let d = dir("cycle", &[("Makefile", "a: b\n\techo a\nb: a\n\techo b\n")]);
        assert_eq!(resolved(&argv(&["make", "a"]), &d), ["echo b", "echo a"]);
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
            resolved(&argv(&["npm", "run", "nuke"]), &d),
            ["echo \"go\"", "rm -rf / --no-preserve-root"]
        );
        assert_eq!(resolved(&argv(&["yarn", "nuke"]), &d).len(), 2);
        assert_eq!(resolved(&argv(&["pnpm", "build"]), &d), ["tsc"]);
        assert!(resolved(&argv(&["npm", "install"]), &d).is_empty());
        assert_eq!(resolved(&argv(&["bun", "run", "nuke"]), &d).len(), 2);
        let at = d.to_string_lossy();
        assert_eq!(
            resolved(
                &argv(&["bun", "--cwd", &at, "run", "build"]),
                Path::new("/")
            ),
            ["tsc"]
        );
        assert!(resolved(&argv(&["bun", "build"]), &d).is_empty());
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
            resolved(&argv(&["just", "wipe"]), &d),
            ["cargo build", "rm -rf /"]
        );
        assert_eq!(
            resolved(&argv(&["cargo", "make", "wipe"]), &d),
            ["echo hi", "rm -rf /"]
        );
    }

    #[test]
    fn a_missing_file_yields_nothing() {
        let d = dir("empty", &[]);
        assert!(resolved(&argv(&["make", "clean-all"]), &d).is_empty());
        assert!(resolved(&argv(&["npm", "run", "nuke"]), &d).is_empty());
    }
}
