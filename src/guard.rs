//! Writes onto the files the seat keeps for itself (the hook files, the
//! ljos config, the global git hooks and git config), and content writes
//! out of the work tree.

use std::borrow::Cow;

use super::{
    assignment_of, awk_files, awk_inplace, base_of, chown_paths, copy_target, disk, ended_commands,
    fetched_paths, for_literal_list, forget_loop_names, git_configs, git_subcommand, harm,
    inline_program, inline_written_paths, is_assignment, is_name, is_redirection, is_untracked,
    keyword_at, loop_variants, operands, output_target, outside_content_write, patch_paths,
    perl_files, perl_in_place, quoted_body, remember_declared, sed_files, sed_in_place, tar_paths,
    tilde_home, unzip_paths, Checked, Decision, PolicyReason, KEYWORDS,
};

/// Words that can write a seat file. Anything else returns before the
/// path walk, which is the fast path's whole cost for a plain `echo`.
fn guard_writer(w: &str) -> bool {
    if w.contains('>') {
        return true;
    }
    if script_writer(w) {
        return true;
    }
    matches!(
        base_of(w),
        "touch"
            | "mkdir"
            | "tee"
            | "sponge"
            | "cp"
            | "ln"
            | "mv"
            | "install"
            | "dd"
            | "truncate"
            | "sed"
            | "chmod"
            | "rm"
            | "git"
            | "curl"
            | "wget"
            | "rsync"
            | "tar"
            | "unzip"
            | "patch"
            | "awk"
            | "chown"
            | "rmdir"
    )
}

/// `python3.12` and `node20` are the same writers as `python` and `node`.
fn script_writer(w: &str) -> bool {
    let stem = base_of(w).trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        stem,
        "python" | "pypy" | "node" | "nodejs" | "ruby" | "perl"
    )
}

/// A word that could name a seat file once `~` and `$HOME` are expanded.
/// A long script that never says so skips the path walk.
fn seat_marker(w: &str) -> bool {
    if w.contains('~')
        || w.contains("HOME")
        || w.contains("XDG_")
        || w.contains(".cursor")
        || w.contains(".claude")
        || w.contains("ljos")
        || w.contains("LJOS_POLICYD_CONFIG")
        || w.contains("hooks.json")
        || w.contains("gitconfig")
        || w.contains("/git/")
    {
        return true;
    }
    if let Some(name) = policyd_config().and_then(|p| p.rsplit('/').next().map(str::to_string)) {
        if !name.is_empty() && w.contains(&name) {
            return true;
        }
    }
    let hook = w.contains("hook") || w.contains("Hook") || w.contains("HOOK");
    hook && w
        .as_bytes()
        .windows(9)
        .any(|s| s.eq_ignore_ascii_case(b"hookspath"))
}

fn may_touch_seat(argv: &[String], cwd: Option<&str>) -> bool {
    let config = policyd_config();
    let mut writer = false;
    let mut marker = false;
    for w in argv {
        writer |= guard_writer(w);
        marker |= seat_marker(w)
            || config
                .as_deref()
                .is_some_and(|c| names_config(w, c, argv, cwd));
        if writer && marker {
            return true;
        }
    }
    writer && links_to_seat(argv, cwd)
}

/// Whether a path word of the line reaches a seat file through a link
/// already on the disk, such as `/tmp/c/hooks.json` with `/tmp/c` a
/// link to `~/.cursor` made on an earlier line. The text names no seat
/// file, so [`seat_marker`] does not see it. A relative word is placed
/// in `cwd` and in each absolute `cd` or `pushd` directory of the line.
fn links_to_seat(argv: &[String], cwd: Option<&str>) -> bool {
    let bases: Vec<&str> = cwd
        .into_iter()
        .chain(
            argv.windows(2)
                .filter(|p| matches!(base_of(&p[0]), "cd" | "pushd"))
                .map(|p| unquote(&p[1])),
        )
        .filter(|d| d.starts_with('/'))
        .collect();
    let mut guards = None;
    let mut reaches = |abs: String| {
        let disk = disk_path(&abs);
        disk != abs && guards.get_or_insert_with(GuardSet::real).near(&disk)
    };
    argv.iter().any(|w| {
        let w = unquote(w);
        if !w.contains('/') {
            return false;
        }
        [
            w,
            w.rsplit('=').next().unwrap_or(w),
            w.trim_start_matches(|c: char| c.is_ascii_digit() || "<>&|".contains(c)),
        ]
        .into_iter()
        .map(unquote)
        .any(|p| {
            if p.starts_with('/') {
                landed(p, None).is_some_and(&mut reaches)
            } else {
                bases
                    .iter()
                    .any(|b| landed(p, Some(b)).is_some_and(&mut reaches))
            }
        })
    })
}

/// Whether `w` may name the policyd config `config`. A word is placed
/// against `cwd` and matched on the full path, or on the config dir. Only
/// where the line can move or hide the path, by `cd`, a variable or a
/// command, or from inside the config dir, does the file name alone count.
fn names_config(w: &str, config: &str, argv: &[String], cwd: Option<&str>) -> bool {
    let (dir, name) = config.rsplit_once('/').unwrap_or(("", config));
    if name.is_empty() || !w.contains(name) {
        return !dir.is_empty() && w.contains(dir);
    }
    if w.contains(config) || (!dir.is_empty() && w.contains(dir)) {
        return true;
    }
    let unplaced = w.contains('~')
        || cwd.is_none_or(|c| dir.is_empty() || c == dir || c.starts_with(&format!("{dir}/")))
        || argv
            .iter()
            .any(|a| a.contains(['$', '`']) || matches!(base_of(a), "cd" | "pushd" | "popd"));
    if unplaced {
        return true;
    }
    let w = unquote(w);
    [
        w,
        w.rsplit('=').next().unwrap_or(w),
        w.trim_start_matches(|c: char| c.is_ascii_digit() || "<>&|".contains(c)),
    ]
    .into_iter()
    .any(|p| landed(unquote(p), cwd).is_some_and(|p| p == config))
}

/// The config file `$LJOS_POLICYD_CONFIG` names, as an absolute path.
/// The relay is read from it, so no seat may write it.
fn policyd_config() -> Option<String> {
    let p = std::env::var("LJOS_POLICYD_CONFIG")
        .ok()
        .filter(|p| !p.is_empty())?;
    if p.starts_with('/') {
        return Some(lexical_norm(&p));
    }
    let cwd = std::env::current_dir().ok()?;
    Some(lexical_norm(&cwd.join(p).to_string_lossy()))
}

fn process_home() -> String {
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => lexical_norm(&h),
        _ => {
            let h = tilde_home(None);
            if h.is_empty() || h == "$" {
                String::new()
            } else {
                lexical_norm(&h)
            }
        }
    }
}

fn process_xdg(key: &str, home: &str, suffix: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => lexical_norm(&v),
        _ if !home.is_empty() => format!("{home}/{suffix}"),
        _ => String::new(),
    }
}

/// `.` and `..` and a trailing slash come off. The result is the path
/// the shell would open, without asking the filesystem.
pub(crate) fn lexical_norm(path: &str) -> String {
    let abs = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for c in path.split('/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            if abs || out.last().is_some_and(|s| *s != "..") {
                out.pop();
            } else {
                out.push("..");
            }
            continue;
        }
        out.push(c);
    }
    if !abs {
        return out.join("/");
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

pub(crate) fn unquote(w: &str) -> &str {
    let w = quoted_body(w);
    w.strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .filter(|s| !s.contains('\''))
        .unwrap_or(w)
}

struct GuardSet {
    files: Vec<String>,
    dirs: Vec<String>,
    /// `files` and `dirs` as the disk names them, links followed.
    disk_files: Vec<String>,
    disk_dirs: Vec<String>,
}

impl GuardSet {
    /// The seat files on this machine: hook files, the ljos config, the
    /// policyd config that names the relay, the global git hooks
    /// directory, and the global git config. `XDG_*`
    /// comes from the environment, or from `~/.config` and
    /// `~/.local/share` when it is unset.
    fn real() -> Self {
        let home = process_home();
        let cfg = process_xdg("XDG_CONFIG_HOME", &home, ".config");
        let data = process_xdg("XDG_DATA_HOME", &home, ".local/share");
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        if !home.is_empty() {
            files.push(format!("{home}/.cursor/hooks.json"));
            files.push(format!("{home}/.claude/settings.json"));
            files.push(format!("{home}/.claude/settings.local.json"));
            files.push(format!("{home}/.gitconfig"));
            dirs.push(format!("{home}/.config/ljos-policyd"));
        }
        if !cfg.is_empty() {
            files.push(format!("{cfg}/git/config"));
            dirs.push(format!("{cfg}/ljos"));
            dirs.push(format!("{cfg}/ljos-policyd"));
        }
        files.extend(policyd_config());
        if !data.is_empty() {
            dirs.push(format!("{data}/ljos/git-hooks"));
        }
        let disk = |v: &[String]| v.iter().map(|p| disk_path(p)).collect();
        Self {
            disk_files: disk(&files),
            disk_dirs: disk(&dirs),
            files,
            dirs,
        }
    }

    /// Whether a write to the absolute `path` reaches a seat file. A
    /// link already on the disk, such as `/tmp/c` made on an earlier
    /// line to point at `~/.cursor`, is followed, so `/tmp/c/hooks.json`
    /// is that hook file.
    fn hit(&self, path: &str) -> bool {
        if Self::under(&self.files, &self.dirs, path) {
            return true;
        }
        let disk = disk_path(path);
        Self::under(&self.files, &self.dirs, &disk)
            || Self::under(&self.disk_files, &self.disk_dirs, &disk)
    }

    /// Whether `path` is a seat path, or a directory above or below one.
    fn near(&self, path: &str) -> bool {
        let within = |a: &str, b: &str| {
            a == b || a.strip_prefix(b).is_some_and(|rest| rest.starts_with('/'))
        };
        self.files
            .iter()
            .chain(&self.dirs)
            .chain(&self.disk_files)
            .chain(&self.disk_dirs)
            .any(|g| within(path, g) || within(g, path))
    }

    fn under(files: &[String], dirs: &[String], path: &str) -> bool {
        if files.iter().any(|f| f == path) {
            return true;
        }
        dirs.iter().any(|d| {
            path == d
                || path
                    .strip_prefix(d.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }
}

/// The absolute `path` as the kernel would open it, see [`disk::on_disk`].
fn disk_path(path: &str) -> String {
    disk::on_disk(std::path::Path::new(path))
        .to_string_lossy()
        .into_owned()
}

fn push_name(names: &mut Vec<(String, String)>, key: &str, value: &str, append: bool) {
    let value = unquote(value);
    let value = if append {
        names
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map_or_else(|| value.to_string(), |(_, was)| format!("{was}{value}"))
    } else {
        value.to_string()
    };
    names.push((key.to_string(), value));
}

fn note_assignments(cmd: &[&str], names: &mut Vec<(String, String)>, prefix_only: bool) {
    for w in cmd {
        if let Some((k, v, append)) = assignment_of(w) {
            push_name(names, k, v, append);
            continue;
        }
        if prefix_only && !is_redirection(w) {
            break;
        }
    }
}

/// A directory assignment the shell can use: absolute, or `~`, with no
/// parameter left in it. Anything else keeps the previous value.
fn assigned_dir(names: &[(String, String)], key: &str, home: &str) -> Option<String> {
    let (_, raw) = names.iter().rev().find(|(k, _)| k == key)?;
    let v = unquote(raw);
    if v.is_empty() {
        return Some(String::new());
    }
    let v = if let Some(rest) = v.strip_prefix("~/") {
        if home.is_empty() {
            return None;
        }
        format!("{home}/{rest}")
    } else if v == "~" {
        home.to_string()
    } else {
        v.to_string()
    };
    if !v.starts_with('/') || v.contains(['$', '`', '~', '*', '?', '[']) {
        return None;
    }
    Some(lexical_norm(&v))
}

fn shell_dirs(
    names: &[(String, String)],
    real_home: &str,
    real_cfg: &str,
    real_data: &str,
) -> (String, String, String) {
    let home = assigned_dir(names, "HOME", real_home).unwrap_or_else(|| real_home.to_string());
    let cfg = assigned_dir(names, "XDG_CONFIG_HOME", &home).unwrap_or_else(|| real_cfg.to_string());
    let data = assigned_dir(names, "XDG_DATA_HOME", &home).unwrap_or_else(|| real_data.to_string());
    (home, cfg, data)
}

pub(crate) fn param_at(rest: &str) -> Option<(&str, usize)> {
    if let Some(body) = rest.strip_prefix('{') {
        let j = body.find('}')?;
        let name = &body[..j];
        return is_name(name).then_some((name, j + 2));
    }
    let n = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    (n > 0 && is_name(&rest[..n])).then_some((&rest[..n], n))
}

fn lookup_guard<'a>(
    name: &str,
    names: &'a [(String, String)],
    home: &'a str,
    cfg: &'a str,
    data: &'a str,
) -> Option<&'a str> {
    if let Some((_, v)) = names.iter().rev().find(|(k, _)| k == name) {
        return Some(v.as_str());
    }
    match name {
        "HOME" if !home.is_empty() => Some(home),
        "XDG_CONFIG_HOME" if !cfg.is_empty() => Some(cfg),
        "XDG_DATA_HOME" if !data.is_empty() => Some(data),
        _ => None,
    }
}

/// `$name` and `${name}` from an assignment on this line, then `HOME`
/// and the two `XDG` directories. A quoted form is the same text.
fn subst_guard(
    word: &str,
    names: &[(String, String)],
    home: &str,
    cfg: &str,
    data: &str,
) -> String {
    if !word.contains('$') {
        return word.to_string();
    }
    let mut out = String::new();
    let mut rest = word;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let Some((name, len)) = param_at(rest) else {
            out.push('$');
            continue;
        };
        match lookup_guard(name, names, home, cfg, data) {
            Some(v) => {
                out.push_str(unquote(v));
                rest = &rest[len..];
            }
            None => out.push('$'),
        }
    }
    out.push_str(rest);
    out
}

pub(crate) fn expand_guard(
    word: &str,
    names: &[(String, String)],
    home: &str,
    cfg: &str,
    data: &str,
) -> String {
    // Quotes around `$HOME` or `~` are shell syntax, not part of the path.
    let mut w: String = word.chars().filter(|c| *c != '"' && *c != '\'').collect();
    if let Some(config) = policyd_config() {
        w = w
            .replace("${LJOS_POLICYD_CONFIG}", &config)
            .replace("$LJOS_POLICYD_CONFIG", &config);
    }
    for _ in 0..2 {
        if w.contains('$') {
            w = subst_guard(&w, names, home, cfg, data);
        }
        if home.is_empty() {
            break;
        }
        if let Some(rest) = w.strip_prefix("~/") {
            w = format!("{home}/{rest}");
        } else if w == "~" {
            w = home.to_string();
        } else {
            break;
        }
    }
    w
}

pub(crate) fn landed(path: &str, cwd: Option<&str>) -> Option<String> {
    if path.is_empty() || path.contains(['$', '`', '*', '?', '[', '~']) {
        return None;
    }
    if path.starts_with('/') {
        return Some(lexical_norm(path));
    }
    let cwd = cwd.filter(|p| p.starts_with('/'))?;
    Some(lexical_norm(&format!(
        "{}/{}",
        cwd.trim_end_matches('/'),
        path
    )))
}

/// A symlink this line created: `link` is the new path, `target` is where
/// it points. A later write through `link` is a write to `target`.
pub(crate) fn follow_links(path: &str, links: &[(String, String)]) -> String {
    let mut path = path.to_string();
    for _ in 0..8 {
        let Some((link, target)) = links
            .iter()
            .filter(|(link, _)| path == *link || path.starts_with(&format!("{link}/")))
            .max_by_key(|(link, _)| link.len())
        else {
            break;
        };
        path = if path == *link {
            target.clone()
        } else {
            format!("{target}{}", &path[link.len()..])
        };
        path = lexical_norm(&path);
    }
    path
}

/// The directories and the seat files one command is judged against.
pub(crate) struct GuardLook<'a> {
    pub(crate) names: &'a [(String, String)],
    pub(crate) home: &'a str,
    pub(crate) cfg: &'a str,
    pub(crate) data: &'a str,
    pub(crate) cwd: Option<&'a str>,
    guards: &'a GuardSet,
}

fn guard_path(word: &str, look: &GuardLook<'_>, links: &[(String, String)]) -> Option<String> {
    let expanded = expand_guard(word, look.names, look.home, look.cfg, look.data);
    let abs = landed(&expanded, look.cwd)?;
    let abs = follow_links(&abs, links);
    look.guards.hit(&abs).then_some(abs)
}

fn first_guard<'a, I>(words: I, look: &GuardLook<'_>, links: &[(String, String)]) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    words.into_iter().find_map(|w| guard_path(w, look, links))
}

pub(crate) fn redirect_targets_of<'a>(cmd: &'a [&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < cmd.len() {
        let next = cmd.get(i + 1).copied();
        if let Some((target, ate)) = output_target(cmd[i], next) {
            out.push(target);
            if ate {
                i += 1;
            }
        }
        i += 1;
    }
    out
}

/// Non-option words. A short or long option in `eat_short` / `eat_long`
/// consumes the next word when its value is separate (`touch -r REF`).
pub(crate) fn bare_words<'a>(args: &[&'a str], eat_short: &str, eat_long: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut it = args.iter().copied();
    let mut end = false;
    while let Some(a) = it.next() {
        if end || a == "-" || !a.starts_with('-') {
            out.push(a);
            continue;
        }
        if a == "--" {
            end = true;
            continue;
        }
        if let Some(name) = a.strip_prefix("--") {
            let (name, glued) = name
                .split_once('=')
                .map_or((name, false), |(n, _)| (n, true));
            if !glued && eat_long.contains(&name) {
                it.next();
            }
            continue;
        }
        let cluster = &a[1..];
        if let Some((i, _)) = cluster.char_indices().find(|(_, c)| eat_short.contains(*c)) {
            if cluster[i + 1..].is_empty() {
                it.next();
            }
        }
    }
    out
}

fn is_chmod_mode(p: &str) -> bool {
    let p = unquote(p);
    if p.is_empty() || p.contains('/') || p.starts_with(['~', '$', '.']) {
        return false;
    }
    p.chars().all(|c| c.is_ascii_digit()) || p.contains(['+', '=', ','])
}

fn chmod_paths<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut paths = bare_words(args, "", &["reference"]);
    if paths.first().is_some_and(|p| is_chmod_mode(p)) {
        paths.remove(0);
    }
    paths
}

pub(crate) fn cmd_head<'a>(cmd: &[&'a str]) -> Option<(&'a str, Vec<&'a str>)> {
    let words = operands(cmd);
    let mut i = 0;
    while i < words.len() && (is_assignment(words[i]) || keyword_at(&words, i)) {
        i += 1;
    }
    let head = *words.get(i)?;
    Some((base_of(head), words[i + 1..].to_vec()))
}

/// `git config --global` of `core.hooksPath`, an unset of that key, or
/// `git -c core.hooksPath=...`. A `--get` reads the key and is allowed.
/// The path named by `git config --file` / `-f`, still unexpanded.
fn config_file_arg(rest: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        if a == "--file" || a == "-f" {
            return rest.get(i + 1).map(String::as_str);
        }
        if let Some(v) = a.strip_prefix("--file=") {
            return Some(v);
        }
        if let Some(v) = a.strip_prefix("-f").filter(|v| !v.is_empty()) {
            return Some(v);
        }
        i += 1;
    }
    None
}

/// A `git config` that writes a value. `--get` and a bare key read it.
fn config_writes(rest: &[String]) -> bool {
    let unset = rest.iter().any(|a| {
        matches!(
            a.as_str(),
            "--unset" | "--unset-all" | "--replace-all" | "--add" | "--edit"
        )
    });
    let get = rest.iter().any(|a| {
        matches!(
            a.as_str(),
            "--get" | "--get-all" | "--get-regexp" | "--list" | "-l"
        )
    });
    if get && !unset {
        return false;
    }
    if unset {
        return true;
    }
    let mut skip_file = false;
    let mut operands = 0usize;
    for a in rest {
        if skip_file {
            skip_file = false;
            continue;
        }
        if a == "--file" || a == "-f" {
            skip_file = true;
            continue;
        }
        if a.starts_with("--file=") || (a.starts_with("-f") && a.len() > 2 && !a.starts_with("--"))
        {
            continue;
        }
        if !a.starts_with('-') {
            operands += 1;
        }
    }
    operands >= 2
}

/// `core.hooksPath` set with `--global` or `--system`, or any write
/// through `--file` onto a guarded config. A `--get` stays allowed.
fn git_config_guard(
    cmd: &[&str],
    look: &GuardLook<'_>,
    links: &[(String, String)],
) -> Option<String> {
    let git_at = cmd.iter().position(|w| base_of(w) == "git")?;
    let owned: Vec<String> = cmd[git_at..].iter().map(|s| (*s).to_string()).collect();
    if git_configs(&owned)
        .iter()
        .any(|(k, _)| k == "core.hookspath")
    {
        return Some("core.hooksPath".to_string());
    }
    let (sub, rest) = git_subcommand(&owned)?;
    if sub != "config" {
        return None;
    }
    if let Some(file) = config_file_arg(rest) {
        if config_writes(rest) {
            if let Some(hit) = guard_path(file, look, links) {
                return Some(hit);
            }
        }
    }
    let wide = rest.iter().any(|a| {
        let a = harm::expand_long(a, harm::GIT_CONFIG_LONG);
        a.as_ref() == "--global" || a.as_ref() == "--system"
    });
    if !wide || !config_writes(rest) {
        return None;
    }
    let key = rest
        .iter()
        .any(|a| !a.starts_with('-') && a.eq_ignore_ascii_case("core.hooksPath"));
    key.then(|| "core.hooksPath".to_string())
}

/// `(target, link)` of `ln` / `ln -s`. One operand links under the
/// current directory, named by the target's last part.
fn link_pair(args: &[&str]) -> Option<(String, String)> {
    let mut ops = Vec::new();
    let mut it = args.iter().copied();
    while let Some(a) = it.next() {
        if a == "--" {
            ops.extend(it);
            break;
        }
        if a == "-t" || a == "--target-directory" {
            it.next();
            continue;
        }
        if let Some(rest) = a.strip_prefix("--target-directory=") {
            let _ = rest;
            continue;
        }
        if a.starts_with('-') && a != "-" {
            continue;
        }
        ops.push(a);
    }
    match ops.as_slice() {
        [target, link] => Some(((*target).to_string(), (*link).to_string())),
        [target] => Some(((*target).to_string(), base_of(target).to_string())),
        _ => None,
    }
}

fn resolve_word(word: &str, look: &GuardLook<'_>, links: &[(String, String)]) -> Option<String> {
    let expanded = expand_guard(word, look.names, look.home, look.cfg, look.data);
    let abs = landed(&expanded, look.cwd)?;
    Some(follow_links(&abs, links))
}

/// The command word after assignments and `command` / `builtin`.
fn peeled_head<'a>(cmd: &'a [&'a str]) -> Option<(&'a str, &'a [&'a str])> {
    let mut i = 0;
    while i < cmd.len() && (is_assignment(cmd[i]) || is_redirection(cmd[i])) {
        i += 1;
    }
    while i < cmd.len() && matches!(base_of(cmd[i]), "command" | "builtin") {
        i += 1;
    }
    let head = *cmd.get(i)?;
    Some((base_of(head), &cmd[i + 1..]))
}

/// Where `cd` leaves this shell. `None` when the word is not `cd`.
/// `Some(None)` when it is `cd` and the directory is not known (`cd -`).
fn cd_destination(cmd: &[&str], look: &GuardLook<'_>) -> Option<Option<String>> {
    let (head, args) = peeled_head(cmd)?;
    if head != "cd" {
        return None;
    }
    let ops = bare_words(args, "", &[]);
    match ops.first().copied() {
        None => Some((!look.home.is_empty()).then(|| look.home.to_string())),
        Some("-") => Some(None),
        Some(dest) => {
            let expanded = expand_guard(dest, look.names, look.home, look.cfg, look.data);
            Some(landed(&expanded, look.cwd))
        }
    }
}

fn command_guard_hit(
    cmd: &[&str],
    look: &GuardLook<'_>,
    links: &mut Vec<(String, String)>,
) -> Option<String> {
    if let Some(hit) = first_guard(redirect_targets_of(cmd), look, links) {
        return Some(hit);
    }
    let (head, args) = cmd_head(cmd)?;
    if head == "git" {
        if let Some(hit) = git_config_guard(cmd, look, links) {
            return Some(hit);
        }
    }
    let owned_cmd: Vec<String> = cmd.iter().map(|s| (*s).to_string()).collect();
    let paths: Vec<String> = match head {
        "tee" | "sponge" => bare_words(&args, "", &[])
            .into_iter()
            .map(str::to_string)
            .collect(),
        "cp" | "install" | "rsync" => copy_target(&args, false, &|_| false),
        "ln" => {
            let mut t = copy_target(&args, true, &|_| false);
            if let Some((target, _)) = link_pair(&args) {
                t.push(target);
            }
            t
        }
        "mv" => {
            let mut t = copy_target(&args, false, &|_| false);
            t.extend(
                bare_words(&args, "t", &["target-directory"])
                    .into_iter()
                    .map(str::to_string),
            );
            t
        }
        "dd" => args
            .iter()
            .filter_map(|a| a.strip_prefix("of="))
            .map(str::to_string)
            .collect(),
        "truncate" => bare_words(&args, "sr", &["size", "reference"])
            .into_iter()
            .map(str::to_string)
            .collect(),
        "sed" if sed_in_place(&args) => sed_files(&args),
        "chmod" => chmod_paths(&args).into_iter().map(str::to_string).collect(),
        "rm" | "rmdir" => bare_words(&args, "", &[])
            .into_iter()
            .map(str::to_string)
            .collect(),
        "touch" => bare_words(&args, "drt", &["date", "reference", "time"])
            .into_iter()
            .map(str::to_string)
            .collect(),
        "mkdir" => bare_words(&args, "m", &["mode", "context"])
            .into_iter()
            .map(str::to_string)
            .collect(),
        "curl" | "wget" => fetched_paths(&owned_cmd),
        "tar" => tar_paths(&args),
        "unzip" => unzip_paths(&args),
        "patch" => patch_paths(&args),
        "perl" if perl_in_place(&args) => perl_files(&args),
        _ if script_writer(head) => {
            let run: Vec<String> = std::iter::once(head)
                .chain(args.iter().copied())
                .map(str::to_string)
                .collect();
            inline_program(&run)
                .map(|code| inline_written_paths(unquote(code)))
                .unwrap_or_default()
        }
        "awk" if awk_inplace(&args) => awk_files(&args),
        "chown" => chown_paths(&args),
        _ => Vec::new(),
    };
    if let Some(hit) = paths.iter().find_map(|p| guard_path(p, look, links)) {
        return Some(hit);
    }
    if head == "ln" {
        if let Some((target, link)) = link_pair(&args) {
            let link_at = resolve_word(&link, look, links);
            let target_at = resolve_word(&target, look, links);
            if let (Some(link_at), Some(target_at)) = (link_at, target_at) {
                links.push((link_at, target_at));
            }
        }
    }
    None
}

/// A write onto a file the seat keeps for itself: the hook files,
/// the ljos config directory, the global git hooks directory, and the
/// global git config. The shell hook only sees the top-level command,
/// so a script that writes one of these is judged here. `~`, `$HOME`,
/// `${HOME}` and the `XDG` directories are the path the shell opens,
/// with `..` and a trailing slash taken off.
pub(crate) fn seat_guard_denial(argv: &[String], cwd: Option<&std::path::Path>) -> Option<Checked> {
    if !may_touch_seat(argv, cwd.and_then(|p| p.to_str())) {
        return None;
    }
    written_path_denial(argv, cwd, None)
}

/// The path walk: with no `work`, a write onto a seat file, and with
/// one, a content write out of that tree.
fn written_path_denial(
    argv: &[String],
    cwd: Option<&std::path::Path>,
    work: Option<&std::path::Path>,
) -> Option<Checked> {
    let guards = GuardSet::real();
    let real_home = process_home();
    let real_cfg = process_xdg("XDG_CONFIG_HOME", &real_home, ".config");
    let real_data = process_xdg("XDG_DATA_HOME", &real_home, ".local/share");
    let mut names: Vec<(String, String)> = Vec::new();
    let mut cwd = cwd
        .filter(|p| !is_untracked(p))
        .and_then(|p| p.to_str())
        .filter(|p| p.starts_with('/'))
        .map(ToString::to_string);
    let mut links: Vec<(String, String)> = Vec::new();
    let mut each: Vec<(String, Vec<String>)> = Vec::new();
    let mut prev = "";
    for (cmd, end) in ended_commands(argv) {
        let lead = cmd.iter().take_while(|w| KEYWORDS.contains(w)).count();
        if cmd[lead..].iter().all(|w| is_assignment(w)) {
            note_assignments(&cmd[lead..], &mut names, false);
            forget_loop_names(&cmd, &mut each);
            prev = end;
            continue;
        }
        if let Some((name, list)) = for_literal_list(&cmd) {
            each.retain(|(n, _)| *n != name);
            each.push((name, list));
            prev = end;
            continue;
        }
        let (home, cfg, data) = shell_dirs(&names, &real_home, &real_cfg, &real_data);
        let look = GuardLook {
            names: &names,
            home: &home,
            cfg: &cfg,
            data: &data,
            cwd: cwd.as_deref(),
            guards: &guards,
        };
        let in_pipe = end == "|" || prev == "|";
        let moved = if !in_pipe && end != "&" {
            cd_destination(&cmd, &look)
        } else {
            None
        };
        for names in loop_variants(&names, &each, &cmd) {
            let (home, cfg, data) = shell_dirs(&names, &real_home, &real_cfg, &real_data);
            let look = GuardLook {
                names: &names,
                home: &home,
                cfg: &cfg,
                data: &data,
                ..look
            };
            let seat_hit = command_guard_hit(&cmd, &look, &mut links);
            if let Some(path) = seat_hit.filter(|_| work.is_none()) {
                return Some(Checked {
                    decision: Decision::Deny,
                    code: PolicyReason::PathSensitiveDeny,
                    token: Cow::Owned(format!("seat-guard-path: {path}")),
                });
            }
            if let Some((by, path)) =
                work.and_then(|w| outside_content_write(&cmd, &look, &links, w))
            {
                return Some(Checked {
                    decision: Decision::Deny,
                    code: PolicyReason::PathOutsideWorkspace,
                    token: Cow::Owned(format!("writes-outside: {by} with {path}")),
                });
            }
        }
        forget_loop_names(&cmd, &mut each);
        note_assignments(&cmd, &mut names, true);
        remember_declared(&cmd, &mut names);
        if let Some(next) = moved {
            cwd = next;
        }
        prev = end;
    }
    None
}
