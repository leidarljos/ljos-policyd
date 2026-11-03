//! The commands a line runs inside itself: aliases, assigned command words,
//! `-c` scripts, `eval`, `trap`, and container runs.

use std::borrow::Cow;

use super::{
    assignment_of, base_of, bind_positionals, case_head, commands, ended_commands, inline_program,
    is_assignment, keyword_at, literal_text, mapfile_callback, operands, param_at,
    peel_cd_command_word, procsub_body, procsub_of, program_shell_strings, quoted_body,
    script_lines, shell_c_call, shell_stdin, shell_words, split_env_strings, trap_action, unquote,
    unwrap_wrappers, var_command_name, with_names, wrapper_walk, Fed, ProcKind, Walk,
};

/// The commands a line runs once separators are split, wrapper words are
/// taken off, and a shell's `-c` script is read as its own line.
pub(crate) fn inner_commands(argv: &[String]) -> Vec<Vec<String>> {
    inner_commands_at(argv)
        .into_iter()
        .map(|(_, c)| c)
        .collect()
}

/// [`inner_commands`], each with the index in [`commands`] of the command
/// it comes from, once the line's aliases are expanded.
fn inner_commands_at(argv: &[String]) -> Vec<(usize, Vec<String>)> {
    inner_commands_expanded(&expand_aliases(argv))
}

/// `argv` with each command word that an `alias` before it on the line
/// names replaced by the alias's body. dash and zsh expand aliases in a
/// script, as bash does under `shopt -s expand_aliases`, and the line
/// does not say which shell reads it, so expansion may always be on. A
/// body the line does not show (`$`, a backquote) becomes a command word
/// it does not show.
pub(crate) fn expand_aliases(argv: &[String]) -> Cow<'_, [String]> {
    expand_aliases_with(argv, &mut Vec::new())
}

/// [`expand_aliases`] in a shell that already holds `aliases`. The ones
/// `argv` defines are added to it.
fn expand_aliases_with<'a>(
    argv: &'a [String],
    aliases: &mut Vec<(String, String)>,
) -> Cow<'a, [String]> {
    // No alias is defined and none is named, so every word stays as it is.
    // Building the copy and then dropping it was the whole scan.
    if aliases.is_empty() && argv.iter().all(|w| base_of(w) != "alias") {
        return Cow::Borrowed(argv);
    }
    let mut out = Vec::new();
    let mut changed = false;
    for (cmd, end) in ended_commands(argv) {
        let front = (0..cmd.len())
            .take_while(|&i| is_assignment(cmd[i]) || keyword_at(&cmd, i))
            .count();
        let front = front + case_head(&cmd[front..]);
        let mut rest: Vec<String> = cmd[front..].iter().map(|s| (*s).to_string()).collect();
        let mut used: Vec<&String> = Vec::new();
        while let Some((name, body)) = rest
            .first()
            .and_then(|w| aliases.iter().rev().find(|(n, _)| n == w))
            .filter(|(n, _)| !used.contains(&n))
        {
            used.push(name);
            changed = true;
            if body.contains(['$', '`']) {
                rest[0] = format!("${{alias {name}}}");
                break;
            }
            let mut words = shell_words(body);
            words.extend(rest.drain(1..));
            rest = words;
        }
        aliases.extend(alias_defs(&cmd));
        out.extend(cmd[..front].iter().map(|s| (*s).to_string()));
        out.extend(rest);
        out.extend((!end.is_empty()).then(|| end.to_string()));
    }
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(argv)
    }
}

/// The `(name, body)` pairs `cmd` defines when it is `alias`.
fn alias_defs(cmd: &[&str]) -> Vec<(String, String)> {
    let front = (0..cmd.len())
        .take_while(|&i| is_assignment(cmd[i]) || keyword_at(cmd, i))
        .count();
    let front = front + case_head(&cmd[front..]);
    match peel_cd_command_word(&cmd[front..]).split_first() {
        Some((w, defs)) if base_of(w) == "alias" => defs
            .iter()
            .filter_map(|d| d.split_once('='))
            .map(|(n, b)| (n.to_string(), b.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// `$name` or `${name}` when an earlier assignment shows its value.
/// `"$name"` is that word. A longer word is not a command by itself.
fn assigned_words(word: &str, names: &[(String, String)]) -> Option<Vec<String>> {
    let name = var_command_name(word)?;
    let v = names.iter().rev().find(|(k, _)| k == name)?.1.as_str();
    let words = shell_words(v);
    (!words.is_empty()).then_some(words)
}

/// `script` with each `$name` and `${name}` an earlier assignment shows
/// written in place of the parameter. A single-quoted word keeps its
/// `$`. The value is inserted once: the shell does not expand it again.
fn expand_assigned_params<'a>(script: &'a str, names: &[(String, String)]) -> Cow<'a, str> {
    if literal_text(script) || !script.contains('$') {
        return Cow::Borrowed(script);
    }
    let mut out = String::new();
    let mut rest = script;
    let mut changed = false;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let (name, len) = match rest.strip_prefix('{') {
            Some(b) => match b.find('}') {
                Some(j) => (&b[..j], j + 2),
                None => {
                    out.push('$');
                    continue;
                }
            },
            None => {
                let n = rest
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                (&rest[..n], n)
            }
        };
        let plain = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if plain {
            if let Some((_, v)) = names.iter().rev().find(|(k, _)| k == name) {
                out.push_str(v);
                rest = &rest[len..];
                changed = true;
                continue;
            }
        }
        out.push('$');
    }
    out.push_str(rest);
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(script)
    }
}

/// `export`, `readonly`, `declare`, `typeset` and `local` store
/// `NAME=value` in this shell, the same way a bare `NAME=value` does.
/// A flag that does not store that text (`-n`, `-f`, `-a`, `-A`) leaves
/// the name as it was. The plain flags are the ones [`set_vars`] stores.
pub(crate) fn remember_declared(cmd: &[&str], names: &mut Vec<(String, String)>) {
    let words = operands(cmd);
    let front = (0..words.len())
        .take_while(|&i| is_assignment(words[i]) || keyword_at(&words, i))
        .count();
    let rest = peel_cd_command_word(&words[front..]);
    let Some((head, args)) = rest.split_first() else {
        return;
    };
    if !matches!(
        base_of(head),
        "export" | "readonly" | "declare" | "typeset" | "local"
    ) {
        return;
    }
    let plain =
        |a: &&str| !a.starts_with(['-', '+']) || a[1..].chars().all(|c| "-gprx".contains(c));
    if !args.iter().all(plain) {
        return;
    }
    for a in args {
        let Some((k, v, append)) = assignment_of(a) else {
            continue;
        };
        let v = v.trim_matches(['"', '\'']);
        let v = if append {
            names
                .iter()
                .rev()
                .find(|(n, _)| n == k)
                .map_or(v.to_string(), |(_, was)| format!("{was}{v}"))
        } else {
            v.to_string()
        };
        names.push((k.to_string(), v));
    }
}

/// [`inner_commands_at`] on a line whose aliases are already expanded.
pub(crate) fn inner_commands_expanded(argv: &[String]) -> Vec<(usize, Vec<String>)> {
    let mut out = Vec::new();
    // `g=git; $g push -f`: a bare assignment earlier on the line names what
    // a later `$g` or `${g}` command word runs.
    let mut names: Vec<(String, String)> = Vec::new();
    // Set when an assignment can change where a later `~` or `$HOME`
    // lands, so that command is judged with the path the shell opens.
    let mut seat_names = false;
    let cmds = commands(argv);
    for (i, cmd) in cmds.iter().cloned().enumerate() {
        if cmd.iter().all(|w| is_assignment(w)) {
            for w in &cmd {
                if let Some((k, v)) = w.split_once('=') {
                    let v = v.trim_matches(['"', '\'']);
                    let v = match k.strip_suffix('+') {
                        Some(k) => names
                            .iter()
                            .rev()
                            .find(|(n, _)| n == k)
                            .map_or(v.to_string(), |(_, was)| format!("{was}{v}")),
                        None => v.to_string(),
                    };
                    let key = k.trim_end_matches('+');
                    note_seat_name(&mut seat_names, key, &v);
                    names.push((key.to_string(), v));
                }
            }
            continue;
        }
        let before = names.len();
        remember_declared(&cmd, &mut names);
        if !seat_names {
            for (k, v) in &names[before..] {
                note_seat_name(&mut seat_names, k, v);
            }
        }
        let mut owned: Vec<String> = cmd.iter().map(|s| (*s).to_string()).collect();
        if let Some(first) = owned.first_mut() {
            let body = quoted_body(first);
            let name = body
                .trim_start_matches('$')
                .trim_start_matches('{')
                .trim_end_matches('}');
            if body.starts_with('$') {
                if let Some((_, v)) = names.iter().rev().find(|(k, _)| k == name) {
                    let mut words = shell_words(v);
                    if !words.is_empty() {
                        words.extend(owned.drain(1..));
                        owned = words;
                    }
                }
            }
        }
        // The shell expands a `-S` string before env splits it.
        if let Walk::Split(at, taken, _) = wrapper_walk(&owned) {
            for w in &mut owned[at..at + taken] {
                *w = with_names(quoted_body(w), &names, argv);
            }
            out.push((i, owned.clone()));
        }
        // GNU env runs no `$(...)` in a `-S` string, but one is still read
        // as a script, so a substitution in it is judged as before.
        if let Walk::Split(_, _, s) = wrapper_walk(&owned) {
            out.extend(script_lines(s, 0).iter().map(|l| (i, shell_words(l))));
        }
        let owned = split_env_strings(&owned).into_owned();
        if owned.as_slice()
            != cmd
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>()
                .as_slice()
        {
            out.push((i, owned.clone()));
        }
        let (run, handed) = unwrap_wrappers(&owned);
        // `cmd=rm; env $cmd` runs rm. The wrapper is not the command word,
        // so the `$cmd` at the front of what it runs is substituted the
        // same way a bare `$cmd` is.
        let mut run_owned = None;
        if handed.is_none() {
            if let Some(head) = run.first() {
                if head.contains('$') {
                    if let Some(mut words) = assigned_words(head, &names) {
                        words.extend(run.iter().skip(1).cloned());
                        run_owned = Some(words);
                    }
                }
            }
        }
        let run: &[String] = run_owned.as_deref().unwrap_or(run);
        if let Some(code) = inline_program(run) {
            for s in program_shell_strings(code) {
                out.extend(script_lines(&s, 0).iter().map(|l| (i, shell_words(l))));
            }
        }
        if let Some(script) = handed {
            let script = expand_assigned_params(quoted_body(script), &names);
            out.extend(script_lines(&script, 0).iter().map(|l| (i, shell_words(l))));
            continue;
        }
        if run.is_empty() {
            continue;
        }
        if let Some(inside) = container_command(run) {
            out.push((i, inside));
        }
        if let Some((Fed::Text(script), _)) = shell_stdin(run) {
            out.extend(script_lines(script, 0).iter().map(|l| (i, shell_words(l))));
        }
        if let Some(cb) = mapfile_callback(run) {
            out.extend(script_lines(cb, 0).iter().map(|l| (i, shell_words(l))));
        }
        if let Some((script, pos)) = shell_c_call(run) {
            // `"$cmd"` keeps its quotes so a later split can see one
            // parameter. The shell parses the expanded text as the script.
            // Words after the script are `$0`, `$1`, ...
            let script = bind_positionals(quoted_body(script), pos);
            let script = expand_assigned_params(&script, &names);
            out.extend(script_lines(&script, 0).iter().map(|l| (i, shell_words(l))));
        } else if base_of(&run[0]) == "eval" {
            // eval joins its words with spaces and runs that as a script.
            // `cmd=rm; eval "$cmd -rf /var"` is that rm.
            let joined = run[1..]
                .iter()
                .map(|w| quoted_body(w))
                .collect::<Vec<_>>()
                .join(" ");
            let script = expand_assigned_params(&joined, &names);
            out.extend(script_lines(&script, 0).iter().map(|l| (i, shell_words(l))));
        } else if base_of(&run[0]) != "::::" {
            if let Some(action) = trap_action(run) {
                out.extend(script_lines(action, 0).iter().map(|l| (i, shell_words(l))));
            }
            // `bash <(echo git push -f)` runs echo, and bash then runs
            // echo's output as its script. A `cat` of a path is read in
            // the walk, which knows the directory.
            match procsub_of(run) {
                ProcKind::Not => {}
                kind => {
                    if let Some(body) = procsub_body(run) {
                        out.extend(script_lines(body, 0).iter().map(|l| (i, shell_words(l))));
                    }
                    if let ProcKind::Text(text) = kind {
                        out.extend(script_lines(&text, 0).iter().map(|l| (i, shell_words(l))));
                    }
                }
            }
            out.push((
                i,
                if seat_names {
                    rewrite_seat_args(run, &names)
                } else {
                    run.to_vec()
                },
            ));
        }
    }
    out
}

/// An assignment that can move a later seat path: `HOME`, an `XDG`
/// directory, or a value that already names one of those files.
fn note_seat_name(seat: &mut bool, key: &str, value: &str) {
    if *seat {
        return;
    }
    let value = unquote(value);
    if matches!(key, "HOME" | "XDG_CONFIG_HOME" | "XDG_DATA_HOME")
        || value.contains('~')
        || value.contains(".cursor")
        || value.contains(".claude")
        || value.contains("ljos")
        || value.contains("gitconfig")
        || value.contains("/git/")
    {
        *seat = true;
    }
}

fn concrete_value(v: &str) -> bool {
    !v.is_empty() && !v.contains(['$', '`', '*', '?', '[', '\n', ';', ' '])
}

/// `$name` whose assignment is a plain path, then a leading `~` from
/// the `HOME` assigned on this line. Other words stay as written.
fn rewrite_seat_args(run: &[String], names: &[(String, String)]) -> Vec<String> {
    let home = names
        .iter()
        .rev()
        .find(|(k, _)| k == "HOME")
        .and_then(|(_, v)| {
            let v = unquote(v);
            (concrete_value(v) && v.starts_with('/')).then_some(v.to_string())
        });
    run.iter()
        .map(|w| rewrite_seat_word(w, names, home.as_deref()))
        .collect()
}

fn rewrite_seat_word(word: &str, names: &[(String, String)], home: Option<&str>) -> String {
    let w = if word.contains('$') {
        subst_concrete(word, names)
    } else {
        word.to_string()
    };
    let Some(home) = home else {
        return w;
    };
    let bare = unquote(&w);
    let replaced = if bare == "~" {
        home.to_string()
    } else if let Some(rest) = bare.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        return w;
    };
    if bare.len() == w.len() {
        replaced
    } else {
        format!("\"{replaced}\"")
    }
}

fn subst_concrete(word: &str, names: &[(String, String)]) -> String {
    let mut out = String::new();
    let mut rest = word;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let Some((name, len)) = param_at(rest) else {
            out.push('$');
            continue;
        };
        let value = names
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| unquote(v.as_str()))
            .filter(|v| concrete_value(v));
        if let Some(v) = value {
            out.push_str(v);
            rest = &rest[len..];
        } else {
            out.push('$');
            out.push_str(&rest[..len]);
            rest = &rest[len..];
        }
    }
    out.push_str(rest);
    out
}

/// Container runners whose `run` takes `-v HOST:PATH` bind mounts.
const CONTAINER_RUNNERS: &[&str] = &["docker", "podman", "nerdctl"];

/// Flags of `docker run` that take a separate value.
pub(crate) const CONTAINER_VALUED: &[&str] = &[
    "-v",
    "--volume",
    "--mount",
    "-e",
    "--env",
    "--env-file",
    "-w",
    "--workdir",
    "--name",
    "-p",
    "--publish",
    "--network",
    "--net",
    "-u",
    "--user",
    "-l",
    "--label",
    "--platform",
    "-h",
    "--hostname",
    "--entrypoint",
    "-m",
    "--memory",
    "--cpus",
    "--add-host",
    "--device",
    "--cap-add",
    "--cap-drop",
    "--security-opt",
    "--ulimit",
    "--tmpfs",
    "--pull",
    "--restart",
    "--log-driver",
    "--log-opt",
    "--shm-size",
    "--ipc",
    "--pid",
    "--userns",
    "--gpus",
    "--volumes-from",
    "--dns",
    "--expose",
    "--label-file",
    "--cidfile",
    "--stop-signal",
];

/// The command a `docker run` (or `podman`, `nerdctl`) runs, with each path
/// under a bind mount written as the host path it lands on. A path in no
/// mount is inside the container's own disk, so it is written as a path
/// under `/tmp` and the table lets it go. `None` when nothing is mounted
/// from the host or no argument lands in a mount.
fn container_command(run: &[String]) -> Option<Vec<String>> {
    if !CONTAINER_RUNNERS.contains(&base_of(run.first()?)) {
        return None;
    }
    let mut i = 1;
    if run.get(i).map(String::as_str) == Some("container") {
        i += 1;
    }
    if run.get(i).map(String::as_str) != Some("run") {
        return None;
    }
    i += 1;
    let mut mounts: Vec<(String, String)> = Vec::new();
    let mut entry: Option<String> = None;
    while i < run.len() {
        let a = run[i].as_str();
        let (flag, value) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (a, None),
        };
        if !flag.starts_with('-') {
            break;
        }
        let value = match value {
            Some(v) => Some(v),
            None if CONTAINER_VALUED.contains(&flag) => {
                i += 1;
                run.get(i).cloned()
            }
            None => None,
        };
        if let Some(v) = value {
            if matches!(flag, "-v" | "--volume") {
                let mut parts = v.splitn(3, ':');
                if let (Some(h), Some(c)) = (parts.next(), parts.next()) {
                    mounts.push((h.to_string(), c.to_string()));
                }
            } else if flag == "--mount" {
                let field = |names: &[&str]| {
                    v.split(',').find_map(|kv| {
                        let (k, val) = kv.split_once('=')?;
                        names.contains(&k).then(|| val.to_string())
                    })
                };
                if field(&["type"]).as_deref() == Some("bind") {
                    if let (Some(h), Some(c)) = (
                        field(&["source", "src"]),
                        field(&["target", "dst", "destination"]),
                    ) {
                        mounts.push((h, c));
                    }
                }
            } else if flag == "--entrypoint" {
                entry = Some(v);
            }
        }
        i += 1;
    }
    // A named volume (`-v data:/data`) is not a host path.
    mounts.retain(|(h, c)| {
        c.starts_with('/')
            && (h.starts_with('/')
                || h.starts_with('~')
                || h.starts_with('$')
                || h.starts_with('.')
                || h.starts_with('`'))
    });
    if mounts.is_empty() || i >= run.len() {
        return None;
    }
    let host = |h: &str| match h {
        "$(pwd)" | "`pwd`" | "$PWD" | "${PWD}" => ".".to_string(),
        _ => h.trim_end_matches('/').to_string(),
    };
    let mut landed = false;
    let mut out: Vec<String> = entry.into_iter().collect();
    for a in &run[i + 1..] {
        let mapped = mounts.iter().find_map(|(h, c)| {
            let c = c.trim_end_matches('/');
            let rest = a.strip_prefix(c)?;
            (rest.is_empty() || rest.starts_with('/')).then(|| {
                let h = host(h);
                if rest.is_empty() {
                    h
                } else if h == "." {
                    format!(".{rest}")
                } else {
                    format!("{h}{rest}")
                }
            })
        });
        match mapped {
            Some(m) => {
                landed = true;
                out.push(m);
            }
            None if a.starts_with('/') => out.push(format!("/tmp/container{a}")),
            None => out.push(a.clone()),
        }
    }
    landed.then_some(out)
}
