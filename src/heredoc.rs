//! Here-documents: which ones are data, which run as a script, and their
//! bodies.

use super::{
    base_of, braced, heredoc_at, heredoc_substitutions, is_assignment, is_redirection,
    program_word, quote_aware_words, redirection_body, shell_script, shell_words, spelled,
    stdin_interpreter, stdin_runner, unwrap_wrappers, without_redirections, word_may_name_shell,
    HEREDOC_RAW, RUNNERS, SHELLS, WRAPPERS,
};

/// Whether the commands on the line that opened a here-document only
/// read it as text: each command word is a plain program name that is
/// not a shell, an interpreter, `eval`, `source` or a runner that may
/// hand its input to one. `at`, `batch` and `crontab` run their input
/// later, and `ssh` and `docker exec` run it on another host or in a
/// container, so none of them reads it as text. Only a pipeline that
/// has a `<<` takes a body: a command after `&&` or `;` on that line
/// reads nothing from it. A python with no program that a `<<` feeds
/// runs the body as python, which no shell splits.
pub(crate) fn heredoc_read_as_text(line: &[String]) -> bool {
    let list = |w: &String| matches!(w.as_str(), ";" | "&&" | "||" | "&");
    let opens = |w: &String| heredoc_operator(w).is_some();
    let lists: Vec<&[String]> = line.split(list).filter(|p| !p.is_empty()).collect();
    let holding: Vec<&[String]> = lists
        .iter()
        .copied()
        .filter(|p| p.iter().any(opens))
        .collect();
    let lists = if holding.is_empty() { lists } else { holding };
    let mut stages = lists.iter().flat_map(|p| p.split(|w| w == "|"));
    stages.all(|cmd| {
        if cmd.iter().any(opens) && python_reads_stdin(cmd) {
            return true;
        }
        let head = cmd
            .iter()
            .find(|w| !is_assignment(w) && !is_redirection(w))
            .map_or("", String::as_str);
        let b = base_of(head);
        let in_container = matches!(b, "docker" | "podman") && cmd.iter().any(|w| w == "exec");
        let at = cmd
            .iter()
            .position(|w| !is_assignment(w) && !is_redirection(w))
            .unwrap_or(cmd.len());
        let plain = without_redirections(&cmd[at..]);
        !head.contains(['/', '$', '`', '('])
            && !in_container
            && stdin_runner(unwrap_wrappers(&plain).0).is_none()
            && !word_may_name_shell(head)
            && stdin_interpreter(b).is_none()
            && !RUNNERS.iter().any(|(r, _)| *r == b)
            && !WRAPPERS.contains(&b)
            && !matches!(
                b,
                "eval"
                    | "source"
                    | "."
                    | "exec"
                    | "parallel"
                    | "find"
                    | "at"
                    | "batch"
                    | "crontab"
                    | "ssh"
            )
    })
}

/// A shell with no `-c` script, or `python3 -`, runs the here-document
/// body as a program. Every other reader only expands an unquoted body.
pub(crate) fn heredoc_runs_script(line: &[String]) -> bool {
    let list = |w: &String| matches!(w.as_str(), ";" | "&&" | "||" | "&");
    let opens = |w: &String| heredoc_operator(w).is_some();
    let lists: Vec<&[String]> = line.split(list).filter(|p| !p.is_empty()).collect();
    let holding: Vec<&[String]> = lists
        .iter()
        .copied()
        .filter(|p| p.iter().any(opens))
        .collect();
    let lists = if holding.is_empty() { lists } else { holding };
    lists.iter().any(|cmd| {
        cmd.split(|w| w.as_str() == "|").any(|stage| {
            let plain = without_redirections(stage);
            let run = unwrap_wrappers(&plain).0;
            let Some(head) = run.first() else {
                return false;
            };
            let b = base_of(head);
            if SHELLS.contains(&b) {
                return shell_script(run).is_none();
            }
            python_reads_stdin(run)
        })
    })
}

/// A here-document is data when every stage that receives it is `cat`,
/// `tee`, or `printf` redirected into a file. A shell, an interpreter,
/// `eval`, `ssh`, `xargs`, or any other reader is still checked.
fn heredoc_fed_to_writer(line: &[String]) -> bool {
    let list = |w: &String| matches!(w.as_str(), ";" | "&&" | "||" | "&");
    let opens = |w: &String| heredoc_operator(w).is_some();
    let lists: Vec<&[String]> = line.split(list).filter(|p| !p.is_empty()).collect();
    let holding: Vec<&[String]> = lists
        .iter()
        .copied()
        .filter(|p| p.iter().any(&opens))
        .collect();
    let lists = if holding.is_empty() { lists } else { holding };
    !lists.is_empty()
        && lists.iter().all(|segment| {
            let stages: Vec<&[String]> = segment.split(|w| w.as_str() == "|").collect();
            !stages.is_empty() && stages.iter().copied().all(stage_is_file_writer)
        })
}

fn stage_is_file_writer(cmd: &[String]) -> bool {
    let head = cmd
        .iter()
        .find(|w| !is_assignment(w) && !is_redirection(w))
        .map_or("", |w| base_of(w));
    match head {
        "cat" | "tee" => true,
        "printf" => file_redirect(cmd),
        "git" => git_commit_message(cmd),
        _ => false,
    }
}

/// `git commit -F -` reads the message from stdin or a here-document.
fn git_commit_message(cmd: &[String]) -> bool {
    let mut commit = false;
    let mut i = 0;
    while i < cmd.len() {
        let a = cmd[i].as_str();
        if a == "commit" {
            commit = true;
        }
        if commit && (a == "-F" || a == "--file") {
            return cmd
                .get(i + 1)
                .is_some_and(|v| v == "-" || v.starts_with("<<"));
        }
        if commit && (a == "-F-" || a.starts_with("--file=") || a.starts_with("-F")) {
            let value = a
                .strip_prefix("--file=")
                .or_else(|| a.strip_prefix("-F"))
                .unwrap_or("");
            return value.is_empty() || value == "-" || value.starts_with("<<");
        }
        i += 1;
    }
    false
}

fn file_redirect(cmd: &[String]) -> bool {
    cmd.iter().any(|w| {
        let body = redirection_body(w);
        body.starts_with('>') && !body.starts_with(">&") && !body.starts_with(">(")
    })
}

/// A `-c` script with a quoted here-document body removed. A process
/// substitution is left in place: `<(cmd)` and `>(cmd)` run.
pub(crate) fn elide_c_scripts(argv: &[String]) -> Vec<String> {
    let mut out = argv.to_vec();
    let mut i = 0;
    while i < out.len() {
        if out[i] == "-c" || out[i] == "-lc" {
            if let Some(script) = out.get(i + 1) {
                out[i + 1] = elide_data_regions(script);
            }
        }
        i += 1;
    }
    out
}

pub(crate) fn elide_data_regions(script: &str) -> String {
    let chars: Vec<char> = script.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut single = false;
    let mut double = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && !single {
            out.push(c);
            if let Some(next) = chars.get(i + 1) {
                out.push(*next);
                i += 2;
                continue;
            }
        }
        if c == '\'' && !double {
            single = !single;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '"' && !single {
            double = !double;
            out.push(c);
            i += 1;
            continue;
        }
        if !single
            && !double
            && c == '<'
            && chars.get(i + 1) == Some(&'<')
            && chars.get(i + 2) != Some(&'<')
            && elide_heredoc_body(&chars, &mut i, &mut out)
        {
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Drop a here-document body when a file writer receives it and the
/// delimiter is quoted (`<<'EOF'`, `<<"EOF"`, `<<\EOF`). An unquoted
/// body stays, so `$(...)`, backticks and `<(...)` are still scanned.
/// The opener line stays so the command is still visible.
fn elide_heredoc_body(chars: &[char], i: &mut usize, out: &mut String) -> bool {
    let start = (0..*i)
        .rev()
        .find(|k| chars[*k] == '\n')
        .map_or(0, |k| k + 1);
    let line_end = (*i..chars.len())
        .find(|k| chars[*k] == '\n')
        .unwrap_or(chars.len());
    let line: String = chars[start..line_end].iter().collect();
    let words = quote_aware_words(&line);
    if !heredoc_fed_to_writer(&words) {
        return false;
    }
    let Some((delim, tabs, quoted)) = heredoc_at(chars, *i + 2).0 else {
        return false;
    };
    if delim.is_empty() || !quoted {
        return false;
    }
    while *i < chars.len() && chars[*i] != '\n' {
        out.push(chars[*i]);
        *i += 1;
    }
    if *i < chars.len() {
        out.push('\n');
        *i += 1;
    }
    while *i < chars.len() {
        let eol = (*i..chars.len())
            .find(|k| chars[*k] == '\n')
            .unwrap_or(chars.len());
        let raw: String = chars[*i..eol].iter().collect();
        let cmp = if tabs {
            raw.trim_start_matches('\t')
        } else {
            raw.as_str()
        };
        let at_end = eol >= chars.len();
        *i = if at_end { chars.len() } else { eol + 1 };
        if cmp == delim {
            out.push_str(&raw);
            if !at_end {
                out.push('\n');
            }
            break;
        }
    }
    true
}

/// Whether a command on the line that opened a here-document is a
/// batch `sftp -b -`, which reads its batch lines from it.
pub(crate) fn heredoc_fed_to_sftp(out: &[String]) -> bool {
    let sep = |w: &String| matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&");
    let end = out.len() - usize::from(out.last().is_some_and(|w| w == ";"));
    let start = out[..end]
        .iter()
        .rposition(|w| w == ";")
        .map_or(0, |i| i + 1);
    out[start..end].split(sep).any(|cmd| {
        let at = cmd
            .iter()
            .position(|w| !is_assignment(w) && !is_redirection(w))
            .unwrap_or(cmd.len());
        let plain = without_redirections(&cmd[at..]);
        let run = unwrap_wrappers(&plain).0;
        run.first().is_some_and(|w| base_of(w) == "sftp") && stdin_runner(run).is_some()
    })
}

/// sftp batch lines as the local shell sees them. A line may start
/// with `-` or `@`, and one that then starts with `!` runs the rest in
/// a local shell, so the prefix is dropped to judge that command.
pub(crate) fn sftp_batch_lines(body: &str) -> String {
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim_start().trim_start_matches(['-', '@']);
        out.push_str(line.strip_prefix('!').unwrap_or(line));
        out.push('\n');
    }
    out
}

/// The delimiter `<<` / `<<-` names, and whether a leading tab is
/// stripped (`<<-`). An empty name is the next word.
pub(crate) fn heredoc_operator(w: &str) -> Option<(String, bool)> {
    let rest = w.strip_prefix("<<")?;
    if rest.starts_with('<') {
        return None;
    }
    let tabs = rest.starts_with('-');
    let rest = rest.trim_start_matches('-');
    let rest = rest.strip_prefix('\\').unwrap_or(rest);
    Some((heredoc_name(rest), tabs))
}

pub(crate) fn heredoc_name(w: &str) -> String {
    // Quotes wrap part of the word. A `\r` after the closing quote stays,
    // so `<<'EOF'\r` is the delimiter `EOF\r`.
    let chars: Vec<char> = w.chars().collect();
    let mut name = String::new();
    let mut i = 0;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => name.push(c),
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == '\\' => {
                i += 1;
                if let Some(&n) = chars.get(i) {
                    name.push(n);
                }
            }
            None => name.push(c),
        }
        i += 1;
    }
    name
}

/// Read each pending here-document from the raw lines at `i`. The body
/// is tokenized on its own, so a quote in it stops at the delimiter
/// line. The delimiter is then a word of its own, which is how
/// [`heredoc_bodies`] finds the body.
pub(crate) fn take_heredoc_bodies(
    chars: &[char],
    i: &mut usize,
    out: &mut Vec<String>,
    pending: &mut std::collections::VecDeque<(String, bool, bool)>,
    line_start: usize,
) {
    let opener = &out[line_start.min(out.len())..];
    let text = !pending.is_empty() && heredoc_read_as_text(opener);
    let data = !pending.is_empty() && heredoc_fed_to_writer(opener);
    // Same reader set as the substitution scan: a shell or python3 -, or
    // any program that does not read the body as plain text.
    let runs_script = !pending.is_empty() && (heredoc_runs_script(opener) || !text);
    while let Some((delim, tabs, quoted)) = pending.pop_front() {
        let mut body = String::new();
        loop {
            if *i >= chars.len() {
                break;
            }
            let start = *i;
            // A newline ends the line. `\r` stays, so it can be part of
            // the delimiter word.
            while *i < chars.len() && chars[*i] != '\n' {
                *i += 1;
            }
            let raw: String = chars[start..*i].iter().collect();
            if *i < chars.len() {
                *i += 1;
            }
            let line = if tabs {
                raw.trim_start_matches('\t').to_string()
            } else {
                raw
            };
            if line == delim {
                break;
            }
            body.push_str(&line);
            body.push('\n');
        }
        if !body.is_empty() {
            // An unquoted body expands for every reader. Quotes and `#`
            // in it are literal. A reader that runs the body (a shell,
            // python3 -, ssh, docker exec, source, at, batch, crontab)
            // is also scanned as a script, quoted delimiter or not.
            if !quoted {
                for script in heredoc_substitutions(&body) {
                    let words = shell_words(&script);
                    if words.is_empty() {
                        continue;
                    }
                    let open = words
                        .last()
                        .is_none_or(|w| !matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&"));
                    out.extend(words);
                    if open {
                        out.push(";".to_string());
                    }
                }
            }
            if data {
                HEREDOC_RAW.with(|s| {
                    s.borrow_mut()
                        .push((delim.clone(), Vec::new(), true, body.clone()));
                });
                out.push(delim);
                out.push(";".to_string());
                continue;
            }
            // An sftp batch line that starts with `!` is a local shell
            // command. The mark comes off before the script scan.
            if heredoc_fed_to_sftp(out) {
                let words = shell_words(&sftp_batch_lines(&body));
                HEREDOC_RAW.with(|s| {
                    let plain = words
                        .iter()
                        .filter(|w| !matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&"))
                        .cloned()
                        .collect();
                    s.borrow_mut()
                        .push((delim.clone(), plain, quoted, body.clone()));
                });
                let open = words
                    .last()
                    .is_none_or(|w| !matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&"));
                out.extend(words);
                if open {
                    out.push(";".to_string());
                }
                out.push(delim);
                out.push(";".to_string());
                continue;
            }
            if runs_script {
                let words = shell_words(&body);
                HEREDOC_RAW.with(|s| {
                    let plain = words
                        .iter()
                        .filter(|w| !matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&"))
                        .cloned()
                        .collect();
                    s.borrow_mut()
                        .push((delim.clone(), plain, quoted, body.clone()));
                });
                let open = words
                    .last()
                    .is_none_or(|w| !matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&"));
                out.extend(words);
                if open {
                    out.push(";".to_string());
                }
                out.push(delim);
                out.push(";".to_string());
                continue;
            }
            // A quoted delimiter expands nothing, and neither does a body
            // with no `$`, backtick or backslash. Such a body only text
            // reads is data: each line is one word, as if quoted, and no
            // command of the line.
            let literal = quoted || !body.contains(['$', '`', '\\']);
            let words = if literal && text {
                let mut words = Vec::new();
                for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    spelled(line, true);
                    braced(line, false);
                    words.push(line.to_string());
                    words.push(";".to_string());
                }
                words
            } else {
                shell_words(&body)
            };
            HEREDOC_RAW.with(|s| {
                let plain = words
                    .iter()
                    .filter(|w| !matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&"))
                    .cloned()
                    .collect();
                s.borrow_mut()
                    .push((delim.clone(), plain, literal, body.clone()));
            });
            let open = words
                .last()
                .is_none_or(|w| !matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&"));
            out.extend(words);
            if open {
                out.push(";".to_string());
            }
        } else {
            HEREDOC_RAW.with(|s| {
                s.borrow_mut()
                    .push((delim.clone(), Vec::new(), true, String::new()));
            });
        }
        out.push(delim);
        out.push(";".to_string());
    }
}

/// Where the body of a here-document closed by `delim` starts among
/// `after`, the commands from the one that opens it to its delimiter.
/// A command on the opening line, past `&&` or `;`, is no line of the
/// body. The body is the commands whose words [`HEREDOC_RAW`] kept for
/// it, with whether it is written as it reads, and that text. With no
/// such record, the body is all of `after`.
fn python_reads_stdin(cmd: &[String]) -> bool {
    let plain = without_redirections(cmd);
    let run = unwrap_wrappers(&plain).0;
    let Some(b) = run.first().map(|w| base_of(w)) else {
        return false;
    };
    (b.starts_with("python") || b.starts_with("pypy"))
        && program_word(&run[1..], "cm", "WX").is_none()
}

/// The program a python reading stdin at `cmds[i]` takes from the
/// here-document it is fed: `Some(None)` where the line does not show
/// that text, as with a body that expands something. `None` where
/// `cmds[i]` is no such python, no `<<` feeds it, or `cmds` stops before
/// the body: the whole line, which has it, is judged as well.
pub(crate) fn closed_word(w: String) -> String {
    if matches!(w.as_str(), ";" | "&&" | "||" | "|" | "&") || w.ends_with(';') {
        format!("'{w}'")
    } else {
        w
    }
}
