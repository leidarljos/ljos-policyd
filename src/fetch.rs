//! Downloads and decoders: a fetched or decoded script that a later command
//! runs.

use super::{
    base_of, command_at, command_word, elide_data_regions, peeled, pipelines_of, program_word,
    quote_aware_words, redirection_files, runs_stdin, shell_script, shell_stdin, shell_words,
    stages, stdin_interpreter, tee_files, Fed, FETCHERS, SHELLS, SOURCERS,
};

/// A word that runs a download through `$(...)`, `<(...)` or backticks:
/// `<(curl`, `$( wget`, `$(/usr/bin/curl`. A match inside single quotes is
/// text. Inside double quotes, only `$(` and backticks run.
fn runs_download(t: &str) -> bool {
    ["$(", "<(", "`"].iter().any(|open| {
        t.match_indices(open).any(|(i, open)| {
            let (single, double) = quote_at(t, i);
            if single || (double && open == "<(") {
                return false;
            }
            let rest = t[i + open.len()..].trim_start();
            let word = rest
                .split(|c: char| c.is_whitespace() || matches!(c, ')' | '`' | '|' | ';'))
                .next()
                .unwrap_or("");
            FETCHERS.contains(&base_of(word))
        })
    })
}

/// Quote state just before byte `at`.
fn quote_at(t: &str, at: usize) -> (bool, bool) {
    let bytes = t.as_bytes();
    let mut single = false;
    let mut double = false;
    let mut i = 0;
    while i < at && i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && !single {
            i += 2;
            continue;
        }
        if c == b'\'' && !double {
            single = !single;
        } else if c == b'"' && !single {
            double = !double;
        }
        i += 1;
    }
    (single, double)
}

/// `curl` or `$(curl` or `SHA=$(curl` at the start of a pipeline stage.
pub(crate) fn word_fetches(w: &str) -> bool {
    if FETCHERS.contains(&base_of(w)) {
        return true;
    }
    for open in ["$(", "`"] {
        if let Some(i) = w.find(open) {
            if quote_at(w, i).0 {
                continue;
            }
            let rest = w[i + open.len()..].trim_start();
            let name = rest
                .split(|c: char| c.is_whitespace() || matches!(c, ')' | '`' | '|' | ';'))
                .next()
                .unwrap_or("");
            if FETCHERS.contains(&base_of(name)) {
                return true;
            }
        }
    }
    false
}

/// The `-c` argument is itself a download substitution: `sh -c "$(curl ...)"`.
fn download_is_the_program(script: &str) -> bool {
    let script = script.trim();
    (script.starts_with("$(") || script.starts_with("<(") || script.starts_with('`'))
        && runs_download(script)
}

/// A stage that runs a download it reads through a substitution: a shell
/// or `source`, `.` or `eval` with one on the line (`bash <(curl ...)`,
/// `source <(curl ...)`, `eval "$(curl ...)"`), a shell whose `-c` script
/// is a download handed to a shell, or an interpreter whose program is one
/// (`python3 <(curl ...)`, `python3 -c "$(curl ...)"`).
fn runs_substituted_download(s: &[String]) -> bool {
    let s = peeled(s);
    let Some(at) = command_at(s) else {
        return false;
    };
    let b = base_of(&s[at]);
    if SHELLS.contains(&b) || SOURCERS.contains(&b) {
        let script_at = s.windows(2).position(|w| w[0] == "-c").map(|i| i + 1);
        if s.iter().enumerate().any(|(i, t)| {
            if script_at == Some(i) {
                let script = elide_data_regions(t);
                download_is_the_program(&script)
            } else {
                runs_download(t)
            }
        }) {
            return true;
        }
        // `sh -c 'curl ... | sh'`: the script is a line of its own.
        // `SHA=$(curl | python3)` is a pipe into python, not a shell.
        return SHELLS.contains(&b)
            && s.windows(2).any(|w| {
                w[0] == "-c" && {
                    let inner = quote_aware_words(&elide_data_regions(&w[1]));
                    !inner.is_empty() && remote_exec(&inner)
                }
            });
    }
    stdin_interpreter(b).is_some_and(|(_, inline, valued)| {
        program_word(&s[at + 1..], inline, valued).is_some_and(|(w, _)| runs_download(w))
    })
}

/// A download handed to a program runner: a fetching stage with a later
/// stage of its pipeline that runs stdin (`curl URL | sh`, `curl URL |
/// python3`, `curl URL | python3 /dev/stdin`, `curl URL | tee f | sh`), a
/// shell, `source`, `.`, `eval` or an interpreter that runs a download
/// through a substitution, or a file a fetch on the line writes and a later
/// command runs, including a file a redirection or `tee` saves (`curl URL >
/// i.sh && sh i.sh`). Naming a download tool and a shell on one line is not
/// that: `git fetch` and a later `bash build.sh` run nothing they fetched,
/// and `curl URL | python3 -m json.tool` reads the download as data.
pub(crate) fn remote_exec(argv: &[String]) -> bool {
    let fetches = |s: &[String]| {
        command_word(s).is_some_and(|c| FETCHERS.contains(&c)) || s.iter().any(|w| word_fetches(w))
    };
    for line in pipelines_of(argv) {
        let stages = stages(&line);
        if stages
            .iter()
            .enumerate()
            .any(|(i, s)| fetches(s) && stages[i + 1..].iter().any(|t| runs_stdin(t)))
        {
            return true;
        }
        if stages.iter().any(|s| runs_substituted_download(s)) {
            return true;
        }
    }
    fetched_then_run(argv)
}

/// Short `curl` options that take a value, so the rest of a cluster after
/// one is that value: `-fsSLo FILE` writes FILE, `-H x` sends a header.
const CURL_VALUED: &str = "AbcCdDeEFHKmoPQrTtuUwxXyYz";
/// Short `wget` options that take a value.
const WGET_VALUED: &str = "aABeDiIlOoPQRtTUwX";

/// The last path part of a URL, the name `curl -O` and `wget` save it as.
fn url_file_name(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let path = path.split_once("://").map_or(path, |(_, rest)| rest);
    let (_, file) = path.trim_end_matches('/').rsplit_once('/')?;
    (!file.is_empty()).then(|| file.to_string())
}

/// The files a `curl` or `wget` call writes, by last path part: the value
/// of `-o`, `--output`, `-O` (wget) or `--output-document`, or the URL's
/// own name for `curl -O` and for `wget` with no `-O`. Standard output
/// (`-`) and `/dev/null` are no file.
fn fetched_files(cmd: &[String]) -> Vec<String> {
    fetched_paths(cmd)
        .iter()
        .map(|f| base_of(f).to_string())
        .filter(|f| !f.is_empty())
        .collect()
}

/// [`fetched_files`] as the words that name them, before the last path
/// part is taken.
pub(crate) fn fetched_paths(cmd: &[String]) -> Vec<String> {
    let cmd = peeled(cmd);
    let Some(at) = command_at(cmd) else {
        return Vec::new();
    };
    let tool = base_of(&cmd[at]);
    if !matches!(tool, "curl" | "wget") {
        return Vec::new();
    }
    let args = &cmd[at + 1..];
    let (valued, out_flag) = if tool == "curl" {
        (CURL_VALUED, 'o')
    } else {
        (WGET_VALUED, 'O')
    };
    let mut named: Vec<String> = Vec::new();
    let mut dir: Option<String> = None;
    let mut remote = tool == "wget";
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = args.get(i + 1).map(String::as_str);
        i += 1;
        let long_out = if tool == "curl" {
            "--output"
        } else {
            "--output-document"
        };
        if a == long_out {
            if let Some(f) = next {
                named.push(f.to_string());
                i += 1;
            }
            continue;
        }
        if let Some(f) = a.strip_prefix(long_out).and_then(|r| r.strip_prefix('=')) {
            named.push(f.to_string());
            continue;
        }
        if tool == "curl" && matches!(a, "--remote-name" | "--remote-name-all") {
            remote = true;
            continue;
        }
        let long_dir = if tool == "curl" {
            "--output-dir"
        } else {
            "--directory-prefix"
        };
        if a == long_dir {
            dir = next.map(str::to_string);
            i += 1;
            continue;
        }
        if let Some(d) = a.strip_prefix(long_dir).and_then(|r| r.strip_prefix('=')) {
            dir = Some(d.to_string());
            continue;
        }
        let Some(flags) = a
            .strip_prefix('-')
            .filter(|f| !f.is_empty() && !f.starts_with('-'))
        else {
            continue;
        };
        for (k, c) in flags.char_indices() {
            if tool == "curl" && c == 'O' {
                remote = true;
                continue;
            }
            if tool == "wget" && c == 'n' {
                break;
            }
            if valued.contains(c) {
                let rest = &flags[k + c.len_utf8()..];
                let value = if rest.is_empty() {
                    i += 1;
                    next
                } else {
                    Some(rest)
                };
                if let Some(f) = value.filter(|_| c == out_flag) {
                    named.push(f.to_string());
                }
                if tool == "wget" && c == 'P' {
                    dir = value.map(str::to_string);
                }
                break;
            }
        }
    }
    // `wget -O FILE` (or `-O -`) saves nothing under the URL's own name.
    let wget_named = tool == "wget" && !named.is_empty();
    named.retain(|f| !matches!(f.as_str(), "" | "-" | "/dev/null" | "/dev/stdout"));
    // `curl --output-dir` puts every relative name in DIR. `wget -P`
    // puts the names it takes from URLs there, and `-O` ignores it.
    let under = |f: String| match &dir {
        Some(d) if !f.starts_with('/') => format!("{}/{f}", d.trim_end_matches('/')),
        _ => f,
    };
    if tool == "curl" {
        named = named.into_iter().map(under).collect();
    }
    if remote && !wget_named {
        let urls: Vec<_> = args.iter().filter(|a| a.contains("://")).collect();
        let mut named_one = false;
        for u in &urls {
            if let Some(file) = url_file_name(u) {
                named.push(under(file));
                named_one = true;
            } else if tool == "wget" {
                named.push(under("index.html".to_string()));
                named_one = true;
            }
        }
        // `curl -O` of a URL with no file name, then `sh F`, still runs
        // the download. The saved name is not on the line.
        if !named_one {
            named.push("\0".to_string());
        }
    }
    named
}

/// A command that runs one of `saved` (files by last path part): a path
/// with a `/` as its command word (`./i.sh`, `/tmp/i.sh`), or a shell,
/// `source`, `.` or interpreter whose script operand is one (`sh i.sh`,
/// `python3 /tmp/get.py`).
fn runs_a_saved_file(cmd: &[String], saved: &[String]) -> bool {
    if saved.iter().any(|f| f == "\0") && shell_runs_file(cmd) {
        return true;
    }
    ran_paths(cmd)
        .iter()
        .any(|p| saved.iter().any(|f| f == base_of(p)))
}

/// `sh F`, `bash F`, or `. F` after a download whose saved name is unknown.
fn shell_runs_file(cmd: &[String]) -> bool {
    let cmd = peeled(cmd);
    let Some(at) = command_at(cmd) else {
        return false;
    };
    let b = base_of(&cmd[at]);
    if !matches!(b, "sh" | "bash" | "zsh" | "." | "source") {
        return false;
    }
    cmd[at + 1..]
        .iter()
        .any(|w| w != "--" && !w.starts_with('-'))
}

/// The files a command runs as a program, by the words that name them:
/// a command word with a `/` in it, the script operand of a shell,
/// `source`, `.` or an interpreter, and the file on a shell's stdin.
fn ran_paths(cmd: &[String]) -> Vec<&str> {
    let cmd = peeled(cmd);
    let Some(at) = command_at(cmd) else {
        return Vec::new();
    };
    let word = cmd[at].as_str();
    let mut out = Vec::new();
    // A parenthesised group is a subshell, not a path, even when the
    // text inside it contains a slash.
    if word.contains('/') && !word.starts_with('(') {
        out.push(word);
    }
    let b = base_of(word);
    let (inline, valued) = if SHELLS.contains(&b) {
        ("c", "")
    } else if matches!(b, "source" | ".") {
        ("", "")
    } else if let Some((_, inline, valued)) = stdin_interpreter(b) {
        (inline, valued)
    } else {
        return out;
    };
    if let Some((w, false)) = program_word(&cmd[at + 1..], inline, valued) {
        out.push(w);
    } else if let Some((Fed::File(file), _)) = shell_stdin(&cmd[at..]) {
        out.push(file);
    }
    out
}

/// A command that runs one of `saved`, including the text of a shell `-c`
/// script or `eval` (`sh -c './i.sh'`, `eval "sh i.sh"`).
fn runs_saved_command(cmd: &[String], saved: &[String]) -> bool {
    if runs_a_saved_file(cmd, saved) {
        return true;
    }
    let run = peeled(cmd);
    if let Some(script) = shell_script(run) {
        let words = shell_words(script);
        if runs_a_saved_file(&words, saved) {
            return true;
        }
    }
    if command_word(run) == Some("eval") {
        if let Some(at) = command_at(run) {
            let words = shell_words(&run[at + 1..].join(" "));
            if runs_a_saved_file(&words, saved) {
                return true;
            }
        }
    }
    false
}

/// The last path part of a file a command writes, when that part is a real
/// file. Standard output and the null device are not.
pub(crate) fn saved_name(path: &str) -> Option<String> {
    if matches!(
        path,
        "" | "-"
            | "/dev/null"
            | "/dev/stdout"
            | "/dev/stderr"
            | "/dev/fd/1"
            | "/dev/fd/2"
            | "/dev/tty"
    ) {
        return None;
    }
    let base = base_of(path);
    (!base.is_empty()).then(|| base.to_string())
}

/// A file a fetch on the line writes, then a later command on the line
/// runs: `curl -o i.sh URL && sh i.sh`, `curl URL > i.sh && sh i.sh`,
/// `curl URL | tee i.sh && ./i.sh`, `wget URL/get.py; python3 get.py`.
/// `curl -o data.json URL && jq . data.json` runs nothing it fetched, and
/// neither does `curl URL > data.json && python3 parse.py data.json`.
fn fetched_then_run(argv: &[String]) -> bool {
    let mut saved: Vec<String> = Vec::new();
    for line in pipelines_of(argv) {
        let stages = stages(&line);
        let mut upstream = false;
        for stage in &stages {
            let run = peeled(stage);
            let fetches = command_word(run).is_some_and(|c| FETCHERS.contains(&c));
            if fetches {
                upstream = true;
                saved.extend(fetched_files(run));
            }
            if upstream && command_word(run) == Some("tee") {
                saved.extend(tee_files(run));
            }
            if upstream {
                saved.extend(redirection_files(run));
            }
            if !saved.is_empty() && runs_saved_command(run, &saved) {
                return true;
            }
        }
    }
    false
}

/// Commands that turn text no reader can check into a script: decoders
/// and decompressors. Their output handed to a shell runs commands the
/// line never shows.
pub(crate) const DECODERS: &[&str] = &[
    "base64", "base32", "basenc", "xxd", "openssl", "uudecode", "gunzip", "zcat", "gzip", "bzcat",
    "bunzip2", "xzcat", "unxz", "zstdcat", "zstd", "rev",
];

/// A decoded script handed to a shell: a decoding stage piped into a
/// shell stage (`echo ... | base64 -d | sh`), or a shell running a decoder
/// through `$(...)`, `<(...)` or backticks (`bash -c "$(base64 -d f)"`).
/// The table cannot read what such a script runs, so it is refused, as a
/// download piped into a shell is.
pub(crate) fn decoded_exec(argv: &[String]) -> bool {
    let stages = stages(argv);
    let decodes = |s: &[String]| command_word(s).is_some_and(|c| DECODERS.contains(&c));
    let shell = |s: &[String]| command_word(s).is_some_and(|c| SHELLS.contains(&c));
    if stages.windows(2).any(|w| decodes(&w[0]) && shell(&w[1])) {
        return true;
    }
    stages.iter().filter(|s| shell(s)).any(|s| {
        s.iter().any(|t| {
            ["$(", "<(", "`"].iter().any(|open| {
                DECODERS.iter().any(|d| {
                    t.contains(&format!("{open}{d} ")) || t.ends_with(&format!("{open}{d}"))
                })
            })
        })
    })
}
