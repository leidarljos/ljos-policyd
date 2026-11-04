//! Argv law CLI. Typed verdict is Cap'n `PolicyDecision` (see lib).
//! `check-mail` reads an RFC 5322 message on stdin and prints allow.

use std::env;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{self, Command};

use ljos_policyd::{check_mail_argv, check_shell, encode_decision, MAIL_MESSAGE_MAX};

/// Exit status when a warning blocks, and when `check-mail` or `replay`
/// is used wrong.
///
/// Claude Code treats a hook exit of 2 as a block of that tool call.
/// The same status is already the usage error for a missing config.
const BLOCKED: i32 = 2;

fn usage() {
    eprintln!("usage: ljos-policyd check|exec|capnp|version -- argv...");
    eprintln!("usage: ljos-policyd check-mail --config PATH [--argv [--] RECIPIENT...]");
    eprintln!("usage: ljos-policyd replay [DENY_LOG]");
}

fn main() {
    process::exit(enter());
}

/// The process entry. A panic, a parse error, a missing rules file, or an
/// I/O failure inside the check prints `allow` and exits 0.
fn enter() -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(code) => code,
        Err(_) => {
            println!("allow\tfail-open\tmain");
            0
        }
    }
}

fn allow_open(reason: &str) -> i32 {
    println!("allow\tfail-open\t{reason}");
    0
}

/// `LJOS_POLICYD_FAULT` is read only while this binary is built for its
/// own tests. The release binary does not read it.
fn entry_fault(site: &str) {
    #[cfg(test)]
    if std::env::var("LJOS_POLICYD_FAULT").ok().as_deref() == Some(site) {
        panic!("fault {site}");
    }
    #[cfg(not(test))]
    {
        let _ = site;
    }
}

fn run() -> i32 {
    entry_fault("main");
    ljos_policyd::fault("main");
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return allow_open("no args");
    }
    let verb = args.remove(0);
    if args.first().map(String::as_str) == Some("--") {
        args.remove(0);
    }
    match verb.as_str() {
        "check" => {
            let (rules, config, argv) =
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| user_allows(&args)))
                {
                    Ok(parsed) => parsed,
                    Err(_) => return allow_open("user_allows"),
                };
            let mut ctx = ljos_policyd::Context::from_env();
            ctx.user_allow.extend(rules);
            if config.is_some() {
                ctx.config_path = config;
            }
            probe_configured_daemon();
            let v = ljos_policyd::verdict_with(&argv, &ctx);
            if let Some(hit) = v.strip_prefix("allow\twarn\t") {
                if ctx.config_path.as_deref().is_some_and(blocks_on_warning) {
                    println!("deny\t{hit}");
                    return BLOCKED;
                }
            }
            println!("{v}");
            return 0;
        }
        "capnp" => {
            let c = check_shell(&args);
            let bytes = match encode_decision(&c) {
                Ok(bytes) => bytes,
                Err(_) => return allow_open("internal error"),
            };
            if io::stdout().write_all(&bytes).is_err() {
                return allow_open("io");
            }
            return 0;
        }
        "exec" => return exec_verb(&args),
        "check-mail" => {
            let Some(mail) = mail_args(&args) else {
                usage();
                process::exit(2);
            };
            let mut buf = Vec::new();
            let mut input = io::stdin().take(MAIL_MESSAGE_MAX as u64 + 1);
            if input.read_to_end(&mut buf).is_err() {
                return allow_open("io");
            }
            let v = check_mail_argv(&buf, Path::new(&mail.config), &mail.recipients);
            println!("{}", v.json());
        }
        "replay" => {
            let path = args
                .first()
                .map(std::path::PathBuf::from)
                .or_else(ljos_policyd::deny_log_path)
                .unwrap_or_else(|| {
                    eprintln!("replay: no deny log path");
                    process::exit(2);
                });
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("replay: {}: {e}", path.display());
                process::exit(2);
            });
            let (mut seen, mut freed) = (0usize, 0usize);
            for row in text.lines().filter(|l| !l.trim().is_empty()) {
                let mut fields = row.splitn(3, '\t');
                let (Some(_when), Some(was), Some(line)) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    continue;
                };
                seen += 1;
                let argv = ljos_policyd::replay_argv(line);
                let now = ljos_policyd::verdict_quiet(&argv);
                if now.starts_with("allow") {
                    freed += 1;
                }
                println!("was deny\t{was}\tnow {now}\t{line}");
            }
            println!("{freed} of {seen} refused lines would run now");
        }
        "version" | "--version" => {
            println!(
                "ljos-policyd {} ({})",
                env!("CARGO_PKG_VERSION"),
                ljos_policyd::BACKEND
            );
        }
        _ => return allow_open("unknown verb"),
    }
    0
}

/// Run ARGV. A panic while reading policyd's own flags prints the
/// fail-open line on stderr and still runs the argv after those flags.
/// Stdout belongs to the command.
fn exec_verb(args: &[String]) -> i32 {
    let (rules, config, argv) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| user_allows(args))) {
            Ok(parsed) => parsed,
            Err(_) => {
                eprintln!("allow\tfail-open\tuser_allows");
                let (_, _, argv) = leading_flags(args);
                return run_command(&argv);
            }
        };
    let mut ctx = ljos_policyd::Context::from_env();
    ctx.user_allow.extend(rules);
    // The file is read only for the setting. A missing file stays a
    // warning, and the command still runs. `check` fail-opens that case.
    let v = ljos_policyd::verdict_with(&argv, &ctx);
    if let Some(hit) = v.strip_prefix("allow\twarn\t") {
        eprintln!("allow\twarn\t{hit}");
        if config.as_deref().is_some_and(blocks_on_warning) {
            eprintln!("exec: not run because block-on-warning is on");
            return BLOCKED;
        }
    }
    run_command(&argv)
}

fn run_command(argv: &[String]) -> i32 {
    if argv.is_empty() {
        return 0;
    }
    match Command::new(&argv[0]).args(&argv[1..]).status() {
        Ok(status) => status.code().unwrap_or(127),
        Err(e) => {
            eprintln!("exec: {e}");
            127
        }
    }
}

/// `--user-allow PATTERN` and `--config PATH` are policyd's own flags,
/// and only when they lead the command. A `--` ends those flags. Nothing
/// after it, and no `--` inside the command, is read as a policyd flag.
/// The pattern is the line `ljos rule --user` wrote with verdict allow.
/// A `--config` file that is not there allows the command.
fn user_allows(args: &[String]) -> (Vec<String>, Option<String>, Vec<String>) {
    entry_fault("user_allows");
    ljos_policyd::fault("user_allows");
    leading_flags(args)
}

fn leading_flags(args: &[String]) -> (Vec<String>, Option<String>, Vec<String>) {
    let mut rules = Vec::new();
    let mut config = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some(pattern) = arg.strip_prefix("--user-allow=") {
            if !pattern.is_empty() {
                rules.push(pattern.to_string());
            }
            i += 1;
            continue;
        }
        if let Some(path) = arg.strip_prefix("--config=") {
            config = Some(path.to_string());
            i += 1;
            continue;
        }
        if arg == "--user-allow" {
            if let Some(pattern) = args
                .get(i + 1)
                .filter(|p| !p.is_empty() && !p.starts_with('-'))
            {
                rules.push(pattern.clone());
                i += 2;
                continue;
            }
        }
        if arg == "--config" {
            if let Some(path) = args
                .get(i + 1)
                .filter(|p| !p.is_empty() && !p.starts_with('-'))
            {
                config = Some(path.clone());
                i += 2;
                continue;
            }
        }
        if arg == "--" {
            return (rules, config, args[i + 1..].to_vec());
        }
        return (rules, config, args[i..].to_vec());
    }
    (rules, config, Vec::new())
}

/// A `block-on-warning true` line in the `--config` file. The last such
/// line wins, so a later `false` turns the setting off. A file that
/// cannot be read, another value, or no line leaves every warning an allow.
fn blocks_on_warning(path: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    text.lines()
        .rev()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("block-on-warning"))
                .then(|| words.next() == Some("true") && words.next().is_none())
        })
        .unwrap_or(false)
}

/// `LJOS_POLICYD_DAEMON=host:port` is optional. Nothing is read from the
/// socket. When nothing accepts, [`ljos_policyd::probe_daemon`] returns
/// inside the connect timeout and the table answers.
fn probe_configured_daemon() {
    let Ok(text) = env::var("LJOS_POLICYD_DAEMON") else {
        return;
    };
    let Ok(addr) = text.parse() else {
        return;
    };
    let _ = ljos_policyd::probe_daemon(addr);
}

struct MailArgs {
    config: String,
    recipients: Vec<String>,
}

/// `--config PATH` and, when the caller has extra sendmail recipients,
/// `--argv` and those recipients. Anything else is a usage error: a
/// recipient this check does not see is a recipient it cannot refuse.
fn mail_args(args: &[String]) -> Option<MailArgs> {
    let mut config = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some(path) = arg.strip_prefix("--config=") {
            if config.is_some() || path.is_empty() {
                return None;
            }
            config = Some(path.to_string());
            i += 1;
            continue;
        }
        match arg {
            "--config" => {
                if config.is_some() {
                    return None;
                }
                let path = args.get(i + 1)?;
                if path.is_empty() || path.starts_with('-') {
                    return None;
                }
                config = Some(path.clone());
                i += 2;
            }
            "--argv" => {
                i += 1;
                if args.get(i).map(String::as_str) == Some("--") {
                    i += 1;
                }
                return Some(MailArgs {
                    config: config?,
                    recipients: args[i..].to_vec(),
                });
            }
            _ => return None,
        }
    }
    Some(MailArgs {
        config: config?,
        recipients: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    #[test]
    fn argv_recipients_are_the_words_after_the_flag() {
        let got = mail_args(&args(&[
            "--config",
            "mail.conf",
            "--argv",
            "--",
            "evil@blocked.test",
        ]))
        .unwrap();
        assert_eq!(got.config, "mail.conf");
        assert_eq!(got.recipients, vec!["evil@blocked.test".to_string()]);
        let got = mail_args(&args(&["--config=mail.conf", "--argv", "a@ok.test"])).unwrap();
        assert_eq!(got.recipients, vec!["a@ok.test".to_string()]);
        let got = mail_args(&args(&["--config", "mail.conf", "--argv"])).unwrap();
        assert!(got.recipients.is_empty());
        assert!(mail_args(&args(&["--config", "mail.conf", "evil@blocked.test"])).is_none());
        assert!(mail_args(&args(&["--argv", "evil@blocked.test"])).is_none());
    }

    #[test]
    fn the_entry_point_allows_on_a_panic() {
        std::env::set_var("LJOS_POLICYD_FAULT", "main");
        let code = enter();
        std::env::remove_var("LJOS_POLICYD_FAULT");
        assert_eq!(code, 0);
    }

    #[test]
    fn flags_stop_at_the_command() {
        let (rules, config, argv) = user_allows(&args(&[
            "--user-allow",
            "rm -rf /srv/x",
            "--config",
            "/nope",
            "--",
            "rm",
            "-rf",
            "--",
            "/srv/x",
            "--config",
            "/nope",
        ]));
        assert_eq!(rules, vec!["rm -rf /srv/x".to_string()]);
        assert_eq!(config.as_deref(), Some("/nope"));
        assert_eq!(
            argv,
            args(&["rm", "-rf", "--", "/srv/x", "--config", "/nope"])
        );
        let (rules, config, argv) =
            user_allows(&args(&["rm", "-rf", "--", "/srv/x", "--config", "/nope"]));
        assert!(rules.is_empty());
        assert!(config.is_none());
        assert_eq!(
            argv,
            args(&["rm", "-rf", "--", "/srv/x", "--config", "/nope"])
        );
    }
}
