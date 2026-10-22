//! Argv law CLI. Typed verdict is Cap'n `PolicyDecision` (see lib).
//! `check-mail` reads an RFC 5322 message on stdin and only refuses.

use std::env;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{self, Command};

use ljos_policyd::{
    check_mail_bytes, check_shell, encode_decision, verdict, MailVerdict, MAIL_MESSAGE_MAX,
};

fn usage() {
    eprintln!("usage: ljos-policyd check|exec|capnp|version -- argv...");
    eprintln!("usage: ljos-policyd check-mail --config PATH");
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        process::exit(2);
    }
    let verb = args.remove(0);
    if args.first().map(String::as_str) == Some("--") {
        args.remove(0);
    }
    match verb.as_str() {
        "check" => {
            let v = verdict(&args);
            println!("{v}");
            if !v.starts_with("allow") {
                process::exit(2);
            }
        }
        "capnp" => {
            let c = check_shell(&args);
            let bytes = encode_decision(&c).unwrap_or_else(|e| {
                eprintln!("capnp: {e}");
                process::exit(2);
            });
            io::stdout().write_all(&bytes).ok();
            if c.decision != ljos_policyd::policy_capnp::Decision::Allow {
                process::exit(2);
            }
        }
        "exec" => {
            let v = verdict(&args);
            if !v.starts_with("allow") {
                eprintln!("{v}");
                process::exit(2);
            }
            if args.is_empty() {
                process::exit(0);
            }
            let status = Command::new(&args[0])
                .args(&args[1..])
                .status()
                .unwrap_or_else(|e| {
                    eprintln!("exec: {e}");
                    process::exit(127);
                });
            process::exit(status.code().unwrap_or(127));
        }
        "check-mail" => {
            let Some(path) = config_path(&args) else {
                usage();
                process::exit(2);
            };
            let mut buf = Vec::new();
            let mut input = io::stdin().take(MAIL_MESSAGE_MAX as u64 + 1);
            if input.read_to_end(&mut buf).is_err() {
                let v = MailVerdict::refusal("message-invalid", "could not read stdin");
                println!("{}", v.json());
                process::exit(2);
            }
            let v = check_mail_bytes(&buf, Path::new(&path));
            println!("{}", v.json());
            if v.is_refused() {
                process::exit(2);
            }
        }
        "version" | "--version" => {
            println!(
                "ljos-policyd {} ({})",
                env!("CARGO_PKG_VERSION"),
                ljos_policyd::BACKEND
            );
        }
        _ => {
            usage();
            process::exit(2);
        }
    }
}

/// `--config PATH` or `--config=PATH`, and nothing else.
fn config_path(args: &[String]) -> Option<String> {
    match args {
        [flag, path] if flag == "--config" && !path.is_empty() => Some(path.clone()),
        [only] => only
            .strip_prefix("--config=")
            .filter(|path| !path.is_empty())
            .map(str::to_string),
        _ => None,
    }
}
