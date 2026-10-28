//! Argv law CLI. Typed verdict is Cap'n `PolicyDecision` (see lib).
//! `check-mail` reads an RFC 5322 message on stdin and only refuses.

use std::env;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{self, Command};

use ljos_policyd::{
    check_mail_argv, check_shell, encode_decision, load_config, verdict, MailVerdict,
    MAIL_MESSAGE_MAX,
};

fn usage() {
    eprintln!("usage: ljos-policyd check|exec|capnp|version -- argv...");
    eprintln!("usage: ljos-policyd check-mail --config PATH [--argv [--] RECIPIENT...]");
}

fn main() {
    load_config();
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
            let Some(mail) = mail_args(&args) else {
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
            let v = check_mail_argv(&buf, Path::new(&mail.config), &mail.recipients);
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
}
