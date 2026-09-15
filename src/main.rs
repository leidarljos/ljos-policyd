//! Argv law CLI. Typed verdict is Cap'n `PolicyDecision` (see lib).

use std::env;
use std::io::{self, Write};
use std::process::{self, Command};

use ljos_policyd::{encode_decision, check_shell, verdict};

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: ljos-policyd check|exec|capnp|version -- argv...");
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
        "version" | "--version" => {
            println!("ljos-policyd {}", env!("CARGO_PKG_VERSION"));
        }
        _ => {
            eprintln!("usage: ljos-policyd check|exec|capnp|version -- argv...");
            process::exit(2);
        }
    }
}
