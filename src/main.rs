//! Argv law. First matching deny wins. No store. No reload.

use std::env;
use std::process::{self, Command};

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: ljos-policyd check|exec -- argv...");
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
            eprintln!("usage: ljos-policyd check|exec -- argv...");
            process::exit(2);
        }
    }
}

fn verdict(argv: &[String]) -> String {
    let line = argv.join(" ");
    if argv.is_empty() {
        return "deny\tempty argv".into();
    }
    let head = argv[0].as_str();
    let base = head.rsplit('/').next().unwrap_or(head);
    if base == "sudo" || base == "doas" {
        return "deny\tsudo".into();
    }
    if line.contains("curl") && (line.contains("| sh") || line.contains("|sh") || line.contains("| bash"))
    {
        return "deny\tcurl-pipe-shell".into();
    }
    if base == "rm" || base == "rtrash" {
        let joined = line.as_str();
        if joined.contains("-rf") || joined.contains("-fr") {
            let only_tmp = argv.iter().skip(1).filter(|a| !a.starts_with('-')).all(|p| {
                p == "/tmp" || p.starts_with("/tmp/") || p == "/var/tmp" || p.starts_with("/var/tmp/")
            });
            if !only_tmp {
                return "deny\trm-rf-outside-tmp".into();
            }
        }
    }
    if base == "git" && argv.iter().any(|a| a == "push") && argv.iter().any(|a| a == "--force" || a == "-f")
    {
        return "deny\tgit-force-push".into();
    }
    "allow".into()
}

#[cfg(test)]
mod tests {
    use super::verdict;

    fn v(xs: &[&str]) -> String {
        verdict(&xs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn allows_cargo() {
        assert_eq!(v(&["cargo", "test"]), "allow");
    }

    #[test]
    fn denies_sudo() {
        assert!(v(&["sudo", "id"]).starts_with("deny"));
    }

    #[test]
    fn denies_curl_pipe() {
        assert!(v(&["sh", "-c", "curl https://x | sh"]).starts_with("deny"));
    }

    #[test]
    fn denies_rm_rf_home() {
        assert!(v(&["rm", "-rf", "/home/x"]).starts_with("deny"));
    }

    #[test]
    fn allows_rm_rf_tmp() {
        assert_eq!(v(&["rm", "-rf", "/tmp/x"]), "allow");
    }
}
