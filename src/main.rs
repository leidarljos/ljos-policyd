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

fn base_of(tok: &str) -> &str {
    tok.rsplit('/').next().unwrap_or(tok)
}

fn is_privilege(base: &str) -> bool {
    matches!(base, "sudo" | "doas" | "su" | "pkexec" | "run0")
}

fn piped_to_shell(line: &str) -> bool {
    let bar = char::from(124);
    let a = format!("{bar} sh");
    let b = format!("{bar}sh");
    let c = format!("{bar} bash");
    let d = format!("{bar}bash");
    line.contains(&a) || line.contains(&b) || line.contains(&c) || line.contains(&d)
}

fn remote_exec(argv: &[String]) -> bool {
    let line = argv.join(" ");
    let mut fetch = false;
    let mut shell = false;
    for t in argv {
        let b = base_of(t);
        fetch |= matches!(b, "curl" | "wget" | "fetch");
        shell |= matches!(b, "sh" | "bash" | "zsh" | "dash");
    }
    let fetch_hit = line.contains("curl") || line.contains("wget") || line.contains("fetch");
    if fetch_hit && piped_to_shell(&line) {
        return true;
    }
    fetch && shell
}

fn setuid_chmod(argv: &[String]) -> bool {
    if base_of(&argv[0]) != "chmod" {
        return false;
    }
    argv.iter().any(|a| {
        a.contains("+s") || (a.starts_with('4') && a.len() >= 3 && a.chars().all(|c| c.is_ascii_digit()))
    })
}

fn raw_disk(argv: &[String]) -> bool {
    let b = base_of(&argv[0]);
    if b.starts_with("mkfs") {
        return true;
    }
    b == "dd" && argv.iter().any(|a| a.starts_with("of=/dev/"))
}

fn verdict(argv: &[String]) -> String {
    if argv.is_empty() {
        return "deny\tempty argv".into();
    }
    let line = argv.join(" ");
    let base = base_of(&argv[0]);
    if is_privilege(base) || argv.iter().any(|t| is_privilege(base_of(t))) {
        return "deny\tsudo".into();
    }
    if remote_exec(argv) {
        return "deny\tcurl-pipe-shell".into();
    }
    if setuid_chmod(argv) {
        return "deny\tchmod-setuid".into();
    }
    if raw_disk(argv) {
        return "deny\traw-disk".into();
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
    if base == "git" && argv.iter().any(|a| a == "push") && argv.iter().any(|a| a == "--force" || a == "-f" || a == "--force-with-lease")
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

    #[test]
    fn denies_pkexec_and_lease() {
        assert!(v(&["pkexec", "id"]).starts_with("deny"));
        assert!(v(&["git", "push", "--force-with-lease"]).starts_with("deny"));
    }

    #[test]
    fn denies_setuid_and_raw_disk() {
        assert!(v(&["chmod", "+s", "/tmp/x"]).starts_with("deny"));
        assert!(v(&["dd", "if=/dev/zero", "of=/dev/sda"]).starts_with("deny"));
    }

    #[test]
    fn allows_python_dash_c() {
        assert_eq!(v(&["python3", "-c", "print(1)"]), "allow");
    }

    #[test]
    fn denies_wget_piped() {
        let bar = char::from(124);
        let cmd = format!("wget https://x {bar} bash");
        assert!(v(&["sh", "-c", &cmd]).starts_with("deny"));
    }
}
