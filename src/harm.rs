//! Small tables for destructive commands. Each row is a shape on the
//! words the lexer already split. Nothing here walks a directory or a
//! recipe.

use super::{base_of, commands};

/// `find -delete`, `find -exec rm`, and `xargs` or `parallel` whose
/// command is `rm`. The path arrives from the feeder, so the `rm` rule
/// on a written operand never sees it.
pub(crate) fn around_rm(argv: &[String]) -> Option<&'static str> {
    for cmd in commands(argv) {
        if let Some(token) = one_around(&cmd) {
            return Some(token);
        }
    }
    None
}

fn one_around(cmd: &[&str]) -> Option<&'static str> {
    let find = cmd.iter().any(|w| base_of(w) == "find");
    if find && cmd.iter().any(|w| *w == "-delete") {
        return Some("find-delete");
    }
    if find {
        for (i, w) in cmd.iter().enumerate() {
            if matches!(*w, "-exec" | "-execdir" | "-ok" | "-okdir")
                && cmd.get(i + 1).is_some_and(|n| base_of(n) == "rm")
            {
                return Some("find-exec-rm");
            }
        }
    }
    for (i, w) in cmd.iter().enumerate() {
        if matches!(base_of(w), "xargs" | "parallel")
            && command_after(cmd, i).is_some_and(|c| base_of(c) == "rm")
        {
            return Some("feeder-rm");
        }
    }
    None
}

/// The program `xargs` or `parallel` runs: the first word that is not
/// one of its flags. `:::` starts the inputs, so the program was earlier.
fn command_after<'a>(cmd: &[&'a str], at: usize) -> Option<&'a str> {
    const VALUED: &[&str] = &[
        "-I",
        "-J",
        "-L",
        "-n",
        "-s",
        "-P",
        "-a",
        "-E",
        "-e",
        "-d",
        "-R",
        "-S",
        "-j",
        "--jobs",
        "--arg-sep",
        "--replace",
        "--max-args",
        "--max-chars",
        "--max-procs",
        "--delimiter",
        "--arg-file",
        "--eof",
    ];
    let mut i = at + 1;
    while i < cmd.len() {
        let a = cmd[i];
        if a == ":::" || a == "::::" {
            return None;
        }
        if a == "--" {
            return cmd.get(i + 1).copied();
        }
        if a.starts_with('-') && a != "-" {
            let takes = VALUED.iter().any(|f| a == *f) && !a.contains('=');
            i += if takes { 2 } else { 1 };
            continue;
        }
        return Some(a);
    }
    None
}
