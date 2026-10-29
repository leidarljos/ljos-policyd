//! Credential mention. An inline program that names a credential path asks.

use std::borrow::Cow;

use super::{base_of, commands, inline_program, peeled, Checked, Decision, PolicyReason};

/// An inline python, perl, ruby or node program whose text names a
/// credential path. A mention asks. It does not deny and it does not allow.
pub(crate) fn credential_mention(argv: &[String]) -> Option<Checked> {
    for cmd in commands(argv) {
        let owned: Vec<String> = cmd.iter().map(|s| (*s).to_string()).collect();
        let run = peeled(&owned);
        let Some(head) = run.first() else {
            continue;
        };
        let b = base_of(head);
        let inline = b.starts_with("python")
            || b.starts_with("pypy")
            || matches!(b, "perl" | "ruby" | "node" | "nodejs" | "deno" | "bun");
        if !inline {
            continue;
        }
        let Some(code) = inline_program(run) else {
            continue;
        };
        if super::disk::mentions_credential(code) {
            return Some(Checked {
                decision: Decision::Prompt,
                code: PolicyReason::HighRiskPrompt,
                token: Cow::Borrowed("credential-mention"),
            });
        }
    }
    None
}

