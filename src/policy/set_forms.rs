//! Argv-aware classifier for benign `set` / `setopt` shell-option preambles.
//!
//! Returns `Some(PolicyResult { decision: Allow, rule_id: "set-safe-forms", .. })`
//! for a provably benign option-only `set`/`setopt` form; `None` for anything
//! dangerous, positional, env-prefixed, externally-executed, or unrecognized
//! (so the caller's flow yields the default `ask`). Pure function; no I/O.
//!
//! Fail-closed: every branch that is not provably benign falls through to
//! `None`, so a parse gap can only over-ask, never over-allow.
//!
//! The `!is_extra` gate and exact-bare-name match keep this from lifting an
//! external `set`/`setopt` (e.g. `env set -e`, `find -exec set`, `/tmp/set`).
//! See `docs/plans/2026-05-30-r10-safe-set-forms-design.md`.

// Constants, helpers, and recognizer stubs are all used in Tasks 2/3/4.
#![allow(dead_code)]

use crate::domain::{Decision, PolicyResult};
use crate::parser::{Arg, ArgMeta, SimpleCommand};

/// Short-flag cluster letters that enable env-export (`a` = allexport) or
/// keyword (`k`) behaviour affecting a later leaf. Sign-blind: `-a` and `+a`
/// are both rejected.
const DENY_CLUSTER_LETTERS: &[char] = &['a', 'k'];

/// `set -o <name>` / `+o <name>` option names (normalized) that affect a later
/// leaf's env export or command resolution.
const SET_O_DENY_NAMES: &[&str] = &["allexport", "keyword", "posix"];

/// `setopt <name>` option names (normalized) that affect a later leaf.
/// `posixbuiltins` is the zsh analogue of bash `set -o posix`.
const SETOPT_DENY_NAMES: &[&str] = &["allexport", "posixbuiltins"];

/// Normalize a shell-option name the way zsh matches options: lowercase and
/// strip underscores (`ALL_EXPORT` -> `allexport`, `POSIX_BUILTINS` ->
/// `posixbuiltins`).
fn normalize_option_name(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '_')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// True if any argv token's parsed text may diverge from what bash executes.
fn has_unsafe_argv(argv: &[Arg]) -> bool {
    argv.iter().any(|a| matches!(a.meta, ArgMeta::UnsafeString))
}

/// The standard Allow result for a recognized benign form. The `rule_id` is
/// load-bearing: `evaluate_with_extras`'s `all_covered` gate would otherwise
/// downgrade the Allow back to the default decision.
fn allow(form: &str) -> PolicyResult {
    PolicyResult {
        decision: Decision::Allow,
        rule_id: Some("set-safe-forms".to_string()),
        reason: format!("safe shell-option form: {form}"),
    }
}

/// Classify a `set`/`setopt` leaf. See module docs.
pub fn classify_set_forms(cmd: &SimpleCommand) -> Option<PolicyResult> {
    // Exact bare builtin name only — no basename normalization. `/tmp/set`,
    // `./setopt` are external executables, not the shell builtin.
    let name = cmd.name.as_deref()?;
    let is_set = name == "set";
    let is_setopt = name == "setopt";
    if !is_set && !is_setopt {
        return None;
    }

    // Shared pre-guards.
    // Env-prefixed (`GIT_SSH_COMMAND=evil set -e`) persists under POSIX mode;
    // we cannot know the ambient shell mode statically, so refuse to classify.
    if !cmd.assignments.is_empty() {
        return None;
    }
    // Runtime argv may diverge (`set $(cmd)`, `set "$x"`).
    if has_unsafe_argv(&cmd.argv) {
        return None;
    }

    if is_setopt {
        classify_setopt(&cmd.argv)
    } else {
        classify_set(&cmd.argv)
    }
}

/// `set` recognizer. Walks argv left to right, allowing only pure benign
/// option forms. Denylist letters `a`/`k` (sign-blind); `-o`/`+o` consumes the
/// next token as a normalized option name checked against the `-o` denylist;
/// `o` inside a cluster must be the last char. Bare `set`, `--`, positional
/// words, and any malformed/missing-name form -> `None` (ask).
fn classify_set(argv: &[Arg]) -> Option<PolicyResult> {
    // Bare `set` dumps all shell variables/functions -> ask (printenv parity).
    if argv.is_empty() {
        return None;
    }

    let mut i = 0;
    while i < argv.len() {
        let t = argv[i].text.as_str();

        // End-of-options / positional reset.
        if t == "--" {
            return None;
        }

        let is_flag = t.starts_with('-') || t.starts_with('+');
        if !is_flag {
            // Positional word (`set foo`).
            return None;
        }

        // Standalone `-o` / `+o`: next token is the option name.
        if t == "-o" || t == "+o" {
            let name = argv.get(i + 1)?; // missing name -> None
            let norm = normalize_option_name(name.text.as_str());
            if SET_O_DENY_NAMES.contains(&norm.as_str()) {
                return None;
            }
            i += 2;
            continue;
        }

        // Short-flag cluster `-XYZ` / `+XYZ`. `t[1..]` is byte-safe: the first
        // byte is the ASCII sign `-`/`+` confirmed by the is_flag check above.
        let letters: Vec<char> = t[1..].chars().collect();
        if letters.is_empty() {
            // Bare "-" or "+".
            return None;
        }
        for (idx, &c) in letters.iter().enumerate() {
            if DENY_CLUSTER_LETTERS.contains(&c) {
                return None;
            }
            if c == 'o' {
                // `o` must be the last char of the cluster; it consumes the
                // NEXT argv token as its option name (e.g. `-euo pipefail`).
                if idx != letters.len() - 1 {
                    return None;
                }
                let name = argv.get(i + 1)?; // missing name -> None
                let norm = normalize_option_name(name.text.as_str());
                if SET_O_DENY_NAMES.contains(&norm.as_str()) {
                    return None;
                }
                i += 1; // skip the consumed name token
            }
        }
        i += 1; // advance past the cluster token
    }

    Some(allow("set <options>"))
}

/// `setopt` recognizer. zsh `setopt` takes option *names*; reject any flag
/// form (`-m`, single letters, `+o`) wholesale and deny the export/resolution
/// options. Bare `setopt` lists options (benign).
fn classify_setopt(argv: &[Arg]) -> Option<PolicyResult> {
    if argv.is_empty() {
        return Some(allow("setopt"));
    }
    for arg in argv {
        let t = arg.text.as_str();
        // Any flag form (`-m 'all*'`, single-letter, `+o`) is not a plain
        // option-name form — refuse to classify (FP cost ~0).
        if t.starts_with('-') || t.starts_with('+') {
            return None;
        }
        let norm = normalize_option_name(t);
        if SETOPT_DENY_NAMES.contains(&norm.as_str()) {
            return None;
        }
    }
    Some(allow("setopt <names>"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse, Statement};

    /// Parse a single command string into its `SimpleCommand` for testing.
    fn sc(input: &str) -> SimpleCommand {
        match parse(input).expect("parse failed") {
            Statement::SimpleCommand(c) => c,
            other => panic!("expected SimpleCommand, got {other:?}"),
        }
    }

    #[test]
    fn non_set_command_returns_none() {
        assert!(classify_set_forms(&sc("ls -la")).is_none());
        assert!(classify_set_forms(&sc("git status")).is_none());
    }

    #[test]
    fn external_path_set_is_not_classified() {
        // Exact-name match only: a path-named `set` is an external program.
        assert!(classify_set_forms(&sc("/tmp/set -e")).is_none());
        assert!(classify_set_forms(&sc("./setopt NULL_GLOB")).is_none());
    }

    #[test]
    fn normalize_option_name_lowercases_and_strips_underscores() {
        assert_eq!(normalize_option_name("ALL_EXPORT"), "allexport");
        assert_eq!(normalize_option_name("all_export"), "allexport");
        assert_eq!(normalize_option_name("POSIX_BUILTINS"), "posixbuiltins");
        assert_eq!(normalize_option_name("pipefail"), "pipefail");
    }

    #[test]
    fn setopt_benign_names_allow() {
        for input in [
            "setopt",
            "setopt errexit",
            "setopt extended_glob nullglob",
            "setopt noallexport",
        ] {
            let r = classify_set_forms(&sc(input));
            assert_eq!(
                r.as_ref().map(|p| p.decision),
                Some(Decision::Allow),
                "{input}"
            );
            assert_eq!(
                r.unwrap().rule_id.as_deref(),
                Some("set-safe-forms"),
                "{input}"
            );
        }
    }

    #[test]
    fn setopt_dangerous_names_ask() {
        // allexport (env export) and posixbuiltins (persistence/resolution),
        // case/underscore-insensitive.
        for input in [
            "setopt allexport",
            "setopt ALL_EXPORT",
            "setopt posix_builtins",
            "setopt POSIX_BUILTINS",
        ] {
            assert!(classify_set_forms(&sc(input)).is_none(), "{input}");
        }
    }

    #[test]
    fn setopt_mixed_benign_then_dangerous_asks() {
        // A later dangerous token must reject the whole invocation, not just
        // its own position — the loop's core safety invariant.
        assert!(classify_set_forms(&sc("setopt errexit allexport")).is_none());
        assert!(classify_set_forms(&sc("setopt nullglob posix_builtins")).is_none());
    }

    #[test]
    fn setopt_flag_forms_ask() {
        // Single-letter and -m glob-pattern forms are rejected wholesale.
        for input in ["setopt -m 'all*'", "setopt -o", "setopt +o"] {
            assert!(classify_set_forms(&sc(input)).is_none(), "{input}");
        }
    }

    #[test]
    fn set_benign_forms_allow() {
        for input in [
            "set -e",
            "set -eu",
            "set -euo pipefail",
            "set -e -o pipefail",
            "set +e",
            "set -x",
            "set -o pipefail",
        ] {
            let r = classify_set_forms(&sc(input));
            assert_eq!(
                r.as_ref().map(|p| p.decision),
                Some(Decision::Allow),
                "{input}"
            );
            assert_eq!(
                r.unwrap().rule_id.as_deref(),
                Some("set-safe-forms"),
                "{input}"
            );
        }
    }

    #[test]
    fn set_export_keyword_forms_ask() {
        // Sign-blind on a/k; -o names normalized; posix denied.
        for input in [
            "set -a",
            "set -ea",
            "set -ak",
            "set +a",
            "set +k",
            "set -o allexport",
            "set -o keyword",
            "set -o posix",
            "set -euo allexport",
            "set -o ALL_EXPORT",
            "set -o all_export",
            "set -o POSIX",
            "set +o allexport",
        ] {
            assert!(classify_set_forms(&sc(input)).is_none(), "{input}");
        }
    }

    #[test]
    fn set_deny_letter_before_trailing_o_asks() {
        // `a` is hit before the trailing `o` is processed -> reject the whole form.
        assert!(classify_set_forms(&sc("set -eao pipefail")).is_none());
    }

    #[test]
    fn set_positional_and_malformed_forms_ask() {
        for input in [
            "set",      // bare set dumps variables -> ask (printenv parity)
            "set --",   // positional reset
            "set foo",  // positional
            "set -oe",  // o-not-last in cluster
            "set -o",   // -o with no name
            "set -euo", // trailing o with no name token
        ] {
            assert!(classify_set_forms(&sc(input)).is_none(), "{input}");
        }
    }

    #[test]
    fn set_multiple_o_rejects_on_later_dangerous_name() {
        assert!(classify_set_forms(&sc("set -o errexit -o allexport")).is_none());
        let r = classify_set_forms(&sc("set -o errexit -o pipefail"));
        assert_eq!(r.map(|p| p.decision), Some(Decision::Allow));
    }

    #[test]
    fn set_env_prefixed_form_asks() {
        // Assignment pre-guard: inline env on `set` persists under posix mode.
        assert!(classify_set_forms(&sc("GIT_SSH_COMMAND=evil set -e")).is_none());
    }

    #[test]
    fn set_unsafe_argv_form_asks() {
        // UnsafeString pre-guard: runtime argv may diverge.
        assert!(classify_set_forms(&sc("set $(ls)")).is_none());
    }
}
