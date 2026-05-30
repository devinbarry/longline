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

/// `set` recognizer — implemented in Task 3.
fn classify_set(_argv: &[Arg]) -> Option<PolicyResult> {
    None
}

/// `setopt` recognizer — implemented in Task 2.
fn classify_setopt(_argv: &[Arg]) -> Option<PolicyResult> {
    None
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
}
