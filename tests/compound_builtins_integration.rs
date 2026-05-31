//! Binary-level integration tests for shell control-flow builtins inside
//! long, real-world compound commands.
//!
//! Every `command` here is a (lightly trimmed) real entry pulled from the
//! longline audit log that was decided `ask` under the old rules *solely*
//! because a flattened builtin leaf (`exit`/`break`/`continue`) had no
//! allowlist entry and poisoned an otherwise all-safe statement. After adding
//! those control-flow builtins to `core-allowlist.yaml` they decide `allow`.
//!
//! `set`/`setopt` are intentionally NOT allowlisted (they change how sibling
//! leaves execute), so the isolation test below uses a control-flow builtin.
//!
//! These run the full binary through the Claude hook contract (stdin JSON →
//! decision JSON), not just the policy library, so they guard the end-to-end
//! path a real agent hits.

mod support;
use support::claude::{run_claude_hook, ClaudeRunResultExt};

/// Memory-dir loop that skips MEMORY.md via `continue`. Leaves: cd, `[`/test,
/// continue, echo, awk — all safe. (audit log, afterhours memory dump)
#[test]
fn test_continue_in_memory_loop_allows() {
    let cmd = r#"cd /tmp && for f in *.md; do [ "$f" = "MEMORY.md" ] && continue; echo "=== $f ==="; awk '/^---$/{n++; next} n==1{print} n==2{exit}' "$f"; done"#;
    let result = run_claude_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

/// Test-retry loop using `break` to bail on first failure. Leaves: echo,
/// `uv run pytest` (allowlisted), tail, break. (audit log, afterhours flow test)
#[test]
fn test_break_in_pytest_retry_loop_allows() {
    let cmd = r#"for i in 1 2 3 4 5; do echo "=== Run $i ==="; uv run pytest tests/flow/test_repository_flow_run.py::test_apply_marker 2>&1 | tail -3 || break; done"#;
    let result = run_claude_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

/// `cmd || exit 1` guard before more safe work. Leaves: cd, exit, echo.
/// (audit log, review-harness preamble pattern)
#[test]
fn test_cd_or_exit_guard_allows() {
    let cmd = r#"cd REDACTED/git/tools/longline || exit 1; echo done"#;
    let result = run_claude_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

/// Isolation guard at the binary boundary: an allowlisted `exit` leaf must NOT
/// lift the decision on a genuinely-gated sibling. `cat .env` is rule-gated
/// (cat-env-file), so the whole command must still `ask`. Verified that the
/// ask originates from cat .env, not from the builtin.
#[test]
fn test_exit_guard_does_not_lift_gated_cat_env() {
    let cmd = r#"cat .env || exit 1"#;
    let result = run_claude_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
    assert!(
        result.stdout.contains("cat-env-file"),
        "ask must come from the gated cat .env sibling, not the exit builtin; got: {}",
        result.stdout
    );
}

/// Regression guard for the dropped-`set` env-RCE bypass, asserted at the
/// binary boundary. `set -a` exports the following `GIT_SSH_COMMAND=evil`
/// assignment to the later `git fetch`, but longline cannot model that
/// cross-leaf, so the safe outcome is `ask`.
///
/// Two independent leaves now anchor that ask: (1) `set` stays unrecognized
/// (off the allowlist), and (2) R11's sensitive_env classifier flags the
/// commandless `GIT_SSH_COMMAND=evil` assignment leaf directly
/// (rule_id sensitive-env-assignment). Pre-R11 only (1) held; R11 closed the
/// gap on the assignment leaf itself, so the surfaced reason is now the
/// sensitive-env-assignment hit. Either anchor is sufficient — if `set` were
/// re-allowlisted, the assignment leaf would still force the ask.
#[test]
fn test_set_allexport_env_bypass_asks_due_to_set() {
    let cmd = r#"set -a; GIT_SSH_COMMAND=evil; git fetch"#;
    let result = run_claude_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
    assert!(
        result.stdout.contains("sensitive-env-assignment")
            || result.stdout.contains("set isn't on longline's allowlist"),
        "ask must rest on the unrecognized `set` leaf OR the R11 sensitive assignment leaf, \
         not on a lifted git fetch; got: {}",
        result.stdout
    );
}
