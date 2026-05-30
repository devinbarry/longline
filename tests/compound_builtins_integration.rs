//! Binary-level integration tests for shell control-flow builtins inside
//! long, real-world compound commands.
//!
//! Every `command` here is a (lightly trimmed) real entry pulled from the
//! longline audit log that was decided `ask` under the old rules *solely*
//! because a flattened builtin leaf (`exit`/`break`/`continue`/`set`/`setopt`)
//! had no allowlist entry and poisoned an otherwise all-safe statement. After
//! adding those builtins to `core-allowlist.yaml` they decide `allow`.
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

/// zsh `setopt NULL_GLOB` preamble + a glob loop using `continue`. Leaves:
/// setopt, echo, `[ -d ]`/test, continue, wc, basename. (audit log, /tmp review-dir scan)
#[test]
fn test_setopt_and_continue_in_review_scan_allows() {
    let cmd = r#"setopt NULL_GLOB 2>/dev/null; echo "=== review dirs ==="; for d in /tmp/codex-review.*; do [ -d "$d" ] || continue; o=$(wc -c < "$d/output.md"); echo "$(basename "$d"): ${o}B"; done"#;
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

/// Isolation guard: `set -e` no longer poisons, but the command still `ask`s
/// because of the genuinely-gated `git merge --ff-only` leaf — proving the
/// builtin allowlist did not lift the decision on a real sibling. (audit log,
/// afterhours FF-merge + tag script)
#[test]
fn test_set_e_does_not_lift_gated_git_merge() {
    let cmd = r#"MAIN=REDACTED/git/tools/afterhours; set -e; echo "=== merge ==="; git -C "$MAIN" merge --ff-only somebranch; git -C "$MAIN" rev-parse --short develop"#;
    let result = run_claude_hook("Bash", cmd);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}
