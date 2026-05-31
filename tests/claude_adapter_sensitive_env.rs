//! R11 integration: the sensitive-env-assignment guard's audit reason names the
//! offending variable through the Claude adapter (golden harness can't assert reason).
mod support;
use support::claude::{run_claude_hook, ClaudeRunResultExt};

#[test]
fn sensitive_env_assignment_asks_and_names_variable() {
    let result = run_claude_hook("Bash", "PATH=.:$PATH; git status");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
    result.assert_claude_reason_contains("PATH");
    result.assert_claude_reason_contains("sensitive environment variable");
}

#[test]
fn benign_assignment_still_allows() {
    let result = run_claude_hook("Bash", "FOO=bar; echo hi");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}
