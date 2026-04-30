mod support;
use support::claude::{run_claude_hook_with_flags, ClaudeRunResultExt};

#[test]
fn test_e2e_ask_on_deny_downgrades_deny_to_ask() {
    let result = run_claude_hook_with_flags("Bash", "rm -rf /", &["--ask-on-deny"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
    result.assert_claude_reason_contains("[overridden]");
    result.assert_claude_reason_contains("rm-recursive-root");
}

#[test]
fn test_e2e_ask_on_deny_does_not_affect_allow() {
    let result = run_claude_hook_with_flags("Bash", "ls -la", &["--ask-on-deny"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_ask_on_deny_does_not_affect_ask() {
    // chmod 777 triggers ask via chmod-777 rule
    let result = run_claude_hook_with_flags("Bash", "chmod 777 /tmp/f", &["--ask-on-deny"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
    result.assert_claude_reason_not_contains("[overridden]");
}

#[test]
fn test_e2e_ask_ai_flag_accepted() {
    let result = run_claude_hook_with_flags("Bash", "ls -la", &["--ask-ai"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_ask_ai_lenient_flag_accepted() {
    let result = run_claude_hook_with_flags("Bash", "ls -la", &["--ask-ai-lenient"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_lenient_alias_flag_accepted() {
    let result = run_claude_hook_with_flags("Bash", "ls -la", &["--lenient"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_ask_ai_does_not_affect_deny() {
    let result = run_claude_hook_with_flags("Bash", "rm -rf /", &["--ask-ai"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("deny");
}

#[test]
fn test_e2e_ask_ai_falls_back_on_missing_codex() {
    // python3 -c should be ask (not on allowlist).
    // With --ask-ai and a missing AI judge command, fallback to ask.
    let result = run_claude_hook_with_flags("Bash", "python3 -c 'print(1)'", &["--ask-ai"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_e2e_ask_ai_handles_uv_run_python_c() {
    let result = run_claude_hook_with_flags("Bash", "uv run python3 -c 'print(1)'", &["--ask-ai"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_e2e_ask_ai_handles_django_shell_pipeline() {
    let result = run_claude_hook_with_flags(
        "Bash",
        "echo 'print(1)' | python manage.py shell",
        &["--ask-ai"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}
