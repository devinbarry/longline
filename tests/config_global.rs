mod support;
use support::claude::{ClaudeRunResultExt, ClaudeTestEnvExt};
use support::config::TestEnv;

// ---------------------------------------------------------------------------
// Global config tests
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_global_config_overrides_safety_level() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: critical\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_e2e_global_config_disables_rule() {
    let env = TestEnv::new()
        .with_global_config("disable_rules:\n  - chmod-777\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_e2e_global_config_no_file_unchanged() {
    // No global config file -> embedded defaults unchanged
    let env = TestEnv::new().build();
    let result = env.run_claude_hook("ls -la");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_no_global_config_uses_defaults() {
    // No global config -> embedded defaults should allow ls
    let env = TestEnv::new().build();
    let result = env.run_claude_hook("ls -la");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_invalid_global_config_exits_with_code_2() {
    let env = TestEnv::new()
        .with_global_config("not_a_valid_field: oops\n")
        .build();
    let result = env.run_claude_hook("ls");
    assert_eq!(
        result.exit_code, 2,
        "Invalid global config should cause exit code 2"
    );
}
