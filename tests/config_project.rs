mod support;
use support::claude::{ClaudeRunResultExt, ClaudeTestEnvExt};
use support::config::TestEnv;

// ---------------------------------------------------------------------------
// Project config tests
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_project_config_overrides_safety_level() {
    let env = TestEnv::new()
        .with_project_config("override_safety_level: critical\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_e2e_project_config_adds_allowlist() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: sometool, trust: standard }\n",
        )
        .build();
    let result = env.run_claude_hook("sometool --flag");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_project_config_disables_rule() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - chmod-777\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_e2e_project_config_no_file_unchanged() {
    // No project config -> embedded defaults apply unchanged
    let env = TestEnv::new().build();
    let result = env.run_claude_hook("ls -la");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_project_config_unknown_field_exits_2() {
    // "allowlist" is a typo for "allowlists"
    let env = TestEnv::new()
        .with_project_config("allowlist:\n  commands:\n    - docker\n")
        .build();
    let result = env.run_claude_hook("ls -la");
    assert_eq!(
        result.exit_code, 2,
        "Malformed project config should exit with code 2"
    );
}

#[test]
fn test_e2e_project_config_overrides_trust_level() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: minimal\n")
        .build();
    let result = env.run_claude_hook("git commit -m 'test'");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_e2e_hook_cwd_project_config_applies() {
    // Project config sets override_trust_level: full
    // git push requires trust: full -> should be allowed
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_claude_hook("git push origin main");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}
