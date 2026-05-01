mod support;
use support::claude::{ClaudeRunResultExt, ClaudeTestEnvExt};
use support::config::TestEnv;

// ---------------------------------------------------------------------------
// Config overlay tests
// ---------------------------------------------------------------------------

#[test]
fn test_config_disable_rule_by_id() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - chmod-777\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_config_disable_rule_does_not_affect_others() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - chmod-777\n")
        .build();
    let result = env.run_claude_hook("rm -rf /");
    result.assert_claude_decision("deny");
    result.assert_claude_reason_contains("rm-recursive-root");
}

#[test]
fn test_config_disable_multiple_rules() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - chmod-777\n  - npm-install\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    result.assert_claude_reason_not_contains("chmod-777");
    let result2 = env.run_claude_hook("npm install foo");
    result2.assert_claude_reason_not_contains("npm-install");
}

#[test]
fn test_config_disable_nonexistent_rule_no_error() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - this-rule-does-not-exist\n")
        .build();
    let result = env.run_claude_hook("ls");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_config_global_and_project_disable_different_rules() {
    let env = TestEnv::new()
        .with_global_config("disable_rules:\n  - chmod-777\n")
        .with_project_config("disable_rules:\n  - npm-install\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    result.assert_claude_reason_not_contains("chmod-777");
    let result2 = env.run_claude_hook("npm install foo");
    result2.assert_claude_reason_not_contains("npm-install");
}

#[test]
fn test_config_project_adds_custom_rule() {
    let env = TestEnv::new()
        .with_project_config(
            r#"rules:
  - id: custom-deny-mytool
    level: high
    match:
      command: mytool
    decision: deny
    reason: "mytool is dangerous in this project"
"#,
        )
        .build();
    let result = env.run_claude_hook("mytool --flag");
    result.assert_claude_decision("deny");
    result.assert_claude_reason_contains("custom-deny-mytool");
}

#[test]
fn test_config_project_rule_ask() {
    let env = TestEnv::new()
        .with_project_config(
            r#"rules:
  - id: custom-ask-deploy
    level: high
    match:
      command: deploy
    decision: ask
    reason: "Deployment requires approval"
"#,
        )
        .build();
    let result = env.run_claude_hook("deploy --prod");
    result.assert_claude_decision("ask");
    result.assert_claude_reason_contains("custom-ask-deploy");
}

#[test]
fn test_config_project_rule_does_not_leak() {
    let env_with = TestEnv::new()
        .with_project_config(
            r#"rules:
  - id: custom-leak-test
    level: high
    match:
      command: leaktool
    decision: deny
    reason: "test"
"#,
        )
        .build();
    let env_without = TestEnv::new().build();

    env_with
        .run_claude_hook("leaktool")
        .assert_claude_decision("deny");
    env_without
        .run_claude_hook("leaktool")
        .assert_claude_decision("ask");
}

#[test]
fn test_config_project_disable_builtin_add_replacement() {
    // Disable the builtin npm-install rule, then add npm to the allowlist
    // so that `npm install` is allowed in this project.
    // Note: custom rules with `decision: allow` are no-ops (Allow doesn't
    // beat the default Allow in worst-decision), so we use the allowlist instead.
    let env = TestEnv::new()
        .with_project_config(
            r#"disable_rules:
  - npm-install
allowlists:
  commands:
    - { command: npm, trust: standard }
"#,
        )
        .build();
    let result = env.run_claude_hook("npm install express");
    result.assert_claude_decision("allow");
}
