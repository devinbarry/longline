mod support;
use support::claude::{ClaudeRunResultExt, ClaudeTestEnvExt};
use support::config::TestEnv;

// ---------------------------------------------------------------------------
// Config precedence tests
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_cli_trust_level_overrides_global_config_in_hook_mode() {
    // Global config sets override_trust_level: full
    // CLI flag sets --trust-level standard
    // git push requires trust: full
    // Expected: CLI wins -> standard trust -> git push = ask
    let env = TestEnv::new()
        .with_global_config("override_trust_level: full\n")
        .build();
    let result =
        env.run_claude_hook_with_flags("git push origin main", &["--trust-level", "standard"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_e2e_cli_safety_level_overrides_global_config_in_hook_mode() {
    // Global config sets override_safety_level: strict
    // CLI flag sets --safety-level critical
    // git-checkout-dot is a strict-level rule
    // Expected: CLI wins -> critical safety -> strict rule skipped -> allow
    let env = TestEnv::new()
        .with_global_config("override_safety_level: strict\n")
        .build();
    let result = env.run_claude_hook_with_flags("git checkout .", &["--safety-level", "critical"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_e2e_cli_trust_level_overrides_project_config_in_check_mode() {
    // Project config sets override_trust_level: full
    // CLI flag sets --trust-level standard
    // git push requires trust: full
    // Expected: CLI wins -> standard trust -> git push = ask
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();

    // Write a check input file with "git push origin main"
    let check_file = env.project_path().join("commands.txt");
    std::fs::write(&check_file, "git push origin main\n").unwrap();

    let check_file_str = check_file.to_string_lossy().to_string();
    let result = env.run_subcommand(&["--trust-level", "standard", "check", &check_file_str]);

    // The output table should show "ask" for git push, not "allow"
    assert!(
        result.stdout.contains("ask"),
        "CLI --trust-level standard should override project full trust for git push: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_cli_trust_overrides_both_global_and_project_in_hook_mode() {
    // Global config: override_trust_level: full
    // Project config: override_trust_level: full
    // CLI: --trust-level minimal
    // Expected: CLI wins -> minimal trust -> git add (standard trust) = ask
    let env = TestEnv::new()
        .with_global_config("override_trust_level: full\n")
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_claude_hook_with_flags("git add .", &["--trust-level", "minimal"]);
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("ask");
}

#[test]
fn test_e2e_project_config_overrides_global_in_hook_mode() {
    // Global config: override_trust_level: minimal
    // Project config: override_trust_level: full
    // Expected: project wins -> full trust -> git push allowed
    let env = TestEnv::new()
        .with_global_config("override_trust_level: minimal\n")
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_claude_hook("git push origin main");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
}

#[test]
fn test_config_strict_safety_activates_strict_rules() {
    // git-checkout-dot is a strict-level rule. At high (default), it's invisible.
    // At strict safety, it should trigger.
    let env = TestEnv::new()
        .with_project_config("override_safety_level: strict\n")
        .build();
    let result = env.run_claude_hook("git checkout .");
    result.assert_claude_decision("ask");
    result.assert_claude_reason_contains("git-checkout-dot");
}

#[test]
fn test_config_critical_safety_hides_high_rules() {
    let env = TestEnv::new()
        .with_project_config("override_safety_level: critical\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_config_global_strict_project_overrides_to_critical() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: strict\n")
        .with_project_config("override_safety_level: critical\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_config_cli_safety_overrides_project_and_global() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: strict\n")
        .with_project_config("override_safety_level: strict\n")
        .build();
    let result =
        env.run_claude_hook_with_flags("chmod 777 /tmp/f", &["--safety-level", "critical"]);
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_config_no_safety_override_uses_default_high() {
    let env = TestEnv::new().build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    result.assert_claude_decision("ask");
    result.assert_claude_reason_contains("chmod-777");
}

#[test]
fn test_config_full_trust_allows_full_tier_commands() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_claude_hook("git push origin main");
    result.assert_claude_decision("allow");
}

#[test]
fn test_config_minimal_trust_restricts_standard_commands() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: minimal\n")
        .build();
    let result = env.run_claude_hook("git commit -m 'test'");
    result.assert_claude_decision("ask");
}

#[test]
fn test_config_global_full_project_overrides_to_minimal() {
    let env = TestEnv::new()
        .with_global_config("override_trust_level: full\n")
        .with_project_config("override_trust_level: minimal\n")
        .build();
    let result = env.run_claude_hook("git commit -m 'test'");
    result.assert_claude_decision("ask");
}

#[test]
fn test_config_cli_trust_overrides_project() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let result =
        env.run_claude_hook_with_flags("git push origin main", &["--trust-level", "standard"]);
    result.assert_claude_decision("ask");
}

#[test]
fn test_config_git_push_trust_behavior_across_levels() {
    let env_full = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let env_standard = TestEnv::new()
        .with_project_config("override_trust_level: standard\n")
        .build();
    let env_minimal = TestEnv::new()
        .with_project_config("override_trust_level: minimal\n")
        .build();

    env_full
        .run_claude_hook("git push origin main")
        .assert_claude_decision("allow");
    env_standard
        .run_claude_hook("git push origin main")
        .assert_claude_decision("ask");
    env_minimal
        .run_claude_hook("git push origin main")
        .assert_claude_decision("ask");
}

#[test]
fn test_config_precedence_no_configs_uses_defaults() {
    let env = TestEnv::new().build();
    let result = env.run_claude_hook("ls");
    result.assert_claude_decision("allow");
    let result = env.run_claude_hook("rm -rf /");
    result.assert_claude_decision("deny");
}

#[test]
fn test_config_precedence_global_only() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: critical\n")
        .build();
    let result = env.run_claude_hook("chmod 777 /tmp/f");
    result.assert_claude_reason_not_contains("chmod-777");
}

#[test]
fn test_config_precedence_project_only() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_claude_hook("git push origin main");
    result.assert_claude_decision("allow");
}

#[test]
fn test_config_precedence_project_overrides_global() {
    let env = TestEnv::new()
        .with_global_config("override_trust_level: minimal\n")
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_claude_hook("git push origin main");
    result.assert_claude_decision("allow");
}

#[test]
fn test_config_precedence_cli_overrides_all() {
    let env = TestEnv::new()
        .with_global_config("override_trust_level: full\n")
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_claude_hook_with_flags("git add .", &["--trust-level", "minimal"]);
    result.assert_claude_decision("ask");
}

#[test]
fn test_config_isolation_different_envs_different_results() {
    let env_allow = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: isolationtool, trust: standard }\n",
        )
        .build();
    let env_deny = TestEnv::new()
        .with_project_config(
            r#"rules:
  - id: isolation-deny
    level: high
    match:
      command: isolationtool
    decision: deny
    reason: "denied in this project"
"#,
        )
        .build();

    env_allow
        .run_claude_hook("isolationtool")
        .assert_claude_decision("allow");
    env_deny
        .run_claude_hook("isolationtool")
        .assert_claude_decision("deny");
}

#[test]
fn test_config_isolation_project_only_affects_own_dir() {
    let env_with = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: projecttool, trust: standard }\n",
        )
        .build();
    let env_without = TestEnv::new().build();

    env_with
        .run_claude_hook("projecttool")
        .assert_claude_decision("allow");
    env_without
        .run_claude_hook("projecttool")
        .assert_claude_decision("ask");
}

#[test]
fn test_config_isolation_no_cross_test_leakage() {
    let env_a = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    env_a
        .run_claude_hook("git push origin main")
        .assert_claude_decision("allow");
    drop(env_a);

    let env_b = TestEnv::new().build();
    env_b
        .run_claude_hook("git push origin main")
        .assert_claude_decision("ask");
}
