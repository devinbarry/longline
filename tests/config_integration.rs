mod common;
use common::TestEnv;

// ---------------------------------------------------------------------------
// Project config tests
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_project_config_overrides_safety_level() {
    let env = TestEnv::new()
        .with_project_config("override_safety_level: critical\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_e2e_project_config_adds_allowlist() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: sometool, trust: standard }\n",
        )
        .build();
    let result = env.run_hook("sometool --flag");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_e2e_project_config_disables_rule() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - chmod-777\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_e2e_project_config_no_file_unchanged() {
    // No project config -> embedded defaults apply unchanged
    let env = TestEnv::new().build();
    let result = env.run_hook("ls -la");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_e2e_project_config_unknown_field_exits_2() {
    // "allowlist" is a typo for "allowlists"
    let env = TestEnv::new()
        .with_project_config("allowlist:\n  commands:\n    - docker\n")
        .build();
    let result = env.run_hook("ls -la");
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
    let result = env.run_hook("git commit -m 'test'");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

// ---------------------------------------------------------------------------
// Global config tests
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_global_config_overrides_safety_level() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: critical\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_e2e_global_config_disables_rule() {
    let env = TestEnv::new()
        .with_global_config("disable_rules:\n  - chmod-777\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_e2e_global_config_no_file_unchanged() {
    // No global config file -> embedded defaults unchanged
    let env = TestEnv::new().build();
    let result = env.run_hook("ls -la");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_e2e_no_global_config_uses_defaults() {
    // No global config -> embedded defaults should allow ls
    let env = TestEnv::new().build();
    let result = env.run_hook("ls -la");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_e2e_invalid_global_config_exits_with_code_2() {
    let env = TestEnv::new()
        .with_global_config("not_a_valid_field: oops\n")
        .build();
    let result = env.run_hook("ls");
    assert_eq!(
        result.exit_code, 2,
        "Invalid global config should cause exit code 2"
    );
}

// ---------------------------------------------------------------------------
// CLI flag override tests
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
    let result = env.run_hook_with_flags("git push origin main", &["--trust-level", "standard"]);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
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
    let result = env.run_hook_with_flags("git checkout .", &["--safety-level", "critical"]);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
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
fn test_e2e_hook_cwd_project_config_applies() {
    // Project config sets override_trust_level: full
    // git push requires trust: full -> should be allowed
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_hook("git push origin main");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ---------------------------------------------------------------------------
// Combined global + project config tests
// ---------------------------------------------------------------------------

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
    let result = env.run_hook_with_flags("git add .", &["--trust-level", "minimal"]);
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
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
    let result = env.run_hook("git push origin main");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

// ===========================================================================
// Section A: Safety Level Override
// ===========================================================================

#[test]
fn test_config_strict_safety_activates_strict_rules() {
    // git-checkout-dot is a strict-level rule. At high (default), it's invisible.
    // At strict safety, it should trigger.
    let env = TestEnv::new()
        .with_project_config("override_safety_level: strict\n")
        .build();
    let result = env.run_hook("git checkout .");
    result.assert_decision("ask");
    result.assert_reason_contains("git-checkout-dot");
}

#[test]
fn test_config_critical_safety_hides_high_rules() {
    let env = TestEnv::new()
        .with_project_config("override_safety_level: critical\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    assert_eq!(result.exit_code, 0);
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_config_global_strict_project_overrides_to_critical() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: strict\n")
        .with_project_config("override_safety_level: critical\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_config_cli_safety_overrides_project_and_global() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: strict\n")
        .with_project_config("override_safety_level: strict\n")
        .build();
    let result = env.run_hook_with_flags("chmod 777 /tmp/f", &["--safety-level", "critical"]);
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_config_no_safety_override_uses_default_high() {
    let env = TestEnv::new().build();
    let result = env.run_hook("chmod 777 /tmp/f");
    result.assert_decision("ask");
    result.assert_reason_contains("chmod-777");
}

// ===========================================================================
// Section B: Trust Level Override
// ===========================================================================

#[test]
fn test_config_full_trust_allows_full_tier_commands() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_hook("git push origin main");
    result.assert_decision("allow");
}

#[test]
fn test_config_minimal_trust_restricts_standard_commands() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: minimal\n")
        .build();
    let result = env.run_hook("git commit -m 'test'");
    result.assert_decision("ask");
}

#[test]
fn test_config_global_full_project_overrides_to_minimal() {
    let env = TestEnv::new()
        .with_global_config("override_trust_level: full\n")
        .with_project_config("override_trust_level: minimal\n")
        .build();
    let result = env.run_hook("git commit -m 'test'");
    result.assert_decision("ask");
}

#[test]
fn test_config_cli_trust_overrides_project() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_hook_with_flags("git push origin main", &["--trust-level", "standard"]);
    result.assert_decision("ask");
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
        .run_hook("git push origin main")
        .assert_decision("allow");
    env_standard
        .run_hook("git push origin main")
        .assert_decision("ask");
    env_minimal
        .run_hook("git push origin main")
        .assert_decision("ask");
}

// ===========================================================================
// Section C: Allowlist Extensions
// ===========================================================================

#[test]
fn test_config_project_allowlist_allows_command() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: sometool, trust: standard }\n",
        )
        .build();
    let result = env.run_hook("sometool --flag");
    result.assert_decision("allow");
}

#[test]
fn test_config_without_project_allowlist_command_asks() {
    let env = TestEnv::new().build();
    let result = env.run_hook("sometool --flag");
    result.assert_decision("ask");
}

#[test]
fn test_config_project_allowlist_full_trust_only_at_full() {
    let env_standard = TestEnv::new()
        .with_project_config("allowlists:\n  commands:\n    - { command: mytool, trust: full }\n")
        .build();
    let result = env_standard.run_hook("mytool");
    result.assert_decision("ask");

    let env_full = TestEnv::new()
        .with_project_config(
            "override_trust_level: full\nallowlists:\n  commands:\n    - { command: mytool, trust: full }\n",
        )
        .build();
    let result = env_full.run_hook("mytool");
    result.assert_decision("allow");
}

#[test]
fn test_config_project_allowlist_does_not_affect_unrelated() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: sometool, trust: standard }\n",
        )
        .build();
    let result = env.run_hook("othertool --flag");
    result.assert_decision("ask");
}

#[test]
fn test_config_project_allowlist_multiple_entries() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: tool1, trust: standard }\n    - { command: tool2, trust: standard }\n",
        )
        .build();
    env.run_hook("tool1").assert_decision("allow");
    env.run_hook("tool2").assert_decision("allow");
    env.run_hook("tool3").assert_decision("ask");
}

#[test]
fn test_config_project_allowlist_compound_wrapper() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: \"uv run yamllint\", trust: standard }\n",
        )
        .build();
    env.run_hook("uv run yamllint .gitlab-ci.yml")
        .assert_decision("allow");
    env.run_hook("uv run dangeroustool").assert_decision("ask");
}

// ===========================================================================
// Section D: Disable Rules
// ===========================================================================

#[test]
fn test_config_disable_rule_by_id() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - chmod-777\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_config_disable_rule_does_not_affect_others() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - chmod-777\n")
        .build();
    let result = env.run_hook("rm -rf /");
    result.assert_decision("deny");
    result.assert_reason_contains("rm-recursive-root");
}

#[test]
fn test_config_disable_multiple_rules() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - chmod-777\n  - npm-install\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    result.assert_reason_not_contains("chmod-777");
    let result2 = env.run_hook("npm install foo");
    result2.assert_reason_not_contains("npm-install");
}

#[test]
fn test_config_disable_nonexistent_rule_no_error() {
    let env = TestEnv::new()
        .with_project_config("disable_rules:\n  - this-rule-does-not-exist\n")
        .build();
    let result = env.run_hook("ls");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}

#[test]
fn test_config_global_and_project_disable_different_rules() {
    let env = TestEnv::new()
        .with_global_config("disable_rules:\n  - chmod-777\n")
        .with_project_config("disable_rules:\n  - npm-install\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    result.assert_reason_not_contains("chmod-777");
    let result2 = env.run_hook("npm install foo");
    result2.assert_reason_not_contains("npm-install");
}

// ===========================================================================
// Section E: Custom Project Rules
// ===========================================================================

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
    let result = env.run_hook("mytool --flag");
    result.assert_decision("deny");
    result.assert_reason_contains("custom-deny-mytool");
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
    let result = env.run_hook("deploy --prod");
    result.assert_decision("ask");
    result.assert_reason_contains("custom-ask-deploy");
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

    env_with.run_hook("leaktool").assert_decision("deny");
    env_without.run_hook("leaktool").assert_decision("ask");
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
    let result = env.run_hook("npm install express");
    result.assert_decision("allow");
}

// ===========================================================================
// Section F: Config Precedence
// ===========================================================================

#[test]
fn test_config_precedence_no_configs_uses_defaults() {
    let env = TestEnv::new().build();
    let result = env.run_hook("ls");
    result.assert_decision("allow");
    let result = env.run_hook("rm -rf /");
    result.assert_decision("deny");
}

#[test]
fn test_config_precedence_global_only() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: critical\n")
        .build();
    let result = env.run_hook("chmod 777 /tmp/f");
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_config_precedence_project_only() {
    let env = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_hook("git push origin main");
    result.assert_decision("allow");
}

#[test]
fn test_config_precedence_project_overrides_global() {
    let env = TestEnv::new()
        .with_global_config("override_trust_level: minimal\n")
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_hook("git push origin main");
    result.assert_decision("allow");
}

#[test]
fn test_config_precedence_cli_overrides_all() {
    let env = TestEnv::new()
        .with_global_config("override_trust_level: full\n")
        .with_project_config("override_trust_level: full\n")
        .build();
    let result = env.run_hook_with_flags("git add .", &["--trust-level", "minimal"]);
    result.assert_decision("ask");
}

// ===========================================================================
// Section G: Config Isolation
// ===========================================================================

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

    env_allow.run_hook("isolationtool").assert_decision("allow");
    env_deny.run_hook("isolationtool").assert_decision("deny");
}

#[test]
fn test_config_isolation_project_only_affects_own_dir() {
    let env_with = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: projecttool, trust: standard }\n",
        )
        .build();
    let env_without = TestEnv::new().build();

    env_with.run_hook("projecttool").assert_decision("allow");
    env_without.run_hook("projecttool").assert_decision("ask");
}

#[test]
fn test_config_isolation_no_cross_test_leakage() {
    let env_a = TestEnv::new()
        .with_project_config("override_trust_level: full\n")
        .build();
    env_a
        .run_hook("git push origin main")
        .assert_decision("allow");
    drop(env_a);

    let env_b = TestEnv::new().build();
    env_b
        .run_hook("git push origin main")
        .assert_decision("ask");
}

// ===========================================================================
// Section H: Real-World ops/automation Config
// ===========================================================================

/// The ops/automation project config (subset of the actual config).
const OPS_AUTOMATION_CONFIG: &str = r#"
allowlists:
  commands:
    - command: "uv run prefect flow-run logs"
      trust: standard
      reason: "Read Prefect flow run logs"
    - command: "uv run prefect flow-run ls"
      trust: standard
      reason: "List Prefect flow runs"
    - command: "uv run prefect deployment ls"
      trust: standard
      reason: "List Prefect deployments"
    - command: "uv run prefect deployment run"
      trust: standard
      reason: "Trigger Prefect deployment runs"
    - command: "uv run prefect version"
      trust: standard
      reason: "Check Prefect version"
    - command: "uv run yamllint"
      trust: standard
      reason: "YAML linting"
    - command: "validate.sh"
      trust: standard
      reason: "Read-only project validation"
    - command: "shellcheck"
      trust: standard
      reason: "Shell script linting"
    - command: "git push"
      trust: standard
      reason: "Push commits to remote"
    - command: "docker run"
      trust: standard
      reason: "Docker-based validation"
    - command: "chmod"
      trust: standard
      reason: "Change file permissions"

rules:
  - id: env-grep-config
    level: high
    match:
      command: env
    decision: allow
    reason: "Check environment configuration"

disable_rules:
  - printenv
"#;

#[test]
fn test_ops_prefect_flow_run_logs_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("uv run prefect flow-run logs abc-123");
    result.assert_decision("allow");
}

#[test]
fn test_ops_prefect_deployment_ls_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("uv run prefect deployment ls");
    result.assert_decision("allow");
}

#[test]
fn test_ops_prefect_deployment_run_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("uv run prefect deployment run my-deployment/my-flow");
    result.assert_decision("allow");
}

#[test]
fn test_ops_prefect_version_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("uv run prefect version");
    result.assert_decision("allow");
}

#[test]
fn test_ops_yamllint_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("uv run yamllint .gitlab-ci.yml");
    result.assert_decision("allow");
}

#[test]
fn test_ops_prefect_unlisted_subcommand_asks() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("uv run prefect config view");
    result.assert_decision("ask");
}

#[test]
fn test_ops_validate_sh_basename_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("./scripts/local/validate.sh");
    result.assert_decision("allow");
}

#[test]
fn test_ops_shellcheck_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("shellcheck scripts/deploy.sh");
    result.assert_decision("allow");
}

#[test]
fn test_ops_env_custom_rule_allows() {
    // The printenv rule is disabled, and env is in the core allowlist at minimal trust,
    // so `env` is allowed via the allowlist (the custom allow rule is a no-op since
    // Allow doesn't beat Allow in worst-decision evaluation).
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("env");
    result.assert_decision("allow");
}

#[test]
fn test_ops_printenv_rule_disabled() {
    // With the printenv rule disabled, printenv falls through to the core allowlist
    // where it's listed at minimal trust, so it's allowed.
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("printenv");
    result.assert_decision("allow");
}

#[test]
fn test_ops_docker_run_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("docker run --rm alpine echo hello");
    result.assert_decision("allow");
}

#[test]
fn test_ops_random_uv_run_tool_asks() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_hook("uv run some-random-tool");
    result.assert_decision("ask");
}
