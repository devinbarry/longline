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
