mod support;
use support::claude::{ClaudeRunResultExt, ClaudeTestEnvExt};
use support::config::TestEnv;

// ---------------------------------------------------------------------------
// Config allowlist tests
// ---------------------------------------------------------------------------

#[test]
fn test_config_project_allowlist_allows_command() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: sometool, trust: standard }\n",
        )
        .build();
    let result = env.run_claude_hook("sometool --flag");
    result.assert_claude_decision("allow");
}

#[test]
fn test_config_without_project_allowlist_command_asks() {
    let env = TestEnv::new().build();
    let result = env.run_claude_hook("sometool --flag");
    result.assert_claude_decision("ask");
}

#[test]
fn test_config_project_allowlist_full_trust_only_at_full() {
    let env_standard = TestEnv::new()
        .with_project_config("allowlists:\n  commands:\n    - { command: mytool, trust: full }\n")
        .build();
    let result = env_standard.run_claude_hook("mytool");
    result.assert_claude_decision("ask");

    let env_full = TestEnv::new()
        .with_project_config(
            "override_trust_level: full\nallowlists:\n  commands:\n    - { command: mytool, trust: full }\n",
        )
        .build();
    let result = env_full.run_claude_hook("mytool");
    result.assert_claude_decision("allow");
}

#[test]
fn test_config_project_allowlist_does_not_affect_unrelated() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: sometool, trust: standard }\n",
        )
        .build();
    let result = env.run_claude_hook("othertool --flag");
    result.assert_claude_decision("ask");
}

#[test]
fn test_config_project_allowlist_multiple_entries() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: tool1, trust: standard }\n    - { command: tool2, trust: standard }\n",
        )
        .build();
    env.run_claude_hook("tool1").assert_claude_decision("allow");
    env.run_claude_hook("tool2").assert_claude_decision("allow");
    env.run_claude_hook("tool3").assert_claude_decision("ask");
}

#[test]
fn test_config_project_allowlist_compound_wrapper() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: \"uv run yamllint\", trust: standard }\n",
        )
        .build();
    env.run_claude_hook("uv run yamllint .gitlab-ci.yml")
        .assert_claude_decision("allow");
    env.run_claude_hook("uv run dangeroustool")
        .assert_claude_decision("ask");
}

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
    let result = env.run_claude_hook("uv run prefect flow-run logs abc-123");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_prefect_deployment_ls_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("uv run prefect deployment ls");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_prefect_deployment_run_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("uv run prefect deployment run my-deployment/my-flow");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_prefect_version_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("uv run prefect version");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_yamllint_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("uv run yamllint .gitlab-ci.yml");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_prefect_unlisted_subcommand_asks() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("uv run prefect config view");
    result.assert_claude_decision("ask");
}

#[test]
fn test_ops_validate_sh_basename_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("./scripts/local/validate.sh");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_shellcheck_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("shellcheck scripts/deploy.sh");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_env_custom_rule_allows() {
    // The printenv rule is disabled, and env is in the core allowlist at minimal trust,
    // so `env` is allowed via the allowlist (the custom allow rule is a no-op since
    // Allow doesn't beat Allow in worst-decision evaluation).
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("env");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_printenv_rule_disabled() {
    // With the printenv rule disabled, printenv falls through to the core allowlist
    // where it's listed at minimal trust, so it's allowed.
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("printenv");
    result.assert_claude_decision("allow");
}

#[test]
fn custom_allow_env_does_not_override_active_printenv_ask() {
    let env = TestEnv::new()
        .with_project_config(
            r#"rules:
  - id: custom-allow-env-dump
    level: high
    match:
      command: env
    decision: allow
    reason: "project permits env"
"#,
        )
        .build();

    let result = env.run_claude_hook("env");
    result.assert_claude_decision("ask");
    result.assert_claude_reason_contains("printenv");
}

#[test]
fn custom_allow_env_cannot_override_opaque_executable_semantics() {
    let env = TestEnv::new()
        .with_project_config(
            r#"disable_rules: [printenv]
rules:
  - id: custom-allow-all-env
    level: high
    match:
      command: env
    decision: allow
    reason: "project permits env"
"#,
        )
        .build();

    for command in [
        "env --split-string='bash -c id' echo safe",
        "env --chdir=/etc cat shadow",
        "/tmp/env FOO=bar git status",
    ] {
        let result = env.run_claude_hook(command);
        result.assert_claude_decision("ask");
        result.assert_claude_reason_contains("unreviewed option or executable path");
    }
}

#[test]
fn same_id_printenv_allow_replacement_applies_to_env_and_printenv() {
    let env = TestEnv::new()
        .with_project_config(
            r#"disable_rules: [printenv]
rules:
  - id: printenv
    level: high
    match:
      command: printenv
    decision: allow
    reason: "replacement allows environment inspection"
"#,
        )
        .build();

    env.run_claude_hook("env").assert_claude_decision("allow");
    env.run_claude_hook("printenv")
        .assert_claude_decision("allow");
}

#[test]
fn same_id_printenv_deny_replacement_applies_to_env_and_printenv() {
    let env = TestEnv::new()
        .with_project_config(
            r#"disable_rules: [printenv]
rules:
  - id: printenv
    level: high
    match:
      command: printenv
    decision: deny
    reason: "replacement denies environment inspection"
  - id: custom-ask-env-dump
    level: high
    match:
      command: env
    decision: ask
    reason: "project asks for env"
"#,
        )
        .build();

    for command in ["env", "printenv"] {
        let result = env.run_claude_hook(command);
        result.assert_claude_decision("deny");
        result.assert_claude_reason_contains("replacement denies environment inspection");
    }
}

#[test]
fn inactive_same_id_printenv_replacement_respects_its_level() {
    let env = TestEnv::new()
        .with_project_config(
            r#"disable_rules: [printenv]
rules:
  - id: printenv
    level: strict
    match:
      command: printenv
    decision: deny
    reason: "strict replacement is inactive at high safety"
"#,
        )
        .build();

    env.run_claude_hook("env").assert_claude_decision("allow");
    env.run_claude_hook("printenv")
        .assert_claude_decision("allow");
}

#[test]
fn unrelated_same_id_rule_is_not_treated_as_printenv_policy() {
    let env = TestEnv::new()
        .with_project_config(
            r#"disable_rules: [printenv]
rules:
  - id: printenv
    level: high
    match:
      command: unrelated-tool
    decision: deny
    reason: "same id but unrelated matcher"
"#,
        )
        .build();

    env.run_claude_hook("env").assert_claude_decision("allow");
    env.run_claude_hook("printenv")
        .assert_claude_decision("allow");
    env.run_claude_hook("unrelated-tool")
        .assert_claude_decision("deny");
}

#[test]
fn test_ops_docker_run_allows() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("docker run --rm alpine echo hello");
    result.assert_claude_decision("allow");
}

#[test]
fn test_ops_random_uv_run_tool_asks() {
    let env = TestEnv::new()
        .with_project_config(OPS_AUTOMATION_CONFIG)
        .build();
    let result = env.run_claude_hook("uv run some-random-tool");
    result.assert_claude_decision("ask");
}
