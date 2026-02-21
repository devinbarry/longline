mod common;
use common::{run_hook, TestEnv};

#[test]
fn test_e2e_wrapper_allowlist_specific_entry_allows() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: \"uv run yamllint\", trust: standard }\n",
        )
        .build();
    let result = env.run_hook("uv run yamllint .gitlab-ci.yml");
    result.assert_decision("allow");
}

#[test]
fn test_e2e_wrapper_allowlist_rejects_different_inner() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: \"uv run yamllint\", trust: standard }\n",
        )
        .build();
    let result = env.run_hook("uv run dangeroustool");
    result.assert_decision("ask");
}

#[test]
fn test_e2e_wrapper_allowlist_rules_still_deny() {
    let env = TestEnv::new()
        .with_project_config(
            "allowlists:\n  commands:\n    - { command: \"uv run yamllint\", trust: standard }\n",
        )
        .build();
    let result = env.run_hook("uv run rm -rf /");
    result.assert_decision("deny");
}

#[test]
fn test_e2e_wrapper_allowlist_timeout_unknown_still_asks() {
    let result = run_hook("Bash", "timeout 10 some_unknown_command");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("ask");
}

#[test]
fn test_e2e_wrapper_allowlist_timeout_safe_inner_allows() {
    let result = run_hook("Bash", "timeout 30 ls");
    assert_eq!(result.exit_code, 0);
    result.assert_decision("allow");
}
