mod common;

#[test]
fn test_harness_smoke() {
    let env = common::TestEnv::new().build();
    let result = env.run_hook("ls -la");
    result.assert_decision("allow");
}

#[test]
fn test_harness_with_project_config() {
    let env = common::TestEnv::new()
        .with_project_config("override_safety_level: critical")
        .build();
    let result = env.run_hook("ls");
    result.assert_decision("allow");
}

#[test]
fn test_harness_standalone_run_hook() {
    let result = common::run_hook("Bash", "ls -la");
    result.assert_decision("allow");
}

#[test]
fn test_harness_run_result_reason() {
    let result = common::run_hook("Bash", "rm -rf /");
    result.assert_decision("deny");
    result.assert_reason_contains("rm-recursive-root");
}

#[test]
fn test_harness_run_result_reason_not_contains() {
    let result = common::run_hook("Bash", "ls -la");
    result.assert_decision("allow");
    result.assert_reason_not_contains("deny");
}

#[test]
fn test_harness_non_bash_tool() {
    let env = common::TestEnv::new().build();
    let result = env.run_hook_tool("Read", "");
    assert_eq!(result.stdout.trim(), "{}");
}

#[test]
fn test_harness_with_global_config() {
    let env = common::TestEnv::new()
        .with_global_config("override_safety_level: critical")
        .build();
    // chmod 777 is a high-level rule, skipped at critical safety
    let result = env.run_hook("chmod 777 /tmp/f");
    result.assert_reason_not_contains("chmod-777");
}

#[test]
fn test_harness_project_path() {
    let env = common::TestEnv::new()
        .with_project_config("override_safety_level: high")
        .build();
    assert!(env.project_path().join(".git").exists());
    assert!(env.project_path().join(".claude/longline.yaml").exists());
}

#[test]
fn test_harness_home_path() {
    let env = common::TestEnv::new().build();
    assert!(env
        .home_path()
        .join(".config/longline/ai-judge.yaml")
        .exists());
}
