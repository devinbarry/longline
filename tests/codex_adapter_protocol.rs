mod support;

use serde_json::json;
use support::bin::run_longline;
use support::config::TestEnv;

#[test]
fn corrupt_rules_manifest_codex_fail_open() {
    let env = TestEnv::new().build();
    // Write a corrupt rules manifest at ~/.config/longline/rules.yaml
    let rules_dir = env.home_path().join(".config/longline");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rules.yaml"), "this is: not [valid").unwrap();

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"}
    })
    .to_string();
    let result = run_longline(&["hook", "codex"], env.home_path(), Some(&input));

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("rules.yaml"),
        "stderr should name rules.yaml, got: {}",
        result.stderr
    );
}

#[test]
fn corrupt_rules_manifest_claude_keeps_exit_2() {
    let env = TestEnv::new().build();
    let rules_dir = env.home_path().join(".config/longline");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rules.yaml"), "this is: not [valid").unwrap();

    let input = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "ls"}
    })
    .to_string();
    let result = run_longline(&["hook", "claude"], env.home_path(), Some(&input));

    assert_eq!(result.exit_code, 2);
}

#[test]
fn corrupt_rules_manifest_check_keeps_exit_2() {
    let env = TestEnv::new().build();
    let rules_dir = env.home_path().join(".config/longline");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rules.yaml"), "this is: not [valid").unwrap();

    let result = run_longline(&["check"], env.home_path(), Some("ls"));
    assert_eq!(result.exit_code, 2);
}
