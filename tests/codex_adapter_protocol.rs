mod support;

use serde_json::json;
use support::bin::run_longline;
use support::codex::CodexRunResultExt;
use support::config::TestEnv;

fn codex_input(event: &str, tool_name: &str, command: &str) -> String {
    json!({
        "hook_event_name": event,
        "tool_name": tool_name,
        "tool_input": {"command": command},
        "session_id": "test",
        "cwd": "/tmp"
    })
    .to_string()
}

fn codex_input_no_command(event: &str, tool_name: &str) -> String {
    json!({
        "hook_event_name": event,
        "tool_name": tool_name,
        "tool_input": {},
        "session_id": "test",
        "cwd": "/tmp"
    })
    .to_string()
}

fn run_codex(env: &TestEnv, input: &str) -> support::result::RunResult {
    run_longline(&["hook", "codex"], env.home_path(), Some(input))
}

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

// ---------- Layer 2: Bash happy paths ----------

#[test]
fn pre_tool_use_bash_safe_returns_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn pre_tool_use_bash_dangerous_returns_deny_json() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "rm -rf /"));
    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.codex_pre_tool_use_decision().as_deref(),
        Some("deny"),
        "stdout: {:?}",
        result.stdout
    );
    let reason = result.codex_pre_tool_use_reason().unwrap_or_default();
    assert!(
        !reason.is_empty(),
        "deny must include non-empty permissionDecisionReason; stdout: {:?}",
        result.stdout
    );
}

#[test]
fn pre_tool_use_bash_ambiguous_returns_no_decision() {
    let env = TestEnv::new().build();
    // python -c 'import os' triggers ask via the AI judge / interpreter rules
    let result = run_codex(
        &env,
        &codex_input("PreToolUse", "Bash", "python -c 'import os'"),
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
}

#[test]
fn permission_request_bash_safe_returns_allow_behavior() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PermissionRequest", "Bash", "ls"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_permission_request_behavior("allow");
}

#[test]
fn permission_request_bash_dangerous_returns_deny_behavior_with_message() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PermissionRequest", "Bash", "rm -rf /"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_permission_request_behavior("deny");
    let msg = result
        .codex_permission_request_message()
        .unwrap_or_default();
    assert!(
        !msg.is_empty(),
        "PermissionRequest deny should carry a message; stdout: {:?}",
        result.stdout
    );
}

#[test]
fn permission_request_bash_ambiguous_returns_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(
        &env,
        &codex_input("PermissionRequest", "Bash", "python -c 'import os'"),
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
}

// ---------- Layer 2: passthrough ----------

#[test]
fn pre_tool_use_apply_patch_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input_no_command("PreToolUse", "apply_patch"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn permission_request_mcp_tool_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(
        &env,
        &codex_input_no_command("PermissionRequest", "mcp__filesystem__read_file"),
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn post_tool_use_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PostToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn session_start_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, r#"{"hook_event_name":"SessionStart"}"#);
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

#[test]
fn unknown_event_passthrough_no_decision() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, r#"{"hook_event_name":"FutureCodexEvent"}"#);
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert_eq!(result.stderr, "");
}

// ---------- Layer 2: malformed input ----------

#[test]
fn malformed_json_returns_no_decision_with_stderr() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, "{this is not json");
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert!(
        result.stderr.contains("longline:"),
        "stderr: {:?}",
        result.stderr
    );
}

#[test]
fn missing_event_name_returns_no_decision_with_stderr() {
    let env = TestEnv::new().build();
    let result = run_codex(
        &env,
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    assert!(
        result.stderr.contains("longline:"),
        "stderr: {:?}",
        result.stderr
    );
}

// ---------- Layer 2: fail-open observability (per source) ----------

#[test]
fn corrupt_global_config_codex_fail_open_writes_jsonl() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: not-a-real-level\n")
        .build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    result.assert_codex_no_decision();
    assert!(
        result.stderr.contains("longline:"),
        "stderr: {:?}",
        result.stderr
    );

    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().filter(|l| !l.is_empty()).last().unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["parse_ok"], false);
    assert_eq!(entry["decision"], "allow");
    assert!(entry["reason"].as_str().unwrap().contains("config"));
}

#[test]
fn corrupt_project_config_codex_fail_open_writes_jsonl() {
    let env = TestEnv::new()
        .with_project_config("override_safety_level: not-a-real-level\n")
        .build();
    let project_path = env.project_path().to_string_lossy().to_string();
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "session_id": "test",
        "cwd": project_path,
    })
    .to_string();
    let result = run_codex(&env, &input);
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    result.assert_codex_no_decision();

    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().filter(|l| !l.is_empty()).last().unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["parse_ok"], false);
    assert_eq!(entry["decision"], "allow");
}

#[test]
fn corrupt_rules_manifest_codex_fail_open_writes_jsonl() {
    let env = TestEnv::new().build();
    let rules_dir = env.home_path().join(".config/longline");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rules.yaml"), "this is: not [valid").unwrap();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "ls"));
    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    result.assert_codex_no_decision();
    assert!(
        result.stderr.contains("rules.yaml"),
        "stderr should name file path, got {:?}",
        result.stderr
    );

    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("fail-open log entry written");
    let last = content.lines().filter(|l| !l.is_empty()).last().unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["parse_ok"], false);
    assert_eq!(entry["decision"], "allow");
    assert!(entry["reason"].as_str().unwrap().contains("rules manifest"));
}

// ---------- Layer 2: runtime field ----------

#[test]
fn codex_log_entry_includes_runtime_field() {
    let env = TestEnv::new().build();
    let result = run_codex(&env, &codex_input("PreToolUse", "Bash", "rm -rf /"));
    assert_eq!(result.exit_code, 0);
    let log = env.home_path().join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("log file exists");
    let last = content.lines().filter(|l| !l.is_empty()).last().unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["tool"], "Bash");
    assert_eq!(entry["decision"], "deny");
}
