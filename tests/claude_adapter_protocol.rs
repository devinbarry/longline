mod support;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use support::bin::longline_bin;
use support::claude::{run_claude_hook, ClaudeRunResultExt, ClaudeTestEnvExt};
use support::config::TestEnv;
use support::paths::rules_path;
use support::result::RunResult;

fn run_raw_claude_hook(args: &[&str], home: &Path, stdin: &str) -> RunResult {
    let mut child = Command::new(longline_bin())
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    RunResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn run_raw_claude_hook_allow_early_exit(args: &[&str], home: &Path, stdin: &str) -> RunResult {
    let mut child = Command::new(longline_bin())
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());

    let output = child.wait_with_output().unwrap();
    RunResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn temp_home() -> tempfile::TempDir {
    tempfile::TempDir::new().unwrap()
}

#[test]
fn test_e2e_non_bash_tool_passes_through() {
    let result = run_claude_hook("Write", "");
    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.stdout.trim(),
        "{}",
        "Non-Bash tools should passthrough with empty object"
    );
}

#[test]
fn test_e2e_unsupported_tool_passthrough_exact_json() {
    let result = run_claude_hook("Write", "");
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, "{}\n");
    assert_eq!(result.stderr, "");
}

#[test]
fn test_e2e_unsupported_tool_config_finalization_error_exits_2_without_json() {
    let env = TestEnv::new()
        .with_global_config("override_trust_level: impossible\n")
        .build();

    let result = env.run_claude_tool_hook("Write", "");

    assert_eq!(result.exit_code, 2);
    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("longline:"),
        "stderr should contain longline error prefix, got: {}",
        result.stderr
    );
}

#[test]
fn test_e2e_hook_config_finalization_error_exits_2_without_json() {
    let env = TestEnv::new()
        .with_global_config("override_safety_level: not-a-real-level\n")
        .build();

    let result = env.run_claude_hook("ls -la");
    assert_eq!(result.exit_code, 2);
    assert!(result.stdout.is_empty(), "stdout: {}", result.stdout);
    assert!(
        result.stderr.contains("longline:"),
        "stderr should contain longline error, got: {}",
        result.stderr
    );
}

#[test]
fn test_e2e_malformed_hook_json_asks_without_stderr() {
    let home = temp_home();
    let config = rules_path();

    let result = run_raw_claude_hook(&["--config", &config], home.path(), "{not json");

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stderr, "");
    result.assert_claude_decision("ask");
    result.assert_claude_reason_contains("Failed to parse hook input:");
}

#[test]
fn test_e2e_malformed_hook_json_does_not_finalize_global_config() {
    let home = temp_home();
    let config_dir = home.path().join(".config").join("longline");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("longline.yaml"),
        "override_trust_level: impossible\n",
    )
    .unwrap();
    let config = rules_path();

    let result = run_raw_claude_hook(&["--config", &config], home.path(), "{not json");

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stderr, "");
    result.assert_claude_decision("ask");
    result.assert_claude_reason_contains("Failed to parse hook input:");
}

#[test]
fn test_e2e_malformed_hook_json_still_requires_base_config_to_load() {
    let home = temp_home();
    let missing = PathBuf::from("/nonexistent/rules.yaml");

    let result = run_raw_claude_hook_allow_early_exit(
        &["--config", missing.to_str().unwrap()],
        home.path(),
        "{not json",
    );

    assert_eq!(result.exit_code, 2);
    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("longline:"),
        "stderr should contain longline error, got: {}",
        result.stderr
    );
}

#[test]
fn test_e2e_bash_missing_command_reason_unchanged() {
    let input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {},
        "session_id": "test-session",
        "cwd": "/tmp"
    });

    let home = tempfile::TempDir::new().unwrap();
    let config_dir = home.path().join(".config").join("longline");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("ai-judge.yaml"),
        "command: /definitely-not-a-real-ai-judge-command-12345\ntimeout: 1\n",
    )
    .unwrap();

    let mut child = Command::new(longline_bin())
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn longline");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let result = RunResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    };

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.claude_decision(), "allow");
    assert_eq!(result.claude_reason(), "longline: no command");
}

#[test]
fn test_e2e_allow_emits_explicit_decision() {
    let result = run_claude_hook("Bash", "ls -la");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("allow");
    result.assert_claude_reason_contains("longline:");
}

#[test]
fn test_e2e_allow_has_hook_event_name() {
    let result = run_claude_hook("Bash", "ls -la");
    assert_eq!(result.exit_code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse",
        "Allow decisions must include hookEventName: {}",
        result.stdout
    );
}

#[test]
fn test_e2e_claude_log_entry_includes_runtime_field() {
    let env = TestEnv::new().build();
    let result = env.run_claude_hook("rm -rf /");
    assert_eq!(result.exit_code, 0);
    result.assert_claude_decision("deny");

    let log_path = env.home_path().join(".claude/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log_path).expect("claude log file exists");
    let last = content.lines().filter(|l| !l.is_empty()).last().unwrap();
    let entry: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(entry["runtime"], "claude");
    assert_eq!(entry["tool"], "Bash");
    assert_eq!(entry["decision"], "deny");
}
