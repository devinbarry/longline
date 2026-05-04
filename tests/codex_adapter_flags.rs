mod support;

use serde_json::json;
use support::bin::run_longline;
use support::codex::CodexRunResultExt;
use support::config::TestEnv;
use support::result::RunResult;

fn run_codex_with_flags(env: &TestEnv, input: &str, flags: &[&str]) -> RunResult {
    // Flags like --ask-on-deny / --ask-ai are top-level CLI args and must
    // appear BEFORE the `hook codex` subcommand for clap to accept them.
    let mut args: Vec<&str> = flags.to_vec();
    args.push("hook");
    args.push("codex");
    run_longline(&args, env.home_path(), Some(input))
}

fn codex_input(event: &str, command: &str) -> String {
    json!({
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "session_id": "test",
        "cwd": "/tmp"
    })
    .to_string()
}

fn read_last_jsonl(home: &std::path::Path) -> serde_json::Value {
    let log = home.join(".codex/hooks-logs/longline.jsonl");
    let content = std::fs::read_to_string(&log).expect("log file exists");
    let last = content
        .lines()
        .rfind(|l| !l.is_empty())
        .expect("at least one entry");
    serde_json::from_str(last).unwrap()
}

// ---------- --ask-on-deny: empty stdout downgrade + JSONL audit ----------

#[test]
fn ask_on_deny_pre_tool_use_writes_jsonl_with_overridden() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(
        &env,
        &codex_input("PreToolUse", "rm -rf /"),
        &["--ask-on-deny"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();

    let entry = read_last_jsonl(env.home_path());
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["decision"], "ask");
    assert_eq!(entry["original_decision"], "deny");
    assert_eq!(entry["overridden"], true);
}

#[test]
fn ask_on_deny_permission_request_writes_jsonl_with_overridden() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(
        &env,
        &codex_input("PermissionRequest", "rm -rf /"),
        &["--ask-on-deny"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();

    let entry = read_last_jsonl(env.home_path());
    assert_eq!(entry["runtime"], "codex");
    assert_eq!(entry["decision"], "ask");
    assert_eq!(entry["original_decision"], "deny");
    assert_eq!(entry["overridden"], true);
}

#[test]
fn ask_on_deny_does_not_affect_allow() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(
        &env,
        &codex_input("PermissionRequest", "ls"),
        &["--ask-on-deny"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_permission_request_behavior("allow");
}

#[test]
fn ask_on_deny_does_not_affect_ask() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(
        &env,
        &codex_input("PreToolUse", "chmod 777 /tmp/f"),
        &["--ask-on-deny"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
    let entry = read_last_jsonl(env.home_path());
    assert_eq!(entry["decision"], "ask");
    assert_ne!(entry["overridden"], true);
}

// ---------- --ask-ai / --ask-ai-lenient flag plumbing ----------

#[test]
fn ask_ai_flag_accepted_on_codex() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(&env, &codex_input("PreToolUse", "ls"), &["--ask-ai"]);
    assert_eq!(result.exit_code, 0);
    // Safe Bash command -> Allow -> empty stdout on PreToolUse.
    result.assert_codex_no_decision();
}

#[test]
fn ask_ai_lenient_flag_accepted_on_codex() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(
        &env,
        &codex_input("PreToolUse", "ls"),
        &["--ask-ai-lenient"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
}

#[test]
fn lenient_alias_flag_accepted_on_codex() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(&env, &codex_input("PreToolUse", "ls"), &["--lenient"]);
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
}

#[test]
fn ask_ai_does_not_affect_deny_on_codex_pre_tool_use() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(&env, &codex_input("PreToolUse", "rm -rf /"), &["--ask-ai"]);
    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.codex_pre_tool_use_decision().as_deref(),
        Some("deny")
    );
}

#[test]
fn ask_ai_does_not_affect_deny_on_codex_permission_request() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(
        &env,
        &codex_input("PermissionRequest", "rm -rf /"),
        &["--ask-ai"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_permission_request_behavior("deny");
}

#[test]
fn ask_ai_falls_back_on_missing_codex_cli_pre_tool_use() {
    // python3 -c is ask via interpreter rules; --ask-ai with missing codex CLI
    // (TestEnv installs a fake one that doesn't exist) falls back to ask.
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(
        &env,
        &codex_input("PreToolUse", "python3 -c 'print(1)'"),
        &["--ask-ai"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
}

#[test]
fn ask_ai_falls_back_on_missing_codex_cli_permission_request() {
    let env = TestEnv::new().build();
    let result = run_codex_with_flags(
        &env,
        &codex_input("PermissionRequest", "python3 -c 'print(1)'"),
        &["--ask-ai"],
    );
    assert_eq!(result.exit_code, 0);
    result.assert_codex_no_decision();
}
