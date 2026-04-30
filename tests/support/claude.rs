use serde_json::json;

use super::bin::run_longline;
use super::config::{static_test_home, TestEnv};
use super::paths::rules_path;
use super::result::RunResult;

pub trait ClaudeRunResultExt {
    fn claude_decision(&self) -> String;
    fn claude_reason(&self) -> String;
    fn assert_claude_decision(&self, expected: &str);
    fn assert_claude_reason_contains(&self, substring: &str);
    fn assert_claude_reason_not_contains(&self, substring: &str);
}

impl ClaudeRunResultExt for RunResult {
    /// Parse hook JSON stdout and return the permissionDecision value.
    fn claude_decision(&self) -> String {
        let parsed: serde_json::Value = serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "Failed to parse stdout as JSON: {e}\nstdout: {}\nstderr: {}",
                self.stdout, self.stderr
            )
        });
        parsed["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "Missing hookSpecificOutput.permissionDecision in: {}",
                    self.stdout
                )
            })
            .to_string()
    }

    /// Parse hook JSON stdout and return the permissionDecisionReason value.
    fn claude_reason(&self) -> String {
        let parsed: serde_json::Value = serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "Failed to parse stdout as JSON: {e}\nstdout: {}\nstderr: {}",
                self.stdout, self.stderr
            )
        });
        parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "Missing hookSpecificOutput.permissionDecisionReason in: {}",
                    self.stdout
                )
            })
            .to_string()
    }

    /// Assert that the decision matches `expected`, with a descriptive panic on failure.
    fn assert_claude_decision(&self, expected: &str) {
        let actual = self.claude_decision();
        assert_eq!(
            actual, expected,
            "Expected decision '{}' but got '{}'\nstdout: {}\nstderr: {}",
            expected, actual, self.stdout, self.stderr
        );
    }

    /// Assert that the reason contains `substring`.
    fn assert_claude_reason_contains(&self, substring: &str) {
        let reason = self.claude_reason();
        assert!(
            reason.contains(substring),
            "Expected reason to contain '{}' but got: {}\nstdout: {}\nstderr: {}",
            substring,
            reason,
            self.stdout,
            self.stderr
        );
    }

    /// Assert that the reason does NOT contain `substring`.
    fn assert_claude_reason_not_contains(&self, substring: &str) {
        let reason = self.claude_reason();
        assert!(
            !reason.contains(substring),
            "Expected reason to NOT contain '{}' but got: {}\nstdout: {}\nstderr: {}",
            substring,
            reason,
            self.stdout,
            self.stderr
        );
    }
}

pub trait ClaudeTestEnvExt {
    fn run_claude_hook(&self, command: &str) -> RunResult;
    fn run_claude_hook_with_flags(&self, command: &str, extra_args: &[&str]) -> RunResult;
    fn run_claude_tool_hook(&self, tool_name: &str, command: &str) -> RunResult;
}

impl ClaudeTestEnvExt for TestEnv {
    /// Run the longline binary in hook mode with embedded defaults.
    /// Sends a Bash tool hook JSON on stdin.
    fn run_claude_hook(&self, command: &str) -> RunResult {
        self.run_claude_hook_with_flags(command, &[])
    }

    /// Run the longline binary in hook mode with extra CLI flags.
    fn run_claude_hook_with_flags(&self, command: &str, extra_args: &[&str]) -> RunResult {
        let cwd = self
            .project_path_opt()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| "/tmp".to_string());
        let input = claude_command_hook_input("Bash", command, &cwd);

        run_longline(extra_args, self.home_path(), Some(&input))
    }

    /// Run the longline binary in hook mode for a non-Bash tool.
    fn run_claude_tool_hook(&self, tool_name: &str, command: &str) -> RunResult {
        let cwd = self
            .project_path_opt()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| "/tmp".to_string());
        let input = claude_command_hook_input(tool_name, command, &cwd);

        run_longline(&[], self.home_path(), Some(&input))
    }
}

pub fn claude_command_hook_input(tool_name: &str, command: &str, cwd: &str) -> String {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "command": command },
        "session_id": "test-session",
        "cwd": cwd
    })
    .to_string()
}

pub fn run_claude_hook(tool_name: &str, command: &str) -> RunResult {
    run_claude_hook_with_flags(tool_name, command, &[])
}

pub fn run_claude_hook_with_flags(
    tool_name: &str,
    command: &str,
    extra_args: &[&str],
) -> RunResult {
    let input = claude_command_hook_input(tool_name, command, "/tmp");
    let config = rules_path();
    let mut args = vec!["--config", &config];
    args.extend_from_slice(extra_args);

    run_longline(&args, static_test_home(), Some(&input))
}

pub fn run_claude_hook_with_config(tool_name: &str, command: &str, config: &str) -> RunResult {
    let input = claude_command_hook_input(tool_name, command, "/tmp");
    run_longline(&["--config", config], static_test_home(), Some(&input))
}

pub fn run_claude_read_hook(file_path: &str) -> RunResult {
    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": file_path },
        "session_id": "test-session",
        "cwd": "/tmp"
    })
    .to_string();

    let config = rules_path();
    run_longline(&["--config", &config], static_test_home(), Some(&input))
}

pub fn run_claude_grep_hook(pattern: &str, path: Option<&str>) -> RunResult {
    let mut tool_input = json!({ "pattern": pattern });
    if let Some(p) = path {
        tool_input["path"] = serde_json::Value::String(p.to_string());
    }

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": tool_input,
        "session_id": "test-session",
        "cwd": "/tmp"
    })
    .to_string();

    let config = rules_path();
    run_longline(&["--config", &config], static_test_home(), Some(&input))
}

pub fn run_claude_glob_hook(pattern: &str, path: Option<&str>) -> RunResult {
    let mut tool_input = json!({ "pattern": pattern });
    if let Some(p) = path {
        tool_input["path"] = serde_json::Value::String(p.to_string());
    }

    let input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": tool_input,
        "session_id": "test-session",
        "cwd": "/tmp"
    })
    .to_string();

    let config = rules_path();
    run_longline(&["--config", &config], static_test_home(), Some(&input))
}
