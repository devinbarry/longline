use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::evaluator;
use longline::domain::Decision;
use longline::policy;

/// Input JSON from Claude Code hook on stdin.
#[derive(Debug, Deserialize)]
struct ClaudeHookInput {
    session_id: Option<String>,
    cwd: Option<String>,
    #[allow(dead_code)]
    hook_event_name: Option<String>,
    tool_name: String,
    tool_input: ClaudeToolInput,
    #[allow(dead_code)]
    tool_use_id: Option<String>,
}

/// Claude tool-specific input fields.
#[derive(Debug, Deserialize)]
struct ClaudeToolInput {
    command: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    file_path: Option<String>,
    path: Option<String>,
    #[allow(dead_code)]
    pattern: Option<String>,
}

/// Claude hook-specific output wrapper.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaudePreToolUseDecisionOutput {
    hook_event_name: String,
    permission_decision: Decision,
    permission_decision_reason: String,
}

/// Top-level Claude hook output JSON written to stdout.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeHookOutput {
    hook_specific_output: ClaudePreToolUseDecisionOutput,
}

#[derive(Debug, Clone)]
enum ClaudeHookAction {
    Evaluate(evaluator::Invocation),
    Passthrough { cwd: Option<String> },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HookOptions {
    pub ask_on_deny: bool,
    pub ask_ai: bool,
    pub ask_ai_lenient: bool,
    pub cli_trust_level: Option<policy::TrustLevel>,
    pub cli_safety_level: Option<policy::SafetyLevel>,
}

pub(crate) fn run_hook(
    rules_config: policy::RulesConfig,
    home: &Path,
    options: HookOptions,
) -> i32 {
    let mut input_str = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input_str) {
        let output = ClaudeHookOutput::decision(Decision::Ask, "Failed to read stdin");
        print_json(&output);
        eprintln!("longline: failed to read stdin: {e}");
        return 0;
    }

    run_hook_input(rules_config, home, options, &input_str)
}

fn run_hook_input(
    rules_config: policy::RulesConfig,
    home: &Path,
    options: HookOptions,
    input_str: &str,
) -> i32 {
    let hook_input: ClaudeHookInput = match serde_json::from_str(input_str) {
        Ok(h) => h,
        Err(e) => {
            let output = ClaudeHookOutput::decision(
                Decision::Ask,
                &format!("Failed to parse hook input: {e}"),
            );
            print_json(&output);
            return 0;
        }
    };

    match action_from_input(hook_input) {
        ClaudeHookAction::Evaluate(invocation) => {
            let eval_options = evaluator::EvaluationOptions {
                ask_on_deny: options.ask_on_deny,
                ask_ai: options.ask_ai,
                ask_ai_lenient: options.ask_ai_lenient,
                cli_trust_level: options.cli_trust_level,
                cli_safety_level: options.cli_safety_level,
            };

            let outcome = match evaluator::evaluate_invocation(
                rules_config,
                home,
                invocation,
                eval_options,
            ) {
                Ok(outcome) => outcome,
                Err(evaluator::EvaluationError::Config(e)) => {
                    eprintln!("longline: {e}");
                    return 2;
                }
            };

            let output = ClaudeHookOutput::decision(outcome.decision, &outcome.reason);
            print_json(&output);
            0
        }
        ClaudeHookAction::Passthrough { cwd } => {
            let cwd_path = cwd.as_deref().map(PathBuf::from);
            if let Err(e) = evaluator::finalize_config(
                rules_config,
                home,
                cwd_path.as_deref(),
                options.cli_trust_level,
                options.cli_safety_level,
            ) {
                eprintln!("longline: {e}");
                return 2;
            }
            println!("{{}}");
            0
        }
    }
}

fn action_from_input(input: ClaudeHookInput) -> ClaudeHookAction {
    match input.tool_name.as_str() {
        "Read" => ClaudeHookAction::Evaluate(evaluator::Invocation::ReadPath {
            tool_name: input.tool_name.clone(),
            path: input.tool_input.file_path,
            cwd: input.cwd,
            session_id: input.session_id,
        }),
        "Grep" | "Glob" => ClaudeHookAction::Evaluate(evaluator::Invocation::SearchPath {
            tool_name: input.tool_name.clone(),
            path: input.tool_input.path,
            cwd: input.cwd,
            session_id: input.session_id,
        }),
        "Bash" => ClaudeHookAction::Evaluate(evaluator::Invocation::Shell {
            command: input.tool_input.command,
            cwd: input.cwd,
            session_id: input.session_id,
        }),
        _ => ClaudeHookAction::Passthrough { cwd: input.cwd },
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("longline: failed to serialize output: {e}");
            println!("{{}}");
        }
    }
}

impl ClaudeHookOutput {
    fn decision(decision: Decision, reason: &str) -> Self {
        Self {
            hook_specific_output: ClaudePreToolUseDecisionOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision,
                permission_decision_reason: reason.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_action(json: serde_json::Value) -> ClaudeHookAction {
        let input: ClaudeHookInput = serde_json::from_value(json).unwrap();
        action_from_input(input)
    }

    #[test]
    fn deserializes_full_claude_hook_input() {
        let json = r#"{"session_id":"abc123","cwd":"/Users/dev/project","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/build","description":"Clean build directory"},"tool_use_id":"toolu_01ABC123"}"#;
        let input: ClaudeHookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(
            input.tool_input.command.as_deref(),
            Some("rm -rf /tmp/build")
        );
        assert_eq!(input.session_id.as_deref(), Some("abc123"));
        assert_eq!(input.cwd.as_deref(), Some("/Users/dev/project"));
        assert_eq!(input.hook_event_name.as_deref(), Some("PreToolUse"));
        assert_eq!(input.tool_use_id.as_deref(), Some("toolu_01ABC123"));
    }

    #[test]
    fn deserializes_minimal_claude_hook_input() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let input: ClaudeHookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input.command.as_deref(), Some("ls"));
        assert!(input.session_id.is_none());
        assert!(input.cwd.is_none());
    }

    #[test]
    fn serializes_deny_output() {
        let output = ClaudeHookOutput::decision(Decision::Deny, "[rm-root] Destructive operation");
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&output).unwrap()).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"],
            "[rm-root] Destructive operation"
        );
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn serializes_ask_output() {
        let output = ClaudeHookOutput::decision(Decision::Ask, "Risky command");
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&output).unwrap()).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "ask");
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"],
            "Risky command"
        );
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn serializes_allow_output() {
        let output = ClaudeHookOutput::decision(Decision::Allow, "longline: allowlisted");
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&output).unwrap()).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"],
            "longline: allowlisted"
        );
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn maps_bash_to_shell_invocation_with_fields_preserved() {
        let action = parse_action(serde_json::json!({
            "session_id": "session-1",
            "cwd": "/repo",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "ls -la" }
        }));

        match action {
            ClaudeHookAction::Evaluate(evaluator::Invocation::Shell {
                command,
                cwd,
                session_id,
            }) => {
                assert_eq!(command.as_deref(), Some("ls -la"));
                assert_eq!(cwd.as_deref(), Some("/repo"));
                assert_eq!(session_id.as_deref(), Some("session-1"));
            }
            other => panic!("expected shell invocation, got {other:?}"),
        }
    }

    #[test]
    fn maps_read_to_read_path_invocation_with_fields_preserved() {
        let action = parse_action(serde_json::json!({
            "session_id": "session-2",
            "cwd": "/repo",
            "tool_name": "Read",
            "tool_input": { "file_path": "/repo/src/main.rs" }
        }));

        match action {
            ClaudeHookAction::Evaluate(evaluator::Invocation::ReadPath {
                tool_name,
                path,
                cwd,
                session_id,
            }) => {
                assert_eq!(tool_name, "Read");
                assert_eq!(path.as_deref(), Some("/repo/src/main.rs"));
                assert_eq!(cwd.as_deref(), Some("/repo"));
                assert_eq!(session_id.as_deref(), Some("session-2"));
            }
            other => panic!("expected read path invocation, got {other:?}"),
        }
    }

    #[test]
    fn maps_grep_to_search_path_invocation_with_fields_preserved() {
        let action = parse_action(serde_json::json!({
            "session_id": "session-3",
            "cwd": "/repo",
            "tool_name": "Grep",
            "tool_input": { "pattern": "TODO", "path": "src/" }
        }));

        match action {
            ClaudeHookAction::Evaluate(evaluator::Invocation::SearchPath {
                tool_name,
                path,
                cwd,
                session_id,
            }) => {
                assert_eq!(tool_name, "Grep");
                assert_eq!(path.as_deref(), Some("src/"));
                assert_eq!(cwd.as_deref(), Some("/repo"));
                assert_eq!(session_id.as_deref(), Some("session-3"));
            }
            other => panic!("expected search path invocation, got {other:?}"),
        }
    }

    #[test]
    fn maps_glob_to_search_path_invocation_with_fields_preserved() {
        let action = parse_action(serde_json::json!({
            "session_id": "session-4",
            "cwd": "/repo",
            "tool_name": "Glob",
            "tool_input": { "pattern": "*.rs", "path": "src/" }
        }));

        match action {
            ClaudeHookAction::Evaluate(evaluator::Invocation::SearchPath {
                tool_name,
                path,
                cwd,
                session_id,
            }) => {
                assert_eq!(tool_name, "Glob");
                assert_eq!(path.as_deref(), Some("src/"));
                assert_eq!(cwd.as_deref(), Some("/repo"));
                assert_eq!(session_id.as_deref(), Some("session-4"));
            }
            other => panic!("expected search path invocation, got {other:?}"),
        }
    }

    #[test]
    fn classifies_unsupported_tool_as_passthrough_with_cwd_preserved() {
        let action = parse_action(serde_json::json!({
            "session_id": "session-5",
            "cwd": "/repo",
            "tool_name": "Write",
            "tool_input": { "file_path": "/repo/out.txt" }
        }));

        match action {
            ClaudeHookAction::Passthrough { cwd } => {
                assert_eq!(cwd.as_deref(), Some("/repo"));
            }
            other => panic!("expected passthrough, got {other:?}"),
        }
    }
}
