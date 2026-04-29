#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use longline::domain::Decision;

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
}
