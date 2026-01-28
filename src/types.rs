use serde::{Deserialize, Serialize};

/// Input JSON from Claude Code hook on stdin.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    #[allow(dead_code)]
    pub hook_event_name: Option<String>,
    pub tool_name: String,
    pub tool_input: ToolInput,
    #[allow(dead_code)]
    pub tool_use_id: Option<String>,
}

/// Tool-specific input fields.
#[derive(Debug, Deserialize)]
pub struct ToolInput {
    pub command: Option<String>,
    #[allow(dead_code)]
    pub description: Option<String>,
    #[allow(dead_code)]
    pub file_path: Option<String>,
}

/// Decision output for the hook protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Decision::Allow => "allow",
            Decision::Ask => "ask",
            Decision::Deny => "deny",
        })
    }
}

/// Hook-specific output wrapper.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: String,
    pub permission_decision: Decision,
    pub permission_decision_reason: String,
}

/// Top-level output JSON written to stdout.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    pub hook_specific_output: HookSpecificOutput,
}

impl HookOutput {
    pub fn decision(decision: Decision, reason: &str) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision,
                permission_decision_reason: reason.to_string(),
            },
        }
    }
}

/// The result of evaluating a command against the policy engine.
#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub decision: Decision,
    pub rule_id: Option<String>,
    pub reason: String,
}

impl PolicyResult {
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            rule_id: None,
            reason: String::new(),
        }
    }
    #[allow(dead_code)]
    pub fn ask(reason: &str) -> Self {
        Self {
            decision: Decision::Ask,
            rule_id: None,
            reason: reason.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_hook_input() {
        let json = r#"{"session_id":"abc123","cwd":"/Users/dev/project","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/build","description":"Clean build directory"},"tool_use_id":"toolu_01ABC123"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(
            input.tool_input.command.as_deref(),
            Some("rm -rf /tmp/build")
        );
        assert_eq!(input.session_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_deserialize_minimal_hook_input() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert!(input.session_id.is_none());
    }

    #[test]
    fn test_serialize_deny_output() {
        let output = HookOutput::decision(Decision::Deny, "[rm-root] Destructive operation");
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"],
            "[rm-root] Destructive operation"
        );
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn test_serialize_ask_output() {
        let output = HookOutput::decision(Decision::Ask, "Risky command");
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    #[test]
    fn test_hook_output_allow_serializes_correctly() {
        let output = HookOutput::decision(Decision::Allow, "longline: allowlisted");
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecision"],
            "allow"
        );
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"],
            "longline: allowlisted"
        );
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn test_decision_ordering() {
        assert!(Decision::Deny > Decision::Ask);
        assert!(Decision::Ask > Decision::Allow);
    }
}
