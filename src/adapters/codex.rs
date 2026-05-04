use serde::{Deserialize, Serialize};

/// Codex `PreToolUse` hook input. Snake_case JSON, no `deny_unknown_fields`
/// so Codex-specific extensions (`turn_id`, `permission_mode`, etc.) and
/// future fields are tolerated.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CodexPreToolUseInput {
    #[allow(dead_code)]
    session_id: Option<String>,
    cwd: Option<String>,
    #[allow(dead_code)]
    hook_event_name: Option<String>,
    tool_name: Option<String>,
    tool_input: Option<CodexToolInput>,
    // Codex extensions are not consumed but must be tolerated:
    #[allow(dead_code)]
    turn_id: Option<String>,
    #[allow(dead_code)]
    transcript_path: Option<serde_json::Value>,
    #[allow(dead_code)]
    model: Option<String>,
    #[allow(dead_code)]
    permission_mode: Option<String>,
    #[allow(dead_code)]
    tool_use_id: Option<String>,
}

/// Codex `PermissionRequest` hook input. Same shape as PreToolUse minus
/// `tool_use_id`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CodexPermissionRequestInput {
    #[allow(dead_code)]
    session_id: Option<String>,
    cwd: Option<String>,
    #[allow(dead_code)]
    hook_event_name: Option<String>,
    tool_name: Option<String>,
    tool_input: Option<CodexToolInput>,
    #[allow(dead_code)]
    turn_id: Option<String>,
    #[allow(dead_code)]
    transcript_path: Option<serde_json::Value>,
    #[allow(dead_code)]
    model: Option<String>,
    #[allow(dead_code)]
    permission_mode: Option<String>,
}

/// A loose union shape that captures whichever fields a tool sends. For
/// `Bash` we only consume `command`; other tools may set arbitrary fields.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CodexToolInput {
    command: Option<String>,
}

/// Typed enum prevents emitting forbidden literals like "allow" or "ask"
/// on PreToolUse, which would fail open per Codex's
/// `unsupported_permission_decision_fails_open` regression test.
#[derive(Serialize)]
#[allow(dead_code)]
enum PreToolUsePermissionDecision {
    #[serde(rename = "deny")]
    Deny,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
enum PermissionRequestBehavior {
    Allow,
    Deny,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CodexPreToolUseDecisionOutput {
    hook_specific_output: CodexPreToolUseHookSpecificOutput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CodexPreToolUseHookSpecificOutput {
    hook_event_name: &'static str,
    permission_decision: PreToolUsePermissionDecision,
    permission_decision_reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CodexPermissionRequestDecisionOutput {
    hook_specific_output: CodexPermissionRequestHookSpecificOutput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CodexPermissionRequestHookSpecificOutput {
    hook_event_name: &'static str,
    decision: CodexPermissionBehavior,
}

#[derive(Serialize)]
#[allow(dead_code)]
struct CodexPermissionBehavior {
    behavior: PermissionRequestBehavior,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[allow(dead_code)]
impl CodexPreToolUseDecisionOutput {
    fn deny(reason: String) -> Self {
        Self {
            hook_specific_output: CodexPreToolUseHookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: PreToolUsePermissionDecision::Deny,
                permission_decision_reason: reason,
            },
        }
    }
}

#[allow(dead_code)]
impl CodexPermissionRequestDecisionOutput {
    fn allow() -> Self {
        Self {
            hook_specific_output: CodexPermissionRequestHookSpecificOutput {
                hook_event_name: "PermissionRequest",
                decision: CodexPermissionBehavior {
                    behavior: PermissionRequestBehavior::Allow,
                    message: None,
                },
            },
        }
    }

    fn deny(message: String) -> Self {
        Self {
            hook_specific_output: CodexPermissionRequestHookSpecificOutput {
                hook_event_name: "PermissionRequest",
                decision: CodexPermissionBehavior {
                    behavior: PermissionRequestBehavior::Deny,
                    message: Some(message),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_full_pre_tool_use_input() {
        let json = r#"{
            "session_id":"sess-1",
            "turn_id":"turn-1",
            "transcript_path":null,
            "cwd":"/repo",
            "hook_event_name":"PreToolUse",
            "model":"gpt-5",
            "permission_mode":"default",
            "tool_name":"Bash",
            "tool_input":{"command":"ls"},
            "tool_use_id":"tu-1"
        }"#;
        let input: CodexPreToolUseInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert_eq!(input.cwd.as_deref(), Some("/repo"));
        assert_eq!(
            input.tool_input.and_then(|t| t.command).as_deref(),
            Some("ls")
        );
    }

    #[test]
    fn deserialize_pre_tool_use_with_only_required_fields() {
        let json = r#"{
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"ls"}
        }"#;
        let input: CodexPreToolUseInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert!(input.session_id.is_none());
        assert!(input.cwd.is_none());
    }

    #[test]
    fn deserialize_permission_request_input() {
        let json = r#"{
            "session_id":"s",
            "turn_id":"t",
            "cwd":"/repo",
            "hook_event_name":"PermissionRequest",
            "model":"gpt-5",
            "permission_mode":"default",
            "tool_name":"Bash",
            "tool_input":{"command":"rm -rf /"}
        }"#;
        let input: CodexPermissionRequestInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert_eq!(input.cwd.as_deref(), Some("/repo"));
    }

    #[test]
    fn deserialize_with_unknown_future_fields_is_tolerated() {
        let json = r#"{
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"ls"},
            "future_field":"surprise",
            "another":{"nested":42}
        }"#;
        // Must not error; deny_unknown_fields is OFF.
        let input: CodexPreToolUseInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
    }

    #[test]
    fn deserialize_with_empty_cwd_string() {
        let json = r#"{
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"ls"},
            "cwd":""
        }"#;
        let input: CodexPreToolUseInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.cwd.as_deref(), Some(""));
    }

    #[test]
    fn serialize_pre_tool_use_deny_byte_exact() {
        let out = CodexPreToolUseDecisionOutput::deny("rule [rm-root] blocked".to_string());
        let json = serde_json::to_string(&out).unwrap();
        assert_eq!(
            json,
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"rule [rm-root] blocked"}}"#
        );
    }

    #[test]
    fn serialize_permission_request_allow_byte_exact() {
        let out = CodexPermissionRequestDecisionOutput::allow();
        let json = serde_json::to_string(&out).unwrap();
        assert_eq!(
            json,
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#
        );
    }

    #[test]
    fn serialize_permission_request_deny_with_message_byte_exact() {
        let out =
            CodexPermissionRequestDecisionOutput::deny("rule [curl-pipe-sh] blocked".to_string());
        let json = serde_json::to_string(&out).unwrap();
        assert_eq!(
            json,
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"rule [curl-pipe-sh] blocked"}}}"#
        );
    }
}
