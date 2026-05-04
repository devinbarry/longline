use serde::{Deserialize, Serialize};

use crate::evaluator;

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

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum CodexEvent {
    PreToolUse,
    PermissionRequest,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum CodexHookAction {
    /// Bash on a recognized event: evaluate the command.
    Evaluate {
        event: CodexEvent,
        invocation: evaluator::Invocation,
    },
    /// Recognized event with non-Bash tool, or recognized-but-unhandled event.
    /// Empty stdout, no stderr, no JSONL.
    SilentPassthrough,
    /// Malformed input (parse failed, missing/empty hook_event_name, etc.).
    /// Empty stdout + stderr message + JSONL fail-open entry.
    Malformed { reason: String },
}

#[allow(dead_code)]
fn action_from_pre_tool_use(input: CodexPreToolUseInput) -> CodexHookAction {
    match input.tool_name.as_deref() {
        Some("Bash") => CodexHookAction::Evaluate {
            event: CodexEvent::PreToolUse,
            invocation: evaluator::Invocation::Shell {
                command: input.tool_input.and_then(|t| t.command),
                cwd: input.cwd,
                session_id: input.session_id,
            },
        },
        _ => CodexHookAction::SilentPassthrough,
    }
}

#[allow(dead_code)]
fn action_from_permission_request(input: CodexPermissionRequestInput) -> CodexHookAction {
    match input.tool_name.as_deref() {
        Some("Bash") => CodexHookAction::Evaluate {
            event: CodexEvent::PermissionRequest,
            invocation: evaluator::Invocation::Shell {
                command: input.tool_input.and_then(|t| t.command),
                cwd: input.cwd,
                session_id: input.session_id,
            },
        },
        _ => CodexHookAction::SilentPassthrough,
    }
}

#[allow(dead_code)]
fn action_from_input_str(raw: &str) -> CodexHookAction {
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return CodexHookAction::Malformed {
                reason: format!("failed to parse hook input JSON: {e}"),
            };
        }
    };

    let event_name = value
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match event_name {
        "" => CodexHookAction::Malformed {
            reason: "missing or empty hook_event_name".into(),
        },
        "PreToolUse" => match serde_json::from_value::<CodexPreToolUseInput>(value) {
            Ok(input) => action_from_pre_tool_use(input),
            Err(e) => CodexHookAction::Malformed {
                reason: format!("failed to parse PreToolUse input: {e}"),
            },
        },
        "PermissionRequest" => match serde_json::from_value::<CodexPermissionRequestInput>(value) {
            Ok(input) => action_from_permission_request(input),
            Err(e) => CodexHookAction::Malformed {
                reason: format!("failed to parse PermissionRequest input: {e}"),
            },
        },
        // Recognized-but-unhandled event names AND unknown event names take
        // the same silent-passthrough path. Forward-compatible with future
        // Codex events.
        _ => CodexHookAction::SilentPassthrough,
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

    #[test]
    fn action_pre_tool_use_bash_routes_to_evaluate() {
        let json = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/repo","session_id":"s"}"#;
        match action_from_input_str(json) {
            CodexHookAction::Evaluate {
                event: CodexEvent::PreToolUse,
                invocation:
                    evaluator::Invocation::Shell {
                        command,
                        cwd,
                        session_id,
                    },
            } => {
                assert_eq!(command.as_deref(), Some("ls"));
                assert_eq!(cwd.as_deref(), Some("/repo"));
                assert_eq!(session_id.as_deref(), Some("s"));
            }
            other => panic!("expected Evaluate(PreToolUse, Shell), got {other:?}"),
        }
    }

    #[test]
    fn action_permission_request_bash_routes_to_evaluate() {
        let json = r#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        match action_from_input_str(json) {
            CodexHookAction::Evaluate {
                event: CodexEvent::PermissionRequest,
                invocation: evaluator::Invocation::Shell { command, .. },
            } => {
                assert_eq!(command.as_deref(), Some("rm -rf /"));
            }
            other => panic!("expected Evaluate(PermissionRequest, Shell), got {other:?}"),
        }
    }

    #[test]
    fn action_pre_tool_use_apply_patch_is_silent_passthrough() {
        let json = r#"{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{}}"#;
        assert!(matches!(
            action_from_input_str(json),
            CodexHookAction::SilentPassthrough
        ));
    }

    #[test]
    fn action_pre_tool_use_mcp_is_silent_passthrough() {
        let json = r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__filesystem__read_file","tool_input":{}}"#;
        assert!(matches!(
            action_from_input_str(json),
            CodexHookAction::SilentPassthrough
        ));
    }

    #[test]
    fn action_post_tool_use_is_silent_passthrough() {
        let json =
            r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        assert!(matches!(
            action_from_input_str(json),
            CodexHookAction::SilentPassthrough
        ));
    }

    #[test]
    fn action_session_start_is_silent_passthrough() {
        let json = r#"{"hook_event_name":"SessionStart"}"#;
        assert!(matches!(
            action_from_input_str(json),
            CodexHookAction::SilentPassthrough
        ));
    }

    #[test]
    fn action_unknown_event_is_silent_passthrough() {
        let json = r#"{"hook_event_name":"FutureCodexEvent","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        assert!(matches!(
            action_from_input_str(json),
            CodexHookAction::SilentPassthrough
        ));
    }

    #[test]
    fn action_missing_event_name_is_malformed() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        assert!(matches!(
            action_from_input_str(json),
            CodexHookAction::Malformed { .. }
        ));
    }

    #[test]
    fn action_empty_event_name_is_malformed() {
        let json = r#"{"hook_event_name":"","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        assert!(matches!(
            action_from_input_str(json),
            CodexHookAction::Malformed { .. }
        ));
    }

    #[test]
    fn action_invalid_json_is_malformed() {
        let json = r#"{"this is": "not valid"#;
        assert!(matches!(
            action_from_input_str(json),
            CodexHookAction::Malformed { .. }
        ));
    }
}
