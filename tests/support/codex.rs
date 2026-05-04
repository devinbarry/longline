use super::result::RunResult;

pub trait CodexRunResultExt {
    fn codex_pre_tool_use_decision(&self) -> Option<String>;
    fn codex_pre_tool_use_reason(&self) -> Option<String>;
    fn codex_permission_request_behavior(&self) -> Option<String>;
    fn codex_permission_request_message(&self) -> Option<String>;
    fn assert_codex_no_decision(&self);
    fn assert_codex_permission_request_behavior(&self, expected: &str);
}

impl CodexRunResultExt for RunResult {
    fn codex_pre_tool_use_decision(&self) -> Option<String> {
        if self.stdout.is_empty() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&self.stdout).ok()?;
        v["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .map(String::from)
    }

    fn codex_pre_tool_use_reason(&self) -> Option<String> {
        if self.stdout.is_empty() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&self.stdout).ok()?;
        v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .map(String::from)
    }

    fn codex_permission_request_behavior(&self) -> Option<String> {
        if self.stdout.is_empty() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&self.stdout).ok()?;
        v["hookSpecificOutput"]["decision"]["behavior"]
            .as_str()
            .map(String::from)
    }

    fn codex_permission_request_message(&self) -> Option<String> {
        if self.stdout.is_empty() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&self.stdout).ok()?;
        v["hookSpecificOutput"]["decision"]["message"]
            .as_str()
            .map(String::from)
    }

    fn assert_codex_no_decision(&self) {
        assert!(
            self.stdout.is_empty(),
            "expected empty stdout for no-decision; got: {:?}",
            self.stdout
        );
    }

    fn assert_codex_permission_request_behavior(&self, expected: &str) {
        assert_eq!(
            self.codex_permission_request_behavior().as_deref(),
            Some(expected),
            "stdout: {:?}",
            self.stdout
        );
    }
}
