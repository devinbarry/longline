use serde::{Deserialize, Serialize};

/// Decision output for policy and hook evaluation.
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
    fn test_decision_ordering() {
        assert!(Decision::Deny > Decision::Ask);
        assert!(Decision::Ask > Decision::Allow);
    }
}
